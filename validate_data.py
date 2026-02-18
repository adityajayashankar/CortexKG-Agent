"""
validate_dataset.py
-------------------
Pre-training dataset health check.

Run BEFORE finetuning.py to surface problems early:
  • Length distribution (too-short / too-long examples)
  • Layer balance (are some layers severely under-represented?)
  • Output quality (blank, duplicate, or truncated outputs)
  • Tokenizer fit (how many examples exceed max_length at actual token level)
  • Dataset readiness verdict

Usage:
    python validate_dataset.py
    python validate_dataset.py --path data/training_pairs.jsonl --max-tokens 2048
    python validate_dataset.py --fix   # auto-drop bad examples and rewrite file
"""

import json
import re
import argparse
from collections import Counter
from pathlib import Path


# ── Config ─────────────────────────────────────────────────────────────────────
DEFAULT_PATH      = "data/training_pairs.jsonl"
MIN_OUTPUT_CHARS  = 80          # same threshold as filter_training_pairs in build_dataset.py
MAX_TOKENS        = 2048        # must match SFTConfig.max_length in finetuning.py
CHARS_PER_TOKEN   = 3.8         # conservative estimate for security/technical text
IDEAL_LAYER_SHARE = 0.05        # flag if any layer is below 5% of total

PROMPT_TEMPLATE = (
    "### Instruction:\n{instruction}\n\n"
    "### Input:\n{input}\n\n"
    "### Response:\n{output}"
)


def load_pairs(path: str) -> list:
    p = Path(path)
    if not p.exists():
        print(f"❌ File not found: {path}")
        return []
    pairs = []
    with open(p, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                pairs.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  ⚠️  Line {i+1}: JSON parse error — {e}")
    return pairs


def estimate_tokens(pair: dict) -> int:
    text = PROMPT_TEMPLATE.format(
        instruction=pair.get("instruction", ""),
        input=pair.get("input", ""),
        output=pair.get("output", ""),
    )
    return int(len(text) / CHARS_PER_TOKEN)


def validate(pairs: list, max_tokens: int = MAX_TOKENS) -> dict:
    issues = {
        "empty_output":      [],
        "short_output":      [],
        "truncated_likely":  [],   # estimated tokens > max_tokens
        "duplicate":         [],
        "no_layer":          [],
        "instruction_equals_output": [],
    }

    layer_counts:   Counter = Counter()
    token_estimates: list   = []
    seen: dict              = {}

    for i, p in enumerate(pairs):
        instr  = p.get("instruction", "").strip()
        inp    = p.get("input", "").strip()
        output = p.get("output", "").strip()
        layer  = p.get("layer", "")

        # Track layers
        layer_counts[layer or "MISSING"] += 1
        if not layer:
            issues["no_layer"].append(i)

        # Empty / short outputs
        if not output:
            issues["empty_output"].append(i)
        elif len(output) < MIN_OUTPUT_CHARS:
            issues["short_output"].append(i)

        # Instruction == output (copy failure)
        if instr and output and instr == output:
            issues["instruction_equals_output"].append(i)

        # Deduplication
        key = (instr[:150], output[:200])
        if key in seen:
            issues["duplicate"].append((i, seen[key]))
        else:
            seen[key] = i

        # Token estimate
        est = estimate_tokens(p)
        token_estimates.append(est)
        if est > max_tokens:
            issues["truncated_likely"].append(i)

    return {
        "total":          len(pairs),
        "issues":         issues,
        "layer_counts":   layer_counts,
        "token_estimates": token_estimates,
    }


def print_report(result: dict, max_tokens: int):
    total  = result["total"]
    issues = result["issues"]
    layers = result["layer_counts"]
    tokens = result["token_estimates"]

    print("\n" + "=" * 62)
    print("  DATASET VALIDATION REPORT")
    print("=" * 62)
    print(f"\n  Total examples:   {total:,}")

    # ── Issue summary ──────────────────────────────────────────────
    print(f"\n  {'Issue':<42} {'Count':>8}  {'%':>6}")
    print(f"  {'-'*58}")
    checks = [
        ("Empty outputs",              "empty_output"),
        ("Short outputs (< 80 chars)", "short_output"),
        ("Likely truncated (> token limit)", "truncated_likely"),
        ("Duplicates",                 "duplicate"),
        ("Missing layer field",        "no_layer"),
        ("Instruction == output",      "instruction_equals_output"),
    ]
    total_issues = 0
    for label, key in checks:
        count = len(issues[key])
        pct   = 100 * count / max(total, 1)
        flag  = " ⚠️" if count > 0 else " ✅"
        print(f"  {label:<42} {count:>8,}  {pct:>5.1f}%{flag}")
        total_issues += count

    # ── Layer balance ──────────────────────────────────────────────
    print(f"\n  {'Layer':<42} {'Count':>8}  {'%':>6}")
    print(f"  {'-'*58}")
    for layer, count in sorted(layers.items(), key=lambda x: -x[1]):
        pct  = 100 * count / max(total, 1)
        flag = " ⚠️  (low)" if pct < IDEAL_LAYER_SHARE * 100 else ""
        print(f"  {layer:<42} {count:>8,}  {pct:>5.1f}%{flag}")

    # ── Token distribution ─────────────────────────────────────────
    if tokens:
        tokens_sorted = sorted(tokens)
        n = len(tokens_sorted)
        p50 = tokens_sorted[n // 2]
        p90 = tokens_sorted[int(n * 0.90)]
        p95 = tokens_sorted[int(n * 0.95)]
        p99 = tokens_sorted[int(n * 0.99)]
        over_limit = sum(1 for t in tokens if t > max_tokens)

        print(f"\n  Token estimates (chars / {CHARS_PER_TOKEN} — approximate):")
        print(f"    p50:  {p50:>6,} tokens")
        print(f"    p90:  {p90:>6,} tokens")
        print(f"    p95:  {p95:>6,} tokens")
        print(f"    p99:  {p99:>6,} tokens")
        print(f"    Over {max_tokens}-token limit: {over_limit:,} ({100*over_limit/max(n,1):.1f}%)")
        if over_limit / max(n, 1) > 0.15:
            print(f"    ⚠️  >15% of examples exceed max_length={max_tokens} — consider increasing or truncating.")

    # ── Verdict ────────────────────────────────────────────────────
    critical = (
        len(issues["empty_output"]) +
        len(issues["instruction_equals_output"])
    )
    severe = len(issues["short_output"]) + len(issues["duplicate"])

    print(f"\n  {'=' * 58}")
    if critical > 0:
        print(f"  ❌ VERDICT: NOT READY — {critical} critical issues must be fixed before training.")
    elif severe > total * 0.05:
        print(f"  ⚠️  VERDICT: MARGINAL — {severe} examples ({100*severe/max(total,1):.1f}%) below quality bar.")
        print(f"      Run with --fix to auto-clean, or re-run build_dataset.py.")
    else:
        print(f"  ✅ VERDICT: READY FOR FINE-TUNING")
        print(f"      {total:,} examples, {len(issues['truncated_likely'])} may be slightly truncated (acceptable).")
    print(f"  {'=' * 58}\n")


def fix_dataset(pairs: list, path: str):
    """Drop low-quality examples and rewrite the file in-place."""
    seen: dict  = {}
    clean: list = []
    dropped = 0

    for p in pairs:
        instr  = p.get("instruction", "").strip()
        output = p.get("output", "").strip()

        # Drop empty / too short
        if len(output) < MIN_OUTPUT_CHARS:
            dropped += 1
            continue

        # Drop instruction == output
        if instr and output == instr:
            dropped += 1
            continue

        # Drop duplicates
        key = (instr[:150], output[:200])
        if key in seen:
            dropped += 1
            continue
        seen[key] = True

        clean.append(p)

    with open(path, "w", encoding="utf-8") as f:
        for p in clean:
            f.write(json.dumps(p) + "\n")

    print(f"\n✅ Fixed dataset written to {path}")
    print(f"   Kept: {len(clean):,}  |  Dropped: {dropped:,}")


def main():
    parser = argparse.ArgumentParser(description="Validate training_pairs.jsonl before fine-tuning")
    parser.add_argument("--path",       default=DEFAULT_PATH,  help="Path to training_pairs.jsonl")
    parser.add_argument("--max-tokens", type=int, default=MAX_TOKENS, help="Max token budget per example")
    parser.add_argument("--fix",        action="store_true",   help="Auto-drop bad examples and rewrite file")
    args = parser.parse_args()

    print(f"\nLoading: {args.path}")
    pairs = load_pairs(args.path)
    if not pairs:
        return

    print(f"Loaded {len(pairs):,} examples. Running validation...")
    result = validate(pairs, max_tokens=args.max_tokens)
    print_report(result, max_tokens=args.max_tokens)

    if args.fix:
        print("--fix enabled: cleaning dataset...")
        fix_dataset(pairs, args.path)


if __name__ == "__main__":
    main()