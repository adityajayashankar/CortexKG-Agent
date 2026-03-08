"""
run_graphrag_benchmark.py
-------------------------
Held-out CVE benchmark evaluation for GraphRAG retrieval quality.

Features:
1) Uses GraphRAG retrieval API path (`pipeline.tools.tool_graphrag_query`).
2) Computes P@K, R@K, false-positive rate, and false-negative counts.
3) Auto-generates benchmark JSONL from raw artifacts if missing.

Benchmark JSONL schema:
  {
    "query_cve": "CVE-2021-12345",
    "expected_positive": ["CVE-....", "..."],
    "expected_negative": ["CVE-....", "..."],
    "notes": "optional"
  }
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


K_SET = (5, 10, 20)


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_cve(value: Any) -> str:
    return _normalize(value).upper()


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _iter_json_array_stream(path: Path) -> Iterator[Any]:
    if not path.exists():
        return
    decoder = json.JSONDecoder()
    in_array = False
    buf = ""
    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            if not in_array:
                idx = buf.find("[")
                if idx < 0:
                    if len(buf) > 32:
                        buf = buf[-32:]
                    continue
                buf = buf[idx + 1 :]
                in_array = True
            while in_array:
                buf = buf.lstrip()
                if not buf:
                    break
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                if buf[0] == "]":
                    return
                try:
                    obj, end = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                buf = buf[end:]
                yield obj


def _iter_named_array_stream(path: Path, key_name: str) -> Iterator[Any]:
    if not path.exists():
        return
    decoder = json.JSONDecoder()
    key = f'"{key_name}"'
    in_array = False
    buf = ""
    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            if not in_array:
                key_idx = buf.find(key)
                if key_idx < 0:
                    if len(buf) > len(key):
                        buf = buf[-len(key) :]
                    continue
                arr_idx = buf.find("[", key_idx)
                if arr_idx < 0:
                    continue
                buf = buf[arr_idx + 1 :]
                in_array = True
            while in_array:
                buf = buf.lstrip()
                if not buf:
                    break
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                if buf[0] == "]":
                    return
                try:
                    obj, end = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                buf = buf[end:]
                yield obj


def _stable_bucket(seed: int, key: str, modulo: int = 100) -> int:
    h = hashlib.sha1(f"{seed}:{key}".encode("utf-8")).hexdigest()
    return int(h[:8], 16) % modulo


def _upsert_topk(scores: dict[str, float], cve: str, score: float, cap: int) -> None:
    prev = scores.get(cve)
    if prev is None or score > prev:
        scores[cve] = score
    if len(scores) > cap * 3:
        items = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:cap]
        scores.clear()
        scores.update(items)


def generate_benchmark(
    benchmark_path: Path,
    corr_path: Path,
    cooc_path: Path,
    min_positive: int = 5,
    holdout_ratio: float = 0.2,
    max_queries: int = 300,
    expected_positive_cap: int = 20,
    expected_negative_count: int = 20,
    seed: int = 42,
) -> dict[str, Any]:
    corr_neighbors: dict[str, dict[str, float]] = defaultdict(dict)
    degree: Counter[str] = Counter()

    for rec in _iter_json_array_stream(corr_path):
        if not isinstance(rec, dict):
            continue
        cve = _normalize_cve(rec.get("cve_id"))
        if not cve.startswith("CVE-"):
            continue
        rels = rec.get("related_vulnerabilities", [])
        if not isinstance(rels, list):
            continue
        for rel in rels:
            if not isinstance(rel, dict):
                continue
            tgt = _normalize_cve(rel.get("cve_id"))
            if not tgt.startswith("CVE-") or tgt == cve:
                continue
            score = _to_float(rel.get("correlation_score"), 0.0)
            _upsert_topk(corr_neighbors[cve], tgt, score, expected_positive_cap)
            degree[cve] += 1
            degree[tgt] += 1

    candidates = [cve for cve, n in corr_neighbors.items() if len(n) >= min_positive]
    candidates.sort()

    holdout = [
        cve
        for cve in candidates
        if _stable_bucket(seed=seed, key=cve, modulo=100) < int(max(1, min(99, holdout_ratio * 100)))
    ]
    if not holdout:
        holdout = candidates[: max_queries]
    holdout = holdout[:max_queries]
    holdout_set = set(holdout)

    cooc_neighbors: dict[str, dict[str, float]] = defaultdict(dict)
    for pair in _iter_named_array_stream(cooc_path, "cooccurrence_pairs"):
        if not isinstance(pair, dict):
            continue
        a = _normalize_cve(pair.get("cve_a"))
        b = _normalize_cve(pair.get("cve_b"))
        if not a.startswith("CVE-") or not b.startswith("CVE-") or a == b:
            continue
        conf = _to_float(pair.get("confidence"), 0.0)
        if a in holdout_set:
            _upsert_topk(cooc_neighbors[a], b, conf, expected_positive_cap)
        if b in holdout_set:
            _upsert_topk(cooc_neighbors[b], a, conf, expected_positive_cap)
        degree[a] += 1
        degree[b] += 1

    frequent_pool = [cve for cve, _ in degree.most_common(10000)]
    rows: list[dict[str, Any]] = []
    for query in holdout:
        merged: dict[str, float] = {}
        for tgt, score in corr_neighbors.get(query, {}).items():
            if tgt != query:
                merged[tgt] = max(merged.get(tgt, 0.0), score)
        for tgt, score in cooc_neighbors.get(query, {}).items():
            if tgt != query:
                merged[tgt] = max(merged.get(tgt, 0.0), score)

        positives = [cve for cve, _ in sorted(merged.items(), key=lambda x: x[1], reverse=True)[:expected_positive_cap]]
        if len(positives) < min_positive:
            continue

        negatives = []
        for cve in frequent_pool:
            if cve == query or cve in merged:
                continue
            negatives.append(cve)
            if len(negatives) >= expected_negative_count:
                break

        rows.append(
            {
                "query_cve": query,
                "expected_positive": positives,
                "expected_negative": negatives,
                "notes": f"auto_generated seed={seed} positives={len(positives)} negatives={len(negatives)}",
            }
        )

    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    with benchmark_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {
        "path": str(benchmark_path),
        "rows_written": len(rows),
        "candidates": len(candidates),
        "holdout_selected": len(holdout),
    }


def load_benchmark(path: Path, max_probes: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            query = _normalize_cve(row.get("query_cve"))
            if not query.startswith("CVE-"):
                continue
            pos = [
                _normalize_cve(c)
                for c in row.get("expected_positive", [])
                if _normalize_cve(c).startswith("CVE-")
            ]
            neg = [
                _normalize_cve(c)
                for c in row.get("expected_negative", [])
                if _normalize_cve(c).startswith("CVE-")
            ]
            rows.append(
                {
                    "query_cve": query,
                    "expected_positive": list(dict.fromkeys(pos)),
                    "expected_negative": list(dict.fromkeys(neg)),
                    "notes": _normalize(row.get("notes")),
                }
            )
            if max_probes > 0 and len(rows) >= max_probes:
                break
    return rows


def _collect_predictions(payload: dict[str, Any], cap: int) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for tier_key in ("direct_evidence", "inferred_candidates"):
        items = payload.get(tier_key, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            cve = _normalize_cve(item.get("cve_id"))
            if not cve.startswith("CVE-"):
                continue
            score = _to_float(item.get("likelihood"), 0.0)
            rel_type = _normalize(item.get("rel_type"))
            evidence_tier = _normalize(item.get("evidence_tier"))
            cur = merged.get(cve)
            if cur is None or score > cur["likelihood"]:
                merged[cve] = {
                    "cve_id": cve,
                    "likelihood": score,
                    "rel_type": rel_type,
                    "evidence_tier": evidence_tier,
                }
    ordered = sorted(merged.values(), key=lambda x: x["likelihood"], reverse=True)
    return ordered[:cap]


def _metric_at_k(pred: list[str], pos_set: set[str], neg_set: set[str], k: int) -> dict[str, Any]:
    top = pred[:k]
    tp = sum(1 for c in top if c in pos_set)
    fp_explicit = sum(1 for c in top if c in neg_set)
    precision = tp / k if k > 0 else 0.0
    recall = tp / max(len(pos_set), 1)
    fp_rate = fp_explicit / k if k > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fp_rate": round(fp_rate, 4),
        "tp": tp,
        "fp_explicit": fp_explicit,
    }


def evaluate_entry(
    entry: dict[str, Any],
    top_k: int,
    max_hops: int,
    use_vector: bool,
) -> dict[str, Any]:
    from pipeline.tools import tool_graphrag_query

    query_cve = entry["query_cve"]
    req = {
        "query": query_cve,
        "entity": {"type": "cve", "id": query_cve},
        "top_k": top_k,
        "max_hops": max_hops,
        "use_vector": use_vector,
    }
    raw_resp = tool_graphrag_query(json.dumps(req))
    payload = json.loads(raw_resp)

    expected_pos = set(entry.get("expected_positive", []))
    expected_neg = set(entry.get("expected_negative", []))
    preds = _collect_predictions(payload, cap=max(20, top_k))
    pred_ids = [p["cve_id"] for p in preds]

    by_k = {f"K{k}": _metric_at_k(pred_ids, expected_pos, expected_neg, k) for k in K_SET}
    top20 = set(pred_ids[:20])
    false_negatives = sorted(expected_pos - top20)

    rel_counter: Counter[str] = Counter()
    rel_tp_counter: Counter[str] = Counter()
    for p in preds[:top_k]:
        rel = p.get("rel_type") or "UNKNOWN"
        rel_counter[rel] += 1
        if p["cve_id"] in expected_pos:
            rel_tp_counter[rel] += 1
    rel_precision = {
        rel: round(rel_tp_counter[rel] / rel_counter[rel], 4) for rel in sorted(rel_counter.keys())
    }

    explicit_fp_items = [
        {
            "predicted_cve": p["cve_id"],
            "likelihood": p["likelihood"],
            "rel_type": p["rel_type"],
            "tier": p["evidence_tier"],
        }
        for p in preds[:top_k]
        if p["cve_id"] in expected_neg
    ]

    return {
        "query_cve": query_cve,
        "status": payload.get("status", "unknown"),
        "expected_positive_count": len(expected_pos),
        "expected_negative_count": len(expected_neg),
        "returned_count": len(preds),
        "metrics_at_k": by_k,
        "false_negative_count": len(false_negatives),
        "false_negatives": false_negatives[:25],
        "relation_precision": rel_precision,
        "explicit_false_positives": explicit_fp_items[:25],
        "top_predictions": preds[:10],
        "confidence_summary": payload.get("confidence_summary", {}),
    }


def _mean(values: list[float]) -> float:
    return round(sum(values) / max(len(values), 1), 4)


def write_csv(results: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "query_cve",
        "status",
        "expected_positive_count",
        "expected_negative_count",
        "returned_count",
        "p_at_5",
        "p_at_10",
        "p_at_20",
        "r_at_5",
        "r_at_10",
        "r_at_20",
        "fp_rate_5",
        "fp_rate_10",
        "fp_rate_20",
        "false_negative_count",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            m = r.get("metrics_at_k", {})
            writer.writerow(
                {
                    "query_cve": r.get("query_cve"),
                    "status": r.get("status"),
                    "expected_positive_count": r.get("expected_positive_count"),
                    "expected_negative_count": r.get("expected_negative_count"),
                    "returned_count": r.get("returned_count"),
                    "p_at_5": m.get("K5", {}).get("precision"),
                    "p_at_10": m.get("K10", {}).get("precision"),
                    "p_at_20": m.get("K20", {}).get("precision"),
                    "r_at_5": m.get("K5", {}).get("recall"),
                    "r_at_10": m.get("K10", {}).get("recall"),
                    "r_at_20": m.get("K20", {}).get("recall"),
                    "fp_rate_5": m.get("K5", {}).get("fp_rate"),
                    "fp_rate_10": m.get("K10", {}).get("fp_rate"),
                    "fp_rate_20": m.get("K20", {}).get("fp_rate"),
                    "false_negative_count": r.get("false_negative_count"),
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Held-out GraphRAG retrieval benchmark.")
    parser.add_argument("--benchmark-file", default="eval/heldout_cve_benchmark.jsonl")
    parser.add_argument("--ground-truth", default="eval/ground_truth_benchmark.jsonl",
                        help="Path to curated analyst-labeled ground truth benchmark. "
                             "Use --use-ground-truth to run against this instead.")
    parser.add_argument("--use-ground-truth", action="store_true",
                        help="Run evaluation against the curated ground truth benchmark "
                             "instead of the auto-generated holdout set.")
    parser.add_argument("--corr-file", default="data/raw_correlations.json")
    parser.add_argument("--cooc-file", default="data/raw_cooccurrence_v2.json")
    parser.add_argument("--max-probes", type=int, default=120)
    parser.add_argument("--top-k", type=int, default=20)
    parser.add_argument("--max-hops", type=int, default=2)
    parser.add_argument("--use-vector", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-positive", type=int, default=5)
    parser.add_argument("--holdout-ratio", type=float, default=0.2)
    parser.add_argument("--max-benchmark-size", type=int, default=400)
    parser.add_argument("--expected-positive-cap", type=int, default=20)
    parser.add_argument("--expected-negative-count", type=int, default=20)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-csv", default="")
    parser.add_argument("--no-generate-if-missing", action="store_true")
    args = parser.parse_args()

    bench_path = Path(args.ground_truth) if args.use_ground_truth else Path(args.benchmark_file)
    if args.use_ground_truth:
        print(f"Using curated ground truth benchmark: {bench_path}")
    if not bench_path.exists():
        if args.no_generate_if_missing:
            print(f"Benchmark file not found and auto-generation disabled: {bench_path}")
            return 2
        gen = generate_benchmark(
            benchmark_path=bench_path,
            corr_path=Path(args.corr_file),
            cooc_path=Path(args.cooc_file),
            min_positive=max(1, args.min_positive),
            holdout_ratio=max(0.01, min(0.95, args.holdout_ratio)),
            max_queries=max(10, args.max_benchmark_size),
            expected_positive_cap=max(5, args.expected_positive_cap),
            expected_negative_count=max(5, args.expected_negative_count),
            seed=args.seed,
        )
        print(f"Generated benchmark: {gen}")

    probes = load_benchmark(bench_path, max_probes=max(1, args.max_probes))
    if not probes:
        print("No valid benchmark probes found.")
        return 2 if args.strict else 1

    results = []
    errors = 0
    for i, probe in enumerate(probes, start=1):
        try:
            res = evaluate_entry(
                entry=probe,
                top_k=max(1, args.top_k),
                max_hops=max(1, args.max_hops),
                use_vector=bool(args.use_vector),
            )
        except Exception as e:
            res = {
                "query_cve": probe.get("query_cve"),
                "status": "error",
                "error": str(e),
                "metrics_at_k": {},
                "false_negative_count": len(probe.get("expected_positive", [])),
                "relation_precision": {},
                "explicit_false_positives": [],
                "top_predictions": [],
                "expected_positive_count": len(probe.get("expected_positive", [])),
                "expected_negative_count": len(probe.get("expected_negative", [])),
                "returned_count": 0,
            }
            errors += 1
        results.append(res)
        if i % 20 == 0:
            print(f"evaluated {i}/{len(probes)} probes...")

    ok_results = [r for r in results if r.get("status") in {"ok", "needs_human_review"}]
    p5 = [_to_float(r.get("metrics_at_k", {}).get("K5", {}).get("precision"), 0.0) for r in ok_results]
    p10 = [_to_float(r.get("metrics_at_k", {}).get("K10", {}).get("precision"), 0.0) for r in ok_results]
    p20 = [_to_float(r.get("metrics_at_k", {}).get("K20", {}).get("precision"), 0.0) for r in ok_results]
    r5 = [_to_float(r.get("metrics_at_k", {}).get("K5", {}).get("recall"), 0.0) for r in ok_results]
    r10 = [_to_float(r.get("metrics_at_k", {}).get("K10", {}).get("recall"), 0.0) for r in ok_results]
    r20 = [_to_float(r.get("metrics_at_k", {}).get("K20", {}).get("recall"), 0.0) for r in ok_results]
    fp5 = [_to_float(r.get("metrics_at_k", {}).get("K5", {}).get("fp_rate"), 0.0) for r in ok_results]
    fp10 = [_to_float(r.get("metrics_at_k", {}).get("K10", {}).get("fp_rate"), 0.0) for r in ok_results]
    fp20 = [_to_float(r.get("metrics_at_k", {}).get("K20", {}).get("fp_rate"), 0.0) for r in ok_results]

    rel_total: Counter[str] = Counter()
    rel_weighted_tp: Counter[str] = Counter()
    for r in ok_results:
        rel_prec = r.get("relation_precision", {})
        for rel, prec in rel_prec.items():
            rel_total[rel] += 1
            rel_weighted_tp[rel] += float(prec)

    top_fp_examples = []
    for r in ok_results:
        for fp in r.get("explicit_false_positives", []):
            top_fp_examples.append(
                {
                    "query_cve": r.get("query_cve"),
                    "predicted_cve": fp.get("predicted_cve"),
                    "likelihood": fp.get("likelihood"),
                    "rel_type": fp.get("rel_type"),
                    "tier": fp.get("tier"),
                }
            )
    top_fp_examples = sorted(top_fp_examples, key=lambda x: _to_float(x.get("likelihood"), 0.0), reverse=True)[:50]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_file": str(bench_path),
        "n_probes_total": len(probes),
        "n_probes_ok": len(ok_results),
        "n_probes_error": errors,
        "settings": {
            "top_k": args.top_k,
            "max_hops": args.max_hops,
            "use_vector": bool(args.use_vector),
            "seed": args.seed,
        },
        "overall_metrics": {
            "P@5": _mean(p5),
            "P@10": _mean(p10),
            "P@20": _mean(p20),
            "R@5": _mean(r5),
            "R@10": _mean(r10),
            "R@20": _mean(r20),
            "FP@5": _mean(fp5),
            "FP@10": _mean(fp10),
            "FP@20": _mean(fp20),
            "avg_false_negative_count": _mean([_to_float(r.get("false_negative_count"), 0.0) for r in ok_results]),
        },
        "per_relation_precision": {
            rel: round(rel_weighted_tp[rel] / rel_total[rel], 4) for rel in sorted(rel_total.keys())
        },
        "top_false_positive_examples": top_fp_examples,
    }

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = Path(args.output_json) if args.output_json else Path(f"eval/results/graphrag_eval_{stamp}.json")
    out_csv = Path(args.output_csv) if args.output_csv else Path(f"eval/results/graphrag_eval_{stamp}.csv")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps({"summary": summary, "per_query": results}, indent=2), encoding="utf-8")
    write_csv(results, out_csv)

    print(json.dumps(summary["overall_metrics"], indent=2))
    print(f"JSON: {out_json}")
    print(f"CSV : {out_csv}")

    if args.strict and (errors > 0 or len(ok_results) == 0):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
