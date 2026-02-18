#!/usr/bin/env python3
"""
run_pipeline.py
---------------
Master script — runs all crawlers in the correct order, then builds the dataset.

Usage:
    python run_pipeline.py              # full pipeline
    python run_pipeline.py --open-only  # skip closed/auth-required sources
    python run_pipeline.py --from-build # skip crawling, only rebuild dataset
    python run_pipeline.py --correlate  # (re)run correlation step then rebuild

Order:
    1.  NVD               → data/raw_nvd.json
    2.  EPSS              → data/raw_epss.json
    3.  GitHub            → data/raw_github.json
    4.  Blogs             → data/raw_blogs.json
    5.  Exploit-DB        → data/raw_exploitdb.json
    6.  CISA KEV          → data/raw_cisa_kev.json
    7.  Papers            → data/raw_papers.json
    8.  MITRE ATT&CK      → data/raw_mitre_attack.json   ← NEW
    9.  Vendor Advisories → data/raw_vendor_advisories.json  ← NEW
   10.  Closed Sources    → data/raw_closed.json
   11.  Correlations      → data/raw_correlations.json   ← NEW
   12.  Co-occurrence     → data/raw_cooccurrence.json   ← NEW
   13.  Build             → data/vuln_dataset.jsonl + data/training_pairs.jsonl
"""

import sys
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "data"))


def step(label: str, fn, *args, **kwargs):
    """Run a pipeline step with timing and error isolation."""
    print(f"\n{'='*60}")
    print(f"  STEP: {label}")
    print(f"{'='*60}")
    t0 = time.time()
    try:
        fn(*args, **kwargs)
        elapsed = time.time() - t0
        print(f"\n  ✅ {label} done in {elapsed:.1f}s")
    except Exception as e:
        print(f"\n  ❌ {label} FAILED: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Vulnerability dataset pipeline")
    parser.add_argument("--open-only",   action="store_true", help="Skip closed/auth sources")
    parser.add_argument("--from-build",  action="store_true", help="Skip crawling, rebuild dataset only")
    parser.add_argument("--correlate",   action="store_true", help="Re-run correlation step then rebuild")
    parser.add_argument("--nvd-total",   type=int, default=10000, help="NVD records to fetch")
    args = parser.parse_args()

    Path("data").mkdir(exist_ok=True)

    # Load .env if present (API keys)
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                import os
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    if args.correlate:
        # Just re-run correlation + co-occurrence + rebuild
        from data.build_correlations import run as run_correlations
        step("Vulnerability Correlation Graph", run_correlations)
        from data.build_cooccurrence import run as run_cooccurrence
        step("Vulnerability Co-occurrence Model", run_cooccurrence)
        from data.build_dataset import run as run_build
        step("Build Dataset (merge + training pairs)", run_build)
        _print_summary()
        return

    if not args.from_build:
        # ── Open sources (no credentials needed) ──────────────────────────
        from data.crawl_nvd import run as run_nvd
        step("NVD CVE Database", run_nvd, total=args.nvd_total)

        from data.crawl_epss import run as run_epss
        step("EPSS Exploit Scores", run_epss)

        from data.crawl_github import run as run_github
        step("GitHub Security Advisories", run_github)

        from data.crawl_blogs import run as run_blogs
        step("Security Blogs (Exploit-DB / OWASP / Vulhub)", run_blogs)

        from data.crawl_exploitdb import run as run_exploitdb
        step("Exploit-DB Bulk CSV", run_exploitdb)

        from data.crawl_cisa_kev import run as run_kev
        step("CISA Known Exploited Vulnerabilities", run_kev)

        from data.crawl_papers import run as run_papers
        step("Research Papers (arXiv + Semantic Scholar + OSV)", run_papers)

        # ── NEW: MITRE ATT&CK + CAPEC (authoritative, non-aggregated) ─────
        from data.crawl_mitre_attack import run as run_mitre
        step("MITRE ATT&CK + CAPEC Correlation Data", run_mitre)

        # ── NEW: Vendor advisories (Cisco, Red Hat, Ubuntu, Debian) ───────
        from data.crawl_vendor_advisories import run as run_vendors
        step("Vendor Security Advisories (Cisco/RedHat/Ubuntu/Debian)", run_vendors)

        if not args.open_only:
            # ── Closed / auth-required sources ────────────────────────────
            from data.crawl_closed_sources import run as run_closed
            step("Closed Sources (KEV/HackerOne/MSRC/Full Disclosure)", run_closed)

        # ── NEW: Build vulnerability correlation graph ─────────────────────
        # Must run AFTER all crawlers so it has complete data
        from data.build_correlations import run as run_correlations
        step("Vulnerability Correlation Graph", run_correlations)

        # ── NEW: Build statistical co-occurrence model ─────────────────────
        from data.build_cooccurrence import run as run_cooccurrence
        step("Vulnerability Co-occurrence Model (P(B|A), P(B|¬A))", run_cooccurrence)

    # ── Build dataset from all raw files ──────────────────────────────────
    from data.build_dataset import run as run_build
    step("Build Dataset (merge + training pairs)", run_build)

    _print_summary()


def _print_summary():
    print(f"\n{'='*60}")
    print("  🚀 Pipeline complete!")
    print(f"{'='*60}")
    print("  Outputs:")
    print("    data/raw_mitre_attack.json         — ATT&CK + CAPEC data")
    print("    data/raw_vendor_advisories.json    — Cisco/RedHat/Ubuntu/Debian")
    print("    data/raw_correlations.json         — CVE correlation graph")
    print("    data/raw_cooccurrence.json         — P(B|A) co-occurrence model")
    print("    data/vuln_dataset.jsonl            — full schema records")
    print("    data/training_pairs.jsonl          — fine-tuning pairs")
    print("\n  Next step: python training/finetuning.py")
    print("  Quick correlate: python run_pipeline.py --correlate")


if __name__ == "__main__":
    main()