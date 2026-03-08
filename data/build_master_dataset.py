"""
build_master_dataset.py
-----------------------
Build a combined CVE master dataset by joining vuln_dataset with correlation/
co-occurrence artifacts and additional scraped raw sources.

Primary joins:
  1) data/vuln_dataset.jsonl
  2) data/raw_correlations.json
  3) data/raw_cooccurrence_v2.json

Optional enrichment (when --use-all-raw):
  raw_nvd, raw_epss, raw_cisa_kev, raw_github, raw_vendor_advisories,
  raw_blogs, raw_papers, raw_closed, raw_exploitdb, raw_cwe_chains,
  raw_kev_clusters, raw_mitre_attack
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator


DATA_DIR = Path("data")
DEFAULT_VULN_FILE = DATA_DIR / "vuln_dataset.jsonl"
DEFAULT_CORR_FILE = DATA_DIR / "raw_correlations.json"
DEFAULT_COOC_FILE = DATA_DIR / "raw_cooccurrence_v2.json"
DEFAULT_OUT_FILE = DATA_DIR / "master_vuln_context.jsonl"
DEFAULT_MAX_SOURCE_ITEMS = 3


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_cve(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().upper()


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def _iter_json_array_stream(path: Path) -> Iterator[Any]:
    """
    Stream parse a top-level JSON array from disk without loading whole file.
    """
    if not path.exists():
        return

    decoder = json.JSONDecoder()
    in_array = False
    buf = ""

    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(1 << 20)  # 1 MiB
            if not chunk:
                break
            buf += chunk

            if not in_array:
                arr_idx = buf.find("[")
                if arr_idx < 0:
                    if len(buf) > 32:
                        buf = buf[-32:]
                    continue
                buf = buf[arr_idx + 1 :]
                in_array = True

            while in_array:
                stripped = buf.lstrip()
                consumed = len(buf) - len(stripped)
                if consumed:
                    buf = stripped
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
    """
    Stream parse a named top-level array from a JSON object file.
    Example: key_name='cooccurrence_pairs' for raw_cooccurrence_v2.json
    """
    if not path.exists():
        return

    decoder = json.JSONDecoder()
    key = f'"{key_name}"'
    in_array = False
    buf = ""

    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(1 << 20)  # 1 MiB
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
                stripped = buf.lstrip()
                consumed = len(buf) - len(stripped)
                if consumed:
                    buf = stripped
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


def _iter_cooccurrence_pairs_stream(path: Path) -> Iterator[dict[str, Any]]:
    for obj in _iter_named_array_stream(path, "cooccurrence_pairs"):
        if isinstance(obj, dict):
            yield obj


def _iter_negative_rules_stream(path: Path) -> Iterator[dict[str, Any]]:
    for obj in _iter_named_array_stream(path, "negative_rules"):
        if isinstance(obj, dict):
            yield obj


def _upsert_topk_neighbor(
    buckets: dict[str, list[dict[str, Any]]],
    src_cve: str,
    neighbor: dict[str, Any],
    max_per_cve: int,
) -> None:
    entries = buckets[src_cve]
    neighbor_cve = neighbor.get("cve_id", "")

    # Keep highest-confidence version of the same neighbor.
    for idx, item in enumerate(entries):
        if item.get("cve_id") == neighbor_cve:
            if neighbor.get("confidence", 0.0) > item.get("confidence", 0.0):
                entries[idx] = neighbor
            return

    if len(entries) < max_per_cve:
        entries.append(neighbor)
        return

    min_idx = min(range(len(entries)), key=lambda i: entries[i].get("confidence", 0.0))
    if neighbor.get("confidence", 0.0) > entries[min_idx].get("confidence", 0.0):
        entries[min_idx] = neighbor


def _build_cooccurrence_lookup(
    cooc_path: Path,
    cve_whitelist: set[str],
    max_per_cve: int,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    neighbors: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stats = {
        "pairs_seen": 0,
        "pairs_kept": 0,
        "pairs_skipped_invalid": 0,
        "pairs_skipped_not_in_dataset": 0,
    }

    for pair in _iter_cooccurrence_pairs_stream(cooc_path):
        stats["pairs_seen"] += 1

        a = _normalize_cve(pair.get("cve_a"))
        b = _normalize_cve(pair.get("cve_b"))
        if not a or not b or a == b:
            stats["pairs_skipped_invalid"] += 1
            continue

        a_in = a in cve_whitelist
        b_in = b in cve_whitelist
        if not a_in and not b_in:
            stats["pairs_skipped_not_in_dataset"] += 1
            continue

        conf = _to_float(pair.get("confidence"), 0.0)
        source = str(pair.get("source", "raw_cooccurrence_v2"))
        reason = str(pair.get("reason", ""))

        if a_in:
            _upsert_topk_neighbor(
                neighbors,
                a,
                {
                    "cve_id": b,
                    "confidence": conf,
                    "source": source,
                    "sources_combined": pair.get("sources_combined", [source]),
                    "source_count": int(pair.get("source_count", 1) or 1),
                    "reason": reason,
                    "profile": pair.get("profile"),
                },
                max_per_cve=max_per_cve,
            )
            stats["pairs_kept"] += 1

        if b_in:
            _upsert_topk_neighbor(
                neighbors,
                b,
                {
                    "cve_id": a,
                    "confidence": conf,
                    "source": source,
                    "sources_combined": pair.get("sources_combined", [source]),
                    "source_count": int(pair.get("source_count", 1) or 1),
                    "reason": reason,
                    "profile": pair.get("profile"),
                },
                max_per_cve=max_per_cve,
            )
            stats["pairs_kept"] += 1

    for cve, rels in neighbors.items():
        neighbors[cve] = sorted(rels, key=lambda x: x.get("confidence", 0.0), reverse=True)

    return dict(neighbors), stats


def _build_negative_rules_catalog(cooc_path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    catalog: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    stats = {
        "rules_seen": 0,
        "rules_kept": 0,
    }

    for rule in _iter_negative_rules_stream(cooc_path):
        stats["rules_seen"] += 1
        profile = _normalize(rule.get("profile"))
        condition = _normalize(rule.get("condition"))
        if not profile or not condition:
            continue
        key = (profile + "|" + condition).lower()
        if key in seen_keys:
            continue
        seen_keys.add(key)

        absent = []
        for c in rule.get("absent_cves", []) if isinstance(rule.get("absent_cves", []), list) else []:
            cv = _normalize_cve(c)
            if cv.startswith("CVE-"):
                absent.append(cv)

        still = []
        for c in rule.get("still_assess", []) if isinstance(rule.get("still_assess", []), list) else []:
            cv = _normalize_cve(c)
            if cv.startswith("CVE-"):
                still.append(cv)

        catalog.append(
            {
                "profile": profile,
                "display": _normalize(rule.get("display")),
                "condition": condition,
                "reason": _normalize(rule.get("reason")),
                "absent_cves": list(dict.fromkeys(absent)),
                "still_assess": list(dict.fromkeys(still)),
            }
        )
        stats["rules_kept"] += 1

    return catalog, stats


def _normalize_correlations(
    raw_related: Any,
    self_cve: str,
    max_related: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(raw_related, list):
        return out

    for rel in raw_related:
        if not isinstance(rel, dict):
            continue
        rel_cve = _normalize_cve(rel.get("cve_id"))
        if not rel_cve or rel_cve == self_cve:
            continue
        out.append(
            {
                "cve_id": rel_cve,
                "correlation_score": _to_float(rel.get("correlation_score"), 0.0),
                "signals": rel.get("signals", []),
            }
        )

    out.sort(key=lambda x: x.get("correlation_score", 0.0), reverse=True)
    if max_related > 0:
        out = out[:max_related]
    return out


def _normalize_score_01(raw_score: float, max_score: float) -> float:
    if max_score <= 0:
        return 0.0
    val = raw_score / max_score
    if val < 0:
        return 0.0
    if val > 1:
        return 1.0
    return round(val, 6)


def _merge_correlations(
    primary: list[dict[str, Any]],
    secondary: list[dict[str, Any]],
    max_related: int,
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for rel in primary + secondary:
        cve = _normalize_cve(rel.get("cve_id"))
        if not cve:
            continue
        score = _to_float(rel.get("correlation_score"), 0.0)
        signals = rel.get("signals", []) if isinstance(rel.get("signals", []), list) else []
        if cve not in merged:
            merged[cve] = {"cve_id": cve, "correlation_score": score, "signals": list(dict.fromkeys(signals))}
            continue
        cur = merged[cve]
        if score > cur.get("correlation_score", 0.0):
            cur["correlation_score"] = score
        cur["signals"] = list(dict.fromkeys((cur.get("signals", []) or []) + signals))

    out = sorted(merged.values(), key=lambda x: x.get("correlation_score", 0.0), reverse=True)
    if max_related > 0:
        out = out[:max_related]
    return out


def _build_raw_correlation_lookup(
    corr_path: Path,
    cve_whitelist: set[str],
    max_related: int,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    lookup: dict[str, dict[str, Any]] = {}
    stats = {
        "records_seen": 0,
        "records_kept": 0,
        "records_skipped_not_in_dataset": 0,
        "max_raw_correlation_score": 0.0,
    }

    for rec in _iter_json_array_stream(corr_path):
        if not isinstance(rec, dict):
            continue
        stats["records_seen"] += 1
        cve = _normalize_cve(rec.get("cve_id"))
        if not cve:
            continue
        if cve not in cve_whitelist:
            stats["records_skipped_not_in_dataset"] += 1
            continue
        lookup[cve] = {
            "cwe_id": str(rec.get("cwe_id", "")).strip().upper(),
            "correlation_signal_count_raw": int(rec.get("correlation_signal_count", 0) or 0),
            "attack_techniques_raw": rec.get("attack_techniques", [])[:20] if isinstance(rec.get("attack_techniques", []), list) else [],
            "capec_patterns_raw": rec.get("capec_patterns", [])[:20] if isinstance(rec.get("capec_patterns", []), list) else [],
            "related_vulnerabilities_raw": _normalize_correlations(
                raw_related=rec.get("related_vulnerabilities", []),
                self_cve=cve,
                max_related=max_related,
            ),
        }
        for rel in lookup[cve]["related_vulnerabilities_raw"]:
            score = _to_float(rel.get("correlation_score"), 0.0)
            if score > stats["max_raw_correlation_score"]:
                stats["max_raw_correlation_score"] = score
        stats["records_kept"] += 1

    return lookup, stats


def _extract_cves_from_record(rec: dict[str, Any]) -> set[str]:
    out: set[str] = set()

    def add_one(v: Any):
        c = _normalize_cve(v)
        if c.startswith("CVE-"):
            out.add(c)

    add_one(rec.get("cve_id"))
    add_one(rec.get("cve_a"))
    add_one(rec.get("cve_b"))
    add_one(rec.get("trigger_cve"))
    add_one(rec.get("related_cve"))

    for key in ("cve_ids", "all_cve_ids", "cves_mentioned"):
        val = rec.get(key, [])
        if isinstance(val, list):
            for item in val:
                add_one(item)

    return out


def _add_capped_item(
    raw_context: dict[str, dict[str, Any]],
    cve: str,
    source_key: str,
    item: dict[str, Any],
    max_items: int,
) -> None:
    holder = raw_context[cve].setdefault(source_key, [])
    if not isinstance(holder, list):
        return
    if item in holder:
        return
    if len(holder) < max_items:
        holder.append(item)


def _build_all_raw_context(
    data_dir: Path,
    cve_whitelist: set[str],
    max_items_per_source: int,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    raw_context: dict[str, dict[str, Any]] = defaultdict(dict)
    stats: dict[str, Any] = {}

    # raw_epss.json: {CVE-ID: score}
    epss_path = data_dir / "raw_epss.json"
    if epss_path.exists():
        epss = json.load(epss_path.open(encoding="utf-8"))
        kept = 0
        if isinstance(epss, dict):
            for cve, score in epss.items():
                c = _normalize_cve(cve)
                if c in cve_whitelist:
                    raw_context[c]["epss_raw"] = _to_float(score, 0.0)
                    kept += 1
        stats["raw_epss"] = {"kept": kept}

    # raw_cisa_kev.json
    kev_path = data_dir / "raw_cisa_kev.json"
    if kev_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(kev_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cve = _normalize_cve(rec.get("cve_id"))
            if cve not in cve_whitelist:
                continue
            _add_capped_item(
                raw_context,
                cve,
                "kev_records_raw",
                {
                    "vendor": rec.get("vendor"),
                    "product": rec.get("product"),
                    "date_added": rec.get("date_added"),
                    "known_ransomware": rec.get("known_ransomware"),
                    "required_action": rec.get("required_action"),
                },
                max_items_per_source,
            )
            kept += 1
        stats["raw_cisa_kev"] = {"seen": seen, "kept": kept}

    # raw_nvd.json
    nvd_path = data_dir / "raw_nvd.json"
    if nvd_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(nvd_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cve = _normalize_cve(rec.get("cve_id"))
            if cve not in cve_whitelist:
                continue
            refs = rec.get("references", []) if isinstance(rec.get("references", []), list) else []
            sw = rec.get("affected_software", []) if isinstance(rec.get("affected_software", []), list) else []
            _add_capped_item(
                raw_context,
                cve,
                "nvd_records_raw",
                {
                    "published": rec.get("published"),
                    "cvss_score_raw": rec.get("cvss_score"),
                    "cvss_severity_raw": rec.get("cvss_severity"),
                    "affected_software": sw[:8],
                    "reference_count": len(refs),
                    "references": refs[:5],
                },
                max_items_per_source,
            )
            kept += 1
        stats["raw_nvd"] = {"seen": seen, "kept": kept}

    # raw_github.json
    github_path = data_dir / "raw_github.json"
    if github_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(github_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            if not cves:
                continue
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "ghsa_id": rec.get("ghsa_id"),
                "vulnerability_name": rec.get("vulnerability_name"),
                "severity": rec.get("cvss_severity"),
                "cvss_score": rec.get("cvss_score"),
                "affected_packages": rec.get("affected_packages", [])[:5] if isinstance(rec.get("affected_packages", []), list) else [],
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "github_advisories_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_github"] = {"seen": seen, "kept": kept}

    # raw_vendor_advisories.json
    vendor_path = data_dir / "raw_vendor_advisories.json"
    if vendor_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(vendor_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "source": rec.get("source"),
                "title": rec.get("title"),
                "severity": rec.get("severity"),
                "public_date": rec.get("public_date"),
                "affected_packages": rec.get("affected_packages", [])[:5] if isinstance(rec.get("affected_packages", []), list) else [],
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "vendor_advisories_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_vendor_advisories"] = {"seen": seen, "kept": kept}

    # raw_blogs.json
    blogs_path = data_dir / "raw_blogs.json"
    if blogs_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(blogs_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "url": rec.get("url"),
                "source_type": rec.get("source_type"),
                "pair_count": len(rec.get("cve_pairs", []) if isinstance(rec.get("cve_pairs", []), list) else []),
                "exploit_chain_count": len(rec.get("exploit_chains", []) if isinstance(rec.get("exploit_chains", []), list) else []),
                "campaign_signal_count": len(rec.get("campaign_signals", []) if isinstance(rec.get("campaign_signals", []), list) else []),
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "blog_mentions_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_blogs"] = {"seen": seen, "kept": kept}

    # raw_papers.json
    papers_path = data_dir / "raw_papers.json"
    if papers_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(papers_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "title": rec.get("title"),
                "arxiv_id": rec.get("arxiv_id"),
                "published": rec.get("published"),
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "papers_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_papers"] = {"seen": seen, "kept": kept}

    # raw_closed.json
    closed_path = data_dir / "raw_closed.json"
    if closed_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(closed_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "source": rec.get("source"),
                "title": rec.get("title"),
                "vendor": rec.get("vendor"),
                "product": rec.get("product"),
                "date_added": rec.get("date_added"),
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "closed_sources_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_closed"] = {"seen": seen, "kept": kept}

    # raw_exploitdb.json
    exploitdb_path = data_dir / "raw_exploitdb.json"
    if exploitdb_path.exists():
        seen = kept = 0
        for rec in _iter_json_array_stream(exploitdb_path):
            if not isinstance(rec, dict):
                continue
            seen += 1
            cves = _extract_cves_from_record(rec)
            target = cves & cve_whitelist
            if not target:
                continue
            snippet = {
                "title": rec.get("title"),
                "url": rec.get("url"),
                "exploit_id": rec.get("exploit_id"),
            }
            for cve in target:
                _add_capped_item(raw_context, cve, "exploitdb_raw", snippet, max_items_per_source)
                kept += 1
        stats["raw_exploitdb"] = {"seen": seen, "kept": kept}

    # raw_cwe_chains.json
    cwe_chain_path = data_dir / "raw_cwe_chains.json"
    if cwe_chain_path.exists():
        data = json.load(cwe_chain_path.open(encoding="utf-8"))
        chains = data.get("cve_chains", []) if isinstance(data, dict) else []
        seen = kept = 0
        for chain in chains:
            if not isinstance(chain, dict):
                continue
            seen += 1
            a = _normalize_cve(chain.get("trigger_cve"))
            b = _normalize_cve(chain.get("related_cve"))
            conf = _to_float(chain.get("confidence"), 0.0)
            rel_type = chain.get("chain_type")
            path = chain.get("chain_path", []) if isinstance(chain.get("chain_path", []), list) else []
            if a in cve_whitelist:
                _add_capped_item(
                    raw_context,
                    a,
                    "cwe_chains_raw",
                    {"related_cve": b, "confidence": conf, "chain_type": rel_type, "chain_path": path[:6]},
                    max_items_per_source,
                )
                kept += 1
            if b in cve_whitelist:
                _add_capped_item(
                    raw_context,
                    b,
                    "cwe_chains_raw",
                    {"related_cve": a, "confidence": conf, "chain_type": rel_type, "chain_path": list(reversed(path[:6]))},
                    max_items_per_source,
                )
                kept += 1
        stats["raw_cwe_chains"] = {"seen": seen, "kept": kept}

    # raw_kev_clusters.json
    kev_cluster_path = data_dir / "raw_kev_clusters.json"
    if kev_cluster_path.exists():
        data = json.load(kev_cluster_path.open(encoding="utf-8"))
        seen = kept = 0

        for cluster in data.get("temporal_clusters", []) if isinstance(data, dict) else []:
            if not isinstance(cluster, dict):
                continue
            cid = cluster.get("cluster_id")
            week = cluster.get("week")
            conf = cluster.get("confidence")
            for cve in cluster.get("cves", []) if isinstance(cluster.get("cves", []), list) else []:
                c = _normalize_cve(cve)
                if c in cve_whitelist:
                    _add_capped_item(
                        raw_context,
                        c,
                        "kev_clusters_raw",
                        {"cluster_id": cid, "cluster_type": "temporal", "week": week, "confidence": conf},
                        max_items_per_source,
                    )
                    kept += 1
            seen += 1

        for cluster in data.get("vendor_clusters", []) if isinstance(data, dict) else []:
            if not isinstance(cluster, dict):
                continue
            cid = cluster.get("cluster_id")
            stack = cluster.get("stack")
            conf = cluster.get("confidence")
            for cve in cluster.get("cves", []) if isinstance(cluster.get("cves", []), list) else []:
                c = _normalize_cve(cve)
                if c in cve_whitelist:
                    _add_capped_item(
                        raw_context,
                        c,
                        "kev_clusters_raw",
                        {"cluster_id": cid, "cluster_type": "vendor_stack", "stack": stack, "confidence": conf},
                        max_items_per_source,
                    )
                    kept += 1
            seen += 1

        rw = data.get("ransomware_cluster", {}) if isinstance(data, dict) else {}
        if isinstance(rw, dict):
            for cve in rw.get("cves", []) if isinstance(rw.get("cves", []), list) else []:
                c = _normalize_cve(cve)
                if c in cve_whitelist:
                    _add_capped_item(
                        raw_context,
                        c,
                        "kev_clusters_raw",
                        {"cluster_id": rw.get("cluster_id"), "cluster_type": "ransomware", "confidence": rw.get("confidence")},
                        max_items_per_source,
                    )
                    kept += 1
            seen += 1

        for pair in data.get("cooccurrence_pairs", []) if isinstance(data, dict) else []:
            if not isinstance(pair, dict):
                continue
            a = _normalize_cve(pair.get("cve_a"))
            b = _normalize_cve(pair.get("cve_b"))
            conf = _to_float(pair.get("confidence"), 0.0)
            src = pair.get("source")
            week = pair.get("week")
            if a in cve_whitelist:
                _add_capped_item(
                    raw_context,
                    a,
                    "kev_cluster_pairs_raw",
                    {"cve_id": b, "confidence": conf, "source": src, "week": week},
                    max_items_per_source,
                )
                kept += 1
            if b in cve_whitelist:
                _add_capped_item(
                    raw_context,
                    b,
                    "kev_cluster_pairs_raw",
                    {"cve_id": a, "confidence": conf, "source": src, "week": week},
                    max_items_per_source,
                )
                kept += 1
            seen += 1

        stats["raw_kev_clusters"] = {"seen": seen, "kept": kept}

    # raw_mitre_attack.json
    mitre_path = data_dir / "raw_mitre_attack.json"
    if mitre_path.exists():
        data = json.load(mitre_path.open(encoding="utf-8"))
        cve_to_techniques = data.get("cve_to_techniques", {}) if isinstance(data, dict) else {}
        kept = 0
        if isinstance(cve_to_techniques, dict):
            for cve, techniques in cve_to_techniques.items():
                c = _normalize_cve(cve)
                if c not in cve_whitelist:
                    continue
                if isinstance(techniques, list):
                    raw_context[c]["mitre_attack_techniques_raw"] = techniques[: max(6, max_items_per_source * 3)]
                    kept += 1
        stats["raw_mitre_attack"] = {"kept": kept}

    return dict(raw_context), stats


def run(
    vuln_file: str = str(DEFAULT_VULN_FILE),
    correlations_file: str = str(DEFAULT_CORR_FILE),
    cooccurrence_file: str = str(DEFAULT_COOC_FILE),
    out_file: str = str(DEFAULT_OUT_FILE),
    max_correlations: int = 50,
    max_cooccurrences: int = 50,
    use_all_raw: bool = True,
    max_source_items: int = DEFAULT_MAX_SOURCE_ITEMS,
    limit_cves: int = 0,
    embed_negative_rules: bool = True,
) -> dict[str, Any]:
    vuln_path = Path(vuln_file)
    corr_path = Path(correlations_file)
    cooc_path = Path(cooccurrence_file)
    out_path = Path(out_file)

    if not vuln_path.exists():
        raise FileNotFoundError(f"Missing vuln dataset: {vuln_path}")
    if not corr_path.exists():
        raise FileNotFoundError(f"Missing raw correlations: {corr_path}")
    if not cooc_path.exists():
        raise FileNotFoundError(f"Missing co-occurrence file: {cooc_path}")

    print("Building CVE whitelist from vuln_dataset.jsonl...")
    cve_whitelist: set[str] = set()
    total_vuln_rows = 0
    for row in _iter_jsonl(vuln_path):
        total_vuln_rows += 1
        cve_id = _normalize_cve(row.get("cve_id"))
        if cve_id:
            cve_whitelist.add(cve_id)
        if limit_cves > 0 and len(cve_whitelist) >= limit_cves:
            break
    print(f"  vuln rows: {total_vuln_rows:,}")
    print(f"  unique CVEs: {len(cve_whitelist):,}")
    if limit_cves > 0:
        print(f"  LIMIT mode active: first {len(cve_whitelist):,} CVEs")

    print("Indexing raw correlations...")
    corr_lookup, corr_stats = _build_raw_correlation_lookup(
        corr_path=corr_path,
        cve_whitelist=cve_whitelist,
        max_related=max_correlations,
    )
    print(
        "  raw_correlations seen={records_seen:,} kept={records_kept:,} out_of_set={records_skipped_not_in_dataset:,} max_raw_score={max_raw_correlation_score:.3f}".format(
            **corr_stats
        )
    )

    print("Indexing co-occurrence neighbors...")
    cooc_lookup, cooc_stats = _build_cooccurrence_lookup(
        cooc_path=cooc_path,
        cve_whitelist=cve_whitelist,
        max_per_cve=max_cooccurrences,
    )
    print(
        "  pairs seen={pairs_seen:,} kept={pairs_kept:,} invalid={pairs_skipped_invalid:,} out_of_set={pairs_skipped_not_in_dataset:,}".format(
            **cooc_stats
        )
    )
    print(f"  CVEs with co-occurrence context: {len(cooc_lookup):,}")

    all_raw_context: dict[str, dict[str, Any]] = {}
    all_raw_stats: dict[str, Any] = {}
    if use_all_raw:
        print("Indexing all additional raw sources...")
        all_raw_context, all_raw_stats = _build_all_raw_context(
            data_dir=DATA_DIR,
            cve_whitelist=cve_whitelist,
            max_items_per_source=max_source_items,
        )
        print(f"  CVEs with extra raw context: {len(all_raw_context):,}")

    negative_rules_catalog: list[dict[str, Any]] = []
    negative_rules_stats: dict[str, int] = {"rules_seen": 0, "rules_kept": 0}
    if embed_negative_rules:
        print("Indexing negative rule catalog from co-occurrence source...")
        negative_rules_catalog, negative_rules_stats = _build_negative_rules_catalog(cooc_path)
        print(
            "  negative rules seen={rules_seen:,} kept={rules_kept:,}".format(
                **negative_rules_stats
            )
        )

    print("Writing master dataset...")
    written = 0
    metadata_rows = 0
    with out_path.open("w", encoding="utf-8") as out:
        if embed_negative_rules:
            meta = {
                "record_type": "master_metadata",
                "metadata_version": "v1",
                "negative_rules": negative_rules_catalog,
                "source_artifacts": {
                    "cooccurrence": str(cooc_path),
                },
            }
            out.write(json.dumps(meta, ensure_ascii=False) + "\n")
            metadata_rows += 1

        for row in _iter_jsonl(vuln_path):
            cve_id = _normalize_cve(row.get("cve_id"))
            if not cve_id or cve_id not in cve_whitelist:
                continue

            correlations_from_vuln = _normalize_correlations(
                raw_related=row.get("related_vulnerabilities", []),
                self_cve=cve_id,
                max_related=max_correlations,
            )
            correlations_from_raw = corr_lookup.get(cve_id, {}).get("related_vulnerabilities_raw", [])
            correlations = _merge_correlations(
                primary=correlations_from_raw,
                secondary=correlations_from_vuln,
                max_related=max_correlations,
            )
            global_corr_max = _to_float(corr_stats.get("max_raw_correlation_score"), 0.0)
            if global_corr_max <= 0 and correlations:
                global_corr_max = max(_to_float(x.get("correlation_score"), 0.0) for x in correlations)
            normalized_correlations: list[dict[str, Any]] = []
            for rel in correlations:
                raw_score = _to_float(rel.get("correlation_score"), 0.0)
                normalized_correlations.append(
                    {
                        "cve_id": rel.get("cve_id"),
                        "correlation_score": _normalize_score_01(raw_score, global_corr_max),
                        "correlation_score_raw": round(raw_score, 6),
                        "signals": rel.get("signals", []),
                    }
                )
            cooccurrences = cooc_lookup.get(cve_id, [])
            extra_raw = all_raw_context.get(cve_id, {}) if use_all_raw else {}
            corr_raw_meta = corr_lookup.get(cve_id, {})

            unified = []
            for rel in normalized_correlations:
                unified.append(
                    {
                        "relation_type": "CORRELATED_WITH",
                        "cve_id": rel["cve_id"],
                        "score": rel["correlation_score"],
                        "score_raw": rel.get("correlation_score_raw", 0.0),
                        "signals": rel.get("signals", []),
                    }
                )
            for rel in cooccurrences:
                unified.append(
                    {
                        "relation_type": "CO_OCCURS_WITH",
                        "cve_id": rel["cve_id"],
                        "score": rel.get("confidence", 0.0),
                        "source": rel.get("source"),
                        "sources_combined": rel.get("sources_combined", []),
                        "source_count": rel.get("source_count", 1),
                        "reason": rel.get("reason", ""),
                        "profile": rel.get("profile"),
                    }
                )
            unified.sort(key=lambda x: x.get("score", 0.0), reverse=True)

            master_row = {
                "record_type": "cve_context",
                "cve_id": cve_id,
                "cwe_id": str(row.get("cwe_id", "")).strip().upper(),
                "vulnerability_name": row.get("vulnerability_name", ""),
                "description": row.get("description", ""),
                "cvss_score": row.get("cvss_score"),
                "cvss_severity": row.get("cvss_severity"),
                "epss_score": row.get("epss_score"),
                "risk_level": row.get("risk_level"),
                "confirmed_exploited": bool(row.get("confirmed_exploited", False)),
                "correlations": normalized_correlations,
                "correlations_raw_meta": {
                    "correlation_signal_count_raw": corr_raw_meta.get("correlation_signal_count_raw", 0),
                    "attack_techniques_raw": corr_raw_meta.get("attack_techniques_raw", []),
                    "capec_patterns_raw": corr_raw_meta.get("capec_patterns_raw", []),
                },
                "cooccurrences": cooccurrences,
                "context_links": unified,
                "raw_source_context": extra_raw,
                "context_counts": {
                    "correlations": len(normalized_correlations),
                    "cooccurrences": len(cooccurrences),
                    "raw_context_sections": len(extra_raw.keys()) if isinstance(extra_raw, dict) else 0,
                    "total_links": len(unified),
                },
                "source_artifacts": {
                    "vuln_dataset": str(vuln_path),
                    "raw_correlations": str(corr_path),
                    "cooccurrence": str(cooc_path),
                    "all_raw_enabled": use_all_raw,
                    "correlation_score_normalization": {
                        "method": "global_max_divide",
                        "max_raw_score": round(global_corr_max, 6),
                    },
                },
            }

            out.write(json.dumps(master_row, ensure_ascii=False) + "\n")
            written += 1
            if written % 50000 == 0:
                print(f"  written {written:,} rows...")
            if limit_cves > 0 and written >= limit_cves:
                break

    print(f"Done. Wrote {written:,} rows -> {out_path}")
    return {
        "rows_written": written,
        "metadata_rows_written": metadata_rows,
        "output": str(out_path),
        "correlation_stats": corr_stats,
        "cooccurrence_stats": cooc_stats,
        "all_raw_stats": all_raw_stats,
        "negative_rules_stats": negative_rules_stats,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vuln-file", type=str, default=str(DEFAULT_VULN_FILE))
    parser.add_argument("--correlations-file", type=str, default=str(DEFAULT_CORR_FILE))
    parser.add_argument("--cooccurrence-file", type=str, default=str(DEFAULT_COOC_FILE))
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUT_FILE))
    parser.add_argument("--max-correlations", type=int, default=50)
    parser.add_argument("--max-cooccurrences", type=int, default=50)
    parser.add_argument("--max-source-items", type=int, default=DEFAULT_MAX_SOURCE_ITEMS)
    parser.add_argument("--limit-cves", type=int, default=0)
    parser.add_argument("--use-all-raw", dest="use_all_raw", action="store_true")
    parser.add_argument("--no-use-all-raw", dest="use_all_raw", action="store_false")
    parser.add_argument("--embed-negative-rules", dest="embed_negative_rules", action="store_true")
    parser.add_argument("--no-embed-negative-rules", dest="embed_negative_rules", action="store_false")
    parser.set_defaults(use_all_raw=True)
    parser.set_defaults(embed_negative_rules=True)
    args = parser.parse_args()

    run(
        vuln_file=args.vuln_file,
        correlations_file=args.correlations_file,
        cooccurrence_file=args.cooccurrence_file,
        out_file=args.output,
        max_correlations=max(1, args.max_correlations),
        max_cooccurrences=max(1, args.max_cooccurrences),
        use_all_raw=bool(args.use_all_raw),
        max_source_items=max(1, args.max_source_items),
        limit_cves=max(0, args.limit_cves),
        embed_negative_rules=bool(args.embed_negative_rules),
    )


if __name__ == "__main__":
    main()
