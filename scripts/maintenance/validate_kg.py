"""
validate_kg.py
--------------
Automated end-to-end KG validation runner for Neo4j + source alignment checks.

Usage examples:
  python scripts/maintenance/validate_kg.py --strict
  python scripts/maintenance/validate_kg.py --sample-cves 80 --seed 7 --output-json eval/results/kg_validation.json --output-md eval/results/kg_validation.md
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _load_dotenv_if_present() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=env_path, override=False)
    except Exception:
        return


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


@dataclass
class CheckResult:
    name: str
    status: str  # pass|warn|fail
    metrics: dict[str, Any]
    notes: str = ""
    samples: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "metrics": self.metrics,
            "notes": self.notes,
            "samples": self.samples or [],
        }


def _connect_neo4j():
    from neo4j import GraphDatabase

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "").strip()
    if not password:
        raise RuntimeError("NEO4J_PASSWORD is not set")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as s:
        s.run("RETURN 1")
    return driver, uri


def _run_scalar(session, query: str, **params: Any) -> Any:
    row = session.run(query, **params).single()
    if row is None:
        return None
    return row[0]


def _run_list(session, query: str, **params: Any) -> list[dict[str, Any]]:
    return session.run(query, **params).data()


def _upsert_topk(scores: dict[str, float], cve: str, score: float, top_k: int) -> None:
    prev = scores.get(cve)
    if prev is None or score > prev:
        scores[cve] = score
    if len(scores) > max(10, top_k * 4):
        items = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        scores.clear()
        scores.update(items)


def _build_source_alignment_lookup(
    sample_cves: set[str],
    corr_path: Path,
    cooc_path: Path,
    top_k: int,
) -> dict[str, dict[str, dict[str, float]]]:
    out: dict[str, dict[str, dict[str, float]]] = {
        cve: {"CORRELATED_WITH": {}, "CO_OCCURS_WITH": {}} for cve in sample_cves
    }

    for rec in _iter_json_array_stream(corr_path):
        if not isinstance(rec, dict):
            continue
        cve = _normalize_cve(rec.get("cve_id"))
        if cve not in sample_cves:
            continue
        rels = rec.get("related_vulnerabilities", [])
        if not isinstance(rels, list):
            continue
        for rel in rels:
            if not isinstance(rel, dict):
                continue
            tgt = _normalize_cve(rel.get("cve_id"))
            if not tgt or tgt == cve:
                continue
            score = _to_float(rel.get("correlation_score"), 0.0)
            _upsert_topk(out[cve]["CORRELATED_WITH"], tgt, score, top_k)

    for pair in _iter_named_array_stream(cooc_path, "cooccurrence_pairs"):
        if not isinstance(pair, dict):
            continue
        a = _normalize_cve(pair.get("cve_a"))
        b = _normalize_cve(pair.get("cve_b"))
        if not a or not b or a == b:
            continue
        score = _to_float(pair.get("confidence"), 0.0)
        if a in sample_cves:
            _upsert_topk(out[a]["CO_OCCURS_WITH"], b, score, top_k)
        if b in sample_cves:
            _upsert_topk(out[b]["CO_OCCURS_WITH"], a, score, top_k)

    for cve in sample_cves:
        for rel_type in ("CORRELATED_WITH", "CO_OCCURS_WITH"):
            items = sorted(out[cve][rel_type].items(), key=lambda x: x[1], reverse=True)[:top_k]
            out[cve][rel_type] = dict(items)
    return out


def _render_markdown(report: dict[str, Any]) -> str:
    lines = []
    lines.append("# KG Validation Report")
    lines.append("")
    lines.append(f"- Generated: `{report['metadata']['generated_at']}`")
    lines.append(f"- Neo4j URI: `{report['metadata']['neo4j_uri']}`")
    lines.append(f"- Overall: **{report['summary']['overall_status'].upper()}**")
    lines.append(
        f"- Checks: pass={report['summary']['pass']}, warn={report['summary']['warn']}, fail={report['summary']['fail']}"
    )
    lines.append("")
    for check in report["checks"]:
        lines.append(f"## {check['name']} [{check['status'].upper()}]")
        if check.get("notes"):
            lines.append(check["notes"])
        if check.get("metrics"):
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(check["metrics"], indent=2))
            lines.append("```")
        samples = check.get("samples") or []
        if samples:
            lines.append("")
            lines.append("Sample mismatches:")
            lines.append("```json")
            lines.append(json.dumps(samples[:10], indent=2))
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated KG validation runner.")
    parser.add_argument("--sample-cves", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--output-json", type=str, default="")
    parser.add_argument("--output-md", type=str, default="")
    parser.add_argument("--corr-file", type=str, default="data/raw_correlations.json")
    parser.add_argument("--cooc-file", type=str, default="data/raw_cooccurrence_v2.json")
    parser.add_argument("--top-k-align", type=int, default=20)
    parser.add_argument("--expect-negative-rules", action="store_true")
    args = parser.parse_args()

    _load_dotenv_if_present()
    checks: list[CheckResult] = []

    try:
        driver, neo4j_uri = _connect_neo4j()
    except Exception as e:
        report = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            },
            "checks": [],
            "summary": {
                "overall_status": "fail",
                "pass": 0,
                "warn": 0,
                "fail": 1,
            },
            "error": f"Neo4j connection failed: {e}",
        }
        print(json.dumps(report, indent=2))
        return 2 if args.strict else 1

    with driver.session() as s:
        # 1) Schema and volume sanity
        labels_rows = _run_list(s, "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS cnt ORDER BY cnt DESC")
        rel_rows = _run_list(s, "MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS cnt ORDER BY cnt DESC")
        constraints_rows = _run_list(s, "SHOW CONSTRAINTS")
        label_counts = {str(r.get("label")): int(r.get("cnt", 0) or 0) for r in labels_rows}
        rel_counts = {str(r.get("rel")): int(r.get("cnt", 0) or 0) for r in rel_rows}
        constraint_names = {str(r.get("name", "")) for r in constraints_rows}

        required_labels = {"Vulnerability", "CWE", "OWASPCategory", "Software"}
        required_rels = {"CORRELATED_WITH", "CO_OCCURS_WITH", "HAS_CWE", "MAPS_TO_OWASP", "AFFECTS_SOFTWARE"}
        required_constraints = {"vuln_id_unique", "cwe_id_unique", "owasp_id_unique", "software_key_unique"}

        missing_labels = sorted(required_labels - set(label_counts.keys()))
        missing_rels = sorted(required_rels - set(rel_counts.keys()))
        missing_constraints = sorted(required_constraints - constraint_names)
        schema_ok = not (missing_labels or missing_rels or missing_constraints)
        checks.append(
            CheckResult(
                name="schema_and_volume",
                status="pass" if schema_ok else "fail",
                metrics={
                    "labels": label_counts,
                    "relationships": rel_counts,
                    "constraint_count": len(constraints_rows),
                    "missing_labels": missing_labels,
                    "missing_relationships": missing_rels,
                    "missing_constraints": missing_constraints,
                },
                notes="Core labels/relationships/constraints presence check.",
            )
        )

        # 2) Key integrity checks
        missing_vuln_id = int(_run_scalar(s, "MATCH (v:Vulnerability) WHERE v.vuln_id IS NULL RETURN count(v)") or 0)
        dup_vuln_rows = _run_list(
            s,
            "MATCH (v:Vulnerability) WITH v.vuln_id AS id, count(*) AS c WHERE id IS NOT NULL AND c > 1 RETURN id, c LIMIT 20",
        )
        missing_cwe_id = int(_run_scalar(s, "MATCH (w:CWE) WHERE w.cwe_id IS NULL RETURN count(w)") or 0)
        missing_owasp_id = int(
            _run_scalar(s, "MATCH (o:OWASPCategory) WHERE o.owasp_id IS NULL RETURN count(o)") or 0
        )
        integrity_ok = (
            missing_vuln_id == 0
            and missing_cwe_id == 0
            and missing_owasp_id == 0
            and len(dup_vuln_rows) == 0
        )
        checks.append(
            CheckResult(
                name="key_integrity",
                status="pass" if integrity_ok else "fail",
                metrics={
                    "missing_vuln_id": missing_vuln_id,
                    "missing_cwe_id": missing_cwe_id,
                    "missing_owasp_id": missing_owasp_id,
                    "duplicate_vuln_id_rows": len(dup_vuln_rows),
                },
                samples=dup_vuln_rows[:10],
            )
        )

        # 3) Relationship hygiene
        self_loops = int(
            _run_scalar(
                s,
                "MATCH (v:Vulnerability)-[r:CO_OCCURS_WITH|CORRELATED_WITH]->(v) RETURN count(r)",
            )
            or 0
        )
        dup_cooc = _run_list(
            s,
            """
            MATCH (a:Vulnerability)-[r:CO_OCCURS_WITH]->(b:Vulnerability)
            WITH a.vuln_id AS a, b.vuln_id AS b, count(r) AS c
            WHERE c > 1
            RETURN a, b, c LIMIT 20
            """,
        )
        dup_corr = _run_list(
            s,
            """
            MATCH (a:Vulnerability)-[r:CORRELATED_WITH]->(b:Vulnerability)
            WITH a.vuln_id AS a, b.vuln_id AS b, count(r) AS c
            WHERE c > 1
            RETURN a, b, c LIMIT 20
            """,
        )
        hygiene_ok = self_loops == 0 and len(dup_cooc) == 0 and len(dup_corr) == 0
        checks.append(
            CheckResult(
                name="relationship_hygiene",
                status="pass" if hygiene_ok else "fail",
                metrics={
                    "self_loops": self_loops,
                    "duplicate_coocc_rows": len(dup_cooc),
                    "duplicate_corr_rows": len(dup_corr),
                },
                samples=(dup_cooc[:5] + dup_corr[:5]),
            )
        )

        # 4) Coverage checks
        coverage_row = _run_list(
            s,
            """
            MATCH (v:Vulnerability)
            RETURN
              count(v) AS total,
              sum(CASE WHEN EXISTS { (v)-[:HAS_CWE]->() } THEN 1 ELSE 0 END) AS with_cwe,
              sum(CASE WHEN EXISTS { (v)-[:MAPS_TO_OWASP]->() } THEN 1 ELSE 0 END) AS with_owasp,
              sum(CASE WHEN EXISTS { (v)-[:AFFECTS_SOFTWARE]->() } THEN 1 ELSE 0 END) AS with_sw
            """,
        )[0]
        total = int(coverage_row.get("total", 0) or 0)
        with_cwe = int(coverage_row.get("with_cwe", 0) or 0)
        with_owasp = int(coverage_row.get("with_owasp", 0) or 0)
        with_sw = int(coverage_row.get("with_sw", 0) or 0)
        cov = {
            "cwe_ratio": round(with_cwe / total, 4) if total else 0.0,
            "owasp_ratio": round(with_owasp / total, 4) if total else 0.0,
            "sw_ratio": round(with_sw / total, 4) if total else 0.0,
        }
        coverage_ok = total > 0 and with_cwe > 0 and with_owasp > 0 and with_sw > 0
        cov_status = "pass" if coverage_ok and cov["cwe_ratio"] >= 0.5 and cov["owasp_ratio"] >= 0.3 else "warn"
        checks.append(
            CheckResult(
                name="coverage",
                status=cov_status,
                metrics={
                    "total": total,
                    "with_cwe": with_cwe,
                    "with_owasp": with_owasp,
                    "with_sw": with_sw,
                    **cov,
                },
                notes="Warns when coverage is non-zero but lower than target ratios.",
            )
        )

        # 5) Source alignment spot-check
        pool_rows = _run_list(
            s,
            """
            MATCH (v:Vulnerability)-[:CORRELATED_WITH|CO_OCCURS_WITH]-()
            WITH DISTINCT v.vuln_id AS cve_id
            WHERE cve_id IS NOT NULL
            RETURN cve_id
            ORDER BY cve_id
            LIMIT 5000
            """,
        )
        pool = [_normalize_cve(r.get("cve_id")) for r in pool_rows if _normalize_cve(r.get("cve_id"))]
        rng = random.Random(args.seed)
        sample_size = min(max(args.sample_cves, 1), len(pool))
        sampled = rng.sample(pool, sample_size) if sample_size else []
        source_lookup = _build_source_alignment_lookup(
            sample_cves=set(sampled),
            corr_path=Path(args.corr_file),
            cooc_path=Path(args.cooc_file),
            top_k=max(1, args.top_k_align),
        )

        mismatches: list[dict[str, Any]] = []
        checks_run = 0
        checks_good = 0
        for cve in sampled:
            graph_rows = _run_list(
                s,
                """
                MATCH (v:Vulnerability {vuln_id: $cve})-[r:CORRELATED_WITH|CO_OCCURS_WITH]-(x:Vulnerability)
                RETURN x.vuln_id AS cve_id, type(r) AS rel_type,
                       coalesce(r.max_score, r.max_confidence, r.confidence, 0.0) AS score
                ORDER BY score DESC LIMIT $top_k
                """,
                cve=cve,
                top_k=max(1, args.top_k_align),
            )
            graph_by_rel: dict[str, list[str]] = {"CORRELATED_WITH": [], "CO_OCCURS_WITH": []}
            for row in graph_rows:
                rel_type = _normalize(row.get("rel_type"))
                tgt = _normalize_cve(row.get("cve_id"))
                if rel_type in graph_by_rel and tgt:
                    graph_by_rel[rel_type].append(tgt)

            for rel_type in ("CORRELATED_WITH", "CO_OCCURS_WITH"):
                src = list(source_lookup.get(cve, {}).get(rel_type, {}).keys())
                if not src:
                    continue
                checks_run += 1
                gset = set(graph_by_rel[rel_type][: args.top_k_align])
                sset = set(src[: args.top_k_align])
                overlap = len(gset & sset)
                ratio = overlap / max(len(sset), 1)
                if ratio >= 0.4:
                    checks_good += 1
                else:
                    mismatches.append(
                        {
                            "cve_id": cve,
                            "rel_type": rel_type,
                            "overlap_ratio": round(ratio, 3),
                            "source_neighbors": list(sset)[:10],
                            "graph_neighbors": list(gset)[:10],
                        }
                    )
        if checks_run == 0:
            align_status = "warn"
        else:
            good_ratio = checks_good / checks_run
            align_status = "pass" if good_ratio >= 0.7 else "warn" if good_ratio >= 0.5 else "fail"
        checks.append(
            CheckResult(
                name="source_alignment",
                status=align_status,
                metrics={
                    "sample_pool": len(pool),
                    "sampled_cves": len(sampled),
                    "comparisons_run": checks_run,
                    "comparisons_good": checks_good,
                    "good_ratio": round(checks_good / checks_run, 3) if checks_run else 0.0,
                },
                notes="Graph neighbor overlap with raw source artifacts.",
                samples=mismatches[:10],
            )
        )

        # 6) Negative rule graph checks
        nr_count = int(_run_scalar(s, "MATCH (nr:NegativeRule) RETURN count(nr)") or 0)
        has_nr = int(_run_scalar(s, "MATCH ()-[r:HAS_NEGATIVE_RULE]->() RETURN count(r)") or 0)
        abs_if = int(_run_scalar(s, "MATCH ()-[r:RULE_ABSENT_IF]->() RETURN count(r)") or 0)
        still_assess = int(_run_scalar(s, "MATCH ()-[r:RULE_STILL_ASSESS]->() RETURN count(r)") or 0)
        neg_ok = nr_count > 0 and has_nr > 0 and abs_if > 0
        if args.expect_negative_rules:
            neg_status = "pass" if neg_ok else "fail"
        else:
            neg_status = "pass" if neg_ok else "warn"
        checks.append(
            CheckResult(
                name="negative_rule_graph",
                status=neg_status,
                metrics={
                    "negative_rule_nodes": nr_count,
                    "has_negative_rule_edges": has_nr,
                    "rule_absent_if_edges": abs_if,
                    "rule_still_assess_edges": still_assess,
                },
            )
        )

        # 7) Agent path verification via tool_graphrag_query
        agent_query_cve = sampled[0] if sampled else "CVE-2021-28310"
        payload = None
        agent_status = "warn"
        try:
            from pipeline.tools import tool_graphrag_query

            req = {
                "query": agent_query_cve,
                "entity": {"type": "cve", "id": agent_query_cve},
                "top_k": 20,
                "max_hops": 2,
                "use_vector": False,
            }
            raw_resp = tool_graphrag_query(json.dumps(req))
            payload = json.loads(raw_resp)
            direct = payload.get("direct_evidence", []) if isinstance(payload, dict) else []
            rel_types = {
                _normalize(item.get("rel_type"))
                for item in direct
                if isinstance(item, dict) and _normalize(item.get("rel_type"))
            }
            if direct and ("CORRELATED_WITH" in rel_types or "CO_OCCURS_WITH" in rel_types):
                agent_status = "pass"
            elif payload.get("status") == "error":
                agent_status = "fail"
            else:
                agent_status = "warn"
        except Exception as e:
            payload = {"error": str(e)}
            agent_status = "warn"

        checks.append(
            CheckResult(
                name="agent_path",
                status=agent_status,
                metrics={
                    "query_cve": agent_query_cve,
                    "status": payload.get("status") if isinstance(payload, dict) else None,
                    "direct_evidence_count": len(payload.get("direct_evidence", []))
                    if isinstance(payload, dict)
                    else 0,
                    "inferred_candidates_count": len(payload.get("inferred_candidates", []))
                    if isinstance(payload, dict)
                    else 0,
                },
                samples=[payload] if isinstance(payload, dict) else [],
            )
        )

    driver.close()

    pass_count = sum(1 for c in checks if c.status == "pass")
    warn_count = sum(1 for c in checks if c.status == "warn")
    fail_count = sum(1 for c in checks if c.status == "fail")
    overall = "pass" if fail_count == 0 and warn_count == 0 else "warn" if fail_count == 0 else "fail"

    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "neo4j_uri": neo4j_uri,
            "sample_cves": args.sample_cves,
            "seed": args.seed,
            "strict_mode": args.strict,
            "inputs": {
                "corr_file": args.corr_file,
                "cooc_file": args.cooc_file,
            },
        },
        "checks": [c.to_dict() for c in checks],
        "summary": {
            "overall_status": overall,
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
        },
    }

    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.output_md:
        out_md = Path(args.output_md)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(_render_markdown(report), encoding="utf-8")

    print(json.dumps(report["summary"], indent=2))
    if args.strict and overall != "pass":
        return 2
    if overall == "fail":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
