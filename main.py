"""
main.py
-------
Entry point for the vulnerability analysis agent.
Run: python main.py
"""
import json

from dotenv import load_dotenv
load_dotenv()
from pipeline.langgraph_agent import run_agent

W = 80  # column width


def _bar(char="=") -> str:
    return char * W


def _fmt_report(raw: str) -> str:
    """
    Pretty-print the agent's JSON report in human-readable form.
    Falls back to raw text if the output is not valid JSON.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw  # plain text (e.g. from lookup_by_cwe, generate_finding)

    if not isinstance(data, dict):
        return raw

    lines = []

    # ── Status / entity ──────────────────────────────────────────────
    status = data.get("status", "unknown").upper()
    entity = data.get("entity") or {}
    ent_str = f"{entity.get('type','').upper()} {entity.get('id','')}" if entity else ""
    hitl    = data.get("hitl", {})
    conf    = data.get("confidence_summary", {})

    lines.append(f"  Query      : {data.get('query','')}")
    if ent_str:
        lines.append(f"  Entity     : {ent_str}")
    lines.append(f"  Status     : {status}")
    lines.append(f"  Confidence : {conf.get('overall', 0.0):.1%}  —  {conf.get('rationale','')}")
    if hitl.get("required"):
        lines.append(f"  ⚠  Human review required: {'; '.join(hitl.get('reasons', []))}")
    lines.append("")

    # ── Evidence breakdown ───────────────────────────────────────────
    breakdown = data.get("evidence_breakdown", {})
    direct_ev = data.get("direct_evidence", [])
    inferred  = data.get("inferred_candidates", [])

    if breakdown:
        rel_counts = "  |  ".join(
            f"{k}: {v}" for k, v in breakdown.get("by_rel_type", {}).items()
        )
        lines.append(
            f"  Evidence   : {breakdown.get('direct_count',0)} direct  |  "
            f"{breakdown.get('inferred_count',0)} inferred"
            + (f"  [{rel_counts}]" if rel_counts else "")
        )
        lines.append("")

    # ── Direct evidence table ────────────────────────────────────────
    if direct_ev:
        lines.append("  DIRECT EVIDENCE (from Neo4j Knowledge Graph)")
        lines.append("  " + "-" * (W - 4))
        lines.append(f"  {'CVE ID':<20} {'Rel Type':<20} {'Score':>6}  Evidence")
        lines.append("  " + "-" * (W - 4))
        for ev in direct_ev:
            sigs    = ev.get("signals", []) or []
            reasons = ev.get("reasons", []) or []
            if sigs:
                evidence = ", ".join(sigs)
                if reasons:
                    note = reasons[0]
                    evidence += f"  ({note[:45]}{'…' if len(note) > 45 else ''})"
            else:
                evidence = reasons[0] if reasons else "—"
            lines.append(
                f"  {ev.get('cve_id',''):<20} "
                f"{ev.get('rel_type',''):<20} "
                f"{ev.get('likelihood', 0.0):>6.3f}  {evidence}"
            )
        lines.append("")

    # ── Inferred candidates ──────────────────────────────────────────
    if inferred:
        lines.append("  INFERRED CANDIDATES (2-hop)")
        lines.append("  " + "-" * (W - 4))
        lines.append(f"  {'CVE ID':<20} {'Rel Type':<25} {'Score':>6}  Path / Evidence")
        lines.append("  " + "-" * (W - 4))
        for ev in inferred:
            all_sigs = ev.get("signals", []) or []
            # Separate via/origin path markers from real evidence signals
            path_parts = [s for s in all_sigs if s.startswith("via:") or s.startswith("origin:")]
            sig_parts  = [s for s in all_sigs if not s.startswith("via:") and not s.startswith("origin:")]
            inferred_from = ev.get("inferred_from", []) or []
            if path_parts:
                via    = next((p[4:]  for p in path_parts if p.startswith("via:")),    "")
                origin = next((p[7:]  for p in path_parts if p.startswith("origin:")), "")
                path_str = f"{origin} → {via} → {ev.get('cve_id','')}"
            elif inferred_from:
                path_str = " → ".join(inferred_from[:3])
            else:
                path_str = "—"
            evidence = ", ".join(sig_parts) if sig_parts else path_str
            lines.append(
                f"  {ev.get('cve_id',''):<20} "
                f"{ev.get('rel_type',''):<25} "
                f"{ev.get('likelihood', 0.0):>6.3f}  {evidence}"
            )
            # Show the hop path on the line below if there are both evidence signals and a path
            if sig_parts and path_parts:
                lines.append(f"  {'':20} {'':25} {'':6}  ↳ via {via}")
        lines.append("")

    # ── Recommended actions ──────────────────────────────────────────
    actions = data.get("recommended_actions", [])
    if actions:
        lines.append("  RECOMMENDED ACTIONS")
        for i, a in enumerate(actions, 1):
            lines.append(f"  {i}. {a}")
        lines.append("")

    # ── Error note ───────────────────────────────────────────────────
    if data.get("error"):
        lines.append(f"  NOTE: {data['error']}")
        lines.append("")

    return "\n".join(lines)


def main():
    print(_bar())
    print("  Vulnerability Analysis Agent")
    print("  Powered by Neo4j Knowledge Graph  |  Graph-only retrieval")
    print(_bar())
    print("  Commands: CVE ID, CWE ID, or natural language question")
    print("  Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() in {"exit", "quit", "q"}:
            print("Goodbye.")
            break
        if not user_input:
            continue

        print("\nAgent working...\n")
        result = run_agent(user_input, verbose=True)

        print("\n" + _bar())
        print("  REPORT")
        print(_bar())
        print(_fmt_report(result))
        print(_bar() + "\n")


if __name__ == "__main__":
    main()
