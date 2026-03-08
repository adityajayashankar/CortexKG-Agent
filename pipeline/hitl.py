from __future__ import annotations

from typing import Any


def evaluate_hitl_policy(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministic risk-triggered HITL policy.

    Trigger conditions:
      1) Inferred evidence dominates direct evidence.
      2) Overall confidence is low.
      3) Source disagreement is detected.
      4) High-risk context has weak support.
    """
    reasons: list[str] = []

    direct = payload.get("direct_evidence", []) or []
    inferred = payload.get("inferred_candidates", []) or []
    citations = payload.get("citations", []) or []

    overall = float((payload.get("confidence_summary") or {}).get("overall", 0.0))
    top_likelihood = 0.0
    for row in (direct + inferred)[:3]:
        top_likelihood = max(top_likelihood, float(row.get("likelihood", 0.0)))

    if len(inferred) > len(direct) and len(direct) < 2:
        reasons.append("Inferred evidence dominates direct evidence.")

    if overall < 0.40:
        reasons.append("Overall confidence below threshold (0.40).")

    source_types = {str(c.get("source_type", "")).lower() for c in citations}
    if "graph" in source_types and ("vector" in source_types or "raw_cooccurrence_v2" in source_types) and not direct:
        reasons.append("Source disagreement detected with no direct corroboration.")

    entity = payload.get("entity") or {}
    ent_type = str(entity.get("type", "")).lower()
    if ent_type == "cve" and (len(direct) < 2 and top_likelihood < 0.50):
        reasons.append("High-risk CVE context has weak supporting evidence.")

    # Calibration: flag when confidence is high but evidence count is very low
    if overall > 0.60 and len(direct) + len(inferred) < 3:
        reasons.append("High confidence with sparse evidence — potential over-estimation.")

    return {"required": bool(reasons), "reasons": reasons}

