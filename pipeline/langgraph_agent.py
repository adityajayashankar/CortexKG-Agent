"""
pipeline/langgraph_agent.py
---------------------------
LangGraph-based agent loop for vulnerability analysis.

FIXES vs previous version:
  1. [NEW] tool_lookup_by_cwe added to TOOLS registry and imports.
     Enables CWE-first queries: "Given CWE-89, what else co-occurs?"

  2. [NEW] _CORR_HINT_RE expanded to catch natural language phrasings
     that the old narrow regex missed:
       "related to CVE-X", "comes with", "associated with",
       "same campaign", "chained with", "if I see X should I check Y",
       "what other", "companion vuln"

  3. [NEW] _should_force_cwe_tool guardrail — mirrors the existing
     _should_force_likely_tool but routes CWE-only queries directly to
     lookup_by_cwe on step 1, skipping an unnecessary LLM planning step.

  4. [NEW] _planner_node updated to check both CVE and CWE guardrails.
"""

import json
import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from pipeline.model_loader import ask_model
from pipeline.tools import (
    tool_fetch_epss,
    tool_graphrag_query,
    tool_generate_finding,
    tool_get_pentest_method,
    tool_get_remediation,
    tool_likely_on_system,
    tool_lookup_by_cwe,       # FIX 1
    tool_lookup_cve,
    tool_map_owasp,
    tool_score_risk,
    tool_select_tool,
)


TOOLS = {
    "graphrag_query": (
        tool_graphrag_query,
        'Hybrid GraphRAG retrieval with strict JSON output. Arg: JSON '
        '{"query":"...","entity":{"type":"cve|cwe","id":"..."},"top_k":12}',
    ),
    "lookup_cve": (
        tool_lookup_cve,
        "Fetch CVE details, CWE, and CVSS from NVD. Arg: CVE-ID string",
    ),
    "likely_on_system": (
        tool_likely_on_system,
        'Given CVE-X, return likely co-present vulnerabilities from KG. '
        'Arg: CVE-ID string OR JSON {"cve_id":"...","top_k":15}',
    ),
    "lookup_by_cwe": (                                          # FIX 1
        tool_lookup_by_cwe,
        "Given a CWE-ID, return CVEs in that weakness family and their co-occurring vulns. "
        "Arg: CWE-ID string (e.g. 'CWE-89')",
    ),
    "map_owasp": (
        tool_map_owasp,
        "Map vulnerability to OWASP Top 10 category. Arg: description string",
    ),
    "get_pentest_method": (
        tool_get_pentest_method,
        "Get attack method, payloads, detection signals. Arg: vulnerability description",
    ),
    "select_tool": (
        tool_select_tool,
        "Recommend security testing tool. Arg: OWASP category string",
    ),
    "fetch_epss": (
        tool_fetch_epss,
        "Get EPSS exploit probability score. Arg: CVE-ID string",
    ),
    "score_risk": (
        tool_score_risk,
        "Generate full risk assessment. Arg: vulnerability description",
    ),
    "generate_finding": (
        tool_generate_finding,
        'Generate audit finding report. Arg: JSON string — '
        '{"name":"...","cve":"...","desc":"...","cvss":"...","owasp":"..."}',
    ),
    "get_remediation": (
        tool_get_remediation,
        "Get fix recommendation and root cause. Arg: vulnerability description",
    ),
}

TOOL_NAMES = set(TOOLS.keys())
TOOL_MENU  = "\n".join([f"  - {k}: {v[1]}" for k, v in TOOLS.items()])

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# FIX 2: Expanded trigger patterns for co-occurrence / correlation queries
_CORR_HINT_RE = re.compile(
    r"("
    r"correlat"
    r"|co-?occur"
    r"|same system"
    r"|what else"
    r"|likely on"
    r"|related (to|vulnerabilit)"
    r"|comes? with"
    r"|associated with"
    r"|same campaign"
    r"|chained? with"
    r"|if (i|we) (see|find|have)"
    r"|should (i|we) (also|check)"
    r"|what (other|comes?)"
    r"|companion vuln"
    r")",
    re.IGNORECASE,
)

AGENT_SYSTEM_PROMPT = f"""You are a multi-layer cybersecurity audit agent.
You have access to these tools:
{TOOL_MENU}

To call a tool, reply on its own line:
  ACTION: tool_name(argument)

For correlation/co-occurrence questions, prioritize graphrag_query first.
If graph/vector evidence is sparse, clearly separate direct evidence from inferred candidates.

When you have gathered enough information, reply:
  FINAL: <JSON object only>

Always produce strict machine-readable JSON in FINAL output.
"""

_ACTION_RE = re.compile(
    r"(?:ACTION|TOOL|CALL|EXECUTE|USE):\s*(\w+)\s*\((.+?)\)\s*$",
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)
_FINAL_RE = re.compile(
    r"(?:FINAL(?:\s+(?:ANSWER|RESPONSE|REPORT))?|CONCLUSION):\s*(.+)",
    re.IGNORECASE | re.DOTALL,
)


class AgentState(TypedDict):
    user_query:   str
    memory:       list[str]
    max_steps:    int
    step_num:     int
    verbose:      bool
    pending_tool: str
    pending_arg:  str
    final_answer: str
    tool_results: list[str]


def _is_model_error(text: str) -> bool:
    t = (text or "").strip()
    return (
        t.startswith("[")
        and any(
            phrase in t
            for phrase in (
                "OpenRouter failed",
                "OpenRouter auth failed",
                "Local model unavailable",
                "Model not loaded",
                "Inference failed",
                "No LLM backend available",
            )
        )
    )


def _extract_tool_json(tool_results: list[str], tool_name: str) -> dict | None:
    prefix = f"[{tool_name}]:"
    for entry in reversed(tool_results):
        if not entry.startswith(prefix):
            continue
        raw = entry[len(prefix):].strip()
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None


def _fallback_report_from_tools(state: AgentState) -> str:
    graphrag_payload = _extract_tool_json(state.get("tool_results", []), "graphrag_query")
    if isinstance(graphrag_payload, dict):
        return json.dumps(graphrag_payload)

    likely_payload = _extract_tool_json(state.get("tool_results", []), "likely_on_system")
    if isinstance(likely_payload, dict):
        cve = likely_payload.get("query_cve", "unknown")
        rows = likely_payload.get("results", [])
        direct = [r for r in rows if str(r.get("evidence_tier", "")).startswith("direct")]
        inferred = [r for r in rows if r not in direct]
        overall = round(
            sum(float(r.get("likelihood", 0.0)) for r in rows[:5]) / max(len(rows[:5]), 1),
            3,
        )
        contract = {
            "status": "needs_human_review",
            "query": state.get("user_query", ""),
            "entity": {"type": "cve", "id": cve},
            "direct_evidence": direct[:10],
            "inferred_candidates": inferred[:10],
            "citations": [
                {
                    "citation_id": f"legacy-{idx+1}",
                    "source_type": r.get("rel_type", "kg"),
                    "entity_id": r.get("cve_id", ""),
                    "snippet": ", ".join(r.get("signals", [])[:2]) or "legacy tool evidence",
                    "metadata": {"tier": r.get("evidence_tier", "unknown")},
                }
                for idx, r in enumerate(rows[:10])
            ],
            "confidence_summary": {
                "overall": overall,
                "rationale": "Derived from legacy likely_on_system fallback.",
            },
            "hitl": {
                "required": True,
                "reasons": ["LLM unavailable or final synthesis failed."],
            },
            "recommended_actions": [],
        }
        return json.dumps(contract)

    contract = {
        "status": "error",
        "query": state.get("user_query", ""),
        "entity": {"type": "unknown", "id": ""},
        "direct_evidence": [],
        "inferred_candidates": [],
        "citations": [],
        "confidence_summary": {
            "overall": 0.0,
            "rationale": "No tool payload available for synthesis.",
        },
        "hitl": {"required": True, "reasons": ["No retrievable evidence available."]},
        "recommended_actions": [],
        "error": "No model response and no tool payload available.",
    }
    return json.dumps(contract)


def _extract_cve(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def _extract_cwe(text: str) -> str | None:
    m = _CWE_RE.search(text or "")
    return m.group(0).upper() if m else None


def _should_force_likely_tool(state: AgentState) -> bool:
    """Force GraphRAG retrieval on step 1 for CVE + co-occurrence queries."""
    if state["step_num"] > 0 or state["tool_results"]:
        return False
    user_query = state.get("user_query", "")
    return bool(_extract_cve(user_query) and _CORR_HINT_RE.search(user_query))


def _should_force_cwe_tool(state: AgentState) -> str | None:
    """Force GraphRAG retrieval on step 1 for CWE-only co-occurrence queries."""
    if state["step_num"] > 0 or state["tool_results"]:
        return None
    user_query = state.get("user_query", "")
    if _extract_cve(user_query):
        return None  # CVE present — let the CVE guardrail handle it
    cwe = _extract_cwe(user_query)
    if cwe and _CORR_HINT_RE.search(user_query):
        return cwe
    return None


def _parse_action(text: str) -> tuple[str | None, str | None]:
    for match in _ACTION_RE.finditer(text):
        tool_name = match.group(1).strip()
        tool_arg  = match.group(2).strip()
        if tool_name in TOOL_NAMES:
            return tool_name, tool_arg
        for registered in TOOL_NAMES:
            if tool_name.lower() == registered.lower():
                return registered, tool_arg
    return None, None


def _parse_final(text: str) -> str | None:
    m = _FINAL_RE.search(text)
    return m.group(1).strip() if m else None


def _looks_like_contract(payload: dict) -> bool:
    required = {
        "status",
        "query",
        "entity",
        "direct_evidence",
        "inferred_candidates",
        "citations",
        "confidence_summary",
        "hitl",
        "recommended_actions",
    }
    return required.issubset(set(payload.keys()))


def _ensure_contract_json(state: AgentState, raw_answer: str) -> str:
    """
    Guarantee strict JSON contract output regardless of model behavior.
    """
    text = (raw_answer or "").strip()
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and _looks_like_contract(parsed):
                return json.dumps(parsed)
        except Exception:
            pass

    graphrag_payload = _extract_tool_json(state.get("tool_results", []), "graphrag_query")
    if isinstance(graphrag_payload, dict) and _looks_like_contract(graphrag_payload):
        return json.dumps(graphrag_payload)

    return _fallback_report_from_tools(state)


def _call_tool(tool_name: str, tool_arg: str) -> str:
    tool_fn = TOOLS[tool_name][0]
    if tool_name == "generate_finding":
        try:
            kwargs = json.loads(tool_arg)
            return tool_fn(
                vuln_name=kwargs.get("name", ""),
                cve_id=kwargs.get("cve", ""),
                description=kwargs.get("desc", ""),
                cvss=kwargs.get("cvss", ""),
                owasp=kwargs.get("owasp", ""),
            )
        except (json.JSONDecodeError, TypeError):
            parts = [p.strip() for p in tool_arg.split("|")]
            parts += [""] * (5 - len(parts))
            return tool_fn(*parts[:5])
    return tool_fn(tool_arg)


# ── LangGraph nodes ────────────────────────────────────────────────────────────

def _planner_node(state: AgentState) -> AgentState:
    step_num = state["step_num"] + 1
    context  = "\n".join(state["memory"])

    # FIX 3 + 4: Check both guardrails before calling the LLM
    cwe_target = _should_force_cwe_tool(state)
    if _should_force_likely_tool(state):
        cve      = _extract_cve(state["user_query"])
        forced_arg = json.dumps(
            {
                "query": f"cooccurrence for {cve}",
                "entity": {"type": "cve", "id": cve},
                "top_k": 12,
                "max_hops": 2,
            }
        )
        response = f"ACTION: graphrag_query({forced_arg})"
    elif cwe_target:
        forced_arg = json.dumps(
            {
                "query": f"cooccurrence for {cwe_target}",
                "entity": {"type": "cwe", "id": cwe_target},
                "top_k": 12,
                "max_hops": 2,
            }
        )
        response = f"ACTION: graphrag_query({forced_arg})"
    else:
        response = ask_model(
            instruction=(
                "Based on the conversation so far, decide the next step. "
                "Call a tool using ACTION: tool_name(argument) "
                "or provide your complete FINAL JSON contract."
            ),
            context=context,
            layer="general",
        )
        if _is_model_error(response) and state.get("tool_results"):
            response = f"FINAL: {_fallback_report_from_tools(state)}"

    if state["verbose"]:
        preview = response[:250] + ("..." if len(response) > 250 else "")
        print(f"\n[LangGraph Step {step_num}] {preview}")

    memory     = state["memory"] + [f"[AGENT]: {response}"]
    final_text = _parse_final(response)
    tool_name, tool_arg = _parse_action(response)

    return {
        **state,
        "step_num":     step_num,
        "memory":       memory,
        "final_answer": final_text or "",
        "pending_tool": tool_name or "",
        "pending_arg":  tool_arg or "",
    }


def _tool_node(state: AgentState) -> AgentState:
    tool_name = state.get("pending_tool", "")
    tool_arg  = state.get("pending_arg", "")
    try:
        result = _call_tool(tool_name, tool_arg)
        if state["verbose"]:
            print(f"  -> {tool_name}({tool_arg[:60]}...) = {result[:150]}...")
        memory       = state["memory"] + [f"[TOOL {tool_name}]: {result}"]
        tool_results = state["tool_results"] + [f"[{tool_name}]: {result}"]
    except Exception as exc:
        err_msg      = f"Tool {tool_name} failed: {exc}"
        if state["verbose"]:
            print(f"  x {err_msg}")
        memory       = state["memory"] + [f"[TOOL {tool_name} ERROR]: {err_msg}"]
        tool_results = state["tool_results"]

    return {**state, "memory": memory, "tool_results": tool_results,
            "pending_tool": "", "pending_arg": ""}


def _nudge_node(state: AgentState) -> AgentState:
    nudge = (
        "[SYSTEM]: No valid tool call found. "
        "Please call a tool with ACTION: tool_name(argument) "
        f"or end with FINAL: <your analysis>. "
        f"Available tools: {', '.join(sorted(TOOL_NAMES))}"
    )
    if state["verbose"]:
        print("  ! No action parsed; nudging model.")
    return {**state, "memory": state["memory"] + [nudge]}


def _finalize_node(state: AgentState) -> AgentState:
    if state["verbose"]:
        print(f"\n! Max steps ({state['max_steps']}) reached; generating forced contract.")

    summary_context = (
        f"Original query: {state['user_query']}\n\n"
        + "\n\n".join(state["tool_results"])
        if state["tool_results"]
        else "\n".join(state["memory"][-6:])
    )
    forced = ask_model(
        instruction=(
            "Return ONLY a strict JSON object with fields: "
            "status, query, entity, direct_evidence, inferred_candidates, "
            "citations, confidence_summary, hitl, recommended_actions. "
            "No markdown, no prose outside JSON."
        ),
        context=summary_context,
        layer="audit_evidence",
    )
    if _is_model_error(forced):
        forced = _fallback_report_from_tools(state)
    return {**state, "final_answer": forced}


# ── Routing ────────────────────────────────────────────────────────────────────

def _route_after_planner(state: AgentState) -> str:
    if state["final_answer"]:
        return "done"
    if state["pending_tool"]:
        return "tool"
    if state["step_num"] >= state["max_steps"]:
        return "finalize"
    return "nudge"


def _route_after_tool(state: AgentState) -> str:
    if state["step_num"] >= state["max_steps"]:
        return "finalize"
    return "planner"


def _route_after_nudge(state: AgentState) -> str:
    if state["step_num"] >= state["max_steps"]:
        return "finalize"
    return "planner"


# ── Graph assembly ─────────────────────────────────────────────────────────────

def _build_graph() -> StateGraph:
    g = StateGraph(AgentState)
    g.add_node("planner",  _planner_node)
    g.add_node("tool",     _tool_node)
    g.add_node("nudge",    _nudge_node)
    g.add_node("finalize", _finalize_node)

    g.add_edge(START, "planner")
    g.add_conditional_edges(
        "planner",
        _route_after_planner,
        {"done": END, "tool": "tool", "nudge": "nudge", "finalize": "finalize"},
    )
    g.add_conditional_edges(
        "tool",
        _route_after_tool,
        {"planner": "planner", "finalize": "finalize"},
    )
    g.add_conditional_edges(
        "nudge",
        _route_after_nudge,
        {"planner": "planner", "finalize": "finalize"},
    )
    g.add_edge("finalize", END)
    return g.compile()


_GRAPH = None


def run_agent(
    user_query: str,
    max_steps:  int  = 10,
    verbose:    bool = True,
) -> str:
    """
    Run the LangGraph vulnerability analysis agent.

    Args:
        user_query: Free-text question or CVE/CWE ID to analyze.
        max_steps:  Max reasoning steps before forcing final answer.
        verbose:    Print step-by-step reasoning.

    Returns:
        str: Final strict JSON contract.
    """
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = _build_graph()

    initial_state: AgentState = {
        "user_query":   user_query,
        "memory":       [f"[SYSTEM]: {AGENT_SYSTEM_PROMPT}", f"[USER]: {user_query}"],
        "max_steps":    max_steps,
        "step_num":     0,
        "verbose":      verbose,
        "pending_tool": "",
        "pending_arg":  "",
        "final_answer": "",
        "tool_results": [],
    }

    final_state = _GRAPH.invoke(initial_state)
    return _ensure_contract_json(
        final_state,
        final_state.get("final_answer", ""),
    )
