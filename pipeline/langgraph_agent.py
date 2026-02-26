"""
pipeline/langgraph_agent.py
---------------------------
LangGraph-based agent loop for vulnerability analysis.

This keeps the same ACTION:/FINAL: interaction contract used by the
existing agent, but runs it inside an explicit state graph.
"""

import json
import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from pipeline.model_loader import ask_model
from pipeline.tools import (
    tool_fetch_epss,
    tool_generate_finding,
    tool_get_pentest_method,
    tool_get_remediation,
    tool_likely_on_system,
    tool_lookup_cve,
    tool_map_owasp,
    tool_score_risk,
    tool_select_tool,
)


TOOLS = {
    "lookup_cve": (
        tool_lookup_cve,
        "Fetch CVE details, CWE, and CVSS from NVD. Arg: CVE-ID string",
    ),
    "likely_on_system": (
        tool_likely_on_system,
        'Given CVE-X, return likely co-present vulnerabilities from KG. Arg: CVE-ID string OR JSON {"cve_id":"...","top_k":15}',
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
        'Generate audit finding report. Arg: JSON string — {"name":"...","cve":"...","desc":"...","cvss":"...","owasp":"..."}',
    ),
    "get_remediation": (
        tool_get_remediation,
        "Get fix recommendation and root cause. Arg: vulnerability description",
    ),
}

TOOL_NAMES = set(TOOLS.keys())
TOOL_MENU = "\n".join([f"  - {k}: {v[1]}" for k, v in TOOLS.items()])
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CORR_HINT_RE = re.compile(r"(correlat|co-?occur|same system|what else|likely on|related vulnerabilities)", re.IGNORECASE)

AGENT_SYSTEM_PROMPT = f"""You are a multi-layer cybersecurity audit agent.
You have access to these tools:
{TOOL_MENU}

To call a tool, reply on its own line:
  ACTION: tool_name(argument)

When the user asks what else is likely on the same system for CVE-X,
prioritize calling likely_on_system first.
If likely_on_system returns sparse evidence, use its inferred gap-filled candidates
and clearly label them as inferred, not confirmed.

When you have gathered enough information, reply:
  FINAL: <your complete vulnerability analysis report>

Think step by step. Cover: vulnerability details, OWASP mapping, EPSS score, risk scoring, and remediation.
Always end with FINAL: when your analysis is complete.
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
    user_query: str
    memory: list[str]
    max_steps: int
    step_num: int
    verbose: bool
    pending_tool: str
    pending_arg: str
    final_answer: str
    tool_results: list[str]


def _is_model_error(text: str) -> bool:
    t = (text or "").strip()
    return (
        t.startswith("[")
        and (
            "OpenRouter failed" in t
            or "OpenRouter auth failed" in t
            or "Local model unavailable" in t
            or "Model not loaded" in t
            or "Inference failed" in t
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
    payload = _extract_tool_json(state.get("tool_results", []), "likely_on_system")
    if not payload:
        return (
            "No model response available. Tool results were collected but could not be "
            "synthesized automatically. Re-run with a working LLM backend."
        )

    cve = payload.get("query_cve", "unknown CVE")
    direct = payload.get("direct_count", 0)
    inferred = payload.get("inferred_count", 0)
    rows = payload.get("results", [])[:10]

    lines = [
        f"Knowledge-gap co-occurrence/correlation report for {cve}.",
        f"Evidence summary: direct={direct}, inferred={inferred}.",
        "Top likely co-present vulnerabilities:",
    ]

    for i, r in enumerate(rows, 1):
        rid = r.get("cve_id", "unknown")
        likelihood = r.get("likelihood", 0.0)
        tier = r.get("evidence_tier", "inferred")
        inferred_from = r.get("inferred_from", [])
        reason = ""
        if inferred_from:
            reason = f" | inferred_from={', '.join(inferred_from)}"
        lines.append(f"{i}. {rid} | likelihood={likelihood} | tier={tier}{reason}")

    lines.append("Validation note: inferred entries are hypothesis-grade and should be confirmed with active testing.")
    return "\n".join(lines)


def _extract_cve(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def _should_force_likely_tool(state: AgentState) -> bool:
    """
    Deterministic guardrail:
    For correlation/co-occurrence user queries with an explicit CVE, force
    likely_on_system tool call on the first planner step.
    """
    if state["step_num"] > 0 or state["tool_results"]:
        return False
    user_query = state.get("user_query", "")
    return bool(_extract_cve(user_query) and _CORR_HINT_RE.search(user_query))


def _parse_action(text: str) -> tuple[str | None, str | None]:
    for match in _ACTION_RE.finditer(text):
        tool_name = match.group(1).strip()
        tool_arg = match.group(2).strip()
        if tool_name in TOOL_NAMES:
            return tool_name, tool_arg
        for registered in TOOL_NAMES:
            if tool_name.lower() == registered.lower():
                return registered, tool_arg
    return None, None


def _parse_final(text: str) -> str | None:
    m = _FINAL_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


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


def _planner_node(state: AgentState) -> AgentState:
    step_num = state["step_num"] + 1
    context = "\n".join(state["memory"])

    if _should_force_likely_tool(state):
        cve = _extract_cve(state["user_query"])
        response = f"ACTION: likely_on_system({cve})"
    else:
        response = ask_model(
            instruction=(
                "Based on the conversation so far, decide the next step. "
                "Call a tool using ACTION: tool_name(argument) "
                "or provide your complete FINAL: analysis."
            ),
            context=context,
            layer="general",
        )
        if _is_model_error(response) and state.get("tool_results"):
            response = f"FINAL: {_fallback_report_from_tools(state)}"

    if state["verbose"]:
        preview = response[:250] + ("..." if len(response) > 250 else "")
        print(f"\n[LangGraph Step {step_num}] {preview}")

    memory = state["memory"] + [f"[AGENT]: {response}"]
    final_text = _parse_final(response)
    tool_name, tool_arg = _parse_action(response)

    return {
        **state,
        "step_num": step_num,
        "memory": memory,
        "final_answer": final_text or "",
        "pending_tool": tool_name or "",
        "pending_arg": tool_arg or "",
    }


def _tool_node(state: AgentState) -> AgentState:
    tool_name = state.get("pending_tool", "")
    tool_arg = state.get("pending_arg", "")

    try:
        result = _call_tool(tool_name, tool_arg)
        if state["verbose"]:
            print(f"  -> {tool_name}({tool_arg[:60]}...) = {result[:150]}...")
        memory = state["memory"] + [f"[TOOL {tool_name}]: {result}"]
        tool_results = state["tool_results"] + [f"[{tool_name}]: {result}"]
    except Exception as exc:
        err_msg = f"Tool {tool_name} failed: {exc}"
        if state["verbose"]:
            print(f"  x {err_msg}")
        memory = state["memory"] + [f"[TOOL {tool_name} ERROR]: {err_msg}"]
        tool_results = state["tool_results"]

    return {
        **state,
        "memory": memory,
        "tool_results": tool_results,
        "pending_tool": "",
        "pending_arg": "",
    }


def _nudge_node(state: AgentState) -> AgentState:
    nudge = (
        "[SYSTEM]: No valid tool call found. "
        "Please call a tool with ACTION: tool_name(argument) "
        f"or end with FINAL: <your analysis>. Available tools: {', '.join(TOOL_NAMES)}"
    )
    if state["verbose"]:
        print("  ! No action parsed; nudging model.")
    return {
        **state,
        "memory": state["memory"] + [nudge],
    }


def _finalize_node(state: AgentState) -> AgentState:
    if state["verbose"]:
        print(f"\n! Max steps ({state['max_steps']}) reached; generating forced summary.")

    if state["tool_results"]:
        summary_context = (
            f"Original query: {state['user_query']}\n\n" + "\n\n".join(state["tool_results"])
        )
    else:
        summary_context = "\n".join(state["memory"][-6:])

    forced = ask_model(
        instruction=(
            "The analysis agent has gathered the following information. "
            "Synthesize it into a complete vulnerability analysis report covering: "
            "CVE details, OWASP category, risk score, attack method, remediation, and "
            "co-occurrence/correlation candidates. Clearly distinguish direct evidence "
            "from inferred gap-filled candidates."
        ),
        context=summary_context,
        layer="audit_evidence",
    )
    if _is_model_error(forced):
        forced = _fallback_report_from_tools(state)

    return {
        **state,
        "final_answer": forced,
    }


def _route_after_plan(state: AgentState) -> str:
    if state.get("final_answer"):
        return "finish"
    if state.get("pending_tool"):
        return "tool"
    if state["step_num"] >= state["max_steps"]:
        return "finalize"
    return "nudge"


def _build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("planner", _planner_node)
    graph.add_node("tool", _tool_node)
    graph.add_node("nudge", _nudge_node)
    graph.add_node("finalize", _finalize_node)

    graph.add_edge(START, "planner")
    graph.add_conditional_edges(
        "planner",
        _route_after_plan,
        {
            "finish": END,
            "tool": "tool",
            "nudge": "nudge",
            "finalize": "finalize",
        },
    )
    graph.add_edge("tool", "planner")
    graph.add_edge("nudge", "planner")
    graph.add_edge("finalize", END)

    return graph.compile()


_LANGGRAPH_APP = _build_graph()


def run_langgraph_agent(
    user_query: str,
    max_steps: int = 8,
    verbose: bool = True,
) -> str:
    """
    Run the vulnerability agent using LangGraph.
    """
    initial_state: AgentState = {
        "user_query": user_query,
        "memory": [
            f"[SYSTEM]: {AGENT_SYSTEM_PROMPT}",
            f"[USER]: {user_query}",
        ],
        "max_steps": max_steps,
        "step_num": 0,
        "verbose": verbose,
        "pending_tool": "",
        "pending_arg": "",
        "final_answer": "",
        "tool_results": [],
    }

    final_state = _LANGGRAPH_APP.invoke(initial_state)
    return final_state.get("final_answer", "[Agent returned no final answer]")
