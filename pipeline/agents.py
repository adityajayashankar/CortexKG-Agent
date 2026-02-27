"""
pipeline/agents.py
------------------
Agentic pipeline loop for vulnerability analysis.

FIXES vs previous version:
  1. parse_action() was case-sensitive. Now uses case-insensitive regex
     accepting ACTION/TOOL/CALL/EXECUTE/USE variants.

  2. generate_finding pipe-delimiter arg bug fixed — now uses JSON string.

  3. FINAL: extraction handles "FINAL ANSWER:", "FINAL RESPONSE:", "CONCLUSION:".

  4. Agent loop produces a meaningful summary even if model never calls FINAL:.

  5. [NEW] tool_likely_on_system and tool_lookup_by_cwe added to the tool
     registry. These existed in langgraph_agent.py but were missing here,
     meaning the co-occurrence / KG features were completely unavailable
     when using agents.py.

  6. [NEW] _CORR_HINT_RE expanded — was too narrow and missed natural phrasings
     like "related to CVE-X", "if I see X should I check Y", "comes with",
     "associated with", "same campaign", "chained with".

  7. [NEW] Deterministic guardrail (_should_force_likely_tool) ported from
     langgraph_agent.py — forces likely_on_system on first step for
     co-occurrence queries instead of hoping the LLM will call it.
"""

import re
import json

from pipeline.model_loader import ask_model
from pipeline.tools import (
    tool_graphrag_query,
    tool_lookup_cve,
    tool_map_owasp,
    tool_get_pentest_method,
    tool_select_tool,
    tool_fetch_epss,
    tool_score_risk,
    tool_generate_finding,
    tool_get_remediation,
    tool_likely_on_system,   # FIX 5: was missing
    tool_lookup_by_cwe,      # FIX 5: was missing
)


# ── Tool registry ──────────────────────────────────────────────────────────────

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
    "likely_on_system": (                                           # FIX 5
        tool_likely_on_system,
        'Given CVE-X, return likely co-present vulnerabilities from KG. '
        'Arg: CVE-ID string OR JSON {"cve_id":"...","top_k":15}',
    ),
    "lookup_by_cwe": (                                              # FIX 5
        tool_lookup_by_cwe,
        "Given a CWE-ID, return CVEs in that weakness family and co-occurring vulns. "
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

AGENT_SYSTEM_PROMPT = f"""You are a multi-layer cybersecurity audit agent.
...
When synthesizing likely_on_system results, you MUST:
1. List the top 5 co-occurring CVEs by name with their likelihood scores
2. Note which are KEV-confirmed (actively exploited)
3. Explain WHY they co-occur (the reason field from the tool)
4. Only then give remediation advice
Do NOT write generic summaries — use the exact CVE IDs and data from the tool results.
...
"""


# ── FIX 1 + 3: Robust action and FINAL parsing ───────────────────────────────

_ACTION_RE = re.compile(
    r"(?:ACTION|TOOL|CALL|EXECUTE|USE):\s*(\w+)\s*\((.+?)\)\s*$",
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)
_FINAL_RE = re.compile(
    r"(?:FINAL(?:\s+(?:ANSWER|RESPONSE|REPORT))?|CONCLUSION):\s*(.+)",
    re.IGNORECASE | re.DOTALL,
)

# FIX 6: Expanded co-occurrence / correlation trigger patterns
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
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


def parse_action(text: str) -> tuple[str | None, str | None]:
    """
    Extract (tool_name, argument) from agent output.
    FIX 1: Case-insensitive, accepts ACTION/TOOL/CALL/EXECUTE/USE.
    """
    for match in _ACTION_RE.finditer(text):
        tool_name = match.group(1).strip()
        tool_arg  = match.group(2).strip()
        if tool_name in TOOL_NAMES:
            return tool_name, tool_arg
        for registered in TOOL_NAMES:
            if tool_name.lower() == registered.lower():
                return registered, tool_arg
    return None, None


def parse_final(text: str) -> str | None:
    """
    FIX 3: Handles FINAL ANSWER:, FINAL RESPONSE:, CONCLUSION: variants.
    """
    m = _FINAL_RE.search(text)
    return m.group(1).strip() if m else None


def call_tool(tool_name: str, tool_arg: str) -> str:
    """
    Execute a tool call with proper argument handling.
    FIX 2: generate_finding uses JSON arg to avoid pipe-in-content bugs.
    """
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


# FIX 7: Deterministic guardrail (ported from langgraph_agent.py)
def _should_force_likely_tool(user_query: str, step_num: int, tools_called: list) -> bool:
    """
    On step 1, if the query contains a CVE and a co-occurrence hint,
    skip the LLM planner and directly call likely_on_system.
    Prevents the LLM from wasting a step summarising before calling the tool.
    """
    if step_num > 1 or tools_called:
        return False
    m = _CVE_RE.search(user_query or "")
    return bool(m and _CORR_HINT_RE.search(user_query))


def _should_force_cwe_tool(user_query: str, step_num: int, tools_called: list) -> str | None:
    """
    On step 1, if the query contains a CWE ID and no CVE, route to lookup_by_cwe.
    Returns the CWE ID string if the guardrail fires, else None.
    """
    if step_num > 1 or tools_called:
        return None
    if _CVE_RE.search(user_query or ""):
        return None  # CVE present → let CVE guardrail handle it
    m = re.search(r"CWE-\d+", user_query or "", re.IGNORECASE)
    if m and _CORR_HINT_RE.search(user_query):
        return m.group(0).upper()
    return None


# ── Agent loop ─────────────────────────────────────────────────────────────────

def run_agent(
    user_query: str,
    max_steps:  int  = 8,
    verbose:    bool = True,
) -> str:
    """
    Run the vulnerability analysis agent loop.

    Args:
        user_query: Free-text question or CVE/CWE ID to analyze.
        max_steps:  Max reasoning steps before forcing final answer.
        verbose:    Print step-by-step reasoning.

    Returns:
        str: Final analysis report.
    """
    memory: list[str] = [
        f"[SYSTEM]: {AGENT_SYSTEM_PROMPT}",
        f"[USER]: {user_query}",
    ]
    tools_called: list[str] = []
    tool_results: list[str] = []

    for step_num in range(1, max_steps + 1):

        # FIX 7: Deterministic guardrails — bypass LLM on first correlation step
        cwe_target = _should_force_cwe_tool(user_query, step_num, tools_called)
        if _should_force_likely_tool(user_query, step_num, tools_called):
            cve = _CVE_RE.search(user_query).group(0).upper()
            forced_arg = json.dumps(
                {
                    "query": f"cooccurrence for {cve}",
                    "entity": {"type": "cve", "id": cve},
                    "top_k": 12,
                    "max_hops": 2,
                }
            )
            response = f"ACTION: graphrag_query({forced_arg})"
            if verbose:
                print(f"\n[Step {step_num}] [GUARDRAIL] Forcing graphrag_query for {cve}")
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
            if verbose:
                print(f"\n[Step {step_num}] [GUARDRAIL] Forcing graphrag_query for {cwe_target}")
        else:
            context  = "\n".join(memory)
            response = ask_model(
                instruction=(
                    "Based on the conversation so far, decide the next step. "
                    "Call a tool using ACTION: tool_name(argument) "
                    "or provide your complete FINAL: analysis."
                ),
                context=context,
                layer="general",
            )
            if verbose:
                preview = response[:250] + ("..." if len(response) > 250 else "")
                print(f"\n[Step {step_num}] {preview}")

        memory.append(f"[AGENT]: {response}")

        # Check for final answer
        final_text = parse_final(response)
        if final_text:
            if verbose:
                print(f"\n✅ Agent completed in {step_num} step(s).")
            return final_text

        # Parse and execute tool call
        tool_name, tool_arg = parse_action(response)

        if tool_name:
            try:
                result = call_tool(tool_name, tool_arg)
                tools_called.append(tool_name)
                tool_results.append(f"[{tool_name}]: {result}")
                if verbose:
                    print(f"  → {tool_name}({tool_arg[:60]}...) = {result[:150]}...")
                memory.append(f"[TOOL {tool_name}]: {result}")
            except Exception as exc:
                err_msg = f"Tool {tool_name} failed: {exc}"
                memory.append(f"[TOOL {tool_name} ERROR]: {err_msg}")
                if verbose:
                    print(f"  ❌ {err_msg}")
        else:
            nudge = (
                "[SYSTEM]: No valid tool call found. "
                "Please call a tool with ACTION: tool_name(argument) "
                f"or end with FINAL: <your analysis>. "
                f"Available tools: {', '.join(sorted(TOOL_NAMES))}"
            )
            memory.append(nudge)
            if verbose:
                print("  ⚠️  No action parsed — nudging model.")

    # FIX 4: Fallback summary when max steps reached without FINAL
    if verbose:
        print(f"\n⚠️  Max steps ({max_steps}) reached — generating forced summary.")

    summary_context = (
        f"Original query: {user_query}\n\n" + "\n\n".join(tool_results)
        if tool_results
        else "\n".join(memory[-6:])
    )

    return ask_model(
        instruction=(
            "The analysis agent has gathered the following information. "
            "Synthesize it into a complete vulnerability analysis report covering: "
            "CVE details, OWASP category, risk score, attack method, remediation, "
            "and co-occurrence/correlation candidates. Clearly distinguish direct "
            "evidence from inferred gap-filled candidates."
        ),
        context=summary_context,
        layer="audit_evidence",
    )
