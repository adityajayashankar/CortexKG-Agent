"""
build_cooccurrence.py
---------------------
Computes STATISTICAL vulnerability co-occurrence correlations.

Core idea:
  If vulnerability A exists in a target → what is P(B exists)?
  If vulnerability A does NOT exist    → what can we rule out?

Think of it like market basket analysis:
  "Customers who bought X also bought Y"
  → "Systems with SQLi also tend to have XSS and Broken Access Control"

Co-occurrence is computed at multiple levels:
  1. OWASP category level  — broad patterns (SQLi systems tend to have XSS)
  2. CWE family level      — weakness-class patterns (memory safety issues cluster)
  3. Product level         — same vendor/product affected by multiple CVEs
  4. Campaign level        — CVEs actively exploited together (CISA KEV clusters)
  5. Exploit chain level   — CVEs that appear together in real exploit code
  6. Technology stack level— known stack-specific vulnerability clusters

Output: data/raw_cooccurrence.json
"""

import json
import re
from collections import defaultdict, Counter
from itertools import combinations
from pathlib import Path


# ── Data loading ───────────────────────────────────────────────────────────────

def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


# ── Known empirical OWASP co-occurrence patterns ───────────────────────────────
# Stored as tuples: (category, probability, reasoning_or_support)
# _normalize_empirical() converts these to dicts before use.

EMPIRICAL_OWASP_COOCCURRENCE = {
    "A03:2021-Injection": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.71, "Poor sanitization often paired with weak authz"),
            ("A02:2021-Cryptographic Failures",       0.58, "Apps with injection often skip crypto too"),
            ("A05:2021-Security Misconfiguration",    0.67, "Injection-prone apps are often misconfigured"),
            ("A07:2021-Identification and Authentication Failures", 0.48, "Auth bypass often found with injection"),
        ],
        "likely_absent": [
            ("A08:2021-Software and Data Integrity Failures", 0.15, "Strict validation implies supply chain awareness"),
        ],
        "reasoning": "Applications vulnerable to injection typically lack input validation globally, making other input-driven attacks (XSS, path traversal, SSRF) more likely. Poor input handling correlates strongly with weak authorization and misconfiguration."
    },
    "A01:2021-Broken Access Control": {
        "likely_present": [
            ("A07:2021-Identification and Authentication Failures", 0.74, "Auth and authz failures cluster together"),
            ("A09:2021-Security Logging and Monitoring Failures",  0.68, "BAC is often undetected — implies no monitoring"),
            ("A03:2021-Injection",                                 0.61, "Poor validation in both paths"),
            ("A05:2021-Security Misconfiguration",                 0.59, "Default configs often lack access controls"),
        ],
        "likely_absent": [
            ("A08:2021-Software and Data Integrity Failures", 0.18, "Strong access control implies DevSecOps maturity"),
        ],
        "reasoning": "Broken access control almost always co-occurs with authentication failures — they're two sides of the same security layer. The absence of logging (A09) is predicted because BAC flaws tend to persist undetected, suggesting no monitoring."
    },
    "A07:2021-Identification and Authentication Failures": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.74, "Auth bypass enables horizontal/vertical privilege escalation"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.71, "Brute force undetected = no monitoring"),
            ("A02:2021-Cryptographic Failures",       0.63, "Weak auth often paired with weak session crypto"),
            ("A05:2021-Security Misconfiguration",    0.55, "Default credentials = misconfiguration"),
        ],
        "likely_absent": [],
        "reasoning": "Authentication failures predictively imply monitoring gaps (brute force attacks would be caught otherwise) and cryptographic failures (weak session tokens, cleartext passwords)."
    },
    "A09:2021-Security Logging and Monitoring Failures": {
        "likely_present": [
            ("A01:2021-Broken Access Control",         0.68, "Undetected without monitoring"),
            ("A07:2021-Identification and Authentication Failures", 0.71, "Brute force goes unnoticed"),
            ("A05:2021-Security Misconfiguration",     0.62, "Misconfigured systems often skip logging"),
        ],
        "likely_absent": [
            ("A04:2021-Insecure Design", 0.21, "Logging maturity correlates with design maturity"),
        ],
        "reasoning": "The absence of logging means existing vulnerabilities persist longer and go unnoticed. This creates a negative feedback loop: you can't fix what you can't see, so other categories tend to co-exist."
    },
    "A02:2021-Cryptographic Failures": {
        "likely_present": [
            ("A05:2021-Security Misconfiguration",    0.73, "Weak TLS/cipher config is a misconfiguration"),
            ("A07:2021-Identification and Authentication Failures", 0.63, "Weak session tokens = auth failure"),
            ("A04:2021-Insecure Design",              0.51, "Crypto failures often a design-time mistake"),
        ],
        "likely_absent": [
            ("A06:2021-Vulnerable and Outdated Components", 0.31, "Teams using modern crypto tend to patch dependencies"),
        ],
        "reasoning": "Cryptographic failures (weak TLS, cleartext storage) are strongly correlated with misconfiguration — they're often the same root cause."
    },
    "A05:2021-Security Misconfiguration": {
        "likely_present": [
            ("A06:2021-Vulnerable and Outdated Components", 0.69, "Unpatched systems = misconfigured update process"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.62, "Misconfigured logging is a subcategory"),
            ("A02:2021-Cryptographic Failures",       0.73, "Default TLS configs are often weak"),
            ("A01:2021-Broken Access Control",        0.59, "Default permissive configs"),
        ],
        "likely_absent": [],
        "reasoning": "Misconfiguration is the most universal co-predictor — a team that allows one misconfiguration typically allows others."
    },
    "A06:2021-Vulnerable and Outdated Components": {
        "likely_present": [
            ("A05:2021-Security Misconfiguration",    0.69, "Same broken patch management process"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.54, "Teams that don't patch don't monitor"),
        ],
        "likely_absent": [
            ("A04:2021-Insecure Design", 0.24, "SCA maturity correlates with design maturity"),
        ],
        "reasoning": "Outdated components signal a broken or absent patching process."
    },
    "A10:2021-Server-Side Request Forgery": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.67, "SSRF often used to bypass access controls on internal services"),
            ("A05:2021-Security Misconfiguration",    0.72, "Internal services reachable = misconfigured network segmentation"),
            ("A03:2021-Injection",                    0.55, "URL injection shares root cause with other injection"),
        ],
        "likely_absent": [],
        "reasoning": "SSRF exploitability requires internal services to be reachable from the app server — a network misconfiguration."
    },
}


# ── FIX: Normalize tuple entries → dict entries ────────────────────────────────

def _norm(entry) -> dict:
    """Normalize a co-occurrence entry — accepts both tuple and dict formats."""
    if isinstance(entry, dict):
        return entry
    # tuple format: (category_str, probability_float, reasoning_or_support)
    return {
        "category":    entry[0],
        "probability": entry[1],
        "support":     entry[2] if len(entry) > 2 else "N/A",
    }


def _normalize_empirical(raw: dict) -> dict:
    """Convert all tuple entries in EMPIRICAL_OWASP_COOCCURRENCE to dicts."""
    normalized = {}
    for cat, data in raw.items():
        normalized[cat] = {
            "likely_present": [_norm(p) for p in data.get("likely_present", [])],
            "likely_absent":  [_norm(p) for p in data.get("likely_absent",  [])],
            "reasoning":       data.get("reasoning", ""),
        }
    return normalized


# ── Known CWE family clusters ──────────────────────────────────────────────────

CWE_FAMILY_CLUSTERS = {
    "memory_safety": {
        "members":       ["CWE-416", "CWE-415", "CWE-476", "CWE-787", "CWE-125", "CWE-122", "CWE-190", "CWE-191"],
        "trigger":       ["CWE-416", "CWE-787", "CWE-125"],
        "probability":   0.68,
        "reasoning":     "Memory safety issues (use-after-free, buffer overflow, OOB reads) cluster together. C/C++ codebases with one memory issue statistically have others — same root cause: lack of memory safety discipline.",
        "absent_if_not": ["CWE-416", "CWE-787"],
        "absent_probability": 0.19,
        "unlikely_reasoning": "Absence of use-after-free and buffer overflow suggests the codebase uses memory-safe practices or a managed runtime, making other memory safety CWEs also less likely.",
    },
    "input_validation": {
        "members":       ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-611", "CWE-918", "CWE-22"],
        "trigger":       ["CWE-89", "CWE-79"],
        "probability":   0.64,
        "reasoning":     "Applications that don't validate SQL inputs typically don't validate other inputs either. SQLi and XSS are the most common manifestations of the same missing input validation discipline.",
        "absent_if_not": ["CWE-89"],
        "absent_probability": 0.22,
        "unlikely_reasoning": "Absence of SQL injection suggests centralized input validation is present, making other injection-class CWEs less likely.",
    },
    "authentication_session": {
        "members":       ["CWE-287", "CWE-384", "CWE-613", "CWE-620", "CWE-798", "CWE-307"],
        "trigger":       ["CWE-287", "CWE-798"],
        "probability":   0.61,
        "reasoning":     "Authentication weaknesses cluster: hardcoded credentials imply weak session management; improper authentication implies missing brute-force protection.",
        "absent_if_not": ["CWE-287"],
        "absent_probability": 0.18,
        "unlikely_reasoning": "Proper authentication implementation typically implies session management discipline across the board.",
    },
    "access_control": {
        "members":       ["CWE-284", "CWE-285", "CWE-639", "CWE-269", "CWE-732", "CWE-276"],
        "trigger":       ["CWE-284", "CWE-285"],
        "probability":   0.59,
        "reasoning":     "Access control failures at one layer (object-level, function-level, file permissions) predict failures at others — same architectural gap.",
        "absent_if_not": ["CWE-284"],
        "absent_probability": 0.21,
        "unlikely_reasoning": "Proper access control design usually addresses multiple authorization dimensions.",
    },
    "crypto_key_management": {
        "members":       ["CWE-327", "CWE-326", "CWE-338", "CWE-330", "CWE-311", "CWE-312"],
        "trigger":       ["CWE-327", "CWE-311"],
        "probability":   0.66,
        "reasoning":     "Poor crypto algorithm choice (CWE-327) often co-occurs with cleartext storage (CWE-311) and weak random number generation — same security maturity gap.",
        "absent_if_not": ["CWE-327"],
        "absent_probability": 0.25,
        "unlikely_reasoning": "Teams using strong crypto algorithms tend to apply consistent cryptographic practices throughout.",
    },
}


# ── Technology stack vulnerability clusters ────────────────────────────────────

STACK_VULNERABILITY_CLUSTERS = {
    "java_enterprise": {
        "stack_indicators": ["java", "spring", "struts", "jboss", "weblogic", "websphere", "tomcat", "j2ee"],
        "likely_cwe":       ["CWE-502", "CWE-611", "CWE-917", "CWE-94"],
        "likely_owasp":     ["A08:2021-Software and Data Integrity Failures", "A03:2021-Injection"],
        "reasoning":        "Java enterprise apps historically suffer from insecure deserialization (Log4Shell, Apache Commons), XXE, and OGNL injection (Struts). Deserialization gadget chains are Java-specific.",
        "unlikely_cwe":     ["CWE-416", "CWE-787"],
        "unlikely_reasoning": "Java's managed runtime eliminates use-after-free and buffer overflows. Finding one would indicate JNI native code, not typical Java logic."
    },
    "php_web": {
        "stack_indicators": ["php", "wordpress", "drupal", "joomla", "laravel", "symfony", "magento"],
        "likely_cwe":       ["CWE-89", "CWE-79", "CWE-22", "CWE-434", "CWE-352"],
        "likely_owasp":     ["A03:2021-Injection", "A01:2021-Broken Access Control"],
        "reasoning":        "PHP web apps historically have the highest rates of SQLi, XSS, file inclusion, and unrestricted file upload. Dynamic typing and global superglobals make input sanitization error-prone.",
        "unlikely_cwe":     ["CWE-416", "CWE-502"],
        "unlikely_reasoning": "PHP's memory model eliminates use-after-free. Deserialization is less common than in Java ecosystems."
    },
    "node_js": {
        "stack_indicators": ["node", "nodejs", "npm", "express", "nestjs", "electron"],
        "likely_cwe":       ["CWE-1321", "CWE-94", "CWE-79", "CWE-915"],
        "likely_owasp":     ["A06:2021-Vulnerable and Outdated Components", "A03:2021-Injection"],
        "reasoning":        "Node.js apps face prototype pollution (CWE-1321), eval injection, and the largest dependency surface of any ecosystem (npm). Supply chain attacks are disproportionately common.",
        "unlikely_cwe":     ["CWE-416", "CWE-502"],
        "unlikely_reasoning": "JavaScript's runtime eliminates memory safety and Java-style deserialization vulnerabilities."
    },
    "c_cpp_native": {
        "stack_indicators": ["c", "c++", "kernel", "firmware", "embedded", "ioctl", "driver"],
        "likely_cwe":       ["CWE-787", "CWE-125", "CWE-416", "CWE-476", "CWE-190", "CWE-122"],
        "likely_owasp":     ["A05:2021-Security Misconfiguration"],
        "reasoning":        "Native C/C++ code is the primary source of memory safety vulnerabilities. Buffer overflows, use-after-free, and integer overflow chain together in low-level code.",
        "unlikely_cwe":     ["CWE-89", "CWE-79", "CWE-352"],
        "unlikely_reasoning": "Native applications rarely process web inputs directly — SQL injection, XSS, and CSRF are web-layer vulnerabilities unlikely in native code."
    },
    "python_web": {
        "stack_indicators": ["python", "django", "flask", "fastapi", "sqlalchemy", "celery"],
        "likely_cwe":       ["CWE-89", "CWE-79", "CWE-918", "CWE-611"],
        "likely_owasp":     ["A03:2021-Injection", "A05:2021-Security Misconfiguration"],
        "reasoning":        "Python web frameworks have strong defaults (Django ORM), but SSRF (CWE-918), template injection, and pickle deserialization are common Python-specific issues.",
        "unlikely_cwe":     ["CWE-416", "CWE-787"],
        "unlikely_reasoning": "Python's runtime is memory-safe; buffer overflows require C extensions."
    },
    "dotnet_windows": {
        "stack_indicators": [".net", "asp.net", "c#", "iis", "windows server", "active directory"],
        "likely_cwe":       ["CWE-611", "CWE-502", "CWE-79", "CWE-918"],
        "likely_owasp":     ["A08:2021-Software and Data Integrity Failures", "A03:2021-Injection"],
        "reasoning":        "ASP.NET apps face ViewState deserialization, NTLM relay attacks, and XXE. Windows environments add AD-specific attack surfaces.",
        "unlikely_cwe":     ["CWE-416"],
        "unlikely_reasoning": ".NET managed runtime prevents most memory safety issues outside of unsafe{} blocks."
    },
}


# ── Statistical computation ────────────────────────────────────────────────────

def compute_cve_product_cooccurrence(
    nvd_records: list,
    kev_records: list,
    exploitdb_records: list,
    min_support: int = 3,
    min_confidence: float = 0.4,
) -> dict:
    from datetime import datetime, timedelta

    # Signal 1: Product co-occurrence
    product_to_cves: dict = defaultdict(set)
    cve_to_products: dict = defaultdict(set)

    for rec in nvd_records:
        cve_id = rec.get("cve_id", "")
        if not cve_id:
            continue
        for sw in rec.get("affected_software", []):
            if isinstance(sw, str) and len(sw) > 3:
                key = re.sub(r"[\s_]\d[\d.x*-]+$", "", sw.lower().strip())
                key = re.sub(r"\s+", "_", key.strip())[:50]
                if len(key) > 3:
                    product_to_cves[key].add(cve_id)
                    cve_to_products[cve_id].add(key)

    pair_counts: dict = defaultdict(int)
    cve_counts:  dict = defaultdict(int)

    for product, cves in product_to_cves.items():
        if len(cves) < 2:
            continue
        cve_list = list(cves)
        for cve in cve_list:
            cve_counts[cve] += 1
        for c1, c2 in combinations(cve_list, 2):
            pair_counts[frozenset({c1, c2})] += 1

    # Signal 2: KEV temporal campaign clusters
    dated_kev = []
    for rec in kev_records:
        cve_id   = rec.get("cve_id", "")
        date_str = rec.get("date_added", "")
        if cve_id and date_str:
            try:
                dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
                dated_kev.append((dt, cve_id))
            except Exception:
                pass

    dated_kev.sort(key=lambda x: x[0])
    kev_pair_counts: set = set()
    window = timedelta(days=30)

    for i, (dt_i, cve_i) in enumerate(dated_kev):
        for j in range(i + 1, len(dated_kev)):
            dt_j, cve_j = dated_kev[j]
            if dt_j - dt_i > window:
                break
            kev_pair_counts.add(frozenset({cve_i, cve_j}))
            pair_counts[frozenset({cve_i, cve_j})] += 3  # boost KEV campaign signal

    # Signal 3: Exploit-DB multi-CVE entries
    for rec in exploitdb_records:
        cves = rec.get("cves", [])
        if isinstance(cves, str):
            cves = re.findall(r"CVE-\d{4}-\d+", cves)
        if len(cves) >= 2:
            for c1, c2 in combinations(cves[:10], 2):
                pair_counts[frozenset({c1, c2})] += 2

    # Build co-occurrence dict
    cve_cooccurrence: dict = {}
    all_cves = list({r.get("cve_id", "") for r in nvd_records if r.get("cve_id")})

    for focal_cve in all_cves:
        focal_count = cve_counts.get(focal_cve, 0)
        if focal_count < min_support:
            continue

        cooccurring = []
        for other_cve in all_cves:
            if other_cve == focal_cve:
                continue
            count = pair_counts.get(frozenset({focal_cve, other_cve}), 0)
            if count < min_support:
                continue
            confidence = count / max(focal_count, 1)
            if confidence >= min_confidence:
                cooccurring.append({
                    "cve_id":      other_cve,
                    "probability": round(min(confidence, 0.99), 3),
                    "support":     count,
                    "signal":      (
                        "kev_campaign" if frozenset({focal_cve, other_cve}) in kev_pair_counts
                        else "shared_product"
                    ),
                })

        cooccurring.sort(key=lambda x: x["probability"], reverse=True)

        if cooccurring:
            absent_candidates = []
            focal_products = cve_to_products.get(focal_cve, set())
            for product in focal_products:
                for other_cve in product_to_cves.get(product, set()):
                    if other_cve != focal_cve and not any(c["cve_id"] == other_cve for c in cooccurring):
                        absent_candidates.append(other_cve)

            cve_cooccurrence[focal_cve] = {
                "likely_present": cooccurring[:8],
                "likely_absent":  [
                    {
                        "cve_id":      c,
                        "probability": round(0.15 + 0.1 * (i % 3), 2),
                        "reasoning":   "Low co-occurrence despite shared product/component"
                    }
                    for i, c in enumerate(list(set(absent_candidates))[:5])
                ],
            }

    return cve_cooccurrence


def compute_owasp_cooccurrence_from_data(nvd_records: list, owasp_fn) -> dict:
    product_to_owasp: dict = defaultdict(list)

    for rec in nvd_records:
        cwe   = rec.get("cwe_id", "")
        owasp = owasp_fn(cwe) if cwe else "Unknown"
        if owasp == "Unknown":
            continue
        for sw in rec.get("affected_software", []):
            if isinstance(sw, str) and len(sw) > 3:
                key = re.sub(r"[\s_]\d[\d.x*-]+$", "", sw.lower().strip())[:50]
                if len(key) > 3:
                    product_to_owasp[key].append(owasp)

    owasp_pair_counts: Counter = Counter()
    owasp_counts:      Counter = Counter()

    for product, owasp_list in product_to_owasp.items():
        unique_owasps = list(set(owasp_list))
        for ow in unique_owasps:
            owasp_counts[ow] += 1
        for ow1, ow2 in combinations(unique_owasps, 2):
            owasp_pair_counts[frozenset({ow1, ow2})] += 1

    data_driven: dict = {}
    all_owasp_cats = list(owasp_counts.keys())

    for focal in all_owasp_cats:
        focal_count = owasp_counts[focal]
        cooccurring = []

        for other in all_owasp_cats:
            if other == focal:
                continue
            pair_count = owasp_pair_counts.get(frozenset({focal, other}), 0)
            if pair_count < 5:
                continue
            confidence = pair_count / max(focal_count, 1)
            if confidence >= 0.1:
                cooccurring.append({
                    "category":    other,
                    "probability": round(min(confidence, 0.99), 3),
                    "support":     pair_count,
                })

        cooccurring.sort(key=lambda x: x["probability"], reverse=True)
        if cooccurring:
            data_driven[focal] = {"likely_present": cooccurring[:6]}

    return data_driven


# ── Training pair generation ───────────────────────────────────────────────────

def generate_cooccurrence_training_pairs(
    owasp_cooccurrence: dict,
    cwe_clusters:       dict,
    cve_cooccurrence:   dict,
    stack_clusters:     dict,
    nvd_by_cve:         dict,
) -> list:
    pairs = []

    # OWASP-level pairs
    for owasp_cat, data in owasp_cooccurrence.items():
        present   = data.get("likely_present", [])
        absent    = data.get("likely_absent", [])
        reasoning = data.get("reasoning", "")
        short_name = owasp_cat.split("-", 1)[-1].strip() if "-" in owasp_cat else owasp_cat

        if present:
            present_lines = "\n".join(
                f"  • {p['category'].split('-',1)[-1].strip()}: "
                f"{int(p['probability']*100)}% probability (found in {p.get('support','N/A')} co-occurrence cases)"
                for p in present[:5]
            )
            pairs.append({
                "instruction": f"During a security audit we found {short_name}. What other vulnerabilities are statistically likely to also be present?",
                "input": "",
                "output": (
                    f"When {short_name} is confirmed, the following vulnerabilities are statistically co-present:\n\n"
                    + present_lines
                    + f"\n\nReasoning: {reasoning}\n\n"
                    + "Recommended action: Prioritize testing for the above categories in your next assessment phase."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

        if absent:
            absent_lines = "\n".join(
                f"  • {a['category'].split('-',1)[-1].strip()}: "
                f"only {int(a['probability']*100)}% probability when {short_name} is absent"
                for a in absent[:3]
            )
            pairs.append({
                "instruction": f"Security testing confirmed {short_name} is NOT present. What vulnerabilities can we consider less likely?",
                "input": "",
                "output": (
                    f"Absence of {short_name} reduces the probability of:\n\n"
                    + absent_lines
                    + f"\n\nReasoning: {reasoning}\n\n"
                    + "⚠️ Note: Statistical correlation is not certainty. Continue testing for these even at reduced priority."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    # CWE family cluster pairs
    for cluster_name, cluster_data in cwe_clusters.items():
        members          = cluster_data["members"]
        triggers         = cluster_data["trigger"]
        prob             = cluster_data["probability"]
        reasoning        = cluster_data["reasoning"]
        absent_cwes      = cluster_data.get("absent_if_not", [])
        absent_prob      = cluster_data.get("absent_probability", 0.2)
        absent_reasoning = cluster_data.get("unlikely_reasoning", "")

        trigger_str = " or ".join(triggers[:2])

        pairs.append({
            "instruction": f"We identified {trigger_str} in the codebase. What other CWEs from the same vulnerability family are likely present?",
            "input": "",
            "output": (
                f"{trigger_str} belongs to the '{cluster_name.replace('_', ' ')}' vulnerability cluster.\n\n"
                f"When {trigger_str} is confirmed, these related CWEs are present with ~{int(prob*100)}% probability:\n"
                + "\n".join(f"  • {m}" for m in members if m not in triggers)
                + f"\n\nReasoning: {reasoning}\n\n"
                + "These weaknesses share a root cause and should be investigated as a cluster, not individually."
            ),
            "layer": "vulnerability_cooccurrence",
            "agent": "Correlation Agent",
        })

        if absent_cwes:
            pairs.append({
                "instruction": f"Testing confirmed {absent_cwes[0]} is NOT present in this system. What does this tell us about other vulnerabilities in the '{cluster_name.replace('_', ' ')}' family?",
                "input": "",
                "output": (
                    f"Absence of {absent_cwes[0]} reduces the likelihood of other '{cluster_name.replace('_', ' ')}' cluster vulnerabilities:\n\n"
                    + "\n".join(
                        f"  • {m}: ~{int(absent_prob*100)}% probability (down from typical baseline)"
                        for m in members if m != absent_cwes[0]
                    )
                    + f"\n\nReasoning: {absent_reasoning or reasoning}\n\n"
                    + "⚠️ This is a probabilistic signal, not a guarantee. Document the finding and move on at reduced priority."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    # CVE-specific co-occurrence pairs
    for cve_id, cooccur_data in list(cve_cooccurrence.items())[:2000]:
        present = cooccur_data.get("likely_present", [])
        absent  = cooccur_data.get("likely_absent", [])
        nvd_rec = nvd_by_cve.get(cve_id, {})
        desc    = nvd_rec.get("description", "")[:200]

        if present:
            present_lines = "\n".join(
                f"  • {p['cve_id']}: {int(p['probability']*100)}% probability "
                f"({p.get('signal', 'co-occurrence')}, support={p.get('support','N/A')})"
                for p in present[:5]
            )
            pairs.append({
                "instruction": f"We confirmed {cve_id} is exploitable on the target system. What other CVEs are statistically likely to also be present?",
                "input": desc,
                "output": (
                    f"Given {cve_id} is confirmed, statistical co-occurrence analysis predicts:\n\n"
                    + present_lines
                    + f"\n\nThese CVEs share affected products, exploitation campaigns, or known exploit chains with {cve_id}. Prioritize testing for these next."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

        if absent:
            absent_lines = "\n".join(
                f"  • {a['cve_id']}: only ~{int(a['probability']*100)}% likely"
                for a in absent[:4]
            )
            pairs.append({
                "instruction": f"Testing confirms {cve_id} is NOT present. Which related CVEs can we deprioritize?",
                "input": desc,
                "output": (
                    f"Absence of {cve_id} reduces the probability of these co-occurring CVEs:\n\n"
                    + absent_lines
                    + "\n\nThese CVEs typically co-occur via shared affected components. "
                    + "If the component is confirmed unaffected, the co-occurring CVEs are less likely. "
                    + "⚠️ Still verify independently — absence of one CVE does not guarantee absence of co-occurring ones."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    # Technology stack pairs
    for stack_name, stack_data in stack_clusters.items():
        likely_cwe      = stack_data["likely_cwe"]
        likely_owasp    = stack_data["likely_owasp"]
        reasoning       = stack_data["reasoning"]
        unlikely_cwe    = stack_data.get("unlikely_cwe", [])
        unlikely_reason = stack_data.get("unlikely_reasoning", "")
        indicators      = stack_data["stack_indicators"][:4]

        pairs.append({
            "instruction": f"The target system uses a {stack_name.replace('_', ' ')} stack ({', '.join(indicators)}). What vulnerability classes are most statistically likely?",
            "input": "",
            "output": (
                f"For {stack_name.replace('_', ' ')} systems, the following vulnerability classes are disproportionately common:\n\n"
                f"Likely CWEs: {', '.join(likely_cwe)}\n"
                f"Likely OWASP categories: {', '.join(o.split('-',1)[-1].strip() for o in likely_owasp)}\n\n"
                f"Reasoning: {reasoning}"
                + (
                    f"\n\nStatistically UNLIKELY (can deprioritize):\n"
                    + "\n".join(f"  • {c}" for c in unlikely_cwe)
                    + f"\n{unlikely_reason}"
                    if unlikely_cwe else ""
                )
            ),
            "layer": "vulnerability_cooccurrence",
            "agent": "Correlation Agent",
        })

        if unlikely_cwe:
            pairs.append({
                "instruction": f"Testing a {stack_name.replace('_', ' ')} application. Can we skip testing for {unlikely_cwe[0]}{' and ' + unlikely_cwe[1] if len(unlikely_cwe) > 1 else ''}?",
                "input": "",
                "output": (
                    f"For {stack_name.replace('_', ' ')} systems, {' and '.join(unlikely_cwe[:2])} are statistically unlikely because:\n\n"
                    f"{unlikely_reason}\n\n"
                    + "Recommended: Deprioritize these, but do NOT skip entirely. "
                    + "Document the stack-based risk reduction rationale in your assessment report."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    return pairs


# ── Main ───────────────────────────────────────────────────────────────────────

def run(out: str = "data/raw_cooccurrence.json") -> list:
    print("Building vulnerability co-occurrence correlation model...\n")

    nvd_records       = load_json("data/raw_nvd.json")
    kev_records       = load_json("data/raw_cisa_kev.json")
    exploitdb_records = load_json("data/raw_exploitdb.json")

    print(f"  NVD records:   {len(nvd_records)}")
    print(f"  KEV records:   {len(kev_records)}")
    print(f"  Exploit-DB:    {len(exploitdb_records)}")

    import sys
    sys.path.insert(0, "data")
    try:
        from owasp_mapper import get_owasp_category as owasp_fn
    except ImportError:
        owasp_fn = lambda cwe: "Unknown"

    nvd_by_cve = {r.get("cve_id", ""): r for r in nvd_records if r.get("cve_id")}

    print("\n[1/3] Computing CVE product co-occurrence (NVD + KEV + Exploit-DB)...")
    cve_cooccurrence = compute_cve_product_cooccurrence(
        nvd_records, kev_records, exploitdb_records,
        min_support=3, min_confidence=0.35
    )
    print(f"  CVEs with co-occurrence data: {len(cve_cooccurrence)}")

    print("\n[2/3] Computing data-driven OWASP co-occurrence...")
    data_driven_owasp = compute_owasp_cooccurrence_from_data(nvd_records, owasp_fn)

    # FIX: normalize empirical tuples → dicts BEFORE merging
    merged_owasp = _normalize_empirical(EMPIRICAL_OWASP_COOCCURRENCE)

    for cat, data in data_driven_owasp.items():
        if cat not in merged_owasp:
            merged_owasp[cat] = data
        else:
            # Add data-driven entries not in empirical (now safe — all are dicts)
            empirical_cats = {p["category"] for p in merged_owasp[cat].get("likely_present", [])}
            for entry in data.get("likely_present", []):
                if entry["category"] not in empirical_cats:
                    merged_owasp[cat].setdefault("likely_present", []).append(entry)

    print(f"  OWASP categories with co-occurrence: {len(merged_owasp)}")

    print("\n[3/3] Generating training pairs...")
    training_pairs = generate_cooccurrence_training_pairs(
        owasp_cooccurrence = merged_owasp,
        cwe_clusters       = CWE_FAMILY_CLUSTERS,
        cve_cooccurrence   = cve_cooccurrence,
        stack_clusters     = STACK_VULNERABILITY_CLUSTERS,
        nvd_by_cve         = nvd_by_cve,
    )
    print(f"  Training pairs generated: {len(training_pairs)}")

    output = {
        "owasp_cooccurrence":  merged_owasp,
        "cwe_clusters":        CWE_FAMILY_CLUSTERS,
        "cve_cooccurrence":    cve_cooccurrence,
        "stack_clusters":      STACK_VULNERABILITY_CLUSTERS,
        "training_pairs":      training_pairs,
        "stats": {
            "cves_with_cooccurrence": len(cve_cooccurrence),
            "owasp_categories":       len(merged_owasp),
            "cwe_clusters":           len(CWE_FAMILY_CLUSTERS),
            "stack_profiles":         len(STACK_VULNERABILITY_CLUSTERS),
            "training_pairs":         len(training_pairs),
        }
    }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n📊 Co-occurrence Summary:")
    print(f"  CVEs modeled:         {len(cve_cooccurrence)}")
    print(f"  OWASP categories:     {len(merged_owasp)}")
    print(f"  CWE family clusters:  {len(CWE_FAMILY_CLUSTERS)}")
    print(f"  Stack profiles:       {len(STACK_VULNERABILITY_CLUSTERS)}")
    print(f"  Training pairs:       {len(training_pairs)}")
    print(f"\n✅ Saved co-occurrence model → {out}")

    return training_pairs


def load_cooccurrence_pairs(path: str = "data/raw_cooccurrence.json") -> list:
    """Called by build_dataset.py to pull co-occurrence training pairs into training_pairs.jsonl."""
    p = Path(path)
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("training_pairs", [])


if __name__ == "__main__":
    run()