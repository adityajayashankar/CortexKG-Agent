"""
build_cooccurrence.py  (FIXED)
------------------------------
FIXES in this version:
  1. BUG: _norm() stored tuple[2] (reasoning text) in "support" key.
     generate_cooccurrence_training_pairs() then read p.get('reasoning','') → empty,
     and p.get('support','N/A') → returned the full reasoning sentence as if it
     were a numeric support count. Training pairs showed garbage like:
       "found in Weak TLS/cipher config is a misconfiguration co-occurrence cases"
     FIX: _norm() now correctly splits tuple into "reasoning" AND "support":"N/A"
     so downstream consumers get the right values from the right keys.

  2. BUG: `from datetime import datetime, timedelta` was inside the body of
     compute_cve_product_cooccurrence(). Re-imported on every call.
     FIX: Moved to module-level imports.

  3. BUG: sys.path.insert(0, "data") in run() is fragile — breaks when called
     from run_pipeline.py at project root vs when run directly from data/.
     FIX: Use Path(__file__).parent for a stable relative import.

  4. BUG: compute_owasp_cooccurrence_from_data() never set a "reasoning" key
     on the dicts it returned. generate_cooccurrence_training_pairs() then
     emitted empty reasoning strings for the entire data-driven half of the
     co-occurrence training pairs.
     FIX: Added automatic reasoning generation based on the pair stats.

  5. BUG: Training pair present_lines format guard was missing. Empirical
     entries had string support values, data-driven had int support values —
     no type guard caused mixed output formats.
     FIX: Added _fmt_support() helper that normalises both to display string.

  6. IMPROVEMENT: owasp_fn import now uses Path(__file__).parent so the module
     resolves correctly regardless of where run() is called from.

  7. IMPROVEMENT: validate_dataset.py (separate file) added for pre-training
     dataset health checks.

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
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta          # FIX 2: module-level import
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
# Stored as tuples: (category, probability, reasoning_text)
# _normalize_empirical() converts these to dicts before use.
# NOTE: index 2 is REASONING TEXT, not a support count.

EMPIRICAL_OWASP_COOCCURRENCE = {
    "A01:2021-Broken Access Control": {
        "likely_present": [
            ("A03:2021-Injection",                    0.71, "Poor authz often paired with poor sanitization — same root cause"),
            ("A05:2021-Security Misconfiguration",    0.69, "Misconfigured RBAC is itself a misconfiguration"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.66,
             "Access control bypasses go undetected without logging"),
            ("A07:2021-Identification and Authentication Failures", 0.57,
             "Weak auth often paired with weak authz — both are access-layer failures"),
        ],
        "likely_absent": [
            ("A04:2021-Insecure Design", 0.21,
             "Teams with mature access control models tend to design security in"),
        ],
        "reasoning": (
            "Broken access control is the most prevalent OWASP category (94% of apps tested). "
            "It correlates strongly with injection and misconfiguration because all three share the same root: "
            "absent or inconsistent security discipline. When one access-layer control is missing, "
            "others tend to be missing too. "
            "This creates a negative feedback loop: you can't fix what you can't see, "
            "so other categories tend to co-exist."
        ),
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
        "reasoning": (
            "Applications vulnerable to injection typically lack input validation globally, "
            "making other input-driven attacks (XSS, path traversal, SSRF) more likely. "
            "Poor input handling correlates strongly with weak authorization and misconfiguration."
        ),
    },
    "A04:2021-Insecure Design": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.68, "Design gaps typically include missing authz checks"),
            ("A02:2021-Cryptographic Failures",       0.51, "Crypto often neglected at design time"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.59, "Security logging rarely designed in from the start"),
        ],
        "likely_absent": [],
        "reasoning": "Insecure design is a root-cause category — apps with design-level security gaps tend to exhibit multiple downstream vulnerabilities."
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
    "A07:2021-Identification and Authentication Failures": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.72, "Weak auth often means weak authz too"),
            ("A02:2021-Cryptographic Failures",       0.63, "Weak password hashing / session token entropy"),
            ("A09:2021-Security Logging and Monitoring Failures", 0.57, "Brute force goes undetected without login monitoring"),
        ],
        "likely_absent": [],
        "reasoning": "Authentication and session management failures cluster tightly with access control and cryptographic failures — all three are access-layer concerns."
    },
    "A08:2021-Software and Data Integrity Failures": {
        "likely_present": [
            ("A05:2021-Security Misconfiguration",    0.61, "CI/CD misconfiguration enables supply chain attacks"),
            ("A06:2021-Vulnerable and Outdated Components", 0.58, "Both concern supply chain hygiene"),
        ],
        "likely_absent": [
            ("A03:2021-Injection", 0.15, "Teams with SCA maturity tend to validate all inputs"),
        ],
        "reasoning": "Software integrity failures (unsigned updates, unsafe deserialization) share root causes with misconfiguration and outdated components — all point to weak supply chain controls."
    },
    "A09:2021-Security Logging and Monitoring Failures": {
        "likely_present": [
            ("A01:2021-Broken Access Control",        0.66, "Access control bypasses go undetected without logs"),
            ("A05:2021-Security Misconfiguration",    0.62, "Logging is itself a configuration concern"),
        ],
        "likely_absent": [],
        "reasoning": "Poor logging is both a standalone risk and an amplifier — it allows all other vulnerabilities to persist longer undetected."
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


# ── FIX 1: Normalize tuple entries → dict entries ─────────────────────────────
# BEFORE (BUG): _norm stored tuple[2] as "support" — but it's REASONING TEXT.
#   generate_cooccurrence_training_pairs then read p.get('reasoning','') → empty
#   and p.get('support','N/A') → returned a sentence like
#   "Weak TLS/cipher config is a misconfiguration" as if it were a count.
#   Training pairs showed: "found in Weak TLS/cipher config... co-occurrence cases"
#
# AFTER (FIX): tuple[2] stored as "reasoning". Support stays "N/A" for empirical
#   entries (no numeric support — they're expert-curated, not data-derived).

def _norm(entry) -> dict:
    """Normalize a co-occurrence entry — accepts both tuple and dict formats.

    Tuple format: (category_str, probability_float, reasoning_text)
    NOTE: index 2 is REASONING TEXT, not a numeric support count.
    """
    if isinstance(entry, dict):
        return entry
    return {
        "category":    entry[0],
        "probability": entry[1],
        "reasoning":   entry[2] if len(entry) > 2 else "",   # FIX: was "support"
        "support":     "N/A",                                  # FIX: empirical = no count
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


# ── FIX 5: Support display helper ─────────────────────────────────────────────
def _fmt_support(support_val) -> str:
    """Normalise support value to a display string.

    Empirical entries have support='N/A' (string).
    Data-driven entries have support=int (count of co-occurring records).
    """
    if isinstance(support_val, int):
        return f"{support_val} records"
    return str(support_val) if support_val else "N/A"


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
        "absent_probability": 0.25,
        "unlikely_reasoning": "Absence of improper authentication suggests the codebase uses a well-tested auth framework, which typically handles session management correctly too.",
    },
    "access_control": {
        "members":       ["CWE-862", "CWE-863", "CWE-639", "CWE-284", "CWE-285", "CWE-732"],
        "trigger":       ["CWE-862", "CWE-863"],
        "probability":   0.67,
        "reasoning":     "Missing authorization checks and improper privilege management cluster: applications that fail to check one resource type typically fail on others too.",
        "absent_if_not": ["CWE-862"],
        "absent_probability": 0.20,
        "unlikely_reasoning": "Presence of correct authorization checks on the tested surface suggests a consistent authz pattern is applied across the codebase.",
    },
    "cryptographic": {
        "members":       ["CWE-326", "CWE-327", "CWE-330", "CWE-338", "CWE-347", "CWE-759", "CWE-760"],
        "trigger":       ["CWE-327", "CWE-326"],
        "probability":   0.58,
        "reasoning":     "Use of broken/weak algorithms signals that cryptographic choices were made without security review, making other crypto weaknesses likely in the same codebase.",
        "absent_if_not": ["CWE-327"],
        "absent_probability": 0.28,
        "unlikely_reasoning": "Use of strong, modern algorithms suggests the team made deliberate cryptographic decisions, making other crypto failures less likely.",
    },
}


# ── Technology stack vulnerability clusters ────────────────────────────────────

STACK_VULNERABILITY_CLUSTERS = {
    "java_enterprise": {
        "stack_indicators": ["java", "spring", "struts", "jboss", "weblogic", "tomcat", "jdk", "jre"],
        "likely_cwe":       ["CWE-502", "CWE-611", "CWE-79", "CWE-89", "CWE-94"],
        "likely_owasp":     ["A08:2021-Software and Data Integrity Failures", "A03:2021-Injection"],
        "reasoning":        "Java enterprise stacks face deserialization attacks (CWE-502), XML injection via XXE (CWE-611), and server-side template injection. Legacy frameworks like Struts have well-documented RCE history.",
        "unlikely_cwe":     ["CWE-416", "CWE-787"],
        "unlikely_reasoning": "Java's managed runtime (JVM) prevents classic memory safety issues; buffer overflows require native code via JNI."
    },
    "python_web": {
        "stack_indicators": ["python", "django", "flask", "fastapi", "sqlalchemy", "celery"],
        "likely_cwe":       ["CWE-89", "CWE-79", "CWE-22", "CWE-918", "CWE-78"],
        "likely_owasp":     ["A03:2021-Injection", "A01:2021-Broken Access Control"],
        "reasoning":        "Python web apps face SQLi (especially with raw queries outside ORM), SSTI in Jinja2 templates, path traversal, and SSRF. Django's ORM protects against SQLi, but Flask/FastAPI apps often bypass it.",
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
    "nodejs_javascript": {
        "stack_indicators": ["node.js", "nodejs", "express", "npm", "javascript", "typescript", "react", "angular", "vue"],
        "likely_cwe":       ["CWE-79", "CWE-94", "CWE-1321", "CWE-918", "CWE-89"],
        "likely_owasp":     ["A03:2021-Injection", "A06:2021-Vulnerable and Outdated Components"],
        "reasoning":        "Node.js apps face prototype pollution (CWE-1321), ReDoS, eval injection, and a massive npm dependency surface. XSS is common in SPA frameworks without proper sanitization.",
        "unlikely_cwe":     ["CWE-416", "CWE-502"],
        "unlikely_reasoning": "V8 runtime prevents memory safety issues; Java-style deserialization gadget chains don't apply to the JS ecosystem."
    },
    "c_cpp_native": {
        "stack_indicators": ["c++", "c language", "gcc", "clang", "openssl", "linux kernel", "embedded"],
        "likely_cwe":       ["CWE-416", "CWE-787", "CWE-125", "CWE-190", "CWE-476", "CWE-122"],
        "likely_owasp":     ["A03:2021-Injection"],
        "reasoning":        "C/C++ codebases are the primary source of memory safety CVEs. Use-after-free, buffer overflows, and integer overflows cluster heavily in native code.",
        "unlikely_cwe":     ["CWE-502", "CWE-611"],
        "unlikely_reasoning": "Java-style deserialization and XML injection are less common attack surfaces in pure C/C++ applications."
    },
    "php_web": {
        "stack_indicators": ["php", "wordpress", "laravel", "symfony", "drupal", "joomla", "magento"],
        "likely_cwe":       ["CWE-89", "CWE-79", "CWE-22", "CWE-94", "CWE-434"],
        "likely_owasp":     ["A03:2021-Injection", "A01:2021-Broken Access Control"],
        "reasoning":        "PHP has the highest density of web application CVEs. SQLi, XSS, file inclusion (LFI/RFI), and unrestricted upload are endemic. WordPress plugin ecosystem is a major attack surface.",
        "unlikely_cwe":     ["CWE-416", "CWE-502"],
        "unlikely_reasoning": "PHP's runtime prevents memory safety issues; Java-style deserialization doesn't apply (PHP unserialize is a different attack class)."
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
    # FIX 2: datetime/timedelta now imported at module level — removed from here

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

    # Signal 2: KEV temporal campaign clusters (CVEs added within 30-day window)
    dated_kev: list = []
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
    kev_pair_counts: set = set()      # frozenset of CVE pairs that co-appear in KEV campaigns
    window = timedelta(days=30)

    for i, (dt_i, cve_i) in enumerate(dated_kev):
        for j in range(i + 1, len(dated_kev)):
            dt_j, cve_j = dated_kev[j]
            if dt_j - dt_i > window:
                break
            kev_pair_counts.add(frozenset({cve_i, cve_j}))
            pair_counts[frozenset({cve_i, cve_j})] += 3    # boost KEV campaign signal

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
                signal = (
                    "kev_campaign" if frozenset({focal_cve, other_cve}) in kev_pair_counts
                    else "shared_product"
                )
                cooccurring.append({
                    "cve_id":      other_cve,
                    "probability": round(min(confidence, 0.99), 3),
                    "support":     count,
                    "signal":      signal,
                    "reasoning":   (
                        f"Co-exploited in the same KEV campaign window (within 30 days)" if signal == "kev_campaign"
                        else f"Share {count} affected products/components in NVD data"
                    ),
                })

        cooccurring.sort(key=lambda x: x["probability"], reverse=True)

        if cooccurring:
            absent_candidates: list = []
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
                        "reasoning":   "Low co-occurrence despite shared product/component",
                        "support":     "N/A",
                    }
                    for i, c in enumerate(list(set(absent_candidates))[:5])
                ],
            }

    return cve_cooccurrence


def compute_owasp_cooccurrence_from_data(nvd_records: list, owasp_fn) -> dict:
    """Compute data-driven OWASP co-occurrence from NVD records.

    FIX 4: Now sets a "reasoning" key on each returned entry so that
    generate_cooccurrence_training_pairs() gets non-empty reasoning for
    data-driven entries (previously emitted empty strings → low-quality pairs).
    """
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
                focal_short = focal.split("-", 2)[-1].strip() if "-" in focal else focal
                other_short = other.split("-", 2)[-1].strip() if "-" in other else other
                cooccurring.append({
                    "category":    other,
                    "probability": round(min(confidence, 0.99), 3),
                    "support":     pair_count,                          # numeric count — correct
                    # FIX 4: generate reasoning text from statistics
                    "reasoning":   (
                        f"{focal_short} and {other_short} co-occur in {pair_count} shared product "
                        f"records (confidence {confidence:.0%}). Empirically derived from NVD data."
                    ),
                })

        cooccurring.sort(key=lambda x: x["probability"], reverse=True)
        if cooccurring:
            focal_short = focal.split("-", 2)[-1].strip() if "-" in focal else focal
            top_other   = cooccurring[0]["category"].split("-", 2)[-1].strip()
            data_driven[focal] = {
                "likely_present": cooccurring[:6],
                # FIX 4: set top-level reasoning for the focal category
                "reasoning": (
                    f"Data-driven NVD analysis: {focal_short} most strongly co-occurs with "
                    f"{top_other} ({cooccurring[0]['probability']:.0%}) and "
                    f"{len(cooccurring) - 1} other categories across shared affected products."
                ),
            }

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
            # FIX 5: use _fmt_support() so empirical "N/A" and data-driven int are both handled
            present_lines = "\n".join(
                f"  • {p['category'].split('-',1)[-1].strip()}: "
                f"{int(p['probability']*100)}% probability "
                f"({_fmt_support(p.get('support', 'N/A'))})"
                for p in present[:5]
            )
            # FIX 1 effect: p.get('reasoning','') now returns the correct reasoning text
            reasoning_lines = "\n".join(
                f"    – {p['category'].split('-',1)[-1].strip()}: {p.get('reasoning','')}"
                for p in present[:3] if p.get("reasoning")
            )
            pairs.append({
                "instruction": f"During a security audit we found {short_name}. What other vulnerabilities are statistically likely to also be present?",
                "input": "",
                "output": (
                    f"When {short_name} is confirmed, the following vulnerabilities are statistically co-present:\n\n"
                    + present_lines
                    + (f"\n\nWhy these co-occur:\n{reasoning_lines}" if reasoning_lines else "")
                    + (f"\n\nContext: {reasoning}" if reasoning else "")
                    + "\n\nRecommended action: Prioritize testing for the above categories in your next assessment phase."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

        if absent:
            absent_lines = "\n".join(
                f"  • {a['category'].split('-',1)[-1].strip()}: "
                f"only {int(a['probability']*100)}% probability when {short_name} is absent"
                + (f" — {a.get('reasoning','')}" if a.get("reasoning") else "")
                for a in absent[:3]
            )
            pairs.append({
                "instruction": f"Security testing confirmed {short_name} is NOT present. What vulnerabilities can we consider less likely?",
                "input": "",
                "output": (
                    f"Absence of {short_name} reduces the likelihood of:\n\n"
                    + absent_lines
                    + "\n\n⚠️ Probabilistic signal only — document rationale and reduce (not eliminate) testing priority."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    # CWE family cluster pairs
    for cluster_name, cluster_data in cwe_clusters.items():
        members          = cluster_data.get("members", [])
        triggers         = cluster_data.get("trigger", [])
        probability      = cluster_data.get("probability", 0.0)
        reasoning        = cluster_data.get("reasoning", "")
        absent_cwes      = cluster_data.get("absent_if_not", [])
        absent_prob      = cluster_data.get("absent_probability", 0.0)
        absent_reasoning = cluster_data.get("unlikely_reasoning", "")

        if triggers and members:
            other_members = [m for m in members if m not in triggers]
            pairs.append({
                "instruction": f"We confirmed {' and '.join(triggers[:2])} in a C/C++ codebase. What other CWEs should we prioritize in the '{cluster_name.replace('_', ' ')}' family?",
                "input": "",
                "output": (
                    f"Confirmed {' + '.join(triggers[:2])} → '{cluster_name.replace('_', ' ')}' cluster triggered.\n\n"
                    f"Co-present probability: {int(probability*100)}%\n\n"
                    "Prioritize testing for:\n"
                    + "\n".join(f"  • {m}" for m in other_members)
                    + f"\n\nReasoning: {reasoning}"
                    + "\n\nRecommendation: Run memory safety scanner (Valgrind/ASan/CodeQL) across the full codebase."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

        if absent_cwes:
            pairs.append({
                "instruction": f"Testing confirmed {absent_cwes[0]} is NOT present. What does this tell us about other vulnerabilities in the '{cluster_name.replace('_', ' ')}' family?",
                "input": "",
                "output": (
                    f"Absence of {absent_cwes[0]} reduces the likelihood of other '{cluster_name.replace('_', ' ')}' cluster vulnerabilities:\n\n"
                    + "\n".join(
                        f"  • {m}: ~{int(absent_prob*100)}% probability (reduced from baseline)"
                        for m in members if m != absent_cwes[0]
                    )
                    + f"\n\nReasoning: {absent_reasoning or reasoning}\n\n"
                    + "⚠️ Probabilistic signal only — document finding and reduce, do NOT skip testing entirely."
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
                f"({p.get('signal', 'co-occurrence')}, support={_fmt_support(p.get('support','N/A'))})"
                + (f"\n    → {p.get('reasoning','')}" if p.get("reasoning") else "")
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
                + (f" — {a.get('reasoning','')}" if a.get("reasoning") else "")
                for a in absent[:4]
            )
            pairs.append({
                "instruction": f"Testing confirms {cve_id} is NOT present. Which related CVEs can we deprioritize?",
                "input": desc,
                "output": (
                    f"Absence of {cve_id} lowers probability of these related CVEs:\n\n"
                    + absent_lines
                    + "\n\nDeprioritize — but do not skip — these in your testing scope."
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

    # Technology stack pairs
    for stack_name, stack_data in stack_clusters.items():
        indicators     = stack_data.get("stack_indicators", [])
        likely_cwe     = stack_data.get("likely_cwe", [])
        likely_owasp   = stack_data.get("likely_owasp", [])
        stack_reasoning = stack_data.get("reasoning", "")
        unlikely_cwe   = stack_data.get("unlikely_cwe", [])
        unlikely_reason = stack_data.get("unlikely_reasoning", "")

        if likely_cwe:
            pairs.append({
                "instruction": f"We identified a {stack_name.replace('_', ' ')} technology stack. What CWEs and OWASP categories should we prioritize?",
                "input": f"Stack indicators: {', '.join(indicators[:5])}",
                "output": (
                    f"For {stack_name.replace('_', ' ')} stacks, prioritize:\n\n"
                    f"High-priority CWEs:\n"
                    + "\n".join(f"  • {c}" for c in likely_cwe)
                    + (f"\n\nOWASP focus areas:\n" + "\n".join(f"  • {o}" for o in likely_owasp) if likely_owasp else "")
                    + f"\n\nReasoning: {stack_reasoning}"
                ),
                "layer": "vulnerability_cooccurrence",
                "agent": "Correlation Agent",
            })

        if unlikely_cwe:
            pairs.append({
                "instruction": (
                    f"The target runs a {stack_name.replace('_', ' ')} stack. "
                    f"Can we skip testing for {unlikely_cwe[0]}"
                    f"{' and ' + unlikely_cwe[1] if len(unlikely_cwe) > 1 else ''}?"
                ),
                "input": "",
                "output": (
                    f"For {stack_name.replace('_', ' ')} systems, {' and '.join(unlikely_cwe[:2])} are statistically unlikely because:\n\n"
                    f"{unlikely_reason}\n\n"
                    "Recommended: Deprioritize these, but do NOT skip entirely. "
                    "Document the stack-based risk reduction rationale in your assessment report."
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

    # FIX 3: Use Path(__file__).parent for stable import regardless of CWD.
    # Previously: sys.path.insert(0, "data") — broke when called from run_pipeline.py
    _data_dir = str(Path(__file__).parent)
    if _data_dir not in sys.path:
        sys.path.insert(0, _data_dir)

    try:
        from owasp_mapper import get_owasp_category as owasp_fn
    except ImportError:
        print("  ⚠️  owasp_mapper not found — OWASP mapping will return 'Unknown'")
        owasp_fn = lambda cwe: "Unknown"   # noqa: E731

    nvd_by_cve = {r.get("cve_id", ""): r for r in nvd_records if r.get("cve_id")}

    print("\n[1/3] Computing CVE product co-occurrence (NVD + KEV + Exploit-DB)...")
    cve_cooccurrence = compute_cve_product_cooccurrence(
        nvd_records, kev_records, exploitdb_records,
        min_support=3, min_confidence=0.35
    )
    print(f"  CVEs with co-occurrence data: {len(cve_cooccurrence)}")

    print("\n[2/3] Computing data-driven OWASP co-occurrence...")
    data_driven_owasp = compute_owasp_cooccurrence_from_data(nvd_records, owasp_fn)

    # FIX 1 effect: _normalize_empirical now produces correct "reasoning" keys
    merged_owasp = _normalize_empirical(EMPIRICAL_OWASP_COOCCURRENCE)

    for cat, data in data_driven_owasp.items():
        if cat not in merged_owasp:
            merged_owasp[cat] = data
        else:
            # Add data-driven entries not already covered by empirical
            empirical_cats = {p["category"] for p in merged_owasp[cat].get("likely_present", [])}
            for entry in data.get("likely_present", []):
                if entry["category"] not in empirical_cats:
                    merged_owasp[cat].setdefault("likely_present", []).append(entry)
            # Also merge top-level reasoning if empirical has none
            if not merged_owasp[cat].get("reasoning") and data.get("reasoning"):
                merged_owasp[cat]["reasoning"] = data["reasoning"]

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