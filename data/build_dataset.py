"""
build_dataset.py
----------------
Merges ALL raw source files into the full 6-layer schema + co-occurrence layer.
Generates instruction-response training pairs for each layer.

DATA SOURCES:
  - raw_nvd.json:                NVD CVE database
  - raw_epss.json:               FIRST EPSS exploit probability scores
  - raw_github.json:             GitHub Security Advisories
  - raw_blogs.json:              Security blog write-ups
  - raw_papers.json:             arXiv, Semantic Scholar, OSV
  - raw_closed.json:             Full Disclosure, Bugtraq, HackerOne, MSRC
  - raw_cisa_kev.json:           CISA KEV catalog
  - raw_exploitdb.json:          Exploit-DB full CSV export
  - raw_mitre_attack.json:       MITRE ATT&CK + CAPEC  [NEW]
  - raw_vendor_advisories.json:  Cisco/RedHat/Ubuntu/Debian [NEW]
  - raw_correlations.json:       CVE correlation graph  [NEW]
  - raw_cooccurrence.json:       P(B|A) co-occurrence model [NEW]

Training layers:
  1. vulnerability_intelligence  — OWASP mapping, CWE analysis
  2. pentesting_intelligence     — attack methods, payloads, tools
  3. risk_scoring                — CVSS, EPSS, business impact
  4. execution_context           — tech stack, tool selection
  5. audit_evidence              — findings, compliance
  6. remediation_learning        — fixes, root cause
  7. vulnerability_cooccurrence  — P(B|A): if A exists, B is likely [NEW]
"""

import json
import re
import sys
import uuid
from pathlib import Path
from collections import defaultdict

# Ensure data/ dir is on path for sibling imports
_data_dir = Path(__file__).parent
if str(_data_dir) not in sys.path:
    sys.path.insert(0, str(_data_dir))

from owasp_mapper import get_owasp_category, get_pentest_intel  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def clean(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', str(text))
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    return text.strip()


def risk_level(cvss_score) -> str:
    if not cvss_score:
        return "Unknown"
    try:
        s = float(cvss_score)
        if s >= 9.0: return "Critical"
        if s >= 7.0: return "High"
        if s >= 4.0: return "Medium"
        return "Low"
    except (ValueError, TypeError):
        return "Unknown"


def business_impact(owasp_cat: str) -> str:
    impacts = {
        "A01:2021-Broken Access Control":                      "Unauthorized data access, privilege escalation",
        "A02:2021-Cryptographic Failures":                     "Sensitive data exposure, credential theft",
        "A03:2021-Injection":                                  "Database compromise, remote code execution",
        "A04:2021-Insecure Design":                            "Systematic security bypass, reputational damage",
        "A05:2021-Security Misconfiguration":                  "System compromise via exposed attack surface",
        "A06:2021-Vulnerable and Outdated Components":         "Full system takeover via known exploits",
        "A07:2021-Identification and Authentication Failures": "Account takeover, session hijacking",
        "A08:2021-Software and Data Integrity Failures":       "Supply chain compromise, malicious updates",
        "A09:2021-Security Logging and Monitoring Failures":   "Undetected breaches, delayed incident response",
        "A10:2021-Server-Side Request Forgery":                "Internal network access, cloud metadata theft",
    }
    return impacts.get(owasp_cat, "Security breach, data loss")


# ── FIXED: CWE-specific, actionable security controls (replaces old generic stub) ──

_OWASP_CONTROLS = {
    "A01:2021-Broken Access Control":                      "Implement RBAC, enforce object-level authorization checks, validate resource ownership before serving",
    "A02:2021-Cryptographic Failures":                     "Use AES-256/TLS 1.2+, replace MD5/SHA1 with bcrypt/argon2, enforce HTTPS, avoid hardcoded keys",
    "A03:2021-Injection":                                  "Use parameterized queries and prepared statements; apply allowlist input validation; avoid dynamic query construction",
    "A04:2021-Insecure Design":                            "Add rate limiting, remove verbose error messages, implement threat modeling, use anti-automation controls",
    "A05:2021-Security Misconfiguration":                  "Harden server configurations, disable unnecessary features, apply security headers (CSP, HSTS, X-Frame-Options)",
    "A06:2021-Vulnerable and Outdated Components":         "Maintain SBOM, use automated dependency scanning (Snyk/Dependabot), apply patches within SLA",
    "A07:2021-Identification and Authentication Failures": "Enforce MFA, implement brute-force lockout, use secure session tokens, invalidate sessions on logout",
    "A08:2021-Software and Data Integrity Failures":       "Verify supply chain integrity (SRI, Sigstore), implement CI/CD security, validate deserialized inputs",
    "A09:2021-Security Logging and Monitoring Failures":   "Deploy SIEM, alert on authentication anomalies, ensure logs are tamper-evident and include all security events",
    "A10:2021-Server-Side Request Forgery":                "Allowlist permitted outbound URLs, block internal IP ranges at egress, disable unnecessary URL-fetching",
}

_CWE_CONTROLS = {
    "CWE-79":  "Implement context-aware output encoding (HTML/JS/CSS), enforce Content Security Policy (CSP) headers",
    "CWE-89":  "Use parameterized queries or ORM — never concatenate user input into SQL strings",
    "CWE-78":  "Use subprocess with argument lists (not shell=True), validate and sanitize all OS command inputs",
    "CWE-22":  "Canonicalize file paths before validation, reject traversal sequences (../), use chroot jails",
    "CWE-94":  "Disable eval()/exec() on user-supplied data, use sandboxed execution environments",
    "CWE-502": "Avoid deserializing untrusted data; use safe libraries; validate type/schema before deserialization",
    "CWE-287": "Enforce MFA, implement account lockout and throttling, use secure session token generation",
    "CWE-798": "Remove all hardcoded credentials, use secrets management (Vault, AWS Secrets Manager)",
    "CWE-476": "Initialize all pointers, use memory-safe languages, add null-pointer checks before dereference",
    "CWE-190": "Validate integer ranges before arithmetic, use safe integer libraries, check for overflow",
    "CWE-416": "Use memory-safe languages; audit all manual memory management; use AddressSanitizer in CI",
    "CWE-125": "Enable compiler bounds checking, validate input lengths, use safe buffer access patterns",
    "CWE-434": "Validate file type by magic bytes (not extension), store uploads outside webroot, restrict execute permissions",
    "CWE-611": "Disable XML external entity (XXE) processing in all parser configurations",
    "CWE-918": "Allowlist permitted outbound URLs/IPs, enforce egress firewall rules to prevent SSRF",
    "CWE-352": "Implement anti-CSRF tokens (Synchronizer Token Pattern), use SameSite=Strict cookie attribute",
    "CWE-601": "Validate redirect targets against a strict allowlist of permitted destinations",
    "CWE-400": "Implement resource quotas, rate limiting, and input size validation to prevent exhaustion",
    "CWE-862": "Add explicit authorization checks at every sensitive operation, not just at route entry",
    "CWE-863": "Implement fine-grained permission checks based on user role and data ownership context",
    "CWE-327": "Replace broken algorithms (MD5, SHA1, DES) with AES-256 and SHA-256/SHA-3",
    "CWE-311": "Encrypt all sensitive data at rest using AES-256; never store passwords in cleartext",
}


def infer_security_control_missing(owasp_cat: str, cwe_id: str = "") -> str:
    """
    Return a specific, actionable missing security control.
    CWE-specific controls take priority over OWASP-level controls.
    """
    if cwe_id and cwe_id in _CWE_CONTROLS:
        return _CWE_CONTROLS[cwe_id]
    return _OWASP_CONTROLS.get(owasp_cat, "Apply vendor patches, enforce least privilege, validate all inputs")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW SOURCE LOADERS
# ═══════════════════════════════════════════════════════════════════════════

def load_json(path: str) -> list | dict:
    p = Path(path)
    if not p.exists():
        print(f"  ⚠️  {path} not found — skipping")
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def build_epss_lookup(epss_path: str) -> dict:
    raw = load_json(epss_path)
    return raw if isinstance(raw, dict) else {}


def build_github_lookup(github_path: str) -> dict:
    """
    Returns lookup keyed by every identifier an advisory has:
      primary cve_id, all alias CVE IDs, and ghsa_id.
    """
    raw    = load_json(github_path)
    lookup = {}
    for item in raw:
        all_cves = item.get("all_cve_ids", [])
        if not all_cves and item.get("cve_id"):
            all_cves = [item["cve_id"]]
        for cve_id in all_cves:
            if cve_id:
                lookup[cve_id] = item
        ghsa_id = item.get("ghsa_id", "")
        if ghsa_id:
            lookup[ghsa_id] = item
    return lookup


def build_blog_lookup(blog_path: str) -> dict:
    raw    = load_json(blog_path)
    lookup: dict[str, str] = {}
    for item in raw:
        content = item.get("content", "")[:3000]
        source  = f"Source: {item.get('url', 'Unknown Blog')}\n\n{content}"
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + source
    return lookup


def build_papers_lookup(papers_path: str) -> dict:
    raw    = load_json(papers_path)
    lookup: dict[str, str] = {}
    for paper in raw:
        title    = paper.get("title", "Unknown Paper")
        abstract = paper.get("abstract", "")
        source   = paper.get("source", "research")
        fulltext = paper.get("fulltext_sample", "")
        content  = f"Research Paper [{source}]: {title}\n\n{abstract}"
        if fulltext:
            content += f"\n\nExcerpt: {fulltext[:1000]}"
        for cve in paper.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + content
    return lookup


def build_closed_sources_lookup(closed_path: str) -> dict:
    raw    = load_json(closed_path)
    lookup: dict[str, str] = {}
    for item in raw:
        source_type = item.get("source", "unknown")
        title   = item.get("title", "")
        content = item.get("content", item.get("summary", item.get("body", item.get("description", ""))))[:1500]
        headers = {
            "full_disclosure": f"Full Disclosure Mailing List:\n{content}",
            "bugtraq":         f"Bugtraq Mailing List:\n{content}",
            "hackerone":       f"HackerOne Report: {title}\nSeverity: {item.get('severity', 'N/A')}\n{content}",
            "microsoft_msrc":  f"Microsoft Security Advisory: {title}\n{content}",
            "reddit_netsec":   f"Reddit /r/netsec: {title}\nScore: {item.get('score', 0)}\n{content}",
            "cisa_kev": (
                f"CISA KEV (Confirmed Exploited): {item.get('vulnerability_name', title)}\n"
                f"Product: {item.get('product', 'N/A')}\n"
                f"Required Action: {item.get('required_action', 'N/A')}\n"
                f"Ransomware: {item.get('known_ransomware', 'Unknown')}\n{content}"
            ),
        }
        header = headers.get(source_type, f"{source_type}: {content}")
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + header
    return lookup


def build_kev_lookup(kev_path: str) -> dict:
    raw = load_json(kev_path)
    return {item["cve_id"]: item for item in raw if item.get("cve_id")}


def build_exploitdb_lookup(exploitdb_path: str) -> dict:
    raw    = load_json(exploitdb_path)
    lookup: dict[str, list] = {}
    for item in raw:
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup.setdefault(cve, []).append(item)
    return lookup


def build_correlations_lookup(corr_path: str) -> dict:
    """CVE → correlation record with related_vulnerabilities, attack_techniques, capec_patterns."""
    p = Path(corr_path)
    if not p.exists():
        return {}
    try:
        records = json.loads(p.read_text(encoding="utf-8"))
        return {r["cve_id"]: r for r in records if r.get("cve_id")}
    except Exception as e:
        print(f"  ⚠️  Correlations load failed: {e}")
        return {}


def build_vendor_lookup(vendor_path: str) -> dict:
    """CVE → list of vendor advisory records (RedHat, Ubuntu, Debian, Cisco, PoC)."""
    p = Path(vendor_path)
    if not p.exists():
        return {}
    try:
        raw    = json.loads(p.read_text(encoding="utf-8"))
        lookup: dict[str, list] = defaultdict(list)
        for item in raw:
            for cve in item.get("cves_mentioned", []):
                lookup[cve.upper()].append(item)
        return dict(lookup)
    except Exception as e:
        print(f"  ⚠️  Vendor advisories load failed: {e}")
        return {}


def load_cooccurrence_pairs(cooccur_path: str) -> list[dict]:
    """Load pre-computed P(B|A) training pairs from build_cooccurrence.py output."""
    p = Path(cooccur_path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        pairs = data.get("training_pairs", [])
        print(f"  Co-occurrence pairs:   {len(pairs)}")
        return pairs
    except Exception as e:
        print(f"  ⚠️  Co-occurrence pairs load failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════
#  RECORD ENRICHMENT (correlations + vendor advisories)
# ═══════════════════════════════════════════════════════════════════════════

def enrich_with_correlations(record: dict, corr_lookup: dict) -> dict:
    """
    Populate the previously always-empty related_vulnerabilities field.
    Also adds attack_techniques and capec_patterns from the correlation graph.
    """
    cve_id = record.get("cve_id", "")
    corr   = corr_lookup.get(cve_id, {})
    if corr:
        record["related_vulnerabilities"] = corr.get("related_vulnerabilities", [])
        record["attack_techniques"]       = corr.get("attack_techniques", [])
        record["capec_patterns"]          = corr.get("capec_patterns", [])
        record["correlation_signals"]     = corr.get("correlation_signal_count", 0)
    return record


def enrich_with_vendor_advisories(record: dict, vendor_lookup: dict) -> dict:
    """
    Add vendor-specific context (Red Hat severity, Ubuntu/Debian package status,
    Cisco workarounds, public PoC repos) to the real_world_exploit field.
    """
    cve_id     = record.get("cve_id", "")
    advisories = vendor_lookup.get(cve_id, [])
    if not advisories:
        return record

    parts           = []
    affected_distros = set()

    for adv in advisories[:5]:
        source = adv.get("source", "")
        if source == "redhat_security":
            sev  = adv.get("severity", "")
            pkgs = adv.get("affected_packages", [])
            parts.append(f"Red Hat: severity={sev}, packages={', '.join(pkgs[:3])}")
            affected_distros.add("RHEL")
        elif source == "ubuntu_usn":
            pkgs = adv.get("affected_packages", [])
            if pkgs:
                parts.append(f"Ubuntu USN: {', '.join(pkgs[:3])}")
            affected_distros.add("Ubuntu")
        elif source == "debian_security":
            pkg   = adv.get("package", "")
            fixed = adv.get("releases_fixed", {})
            fixed_str = ", ".join(f"{r}:{v}" for r, v in list(fixed.items())[:2])
            parts.append(f"Debian package={pkg}, fixed_in={fixed_str or 'pending'}")
            affected_distros.add("Debian")
        elif source == "cisco_psirt":
            adv_id = adv.get("advisory_id", "")
            wk     = adv.get("workarounds", "")[:100]
            parts.append(f"Cisco {adv_id}: {wk or 'see advisory'}")
            affected_distros.add("Cisco IOS/NX-OS")
        elif source == "poc_github":
            repo  = adv.get("repo", "")
            stars = adv.get("stars", 0)
            lang  = adv.get("language", "")
            parts.append(f"Public PoC: {repo} ({stars}⭐, {lang})")

    if parts:
        vendor_block = "Vendor Advisory Context:\n" + "\n".join(f"  • {p}" for p in parts)
        existing = record.get("real_world_exploit", "")
        record["real_world_exploit"] = (
            (existing + "\n\n" + vendor_block).strip() if existing else vendor_block
        )

    if affected_distros:
        sw = list(set(record.get("affected_software", []) + list(affected_distros)))
        record["affected_software"] = sw[:20]

    return record


# ═══════════════════════════════════════════════════════════════════════════
#  BUILD FULL SCHEMA RECORD
# ═══════════════════════════════════════════════════════════════════════════

def build_record(
    nvd_rec:       dict,
    epss_map:      dict,
    github_map:    dict,
    blog_map:      dict,
    papers_map:    dict,
    closed_map:    dict,
    kev_map:       dict,
    exploitdb_map: dict,
) -> dict:
    cve_id = nvd_rec.get("cve_id", "")
    cwe_id = nvd_rec.get("cwe_id", "")
    desc   = clean(nvd_rec.get("description", ""))
    cvss   = nvd_rec.get("cvss_score", "")
    sev    = nvd_rec.get("cvss_severity", "")

    owasp_cat   = get_owasp_category(cwe_id)
    pentest     = get_pentest_intel(owasp_cat)
    epss_score  = epss_map.get(cve_id, "")
    gh_advisory = github_map.get(cve_id, {})
    kev_entry   = kev_map.get(cve_id, {})
    exploits    = exploitdb_map.get(cve_id, [])

    # Fix recommendation: GitHub > KEV mandate > fallback
    fix_rec = gh_advisory.get("fix_recommendation", "")
    if not fix_rec and kev_entry.get("required_action"):
        fix_rec = f"CISA mandate: {kev_entry['required_action']}"
    if not fix_rec:
        fix_rec = "Apply vendor-supplied patches. Implement input validation and follow secure coding practices."

    # Confirmed exploitation signals
    confirmed_exploited = bool(kev_entry)
    kev_ransomware      = kev_entry.get("known_ransomware_campaign_use", "")

    # Exploit-DB enrichment
    exploit_count  = len(exploits)
    exploit_titles = [e.get("title", "") for e in exploits[:3]]
    exploit_types  = list(set(e.get("type", "") for e in exploits if e.get("type")))

    # Real-world exploit context (papers + closed sources + blogs + Exploit-DB + KEV)
    exploit_ctx_parts = []
    if papers_map.get(cve_id):
        exploit_ctx_parts.append(f"Research:\n{papers_map[cve_id][:1000]}")
    if closed_map.get(cve_id):
        exploit_ctx_parts.append(f"Intelligence:\n{closed_map[cve_id][:1000]}")
    if blog_map.get(cve_id):
        exploit_ctx_parts.append(f"Blog:\n{blog_map[cve_id][:500]}")
    if exploits:
        exploit_ctx_parts.append(
            f"Exploit-DB: {exploit_count} exploit(s) — {', '.join(exploit_titles)}"
        )
    if kev_entry:
        exploit_ctx_parts.append(
            f"CISA KEV: Confirmed exploited in the wild. "
            f"Ransomware: {kev_ransomware or 'Unknown'}. "
            f"Required action: {kev_entry.get('required_action', 'Apply patch')}"
        )
    real_world_exploit = "\n\n".join(exploit_ctx_parts)

    # Source tags
    sources = ["NVD"]
    if epss_score:           sources.append("EPSS")
    if gh_advisory:          sources.append("GitHub Advisories")
    if blog_map.get(cve_id): sources.append("Security Blogs")
    if papers_map.get(cve_id): sources.append("Research Papers")
    if closed_map.get(cve_id): sources.append("Closed Sources")
    if kev_entry:            sources.append("CISA KEV")
    if exploits:             sources.append("Exploit-DB")

    return {
        # Core identity
        "cve_id":              cve_id,
        "vulnerability_name":  nvd_rec.get("vulnerability_name", cve_id),
        "cwe_id":              cwe_id,
        "description":         desc,

        # Layer 1: Vulnerability Intelligence
        "owasp_category":      owasp_cat,
        "cvss_score":          cvss,
        "cvss_severity":       sev,
        "epss_score":          epss_score,
        "affected_software":   nvd_rec.get("affected_software", [])[:10],
        "published":           nvd_rec.get("published", ""),

        # Layer 2: Pentesting Intelligence
        "attack_method":       pentest.get("attack_method", "Manual testing required"),
        "payload_example":     pentest.get("payload_example", ""),
        "detection_signals":   pentest.get("detection_signals", []),
        "tool_used":           pentest.get("tool_used", "Burp Suite, OWASP ZAP"),
        "code_pattern":        pentest.get("code_pattern", ""),
        "real_world_exploit":  real_world_exploit,

        # Layer 3: Risk & Scoring
        "risk_level":          risk_level(cvss),
        "business_impact":     business_impact(owasp_cat),
        "confirmed_exploited": confirmed_exploited,
        "kev_ransomware":      kev_ransomware,
        "exploit_count":       exploit_count,
        "exploit_types":       exploit_types,

        # Layer 4: Execution Context
        "tool_recommendation": pentest.get("tool_used", ""),
        "vulnerability_research": (
            f"Identified via CVE database. CVSS: {cvss}. {desc[:120]}..."
        ),

        # Layer 5: Audit Evidence
        "security_control_missing": infer_security_control_missing(owasp_cat, cwe_id),

        # Layer 6: Remediation Learning
        "fix_recommendation":  fix_rec,
        "status":              "Open",

        # Layer 7: Correlation (populated by enrich_with_correlations)
        "related_vulnerabilities": [],
        "attack_techniques":       [],
        "capec_patterns":          [],
        "correlation_signals":     0,

        "source": " + ".join(sources),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  TRAINING PAIR GENERATORS
# ═══════════════════════════════════════════════════════════════════════════

def to_training_pairs(record: dict) -> list[dict]:
    cve    = record["cve_id"]
    desc   = record["description"]
    owasp  = record["owasp_category"]
    cvss   = record["cvss_score"]
    risk   = record["risk_level"]
    sev    = record["cvss_severity"]
    epss   = record["epss_score"]
    fix    = record["fix_recommendation"]
    method = record["attack_method"]
    sigs   = ", ".join(record["detection_signals"])
    biz    = record["business_impact"]
    ctrl   = record["security_control_missing"]
    tool   = record["tool_used"]
    cwe    = record["cwe_id"]
    exploit_ctx        = record.get("real_world_exploit", "")
    kev_ransomware     = record.get("kev_ransomware", "")
    confirmed_exploited = record.get("confirmed_exploited", False)

    pairs = []

    # L1: Vulnerability Intelligence
    if desc:
        pairs.append({
            "instruction": f"Explain the vulnerability {cve} and map it to its OWASP category.",
            "input":       "",
            "output":      f"{desc}\n\nOWASP Category: {owasp}\nCWE: {cwe}",
            "layer":       "vulnerability_intelligence",
            "agent":       "OWASP Mapper Agent",
        })

    # L2: Pentesting Intelligence
    if method:
        pairs.append({
            "instruction": "Describe how to test for this vulnerability during a pentest.",
            "input":       desc,
            "output":      (
                f"Attack Method: {method}\n\n"
                f"Detection Signals: {sigs}\n\n"
                f"Recommended Tool: {tool}"
            ),
            "layer":       "pentesting_intelligence",
            "agent":       "Tool Selector Agent",
        })

    # L2b: Real-world context
    if exploit_ctx:
        pairs.append({
            "instruction": f"Provide real-world exploit examples and research findings for {cve}.",
            "input":       desc,
            "output":      f"Real-world context for {cve}:\n\n{exploit_ctx[:3000]}",
            "layer":       "pentesting_intelligence",
            "agent":       "Scanner Agent",
        })

    # L3: Risk & Scoring
    if cvss:
        kev_note = ""
        if confirmed_exploited:
            kev_note = f"\nCISA KEV: This CVE is CONFIRMED exploited in the wild."
            if kev_ransomware == "Known":
                kev_note += " Known ransomware campaign use."
        pairs.append({
            "instruction": "Perform a risk assessment for this vulnerability.",
            "input":       desc,
            "output":      (
                f"CVSS Score: {cvss} ({sev})\n"
                f"Risk Level: {risk}\n"
                f"EPSS (Exploit Probability): {epss if epss else 'N/A'}\n"
                f"Business Impact: {biz}"
                + kev_note
            ),
            "layer":       "risk_scoring",
            "agent":       "Base Scorer Agent",
        })

    # L4: Execution Context
    if tool:
        pairs.append({
            "instruction": "Which security testing tool should be used for this vulnerability and why?",
            "input":       desc,
            "output":      (
                f"Recommended Tool: {tool}\n\n"
                f"OWASP Category: {owasp}\n"
                f"Testing Approach: {method}"
            ),
            "layer":       "execution_context",
            "agent":       "Tool Selector Agent",
        })

    # L5: Audit Evidence
    if cvss:
        pairs.append({
            "instruction": "Generate an audit finding summary for this vulnerability.",
            "input":       desc,
            "output":      (
                f"Finding: {cve}\n"
                f"CVE: {cve} | CWE: {cwe} | OWASP: {owasp}\n"
                f"CVSS: {cvss} ({sev}) — {risk} Risk\n"
                f"Description: {desc[:300]}\n"
                f"Control Gap: {ctrl}\n"
                f"Business Impact: {biz}\n"
                + (f"Exploitation Status: CONFIRMED (CISA KEV)" if confirmed_exploited else "")
            ),
            "layer":       "audit_evidence",
            "agent":       "Reporting Agent",
        })

    # L6: Remediation Learning
    if fix:
        pairs.append({
            "instruction": "What is the recommended remediation for this vulnerability?",
            "input":       desc,
            "output":      (
                f"Remediation: {fix}\n\n"
                f"Root Cause: {ctrl}\n"
                f"Control Type: Technical"
            ),
            "layer":       "remediation_learning",
            "agent":       "Reflector Agent",
        })

    return pairs


def to_correlation_training_pairs(record: dict) -> list[dict]:
    """
    Generate vulnerability_correlation layer pairs from enriched record.
    Covers: what other CVEs correlate, which ATT&CK techniques, campaign clusters.
    """
    cve_id   = record.get("cve_id", "")
    desc     = record.get("description", "")[:400]
    related  = record.get("related_vulnerabilities", [])
    techniques = record.get("attack_techniques", [])

    if not related or not cve_id:
        return []

    pairs = []

    # Pair 1: What correlates with this CVE?
    related_lines = "\n".join(
        f"  • {r['cve_id']} (score:{r.get('correlation_score', 0)}, "
        f"via: {', '.join({s.split(':')[0] for s in r.get('signals', [])})})"
        for r in related[:5]
    )
    pairs.append({
        "instruction": f"What vulnerabilities are correlated with {cve_id} and why?",
        "input":       desc,
        "output": (
            f"Correlated vulnerabilities for {cve_id}:\n\n{related_lines}\n\n"
            "Signal types: shared_cwe (same weakness class), shared_product (same software), "
            "shared_attack_technique (same MITRE ATT&CK technique), "
            "kev_campaign_temporal (co-listed in CISA KEV within 30 days), "
            "exploit_chain_cooccurrence (appear together in known exploit code)."
        ),
        "layer": "vulnerability_correlation",
        "agent": "Correlation Agent",
    })

    # Pair 2: ATT&CK techniques
    if techniques:
        pairs.append({
            "instruction": f"Which MITRE ATT&CK techniques are linked to {cve_id}?",
            "input":       desc,
            "output": (
                f"MITRE ATT&CK techniques for {cve_id}:\n"
                + "\n".join(f"  • {t}" for t in techniques[:4])
                + (
                    "\n\nOther CVEs exploiting the same techniques:\n"
                    + "\n".join(
                        f"  • {r['cve_id']}"
                        for r in related[:5]
                        if any("attack_technique" in s for s in r.get("signals", []))
                    )
                )
            ),
            "layer": "vulnerability_correlation",
            "agent": "Correlation Agent",
        })

    # Pair 3: KEV campaign cluster
    kev_cluster = [
        r["cve_id"] for r in related
        if any("kev_campaign" in s for s in r.get("signals", []))
    ]
    if kev_cluster:
        pairs.append({
            "instruction": f"Is {cve_id} part of a known active exploitation campaign?",
            "input":       desc,
            "output": (
                f"{cve_id} is part of an active exploitation cluster (CISA KEV temporal analysis).\n\n"
                "CVEs in the same 30-day KEV window (same probable campaign):\n"
                + "\n".join(f"  • {c}" for c in kev_cluster[:6])
                + "\n\nTemporal clustering suggests coordinated use by the same threat actor group."
            ),
            "layer": "vulnerability_correlation",
            "agent": "Correlation Agent",
        })

    # Pair 4: Exploit chain
    chain = [
        r["cve_id"] for r in related
        if any("exploit_chain" in s for s in r.get("signals", []))
    ]
    if chain:
        pairs.append({
            "instruction": f"What exploit chains involve {cve_id}?",
            "input":       desc,
            "output": (
                f"Exploit chain analysis for {cve_id}:\n\n"
                "CVEs that co-appear in exploit code or PoC repositories:\n"
                + "\n".join(f"  • {c}" for c in chain[:5])
                + "\n\nCo-occurrence in exploit code suggests multi-stage attack patterns "
                  "(e.g., initial access via one CVE, privilege escalation via another)."
            ),
            "layer": "vulnerability_correlation",
            "agent": "Correlation Agent",
        })

    return pairs


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def run():
    print("Loading raw data sources...")

    nvd_records   = load_json("data/raw_nvd.json")
    epss_map      = build_epss_lookup("data/raw_epss.json")
    github_map    = build_github_lookup("data/raw_github.json")
    blog_map      = build_blog_lookup("data/raw_blogs.json")
    papers_map    = build_papers_lookup("data/raw_papers.json")
    closed_map    = build_closed_sources_lookup("data/raw_closed.json")
    kev_map       = build_kev_lookup("data/raw_cisa_kev.json")
    exploitdb_map = build_exploitdb_lookup("data/raw_exploitdb.json")
    corr_lookup   = build_correlations_lookup("data/raw_correlations.json")
    vendor_lookup = build_vendor_lookup("data/raw_vendor_advisories.json")

    print(f"  NVD records:           {len(nvd_records)}")
    print(f"  EPSS entries:          {len(epss_map)}")
    print(f"  GitHub entries:        {len(github_map)}")
    print(f"  Blog CVE matches:      {len(blog_map)}")
    print(f"  Paper CVE matches:     {len(papers_map)}")
    print(f"  Closed CVE matches:    {len(closed_map)}")
    print(f"  CISA KEV entries:      {len(kev_map)}")
    print(f"  Exploit-DB CVEs:       {len(exploitdb_map)}")
    print(f"  Correlations loaded:   {len(corr_lookup)}")
    print(f"  Vendor advisories:     {len(vendor_lookup)} CVEs covered")

    seen_cves      = set()
    full_records   = []
    training_pairs = []

    # ── Pass 1: NVD records (main loop) ───────────────────────────────────
    for nvd_rec in nvd_records:
        cve_id = nvd_rec.get("cve_id", "")
        desc   = nvd_rec.get("description", "")
        if not desc or len(desc) < 50:
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        record = build_record(
            nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))

    # ── Pass 2: CISA KEV entries not in NVD batch ─────────────────────────
    kev_only_count = 0
    for cve_id, kev_entry in kev_map.items():
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        desc = kev_entry.get("description", "")
        if not desc:
            desc = (
                f"{kev_entry.get('vulnerability_name', cve_id)} affecting "
                f"{kev_entry.get('vendor', 'Unknown')} {kev_entry.get('product', '')}. "
                f"Actively exploited in the wild per CISA KEV catalog."
            )

        minimal_nvd_rec = {
            "cve_id":             cve_id,
            "vulnerability_name": kev_entry.get("vulnerability_name", cve_id),
            "cwe_id":             "",
            "description":        desc,
            "cvss_score":         "",
            "cvss_severity":      "",
            "affected_software":  [kev_entry.get("product", "")],
            "published":          kev_entry.get("date_added", ""),
        }

        record = build_record(
            minimal_nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))
        kev_only_count += 1

    print(f"  KEV-only records added (not in NVD batch): {kev_only_count}")

    # ── Pass 3: GHSA-only GitHub advisories (no CVE ID) ───────────────────
    raw_github      = load_json("data/raw_github.json")
    ghsa_only_count = 0

    for adv in raw_github:
        ghsa_id = adv.get("ghsa_id", "")
        cve_ids = adv.get("all_cve_ids", []) or ([adv["cve_id"]] if adv.get("cve_id") else [])

        if any(c in seen_cves for c in cve_ids) or ghsa_id in seen_cves:
            continue
        if cve_ids:
            continue
        if not ghsa_id:
            continue

        desc = adv.get("description", "") or adv.get("vulnerability_name", "")
        if not desc or len(desc) < 30:
            continue

        seen_cves.add(ghsa_id)
        cwe_ids = adv.get("cwe_ids", [])

        minimal_nvd_rec = {
            "cve_id":             ghsa_id,
            "vulnerability_name": adv.get("vulnerability_name", ghsa_id),
            "cwe_id":             cwe_ids[0] if cwe_ids else "",
            "description":        desc,
            "cvss_score":         adv.get("cvss_score", ""),
            "cvss_severity":      adv.get("cvss_severity", ""),
            "affected_software":  adv.get("affected_packages", [])[:5],
            "published":          adv.get("published", ""),
        }

        record = build_record(
            minimal_nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))
        ghsa_only_count += 1

    print(f"  GHSA-only records added (no CVE ID):       {ghsa_only_count}")

    # ── Load co-occurrence pairs (pre-computed by build_cooccurrence.py) ──
    cooccurrence_pairs = load_cooccurrence_pairs("data/raw_cooccurrence.json")
    training_pairs.extend(cooccurrence_pairs)

    # ── Save outputs ──────────────────────────────────────────────────────
    with open("data/vuln_dataset.jsonl", "w", encoding="utf-8") as f:
        for r in full_records:
            f.write(json.dumps(r) + "\n")

    with open("data/training_pairs.jsonl", "w", encoding="utf-8") as f:
        for p in training_pairs:
            f.write(json.dumps(p) + "\n")

    # ── Stats ─────────────────────────────────────────────────────────────
    layer_counts: dict[str, int] = {}
    for p in training_pairs:
        l = p.get("layer", "unknown")
        layer_counts[l] = layer_counts.get(l, 0) + 1

    github_matched = sum(1 for r in full_records if "GitHub Advisories" in r.get("source", ""))
    kev_count      = sum(1 for r in full_records if r.get("confirmed_exploited"))
    exploit_recs   = sum(1 for r in full_records if r.get("exploit_count", 0) > 0)
    paper_recs     = sum(1 for r in full_records if "Research Papers" in r.get("source", ""))
    closed_recs    = sum(1 for r in full_records if "Closed Sources" in r.get("source", ""))
    corr_recs      = sum(1 for r in full_records if r.get("related_vulnerabilities"))
    vendor_recs    = sum(1 for r in full_records if "Vendor Advisory Context" in r.get("real_world_exploit", ""))

    print(f"\n✅ Full schema records:  {len(full_records)} → data/vuln_dataset.jsonl")
    print(f"✅ Training pairs total: {len(training_pairs)} → data/training_pairs.jsonl")

    print("\nTraining pairs per layer:")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer:<36} {count:>7} examples")

    print(f"\n📊 Source enrichment:")
    print(f"  GitHub advisories matched:      {github_matched}  (CVE + GHSA)")
    print(f"  CISA KEV (confirmed exploited): {kev_count}")
    print(f"  Records with Exploit-DB data:   {exploit_recs}")
    print(f"  Records with research papers:   {paper_recs}")
    print(f"  Records with closed sources:    {closed_recs}")
    print(f"  Records with correlations:      {corr_recs}  ← NEW")
    print(f"  Records with vendor advisories: {vendor_recs}  ← NEW")
    print(f"  Co-occurrence pairs added:      {len(cooccurrence_pairs)}  ← NEW")


if __name__ == "__main__":
    run()