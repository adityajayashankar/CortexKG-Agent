"""
build_dataset.py  (FIXED)
--------------------------
FIXES in this version:
  1. GitHub lookup: 3000 advisories crawled → only 149 in lookup map
     Root cause: old build_github_lookup only indexed by primary cve_id.
     Since 95% of GHSA advisories only have a ghsa_id (no primary cve_id),
     they were silently dropped. Fixed to index by ALL CVE aliases + ghsa_id.

  2. Training pair quality: no filtering → noisy short outputs in dataset
     Added filter_training_pairs() — drops outputs < 80 chars
     Added dedup_training_pairs()  — deduplicates by (instruction, output[:200])

  3. Training pair enrichment: L1 outputs were just field concatenations
     Now includes reasoning text to teach the model to analyse, not recite.

DATA SOURCES:
  - raw_nvd.json                NVD CVE database
  - raw_epss.json               FIRST EPSS scores
  - raw_github.json             GitHub Security Advisories (GHSA)
  - raw_blogs.json              Security blog write-ups
  - raw_papers.json             arXiv, Semantic Scholar, OSV
  - raw_closed.json             Full Disclosure, OSS-Security, HackerOne, MSRC
  - raw_cisa_kev.json           CISA KEV catalog
  - raw_exploitdb.json          Exploit-DB
  - raw_vendor_advisories.json  Cisco/RedHat/Ubuntu/Debian
  - raw_correlations.json       CVE correlation graph
  - raw_cooccurrence.json       P(B|A) co-occurrence model
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

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
    try:
        s = float(cvss_score)
    except (TypeError, ValueError):
        return "Unknown"
    if s >= 9.0:  return "Critical"
    if s >= 7.0:  return "High"
    if s >= 4.0:  return "Medium"
    return "Low"


def business_impact(owasp_cat: str) -> str:
    impacts = {
        "A01:2021-Broken Access Control":          "Unauthorized data access, privilege escalation, data breach",
        "A02:2021-Cryptographic Failures":         "Exposure of sensitive data, credential theft, regulatory violation",
        "A03:2021-Injection":                      "Data exfiltration, authentication bypass, full system compromise",
        "A04:2021-Insecure Design":                "Systemic architectural risk, difficult to remediate without redesign",
        "A05:2021-Security Misconfiguration":      "Unintended exposure of services, data leakage, unauthorized access",
        "A06:2021-Vulnerable and Outdated Components": "Known exploit availability, supply chain compromise",
        "A07:2021-Identification and Authentication Failures": "Account takeover, session hijacking, identity fraud",
        "A08:2021-Software and Data Integrity Failures": "Supply chain attack, malicious code execution",
        "A09:2021-Security Logging and Monitoring Failures": "Undetected breach, delayed incident response",
        "A10:2021-Server-Side Request Forgery":    "Internal network access, cloud metadata exfiltration, SSRF pivot",
    }
    return impacts.get(owasp_cat, "Potential data breach, service disruption, regulatory penalties")


# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY CONTROL MAPPING
# ═══════════════════════════════════════════════════════════════════════════

_OWASP_CONTROLS = {
    "A01:2021-Broken Access Control":          "Implement server-side access control checks; enforce least privilege; deny by default",
    "A02:2021-Cryptographic Failures":         "Use TLS 1.3, AES-256, SHA-256+; never use MD5/SHA1/DES for security purposes",
    "A03:2021-Injection":                      "Use parameterized queries, prepared statements, and input validation for ALL user-supplied data",
    "A04:2021-Insecure Design":                "Threat model during design phase; enforce security architecture review gates",
    "A05:2021-Security Misconfiguration":      "Harden all configurations; disable unnecessary features; automate configuration validation",
    "A06:2021-Vulnerable and Outdated Components": "Implement SCA scanning in CI/CD; enforce patching SLA; maintain SBOM",
    "A07:2021-Identification and Authentication Failures": "Enforce MFA; implement brute-force protection; use secure session management",
    "A08:2021-Software and Data Integrity Failures": "Verify supply chain integrity (SRI, Sigstore); validate deserialized inputs",
    "A09:2021-Security Logging and Monitoring Failures": "Implement SIEM; alert on anomalies; ensure logs are tamper-evident",
    "A10:2021-Server-Side Request Forgery":    "Allowlist permitted URLs; block internal IP ranges; disable unnecessary URL-fetching",
}

_CWE_CONTROLS = {
    "CWE-79":  "Implement context-aware output encoding (HTML/JS/CSS), enforce Content Security Policy (CSP)",
    "CWE-89":  "Use parameterized queries or ORM — never concatenate user input into SQL statements",
    "CWE-78":  "Use subprocess with argument lists (not shell=True), validate and sanitize all command inputs",
    "CWE-22":  "Canonicalize paths before validation, reject traversal sequences (../), use chroot jails",
    "CWE-94":  "Disable eval()/exec() on user-supplied data, use sandboxed execution environments",
    "CWE-502": "Avoid deserializing untrusted data; if necessary, use safe libraries and validate before deserialization",
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
    if cwe_id and cwe_id in _CWE_CONTROLS:
        return _CWE_CONTROLS[cwe_id]
    return _OWASP_CONTROLS.get(owasp_cat, "Apply vendor patches, enforce least privilege, validate all inputs")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW SOURCE LOADERS
# ═══════════════════════════════════════════════════════════════════════════

def load_json(path: str):
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
    FIX: Index by ALL CVE aliases + ghsa_id, not just primary cve_id.

    Root cause of 149/3000 bug: raw_github.json stores advisories with:
      - ghsa_id:     always present (e.g. GHSA-xxxx-yyyy-zzzz)
      - cve_id:      primary CVE if one is known (empty string for ~95%)
      - all_cve_ids: list of ALL CVE aliases from the identifiers array

    Old code only looked up by cve_id → missed any advisory where
    cve_id was empty or the NVD CVE matched an alias, not the primary.

    This fix indexes every advisory by:
      1. Every CVE ID in all_cve_ids
      2. The primary cve_id (if set and not already covered)
      3. The ghsa_id itself (for Pass 3 GHSA-only records)
    """
    raw    = load_json(github_path)
    lookup = {}

    for item in raw:
        # All CVE aliases (the fix — covers multi-CVE advisories)
        all_cves = item.get("all_cve_ids", [])

        # Fallback for older format without all_cve_ids field
        if not all_cves and item.get("cve_id"):
            all_cves = [item["cve_id"]]

        for cve_id in all_cves:
            if cve_id:
                cve_id_upper = cve_id.upper()
                # Don't overwrite a richer record with a sparse one
                if cve_id_upper not in lookup or not lookup[cve_id_upper].get("description"):
                    lookup[cve_id_upper] = item

        # Also index by GHSA ID for Pass 3
        ghsa_id = item.get("ghsa_id", "")
        if ghsa_id and ghsa_id not in lookup:
            lookup[ghsa_id] = item

    return lookup


def build_blog_lookup(blog_path: str) -> dict:
    raw    = load_json(blog_path)
    lookup: dict = {}
    for item in raw:
        content = item.get("content", "")[:3000]
        source  = f"Source: {item.get('url', 'Unknown Blog')}\n\n{content}"
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + source
    return lookup


def build_papers_lookup(papers_path: str) -> dict:
    raw    = load_json(papers_path)
    lookup: dict = {}
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
    lookup: dict = {}
    for item in raw:
        source_type = item.get("source", "unknown")
        title   = item.get("title", "")
        content = item.get("content", item.get("summary", item.get("body", item.get("description", ""))))[:1500]
        headers = {
            "full_disclosure": f"Full Disclosure Mailing List:\n{content}",
            "bugtraq":         f"OSS-Security / SecurityFocus:\n{content}",
            "hackerone":       f"HackerOne Report: {title}\nSeverity: {item.get('severity', 'N/A')}\n{content}",
            "microsoft_msrc":  f"Microsoft Security Advisory: {title}\n{content}",
            "reddit_netsec":   f"Reddit /r/netsec: {title}\nScore: {item.get('score', 0)}\n{content}",
            "vulners":         f"Vulners Intelligence: {title}\n{content}",
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
    lookup: dict = {}
    for item in raw:
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup.setdefault(cve, []).append(item)
    return lookup


def build_correlations_lookup(corr_path: str) -> dict:
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
    p = Path(vendor_path)
    if not p.exists():
        return {}
    try:
        raw    = json.loads(p.read_text(encoding="utf-8"))
        lookup: dict = defaultdict(list)
        for item in raw:
            for cve in item.get("cves_mentioned", []):
                lookup[cve.upper()].append(item)
        return dict(lookup)
    except Exception as e:
        print(f"  ⚠️  Vendor advisories load failed: {e}")
        return {}


def load_cooccurrence_pairs(cooccur_path: str) -> list:
    p = Path(cooccur_path)
    if not p.exists():
        return []
    try:
        data  = json.loads(p.read_text(encoding="utf-8"))
        pairs = data.get("training_pairs", [])
        print(f"  Co-occurrence pairs:   {len(pairs)}")
        return pairs
    except Exception as e:
        print(f"  ⚠️  Co-occurrence pairs load failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════
#  RECORD ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════

def enrich_with_correlations(record: dict, corr_lookup: dict) -> dict:
    cve_id = record.get("cve_id", "")
    corr   = corr_lookup.get(cve_id, {})
    if corr:
        record["related_vulnerabilities"] = corr.get("related_vulnerabilities", [])
        record["attack_techniques"]       = corr.get("attack_techniques", [])
        record["capec_patterns"]          = corr.get("capec_patterns", [])
        record["correlation_signals"]     = corr.get("correlation_signal_count", 0)
    return record


def enrich_with_vendor_advisories(record: dict, vendor_lookup: dict) -> dict:
    cve_id     = record.get("cve_id", "")
    advisories = vendor_lookup.get(cve_id, [])
    if not advisories:
        return record

    parts            = []
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
            pkg       = adv.get("package", "")
            fixed     = adv.get("releases_fixed", {})
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
        existing     = record.get("real_world_exploit", "")
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

    confirmed_exploited = bool(kev_entry)
    kev_ransomware      = kev_entry.get("known_ransomware_campaign_use", "")

    exploit_count  = len(exploits)
    exploit_titles = [e.get("title", "") for e in exploits[:3]]
    exploit_types  = list(set(e.get("type", "") for e in exploits if e.get("type")))

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

    sources = ["NVD"]
    if epss_score:              sources.append("EPSS")
    if gh_advisory:             sources.append("GitHub Advisories")
    if blog_map.get(cve_id):    sources.append("Security Blogs")
    if papers_map.get(cve_id):  sources.append("Research Papers")
    if closed_map.get(cve_id):  sources.append("Closed Sources")
    if kev_entry:               sources.append("CISA KEV")
    if exploits:                sources.append("Exploit-DB")

    return {
        "cve_id":              cve_id,
        "vulnerability_name":  nvd_rec.get("vulnerability_name", cve_id),
        "cwe_id":              cwe_id,
        "description":         desc,
        "owasp_category":      owasp_cat,
        "cvss_score":          cvss,
        "cvss_severity":       sev,
        "epss_score":          epss_score,
        "affected_software":   nvd_rec.get("affected_software", [])[:10],
        "published":           nvd_rec.get("published", ""),
        "attack_method":       pentest.get("attack_method", "Manual testing required"),
        "payload_example":     pentest.get("payload_example", ""),
        "detection_signals":   pentest.get("detection_signals", []),
        "tool_used":           pentest.get("tool_used", "Burp Suite, OWASP ZAP"),
        "code_pattern":        pentest.get("code_pattern", ""),
        "real_world_exploit":  real_world_exploit,
        "risk_level":          risk_level(cvss),
        "business_impact":     business_impact(owasp_cat),
        "confirmed_exploited": confirmed_exploited,
        "kev_ransomware":      kev_ransomware,
        "exploit_count":       exploit_count,
        "exploit_types":       exploit_types,
        "tool_recommendation": pentest.get("tool_used", ""),
        "vulnerability_research": (
            f"Identified via CVE database. CVSS: {cvss}. {desc[:120]}..."
        ),
        "security_control_missing": infer_security_control_missing(owasp_cat, cwe_id),
        "fix_recommendation":  fix_rec,
        "status":              "Open",
        "related_vulnerabilities": [],
        "attack_techniques":       [],
        "capec_patterns":          [],
        "correlation_signals":     0,
        "source": " + ".join(sources),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  TRAINING PAIR GENERATORS
# ═══════════════════════════════════════════════════════════════════════════

def to_training_pairs(record: dict) -> list:
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
    exploit_ctx         = record.get("real_world_exploit", "")
    kev_ransomware      = record.get("kev_ransomware", "")
    confirmed_exploited = record.get("confirmed_exploited", False)

    pairs = []

    # L1: Vulnerability Intelligence — include reasoning, not just field dump
    if desc:
        owasp_short = owasp.split("-", 1)[-1].strip() if "-" in owasp else owasp
        cwe_context = f" ({cwe})" if cwe else ""
        pairs.append({
            "instruction": f"Explain the vulnerability {cve} and map it to its OWASP category.",
            "input":       "",
            "output":      (
                f"{desc}\n\n"
                f"OWASP Category: {owasp}\n"
                f"CWE: {cwe}\n\n"
                f"This vulnerability falls under {owasp_short}{cwe_context} because it involves "
                f"{ctrl.lower().split(';')[0] if ctrl else 'a failure in the relevant security control'}. "
                f"The business impact includes: {biz}."
            ),
            "layer": "vulnerability_intelligence",
            "agent": "OWASP Mapper Agent",
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
            "layer": "pentesting_intelligence",
            "agent": "Tool Selector Agent",
        })

    # L2b: Real-world context
    if exploit_ctx:
        pairs.append({
            "instruction": f"Provide real-world exploit examples and research findings for {cve}.",
            "input":       desc,
            "output":      f"Real-world context for {cve}:\n\n{exploit_ctx[:3000]}",
            "layer": "pentesting_intelligence",
            "agent": "Scanner Agent",
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
            "layer": "risk_scoring",
            "agent": "Base Scorer Agent",
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
            "layer": "execution_context",
            "agent": "Tool Selector Agent",
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
            "layer": "audit_evidence",
            "agent": "Reporting Agent",
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
            "layer": "remediation_learning",
            "agent": "Reflector Agent",
        })

    return pairs


def to_correlation_training_pairs(record: dict) -> list:
    cve_id = record.get("cve_id", "")
    desc   = record.get("description", "")
    pairs  = []

    related = record.get("related_vulnerabilities", [])
    if related:
        rel_lines = "\n".join(f"  • {r['cve_id']}: {r.get('relationship','co-occurring')}" for r in related[:5])
        pairs.append({
            "instruction": f"What vulnerabilities are related to or often co-occur with {cve_id}?",
            "input":       desc,
            "output":      (
                f"Vulnerabilities correlated with {cve_id}:\n\n"
                + rel_lines
                + "\n\nThese correlations are based on shared affected products, CVSSv3 patterns, and exploitation campaign data."
            ),
            "layer": "vulnerability_correlation",
            "agent": "Correlation Agent",
        })

    techniques = record.get("attack_techniques", [])
    if techniques:
        pairs.append({
            "instruction": f"Which MITRE ATT&CK techniques are associated with {cve_id}?",
            "input":       desc,
            "output":      (
                f"ATT&CK techniques linked to {cve_id}:\n\n"
                + "\n".join(f"  • {t}" for t in techniques[:8])
                + "\n\nThese mappings help correlate CVE exploitation patterns with adversary TTPs."
            ),
            "layer": "vulnerability_correlation",
            "agent": "Correlation Agent",
        })

    capec = record.get("capec_patterns", [])
    if capec:
        chain = [c for c in capec if c.startswith("CVE-")]
        if chain:
            pairs.append({
                "instruction": f"Identify CVEs that form exploit chains with {cve_id}.",
                "input":       desc,
                "output":      (
                    f"Exploit chain analysis for {cve_id}:\n\n"
                    "CVEs that co-appear in exploit code or PoC repositories:\n"
                    + "\n".join(f"  • {c}" for c in chain[:5])
                    + "\n\nCo-occurrence in exploit code suggests multi-stage attack patterns."
                ),
                "layer": "vulnerability_correlation",
                "agent": "Correlation Agent",
            })

    return pairs


# ═══════════════════════════════════════════════════════════════════════════
#  TRAINING PAIR QUALITY FILTERS  (NEW)
# ═══════════════════════════════════════════════════════════════════════════

def filter_training_pairs(pairs: list) -> list:
    """
    Drop training pairs with trivially short or useless outputs.
    Threshold: 80 chars minimum. Anything shorter is a template failure
    (e.g. all fields empty → output is just field labels with no values).
    """
    filtered = []
    dropped  = 0
    for p in pairs:
        output = p.get("output", "")
        instr  = p.get("instruction", "")

        # Drop if output is too short
        if len(output.strip()) < 80:
            dropped += 1
            continue

        # Drop if output is identical to instruction (copy failure)
        if instr and output.strip() == instr.strip():
            dropped += 1
            continue

        # Drop if output is just "N/A" repeated
        if re.fullmatch(r"[\s\nNA/.:-]*", output):
            dropped += 1
            continue

        filtered.append(p)

    if dropped:
        print(f"  Quality filter: dropped {dropped} low-quality pairs ({len(filtered)} remain)")
    return filtered


def dedup_training_pairs(pairs: list) -> list:
    """
    Remove duplicate training pairs.
    Two pairs are considered duplicates if they share the same
    (instruction, first 200 chars of output) — catches template-generated
    duplicates where different CVEs produce identical outputs.
    """
    seen   = set()
    unique = []
    dupes  = 0

    for p in pairs:
        key = (
            p.get("instruction", "").strip()[:150],
            p.get("output", "").strip()[:200],
        )
        if key not in seen:
            seen.add(key)
            unique.append(p)
        else:
            dupes += 1

    if dupes:
        print(f"  Dedup: removed {dupes} duplicate pairs ({len(unique)} remain)")
    return unique


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
    print(f"  GitHub entries:        {len(github_map)}")   # should now be ~3000+ not 149
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

    # ── Pass 1: NVD records (main loop) ────────────────────────────────────
    for nvd_rec in nvd_records:
        cve_id = nvd_rec.get("cve_id", "")
        desc   = nvd_rec.get("description", "")
        if not desc or len(desc) < 50:
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        record = build_record(nvd_rec, epss_map, github_map, blog_map,
                              papers_map, closed_map, kev_map, exploitdb_map)
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))

    # ── Pass 2: CISA KEV entries not in NVD batch ──────────────────────────
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

        record = build_record(minimal_nvd_rec, epss_map, github_map, blog_map,
                              papers_map, closed_map, kev_map, exploitdb_map)
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))
        kev_only_count += 1

    print(f"  KEV-only records added (not in NVD batch): {kev_only_count}")

    # ── Pass 3: GHSA-only GitHub advisories (no CVE ID) ────────────────────
    raw_github      = load_json("data/raw_github.json")
    ghsa_only_count = 0

    for adv in raw_github:
        ghsa_id  = adv.get("ghsa_id", "")
        cve_ids  = adv.get("all_cve_ids", []) or ([adv["cve_id"]] if adv.get("cve_id") else [])

        if any(c in seen_cves for c in cve_ids) or ghsa_id in seen_cves:
            continue
        if cve_ids:
            continue   # has CVE IDs → already processed in Pass 1 or 2
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

        record = build_record(minimal_nvd_rec, epss_map, github_map, blog_map,
                              papers_map, closed_map, kev_map, exploitdb_map)
        record = enrich_with_correlations(record, corr_lookup)
        record = enrich_with_vendor_advisories(record, vendor_lookup)

        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        training_pairs.extend(to_correlation_training_pairs(record))
        ghsa_only_count += 1

    print(f"  GHSA-only records added (no CVE ID):       {ghsa_only_count}")

    # ── Load co-occurrence pairs ────────────────────────────────────────────
    cooccurrence_pairs = load_cooccurrence_pairs("data/raw_cooccurrence.json")
    training_pairs.extend(cooccurrence_pairs)

    # ── Quality filter + dedup (NEW) ───────────────────────────────────────
    print(f"\nRaw training pairs before filtering: {len(training_pairs)}")
    training_pairs = filter_training_pairs(training_pairs)
    training_pairs = dedup_training_pairs(training_pairs)
    print(f"Final training pairs after filtering: {len(training_pairs)}")

    # ── Save outputs ────────────────────────────────────────────────────────
    with open("data/vuln_dataset.jsonl", "w", encoding="utf-8") as f:
        for r in full_records:
            f.write(json.dumps(r) + "\n")

    with open("data/training_pairs.jsonl", "w", encoding="utf-8") as f:
        for p in training_pairs:
            f.write(json.dumps(p) + "\n")

    # ── Stats ───────────────────────────────────────────────────────────────
    layer_counts: dict = {}
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
    print(f"  GitHub advisories matched:      {github_matched}")
    print(f"  CISA KEV (confirmed exploited): {kev_count}")
    print(f"  Records with Exploit-DB data:   {exploit_recs}")
    print(f"  Records with research papers:   {paper_recs}")
    print(f"  Records with closed sources:    {closed_recs}")
    print(f"  Records with correlations:      {corr_recs}")
    print(f"  Records with vendor advisories: {vendor_recs}")
    print(f"  Co-occurrence pairs added:      {len(cooccurrence_pairs)}")


if __name__ == "__main__":
    run()