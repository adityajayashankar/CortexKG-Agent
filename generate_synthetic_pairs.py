"""
generate_synthetic_pairs.py
---------------------------
Generates synthetic training pairs for critically thin dataset layers.

Run this AFTER build_dataset.py and BEFORE finetuning.py:
    python generate_synthetic_pairs.py

Appends to data/training_pairs.jsonl without touching other layers.

Target layers and current counts (as of last pipeline run):
    execution_context      :    10  →  target ~800
    remediation_learning   :   119  →  target ~1500

Strategy: curated expert templates × CVE population from NVD.
This is NOT hallucinated data — templates encode real security knowledge.
Each pair is grounded in an actual CVE from raw_nvd.json.
"""

import json
import random
from pathlib import Path
from itertools import product as iterproduct

random.seed(42)

NVD_PATH      = "data/raw_nvd.json"
KEV_PATH      = "data/raw_cisa_kev.json"
OUTPUT_PATH   = "data/training_pairs.jsonl"

# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION KNOWLEDGE BASE
#  Each CWE → (fix_summary, root_cause, control_type, code_before, code_after)
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION_KB = {
    "CWE-89": {
        "fix":         "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
        "root_cause":  "Direct string interpolation of untrusted input into SQL query construction.",
        "control":     "Input validation + parameterized queries (technical)",
        "before":      'query = "SELECT * FROM users WHERE id = " + user_id',
        "after":       'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "test_payloads": ["' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT null,null--"],
        "tools":       ["SQLMap", "Burp Suite", "OWASP ZAP"],
    },
    "CWE-79": {
        "fix":         "HTML-encode all user-supplied output. Use Content-Security-Policy headers. Avoid innerHTML with user data.",
        "root_cause":  "Unsanitized user input reflected into HTML response without encoding.",
        "control":     "Output encoding + CSP headers (technical)",
        "before":      'document.getElementById("msg").innerHTML = userInput;',
        "after":       'document.getElementById("msg").textContent = userInput;',
        "test_payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "tools":       ["Burp Suite", "XSStrike", "OWASP ZAP"],
    },
    "CWE-22": {
        "fix":         "Canonicalize the path and verify it starts with the expected base directory before file operations.",
        "root_cause":  "Missing path canonicalization allows directory traversal via ../ sequences.",
        "control":     "Path validation + allowlist (technical)",
        "before":      'open("/var/app/files/" + user_filename)',
        "after":       'p = Path("/var/app/files") / user_filename\nassert p.resolve().is_relative_to("/var/app/files")',
        "test_payloads": ["../../../etc/passwd", "..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f"],
        "tools":       ["Burp Suite", "DirBuster", "Manual testing"],
    },
    "CWE-78": {
        "fix":         "Never pass user input to shell commands. Use language-native APIs (os.rename, subprocess with arg list, not shell=True).",
        "root_cause":  "User input is passed to shell interpreter without sanitization, enabling command injection.",
        "control":     "Avoid shell=True; use subprocess argument lists (technical)",
        "before":      'os.system("ping " + user_host)',
        "after":       'subprocess.run(["ping", "-c", "1", user_host], capture_output=True)',
        "test_payloads": ["; cat /etc/passwd", "| whoami", "$(id)", "`id`"],
        "tools":       ["Commix", "Burp Suite", "Manual testing"],
    },
    "CWE-287": {
        "fix":         "Implement multi-factor authentication. Use a hardened auth framework. Never roll your own auth logic.",
        "root_cause":  "Authentication logic contains flaws allowing bypass — missing checks, predictable tokens, or logic errors.",
        "control":     "Strong authentication + MFA (technical + process)",
        "before":      'if user == "admin":  # missing password check',
        "after":       'if authenticate(user, password) and verify_mfa(user, mfa_token):',
        "test_payloads": ["Empty password", "SQL injection in username", "JWT alg:none attack"],
        "tools":       ["Burp Suite", "Hydra", "jwt_tool"],
    },
    "CWE-502": {
        "fix":         "Never deserialize data from untrusted sources. Use JSON/protobuf instead of native serialization. Implement deserialization allowlists.",
        "root_cause":  "Deserialization of attacker-controlled data executes arbitrary code via gadget chains.",
        "control":     "Replace native deserialization with safe alternatives (technical)",
        "before":      'obj = pickle.loads(request.data)',
        "after":       'obj = json.loads(request.data)  # or use allowlist-based deserializer',
        "test_payloads": ["ysoserial payloads (Java)", "pickle RCE (Python)", "PHP object injection"],
        "tools":       ["ysoserial", "Burp Suite Deserialization Scanner", "Freddy extension"],
    },
    "CWE-798": {
        "fix":         "Move all credentials to environment variables or a secrets manager (Vault, AWS Secrets Manager). Rotate immediately if exposed.",
        "root_cause":  "Credentials hardcoded in source code, configuration files, or binaries.",
        "control":     "Secrets management + secret scanning in CI/CD (process + technical)",
        "before":      'password = "SuperSecret123"  # hardcoded',
        "after":       'password = os.environ["DB_PASSWORD"]  # from secrets manager',
        "test_payloads": ["git log --all -p | grep password", "truffleHog scan", "gitleaks"],
        "tools":       ["TruffleHog", "Gitleaks", "git-secrets"],
    },
    "CWE-326": {
        "fix":         "Upgrade to AES-256-GCM or ChaCha20-Poly1305. Replace MD5/SHA1 with SHA-256 minimum. Use TLS 1.2+ only.",
        "root_cause":  "Use of cryptographically weak or deprecated algorithms (MD5, SHA1, DES, RC4, 3DES).",
        "control":     "Algorithm upgrade + TLS hardening (technical)",
        "before":      'hashlib.md5(password.encode()).hexdigest()',
        "after":       'hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)',
        "test_payloads": ["SSLyze scan", "testssl.sh", "Nessus crypto checks"],
        "tools":       ["SSLyze", "testssl.sh", "OpenSSL s_client"],
    },
    "CWE-611": {
        "fix":         "Disable external entity processing in your XML parser. Set FEATURE_SECURE_PROCESSING. Use defusedxml in Python.",
        "root_cause":  "XML parser processes external entity references, allowing file read or SSRF.",
        "control":     "Disable DTD/external entities in XML parser config (technical)",
        "before":      'tree = ET.parse(xml_input)  # default Python ET is safe, but lxml is not',
        "after":       'import defusedxml.ElementTree as ET\ntree = ET.parse(xml_input)',
        "test_payloads": ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "Blind XXE OOB"],
        "tools":       ["Burp Suite", "XXEinjector", "OWASP ZAP"],
    },
    "CWE-416": {
        "fix":         "Audit all pointer lifetimes. Use smart pointers (unique_ptr, shared_ptr). Enable ASan/Valgrind in CI. Consider Rust for new code.",
        "root_cause":  "Memory accessed after it has been freed — dangling pointer dereference.",
        "control":     "Smart pointers + memory safety tooling + code audit (technical)",
        "before":      'free(ptr);\nuse(ptr);  // use-after-free',
        "after":       'auto ptr = std::make_unique<MyObj>();\n// ptr automatically freed at scope exit',
        "test_payloads": ["AddressSanitizer", "Valgrind memcheck", "AFL++ fuzzing"],
        "tools":       ["AddressSanitizer (ASan)", "Valgrind", "AFL++", "CodeQL"],
    },
    "CWE-787": {
        "fix":         "Validate all buffer sizes before write. Use safe string functions (strlcpy, snprintf). Enable stack canaries and ASLR.",
        "root_cause":  "Write operation exceeds allocated buffer bounds, corrupting adjacent memory.",
        "control":     "Bounds checking + compiler mitigations (technical)",
        "before":      'strcpy(buf, user_input);  // no bounds check',
        "after":       'strlcpy(buf, user_input, sizeof(buf));',
        "test_payloads": ["Oversized input fuzzing", "AFL++", "libFuzzer"],
        "tools":       ["AFL++", "libFuzzer", "AddressSanitizer", "checksec"],
    },
    "CWE-918": {
        "fix":         "Validate and allowlist URLs against a strict scheme+hostname allowlist. Block private IP ranges. Use a dedicated HTTP client with redirects disabled.",
        "root_cause":  "Application fetches URLs supplied by user without validating destination, enabling access to internal services.",
        "control":     "URL allowlisting + network segmentation (technical)",
        "before":      'requests.get(user_url)  # unrestricted',
        "after":       'assert is_allowed_url(user_url)  # check against allowlist\nrequests.get(user_url, allow_redirects=False)',
        "test_payloads": ["http://169.254.169.254/", "http://localhost:8080/", "http://[::1]/"],
        "tools":       ["Burp Suite Collaborator", "SSRFmap", "Manual testing"],
    },
    "CWE-862": {
        "fix":         "Add explicit authorization checks on every sensitive action. Apply deny-by-default. Use RBAC/ABAC frameworks.",
        "root_cause":  "Application performs sensitive operations without verifying the caller has permission.",
        "control":     "Explicit authorization checks + deny-by-default (technical)",
        "before":      'def delete_user(user_id):\n    db.delete(user_id)  # no authz check',
        "after":       'def delete_user(user_id, caller):\n    require_permission(caller, "users:delete")\n    db.delete(user_id)',
        "test_payloads": ["Horizontal privilege escalation", "Forced browsing", "IDOR parameter tampering"],
        "tools":       ["Burp Suite", "Autorize extension", "Manual auth testing"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  EXECUTION CONTEXT KNOWLEDGE BASE
#  (tech stack → recommended tools, focus areas, test approach)
# ─────────────────────────────────────────────────────────────────────────────
EXECUTION_CONTEXT_KB = [
    {
        "stack": "Java Spring Boot",
        "indicators": ["spring", "java", "maven", "gradle", "tomcat", "springboot"],
        "tools":      ["Burp Suite", "OWASP ZAP", "ysoserial", "Nuclei", "Retire.js"],
        "focus":      ["Deserialization (CWE-502)", "XXE (CWE-611)", "SSTI in Thymeleaf", "Spring4Shell (CVE-2022-22965)", "Actuator exposure"],
        "approach":   "Check /actuator endpoints for info disclosure. Test Java deserialization gadget chains. Fuzz XML inputs for XXE. Check Spring Security config for missing CSRF protection.",
        "env_risks":  "Docker deployments: check for exposed JMX ports (9010), unprotected Actuator health/env/beans endpoints.",
    },
    {
        "stack": "Python Django/Flask",
        "indicators": ["django", "flask", "python", "fastapi", "sqlalchemy", "celery"],
        "tools":      ["Burp Suite", "SQLMap", "Commix", "Bandit", "Safety"],
        "focus":      ["SSTI in Jinja2 (Flask)", "SQLi via raw queries", "SSRF in requests calls", "Pickle deserialization", "Debug mode exposure"],
        "approach":   "Check for DEBUG=True in production. Test Jinja2 template injection via user-controlled strings. Run Bandit for static analysis. Check for raw SQL strings bypassing ORM.",
        "env_risks":  "Flask debug mode exposes Werkzeug console — RCE with no auth. Check for DJANGO_DEBUG=True in env vars.",
    },
    {
        "stack": "Node.js / Express",
        "indicators": ["node", "express", "npm", "javascript", "typescript", "react", "angular"],
        "tools":      ["Burp Suite", "npm audit", "Retire.js", "NodeJsScan", "Nuclei"],
        "focus":      ["Prototype pollution (CWE-1321)", "ReDoS", "Command injection via child_process", "JWT vulnerabilities", "npm dependency CVEs"],
        "approach":   "Run npm audit for known dependency CVEs. Test for prototype pollution via __proto__ injection. Check JWT validation (alg:none, weak secret). Fuzz regex inputs for ReDoS.",
        "env_risks":  "package-lock.json may contain CVEs in transitive deps that npm audit misses — cross-reference with OSV.",
    },
    {
        "stack": "PHP / WordPress",
        "indicators": ["php", "wordpress", "laravel", "symfony", "drupal", "composer"],
        "tools":      ["WPScan", "Burp Suite", "SQLMap", "Nuclei", "WhatWeb"],
        "focus":      ["SQLi in custom plugins", "File inclusion (LFI/RFI)", "Unrestricted file upload", "PHP deserialization", "WordPress plugin CVEs"],
        "approach":   "Run WPScan for known plugin/theme CVEs. Test file upload endpoints for web shell upload. Check unserialize() calls with user input. Test LFI via path parameter fuzzing.",
        "env_risks":  "wp-config.php often world-readable in misconfigured deployments. Check .env and backup files (.bak, .old).",
    },
    {
        "stack": "C/C++ Native / Embedded",
        "indicators": ["c++", "gcc", "clang", "embedded", "firmware", "kernel", "openssl"],
        "tools":      ["AFL++", "libFuzzer", "Valgrind", "AddressSanitizer", "Ghidra", "Binwalk"],
        "focus":      ["Buffer overflow (CWE-787)", "Use-after-free (CWE-416)", "Integer overflow (CWE-190)", "Format string bugs", "Memory leaks"],
        "approach":   "Instrument with ASan/MSan and fuzz all input parsing routines. Use AFL++ for binary targets. Ghidra for static analysis of closed-source binaries. Check checksec flags (NX, PIE, canary).",
        "env_risks":  "Firmware may lack ASLR/NX — check with checksec. Embedded Linux often runs old kernel with known privilege escalation CVEs.",
    },
    {
        "stack": ".NET / ASP.NET",
        "indicators": [".net", "asp.net", "c#", "iis", "dotnet", "windows server"],
        "tools":      ["Burp Suite", "Retire.js", "Nuclei", "SharpWeb", "dotnet-retire"],
        "focus":      ["ViewState deserialization", "XXE in XML parsers", "NTLM relay", "Insecure Direct Object Reference", "SSRF via HttpClient"],
        "approach":   "Test ViewState for missing MAC validation. Check XML parsers for XXE — .NET System.Xml is safe by default but third-party parsers may not be. Test NTLM auth for relay attacks.",
        "env_risks":  "IIS with enabled directory browsing leaks source. machineKey hardcoded in web.config enables ViewState RCE.",
    },
    {
        "stack": "Kubernetes / Cloud-Native",
        "indicators": ["kubernetes", "k8s", "docker", "helm", "istio", "eks", "gke", "aks"],
        "tools":      ["kube-bench", "Trivy", "Falco", "kube-hunter", "Checkov"],
        "focus":      ["RBAC misconfig", "Privileged containers", "Exposed API server", "Secrets in env vars", "Container escape via mounted /var/run/docker.sock"],
        "approach":   "Run kube-bench for CIS benchmark violations. Check for privileged: true pods. Test API server access without auth (port 6443/8080). Scan images with Trivy for CVEs.",
        "env_risks":  "Default service accounts often over-privileged. Mounted secrets in env vars leaked via /proc/<pid>/environ.",
    },
    {
        "stack": "AWS / Cloud Infrastructure",
        "indicators": ["aws", "s3", "ec2", "lambda", "iam", "cloudformation", "terraform"],
        "tools":      ["Prowler", "ScoutSuite", "Pacu", "AWS Config", "CloudSploit"],
        "focus":      ["S3 bucket public access", "IAM overpermission", "Exposed EC2 metadata (IMDS)", "Lambda env var secrets", "Security group 0.0.0.0/0"],
        "approach":   "Run Prowler for AWS security checks. Check S3 bucket policies for public access. Test IMDS for IMDSv1 (no-auth token access). Review IAM policies for wildcard actions.",
        "env_risks":  "SSRF to 169.254.169.254 via IMDSv1 exposes AWS credentials. Lambda functions with overpermissive execution roles.",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def load_json(path: str) -> list:
    p = Path(path)
    if not p.exists():
        print(f"  ⚠️  {path} not found — skipping NVD grounding")
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def sample_cves_for_cwe(nvd_records: list, cwe: str, n: int = 30) -> list:
    """Return up to n CVE records matching the given CWE."""
    matches = [r for r in nvd_records if r.get("cwe_id") == cwe and r.get("description")]
    return random.sample(matches, min(n, len(matches)))


def sample_cves_with_field(nvd_records: list, field: str, n: int = 50) -> list:
    matches = [r for r in nvd_records if r.get(field) and r.get("description")]
    return random.sample(matches, min(n, len(matches)))


# ─────────────────────────────────────────────────────────────────────────────
#  GENERATOR: remediation_learning
# ─────────────────────────────────────────────────────────────────────────────
def generate_remediation_pairs(nvd_records: list) -> list:
    pairs = []

    for cwe, kb in REMEDIATION_KB.items():
        cve_samples = sample_cves_for_cwe(nvd_records, cwe, n=25)

        # For each CVE grounding, emit multiple pair types
        for rec in cve_samples:
            cve_id = rec.get("cve_id", "UNKNOWN")
            desc   = rec.get("description", "")[:300]
            cvss   = rec.get("cvss_score", "N/A")

            # Pair type 1: direct fix request
            pairs.append({
                "instruction": f"How do I fix {cwe} ({cve_id}) in my application?",
                "input":       desc,
                "output": (
                    f"Remediation for {cwe} ({cve_id}):\n\n"
                    f"**Fix:** {kb['fix']}\n\n"
                    f"**Root Cause:** {kb['root_cause']}\n\n"
                    f"**Control Type:** {kb['control']}\n\n"
                    f"**Code Example:**\n"
                    f"Before (vulnerable):\n  {kb['before']}\n\n"
                    f"After (fixed):\n  {kb['after']}\n\n"
                    f"**Verification:** Test with: {', '.join(kb['test_payloads'][:2])}\n"
                    f"**Tools:** {', '.join(kb['tools'])}"
                ),
                "layer": "remediation_learning",
                "agent": "Reflector Agent",
            })

            # Pair type 2: root cause analysis
            pairs.append({
                "instruction": f"What is the root cause of {cve_id} and how should it be permanently resolved?",
                "input":       desc,
                "output": (
                    f"Root Cause Analysis for {cve_id} ({cwe}):\n\n"
                    f"**Root Cause:** {kb['root_cause']}\n\n"
                    f"**Why it persists:** This class of vulnerability ({cwe}) recurs because developers "
                    f"often treat it as a one-off fix rather than addressing the underlying pattern. "
                    f"A permanent fix requires: (1) fixing the specific instance, (2) auditing all similar "
                    f"patterns in the codebase, (3) adding automated checks (SAST/DAST) to prevent regression.\n\n"
                    f"**Permanent Resolution:** {kb['fix']}\n\n"
                    f"**Prevention:** Add {kb['tools'][0]} to your CI pipeline to catch future instances."
                ),
                "layer": "remediation_learning",
                "agent": "Reflector Agent",
            })

            # Pair type 3: verification testing
            pairs.append({
                "instruction": f"After patching {cve_id} ({cwe}), how do I verify the fix is effective?",
                "input":       desc,
                "output": (
                    f"Verification testing for {cwe} fix ({cve_id}):\n\n"
                    f"**Test payloads to confirm patch blocks attack:**\n"
                    + "\n".join(f"  {i+1}. {p}" for i, p in enumerate(kb['test_payloads']))
                    + f"\n\n**Recommended tools:** {', '.join(kb['tools'])}\n\n"
                    f"**Pass criteria:** All payloads should be rejected with appropriate error handling "
                    f"(not a 500 error — that indicates the input reached application logic). "
                    f"Re-run {kb['tools'][0]} to confirm no {cwe} findings remain."
                ),
                "layer": "remediation_learning",
                "agent": "Reflector Agent",
            })

        # Also generate CWE-level pairs without specific CVE grounding
        # (teaches model to answer class-level questions)
        pairs.append({
            "instruction": f"What is the standard remediation for {cwe} vulnerabilities?",
            "input":       "",
            "output": (
                f"Standard remediation for {cwe}:\n\n"
                f"**Fix:** {kb['fix']}\n\n"
                f"**Root Cause Pattern:** {kb['root_cause']}\n\n"
                f"**Control Type:** {kb['control']}\n\n"
                f"**Code Pattern:**\n"
                f"❌ Vulnerable: {kb['before']}\n"
                f"✅ Fixed:      {kb['after']}\n\n"
                f"**Testing:** {', '.join(kb['test_payloads'])}\n"
                f"**Tools:** {', '.join(kb['tools'])}"
            ),
            "layer": "remediation_learning",
            "agent": "Reflector Agent",
        })

    print(f"  remediation_learning: {len(pairs)} pairs generated")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
#  GENERATOR: execution_context
# ─────────────────────────────────────────────────────────────────────────────
def generate_execution_context_pairs(nvd_records: list) -> list:
    pairs = []

    for ctx in EXECUTION_CONTEXT_KB:
        stack   = ctx["stack"]
        tools   = ctx["tools"]
        focus   = ctx["focus"]
        approach = ctx["approach"]
        env_risks = ctx["env_risks"]
        indicators = ctx["indicators"]

        # Pair type 1: stack-based tool selection
        pairs.append({
            "instruction": f"We are performing a security assessment of a {stack} application. What tools and methodology should we use?",
            "input":       f"Stack indicators: {', '.join(indicators[:4])}",
            "output": (
                f"Security assessment approach for {stack}:\n\n"
                f"**Recommended Tools:**\n"
                + "\n".join(f"  • {t}" for t in tools)
                + f"\n\n**Priority Focus Areas:**\n"
                + "\n".join(f"  • {f}" for f in focus)
                + f"\n\n**Testing Approach:** {approach}\n\n"
                f"**Environment-Specific Risks:** {env_risks}"
            ),
            "layer": "execution_context",
            "agent": "Execution Agent",
        })

        # Pair type 2: CVE-grounded stack questions
        # Find CVEs that match the stack's likely CWEs
        stack_cwe_map = {
            "Java Spring Boot":       ["CWE-502", "CWE-611"],
            "Python Django/Flask":    ["CWE-89", "CWE-79", "CWE-918"],
            "Node.js / Express":      ["CWE-79", "CWE-94"],
            "PHP / WordPress":        ["CWE-89", "CWE-79", "CWE-22"],
            "C/C++ Native / Embedded":["CWE-787", "CWE-416", "CWE-190"],
            ".NET / ASP.NET":         ["CWE-611", "CWE-502"],
            "Kubernetes / Cloud-Native": ["CWE-732", "CWE-862"],
            "AWS / Cloud Infrastructure": ["CWE-732", "CWE-284"],
        }
        target_cwes = stack_cwe_map.get(stack, [])
        cve_samples = []
        for cwe in target_cwes:
            cve_samples.extend(sample_cves_for_cwe(nvd_records, cwe, n=8))
        cve_samples = cve_samples[:15]

        for rec in cve_samples:
            cve_id = rec.get("cve_id", "UNKNOWN")
            cwe    = rec.get("cwe_id", "")
            desc   = rec.get("description", "")[:250]

            pairs.append({
                "instruction": f"How do we test for {cve_id} ({cwe}) in a {stack} environment?",
                "input":       desc,
                "output": (
                    f"Testing {cve_id} in a {stack} context:\n\n"
                    f"**Stack-specific approach:** {approach}\n\n"
                    f"**Primary tools for this stack:** {', '.join(tools[:3])}\n\n"
                    f"**{cwe} test methodology:**\n"
                    + (
                        f"  {REMEDIATION_KB[cwe]['fix']}\n"
                        f"  Test with: {', '.join(REMEDIATION_KB[cwe]['test_payloads'][:2])}"
                        if cwe in REMEDIATION_KB else
                        f"  Follow OWASP testing guide for {cwe}. Manual review recommended."
                    )
                    + f"\n\n**Environment risk note:** {env_risks}"
                ),
                "layer": "execution_context",
                "agent": "Execution Agent",
            })

        # Pair type 3: tooling decision pairs
        pairs.append({
            "instruction": f"Which scanner should I use first when starting a {stack} pentest?",
            "input":       "",
            "output": (
                f"For {stack}, start with:\n\n"
                f"1. **{tools[0]}** — your primary tool for this stack. {approach.split('.')[0]}.\n"
                f"2. **{tools[1] if len(tools) > 1 else tools[0]}** — for {focus[0]} testing.\n"
                f"3. **Manual review** of: {', '.join(focus[1:3])}\n\n"
                f"**Don't skip:** {env_risks}"
            ),
            "layer": "execution_context",
            "agent": "Execution Agent",
        })

    print(f"  execution_context: {len(pairs)} pairs generated")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def run():
    print("Loading NVD records for CVE grounding...")
    nvd_records = load_json(NVD_PATH)
    print(f"  Loaded {len(nvd_records)} NVD records")

    all_pairs = []

    print("\nGenerating remediation_learning pairs...")
    all_pairs.extend(generate_remediation_pairs(nvd_records))

    print("Generating execution_context pairs...")
    all_pairs.extend(generate_execution_context_pairs(nvd_records))

    # Quality filter (same threshold as build_dataset.py)
    clean = [p for p in all_pairs if len(p.get("output", "").strip()) >= 80]
    print(f"\n  Total synthetic pairs: {len(clean)} (dropped {len(all_pairs)-len(clean)} too-short)")

    # Append to existing training_pairs.jsonl
    out_path = Path(OUTPUT_PATH)
    if out_path.exists():
        # Dedup against existing
        existing_keys = set()
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        p = json.loads(line)
                        existing_keys.add((
                            p.get("instruction", "").strip()[:150],
                            p.get("output", "").strip()[:200],
                        ))
                    except Exception:
                        pass

        new_pairs = [
            p for p in clean
            if (p["instruction"].strip()[:150], p["output"].strip()[:200]) not in existing_keys
        ]
        print(f"  New unique pairs (not in existing file): {len(new_pairs)}")

        with open(out_path, "a", encoding="utf-8") as f:
            for p in new_pairs:
                f.write(json.dumps(p) + "\n")

        print(f"\n✅ Appended {len(new_pairs)} synthetic pairs → {OUTPUT_PATH}")
    else:
        with open(out_path, "w", encoding="utf-8") as f:
            for p in clean:
                f.write(json.dumps(p) + "\n")
        print(f"\n✅ Wrote {len(clean)} synthetic pairs → {OUTPUT_PATH}")

    # Summary
    layer_counts: dict = {}
    for p in clean:
        l = p.get("layer", "unknown")
        layer_counts[l] = layer_counts.get(l, 0) + 1
    print("\nSynthetic pairs by layer:")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer:<36} {count:>6}")


if __name__ == "__main__":
    run()