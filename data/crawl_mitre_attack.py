"""
crawl_mitre_attack.py
---------------------
Downloads MITRE ATT&CK (Enterprise) STIX bundles and CAPEC attack patterns.
These are NOT indexed by typical security aggregators and provide the richest
cross-CVE correlation signals available for free.

Data sources (all authoritative MITRE feeds):
  - MITRE ATT&CK Enterprise STIX 2.1 bundle (GitHub: mitre-attack/attack-stix-data)
  - MITRE CAPEC XML (capec.mitre.org) → attack pattern → CWE relationships
  - NVD CVE → CWE mappings (already in raw_nvd.json, reused here for chain building)

Output: data/raw_mitre_attack.json
Schema per record:
  {
    "technique_id":   "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "tactic":         "Initial Access",
    "description":    "...",
    "cve_references": ["CVE-2021-44228", ...],   # CVEs explicitly named in ATT&CK
    "capec_ids":      ["CAPEC-1", ...],
    "cwe_ids":        ["CWE-78", ...],
    "platforms":      ["Windows", "Linux", ...],
    "data_sources":   [...],
    "mitigations":    [...],
    "source":         "mitre_attack"
  }

CAPEC records:
  {
    "capec_id":       "CAPEC-66",
    "name":           "SQL Injection",
    "description":    "...",
    "cwe_ids":        ["CWE-89"],
    "related_capec":  ["CAPEC-7"],
    "severity":       "High",
    "likelihood":     "Medium",
    "source":         "capec"
  }
"""

import requests
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# ── MITRE ATT&CK STIX bundle (raw GitHub — authoritative, always up to date) ──
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# ── MITRE CAPEC XML ────────────────────────────────────────────────────────────
CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

# ── MITRE ATT&CK CVE references (supplementary list maintained by community) ──
ATTACK_CVE_MAPPING_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/main/data/attack-to-cve.json"
)


# ── ATT&CK STIX Parser ─────────────────────────────────────────────────────────

def fetch_attack_stix() -> list[dict]:
    """
    Download and parse the full MITRE ATT&CK Enterprise STIX 2.1 bundle.
    Extracts techniques with their CVE references, CAPEC mappings, tactics,
    mitigations, and platform coverage.
    """
    print("Fetching MITRE ATT&CK Enterprise STIX bundle...")
    try:
        resp = requests.get(ATTACK_STIX_URL, timeout=120)
        resp.raise_for_status()
        bundle = resp.json()
    except Exception as e:
        print(f"  ⚠️  ATT&CK STIX fetch failed: {e}")
        return []

    objects = bundle.get("objects", [])
    print(f"  STIX bundle loaded: {len(objects)} objects")

    # Index mitigations and relationships for fast lookup
    mitigations_by_id: dict[str, str] = {}
    relationships: list[dict]          = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type == "course-of-action":
            mitigations_by_id[obj["id"]] = obj.get("name", "")
        elif obj_type == "relationship":
            relationships.append(obj)

    # Build technique → mitigations map
    technique_mitigations: dict[str, list[str]] = {}
    for rel in relationships:
        if rel.get("relationship_type") == "mitigates":
            tgt = rel.get("target_ref", "")
            src = rel.get("source_ref", "")
            if src in mitigations_by_id:
                technique_mitigations.setdefault(tgt, []).append(
                    mitigations_by_id[src]
                )

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        # Extract technique ID (e.g. T1190)
        ext_refs  = obj.get("external_references", [])
        tech_id   = ""
        cve_refs  = []
        capec_ids = []

        for ref in ext_refs:
            src_name = ref.get("source_name", "")
            if src_name == "mitre-attack":
                tech_id = ref.get("external_id", "")
            elif src_name == "cve":
                cve_refs.append(ref.get("external_id", ""))
            elif src_name == "capec":
                capec_ids.append(ref.get("external_id", ""))

            # Also mine CVE IDs from URL and description
            url = ref.get("url", "")
            cve_matches = re.findall(r"CVE-\d{4}-\d+", url, re.IGNORECASE)
            cve_refs.extend(cve_matches)

        # Mine description for CVE IDs
        description = obj.get("description", "")
        desc_cves = re.findall(r"CVE-\d{4}-\d+", description, re.IGNORECASE)
        cve_refs.extend(desc_cves)
        cve_refs = list(set(c.upper() for c in cve_refs if c))

        # Extract kill-chain tactics
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # Extract CWE IDs from description
        cwe_ids = list(set(re.findall(r"CWE-\d+", description, re.IGNORECASE)))

        techniques.append({
            "technique_id":   tech_id,
            "technique_name": obj.get("name", ""),
            "tactic":         ", ".join(tactics),
            "description":    description[:2000],
            "cve_references": cve_refs,
            "capec_ids":      capec_ids,
            "cwe_ids":        cwe_ids,
            "platforms":      obj.get("x_mitre_platforms", []),
            "data_sources":   obj.get("x_mitre_data_sources", []),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "mitigations":    technique_mitigations.get(obj["id"], []),
            "stix_id":        obj.get("id", ""),
            "source":         "mitre_attack",
        })

    print(f"  ✅ ATT&CK: {len(techniques)} techniques parsed")
    cve_linked = sum(1 for t in techniques if t["cve_references"])
    print(f"     {cve_linked} techniques have direct CVE references")
    return techniques


# ── Community ATT&CK → CVE Mapping ────────────────────────────────────────────

def fetch_attack_cve_mapping() -> dict[str, list[str]]:
    """
    Fetch the Center for Threat-Informed Defense's ATT&CK → CVE mapping.
    Maps technique IDs to lists of CVEs that exploit them.
    Returns {technique_id: [CVE-XXXX-YYYY, ...]}
    """
    print("  Fetching ATT&CK → CVE community mapping...")
    try:
        resp = requests.get(ATTACK_CVE_MAPPING_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        mapping: dict[str, list[str]] = {}
        for entry in data if isinstance(data, list) else data.get("mapping", []):
            tid  = entry.get("technique_id", entry.get("attack_id", ""))
            cves = entry.get("cve_ids", entry.get("cves", []))
            if tid and cves:
                mapping.setdefault(tid, []).extend(cves)

        print(f"     {len(mapping)} technique→CVE mappings loaded")
        return mapping
    except Exception as e:
        print(f"     ⚠️  Community mapping failed: {e}")
        return {}


# ── CAPEC XML Parser ───────────────────────────────────────────────────────────

def fetch_capec() -> list[dict]:
    """
    Download and parse MITRE CAPEC XML.
    CAPEC (Common Attack Pattern Enumeration and Classification) provides
    a structured taxonomy of attack patterns with CWE relationships —
    critical for building vulnerability correlation chains.
    """
    print("Fetching MITRE CAPEC XML...")
    try:
        resp = requests.get(CAPEC_XML_URL, timeout=120)
        resp.raise_for_status()
    except Exception as e:
        print(f"  ⚠️  CAPEC fetch failed: {e}")
        return []

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as e:
        print(f"  ⚠️  CAPEC XML parse error: {e}")
        return []

    # CAPEC XML namespace
    ns = {
        "capec": "http://capec.mitre.org/capec-3",
        "Attack_Pattern_Catalog": "http://capec.mitre.org/capec-3",
    }

    # Try to find namespace from actual root tag
    root_tag = root.tag
    if "{" in root_tag:
        ns_uri = root_tag.split("}")[0].lstrip("{")
        ns = {"capec": ns_uri}

    patterns = []
    # Walk all Attack_Pattern elements
    for elem in root.iter():
        if not elem.tag.endswith("Attack_Pattern"):
            continue

        capec_id   = elem.get("ID", "")
        name       = elem.get("Name", "")
        status     = elem.get("Status", "")
        if status in ("Deprecated", "Obsolete"):
            continue
        if not capec_id:
            continue

        # Description
        desc_elem  = elem.find(".//{*}Description")
        description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

        # Severity / Likelihood
        severity   = elem.get("Typical_Severity", "")
        likelihood = elem.get("Typical_Likelihood", "Unknown")
        if not severity:
            sev_elem = elem.find(".//{*}Typical_Severity")
            severity = sev_elem.text.strip() if sev_elem is not None and sev_elem.text else "Unknown"

        # Related CWEs
        cwe_ids = []
        for cwe_elem in elem.findall(".//{*}Related_Weakness"):
            cwe_id_val = cwe_elem.get("CWE_ID", "")
            if cwe_id_val:
                cwe_ids.append(f"CWE-{cwe_id_val}")

        # Related CAPEC patterns
        related_capec = []
        for rel_elem in elem.findall(".//{*}Related_Attack_Pattern"):
            rel_id = rel_elem.get("CAPEC_ID", "")
            if rel_id:
                related_capec.append(f"CAPEC-{rel_id}")

        # Prerequisites / Mitigations / Examples
        prerequisites = [
            e.text.strip() for e in elem.findall(".//{*}Prerequisite")
            if e.text
        ][:3]

        mitigations = [
            e.text.strip()[:200] for e in elem.findall(".//{*}Mitigation")
            if e.text
        ][:3]

        patterns.append({
            "capec_id":      f"CAPEC-{capec_id}",
            "name":          name,
            "description":   description[:1500],
            "cwe_ids":       list(set(cwe_ids)),
            "related_capec": related_capec[:10],
            "severity":      severity,
            "likelihood":    likelihood,
            "prerequisites": prerequisites,
            "mitigations":   mitigations,
            "source":        "capec",
        })

    print(f"  ✅ CAPEC: {len(patterns)} attack patterns parsed")
    cwe_linked = sum(1 for p in patterns if p["cwe_ids"])
    print(f"     {cwe_linked} patterns have CWE mappings")
    return patterns


# ── Build correlation index ────────────────────────────────────────────────────

def build_cwe_to_capec(capec_records: list[dict]) -> dict[str, list[str]]:
    """Build CWE → [CAPEC IDs] lookup for correlation enrichment."""
    index: dict[str, list[str]] = {}
    for p in capec_records:
        for cwe in p["cwe_ids"]:
            index.setdefault(cwe, []).append(p["capec_id"])
    return index


def build_cve_to_techniques(
    techniques: list[dict],
    extra_mapping: dict[str, list[str]]
) -> dict[str, list[str]]:
    """
    Build CVE → [ATT&CK technique IDs] lookup.
    Merges both STIX-native CVE references and community mapping.
    """
    index: dict[str, list[str]] = {}

    # From STIX bundle
    for t in techniques:
        for cve in t["cve_references"]:
            index.setdefault(cve, []).append(t["technique_id"])

    # From community mapping (reversed: technique→CVE → CVE→technique)
    for tech_id, cves in extra_mapping.items():
        for cve in cves:
            index.setdefault(cve.upper(), []).append(tech_id)

    # Deduplicate
    return {cve: list(set(tids)) for cve, tids in index.items()}


# ── Main ───────────────────────────────────────────────────────────────────────

def run(out: str = "data/raw_mitre_attack.json"):
    all_records = []

    # 1. ATT&CK STIX
    techniques = fetch_attack_stix()
    all_records.extend(techniques)
    time.sleep(2)

    # 2. Community ATT&CK → CVE mapping (enrich technique records)
    extra_cve_map = fetch_attack_cve_mapping()
    for t in techniques:
        tid = t["technique_id"]
        if tid in extra_cve_map:
            merged = list(set(t["cve_references"] + extra_cve_map[tid]))
            t["cve_references"] = merged
    time.sleep(2)

    # 3. CAPEC
    capec_records = fetch_capec()
    all_records.extend(capec_records)

    # Build and attach lookup indices (stored as metadata)
    cwe_to_capec     = build_cwe_to_capec(capec_records)
    cve_to_techniques = build_cve_to_techniques(techniques, extra_cve_map)

    output = {
        "techniques":         techniques,
        "capec_patterns":     capec_records,
        "cwe_to_capec":       cwe_to_capec,
        "cve_to_techniques":  cve_to_techniques,
        "stats": {
            "technique_count":  len(techniques),
            "capec_count":      len(capec_records),
            "cve_linked_count": len(cve_to_techniques),
            "cwe_capec_pairs":  sum(len(v) for v in cwe_to_capec.values()),
        }
    }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n📊 MITRE ATT&CK Summary:")
    print(f"  Techniques:            {len(techniques)}")
    print(f"  CAPEC patterns:        {len(capec_records)}")
    print(f"  CVEs linked to ATT&CK: {len(cve_to_techniques)}")
    print(f"  CWE→CAPEC pairs:       {sum(len(v) for v in cwe_to_capec.values())}")
    print(f"\n✅ Saved MITRE ATT&CK + CAPEC data → {out}")


if __name__ == "__main__":
    run()