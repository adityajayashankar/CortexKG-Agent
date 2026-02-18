"""
crawl_vendor_advisories.py
--------------------------
Fetches security advisories directly from vendor sources.
These are NOT well-indexed by open aggregators and represent the
kind of "closed / semi-private" data Suresh sir is asking for.

Sources:
  - Cisco PSIRT openVuln API (free, requires client_id + client_secret)
  - Red Hat Security Data API (free, no auth) — FIXED: updated to hydra endpoint
  - Ubuntu Security Notices (USN) — FIXED: switched to RSS feed (JSON API broken)
  - Debian Security Tracker JSON (free, no auth)
  - PoC-in-GitHub exploit index

FIXES in this version:
  - Red Hat 404: labs/securitydataapi deprecated → hydra/rest/securitydata
  - Ubuntu 422: JSON notices API dropped 'order' param → use RSS feed instead

Output: data/raw_vendor_advisories.json
"""

import requests
import json
import re
import time
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

# ── Endpoints ──────────────────────────────────────────────────────────────────
CISCO_TOKEN_URL    = "https://id.cisco.com/oauth2/default/v1/token"
CISCO_ADVISORIES   = "https://apix.cisco.com/security/advisories/v2/all"

# FIX: Updated from deprecated labs/securitydataapi → hydra/rest/securitydata
REDHAT_API         = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
REDHAT_CVE_API     = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"

# FIX: Ubuntu JSON API broken → using RSS feed
UBUNTU_USN_RSS     = "https://ubuntu.com/security/notices/rss.xml"

DEBIAN_TRACKER     = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_CVE_PREFIX  = "https://security-tracker.debian.org/tracker/{cve_id}"


# ── 1. Cisco PSIRT openVuln API ────────────────────────────────────────────────

def get_cisco_token() -> str:
    """OAuth2 client_credentials flow for Cisco PSIRT API."""
    client_id     = os.getenv("CISCO_CLIENT_ID", "")
    client_secret = os.getenv("CISCO_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        return ""

    try:
        resp = requests.post(
            CISCO_TOKEN_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("access_token", "")
    except Exception as e:
        print(f"  ⚠️  Cisco token failed: {e}")
        return ""


def crawl_cisco_advisories(max_advisories: int = 200) -> list:
    """
    Fetch Cisco PSIRT advisories via openVuln API.
    Cisco advisories often pre-date NVD publication by weeks and contain
    additional CVSS vectors, workarounds, and IOS/NX-OS affected version details
    not available anywhere else.

    Register free at: https://developer.cisco.com/site/psirt/
    Set env vars: CISCO_CLIENT_ID, CISCO_CLIENT_SECRET
    """
    token = get_cisco_token()
    if not token:
        print("  ⚠️  Cisco PSIRT: CISCO_CLIENT_ID/CISCO_CLIENT_SECRET not set. Skipping.")
        print("      Register free: https://developer.cisco.com/site/psirt/")
        return []

    print(f"Fetching Cisco PSIRT advisories (up to {max_advisories})...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    }

    try:
        resp = requests.get(
            CISCO_ADVISORIES,
            headers=headers,
            params={"pageIndex": 1, "count": min(max_advisories, 100)},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  ⚠️  Cisco PSIRT fetch failed: {e}")
        return []

    records = []
    for adv in data.get("advisories", []):
        cves = adv.get("cves", []) or []
        desc = adv.get("advisoryDescription", adv.get("summary", ""))
        extra_cves = re.findall(r"CVE-\d{4}-\d+", desc, re.IGNORECASE)
        all_cves = list(set([c.upper() for c in cves + extra_cves if c]))

        records.append({
            "source":               "cisco_psirt",
            "advisory_id":          adv.get("advisoryId", ""),
            "title":                adv.get("advisoryTitle", ""),
            "description":          desc[:2000],
            "cvss_score":           adv.get("cvssBaseScore", ""),
            "cvss_vector":          adv.get("cvssVector", ""),
            "severity":             adv.get("sir", ""),
            "first_published":      adv.get("firstPublished", ""),
            "last_updated":         adv.get("lastUpdated", ""),
            "products_affected":    adv.get("productNames", [])[:10],
            "workarounds":          adv.get("workarounds", "")[:500],
            "fixed_versions":       adv.get("fixedSoftwareLink", ""),
            "cwe_ids":              adv.get("cwe", []),
            "cves_mentioned":       all_cves,
            "url":                  adv.get("publicationUrl", ""),
        })

    print(f"  ✅ Cisco PSIRT: {len(records)} advisories ({sum(1 for r in records if r['cves_mentioned'])} with CVEs)")
    return records


# ── 2. Red Hat Security Data API ───────────────────────────────────────────────

def crawl_redhat_advisories(days_back: int = 180, max_cves: int = 300) -> list:
    """
    Fetch recent CVE advisories from Red Hat Security Data API (hydra endpoint).
    Red Hat's data is authoritative for RHEL/CentOS/Fedora and includes
    errata IDs, affected RPMs, severity ratings, and CVSS vectors that
    often differ from NVD.

    No authentication required.
    """
    print(f"Fetching Red Hat security advisories (last {days_back} days)...")

    after_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    try:
        resp = requests.get(
            REDHAT_API,
            params={
                "after":    after_date,
                "per_page": min(max_cves, 1000),
                "page":     1,
            },
            headers={"User-Agent": "Mozilla/5.0 (security research)"},
            timeout=60,
        )
        resp.raise_for_status()
        cve_list = resp.json()
    except Exception as e:
        print(f"  ⚠️  Red Hat API failed: {e}")
        print("      Trying fallback per-CVE scrape...")
        return _redhat_fallback_scrape()

    if not isinstance(cve_list, list):
        print(f"  ⚠️  Red Hat returned unexpected format: {type(cve_list)}")
        return _redhat_fallback_scrape()

    records = []
    for i, cve_summary in enumerate(cve_list[:max_cves]):
        cve_id = cve_summary.get("CVE", "")
        if not cve_id:
            continue

        try:
            detail_resp = requests.get(
                REDHAT_CVE_API.format(cve_id=cve_id),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=20,
            )
            detail_resp.raise_for_status()
            detail = detail_resp.json()

            affected_packages = []
            errata_ids        = []
            for pkg in detail.get("affected_packages", []):
                affected_packages.append(pkg.get("package_name", ""))
            for fix in detail.get("package_state", []):
                errata_ids.append(fix.get("advisory", ""))

            bugzilla = detail.get("bugzilla", {})
            desc = detail.get("details", [detail.get("bugzilla", {}).get("description", "")])
            if isinstance(desc, list):
                desc = " ".join(str(d) for d in desc)

            records.append({
                "source":              "redhat_security",
                "cve_id":              cve_id,
                "title":               bugzilla.get("description", cve_id)[:200],
                "description":         str(desc)[:2000],
                "cvss_score":          detail.get("cvss3", {}).get("cvss3_base_score",
                                        detail.get("cvss", {}).get("cvss_base_score", "")),
                "cvss_vector":         detail.get("cvss3", {}).get("cvss3_scoring_vector", ""),
                "severity":            detail.get("threat_severity", ""),
                "cwe_ids":             [detail.get("cwe", "")] if detail.get("cwe") else [],
                "affected_packages":   list(set(filter(None, affected_packages)))[:20],
                "errata_ids":          list(set(filter(None, errata_ids)))[:10],
                "public_date":         detail.get("public_date", ""),
                "acknowledgements":    detail.get("acknowledgement", "")[:300],
                "cves_mentioned":      [cve_id],
                "url":                 f"https://access.redhat.com/security/cve/{cve_id}",
            })

            time.sleep(0.3)

        except Exception:
            continue

        if (i + 1) % 50 == 0:
            print(f"    ... {i + 1}/{min(len(cve_list), max_cves)} Red Hat CVEs fetched")

    print(f"  ✅ Red Hat: {len(records)} advisories")
    return records


def _redhat_fallback_scrape() -> list:
    """
    Fallback: use Red Hat's public CVE listing page to get recent CVE IDs,
    then fetch brief details via the individual CVE endpoint.
    """
    print("  Attempting Red Hat fallback scrape...")
    records = []

    # Try the old labs endpoint for listing (just the CVE IDs — may still work)
    try:
        resp = requests.get(
            "https://access.redhat.com/labs/securitydataapi/cve.json",
            params={"per_page": 100, "page": 1},
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            cve_list = resp.json()
            for item in cve_list[:50]:
                cve_id = item.get("CVE", "")
                if cve_id:
                    records.append({
                        "source":         "redhat_security",
                        "cve_id":         cve_id,
                        "title":          cve_id,
                        "description":    f"Red Hat tracked vulnerability: {cve_id}",
                        "severity":       item.get("severity", ""),
                        "cvss_score":     str(item.get("cvss3_score", item.get("cvss_score", ""))),
                        "cves_mentioned": [cve_id],
                        "url":            f"https://access.redhat.com/security/cve/{cve_id}",
                    })
    except Exception as e:
        print(f"  ⚠️  Red Hat fallback also failed: {e}")

    print(f"  ✅ Red Hat (fallback): {len(records)} records")
    return records


# ── 3. Ubuntu Security Notices (USN) via RSS ──────────────────────────────────

def crawl_ubuntu_usn(max_notices: int = 300) -> list:
    """
    FIX: Fetch Ubuntu Security Notices via RSS feed.
    The JSON notices API (ubuntu.com/security/notices.json) dropped the 'order'
    parameter and now returns 422. The RSS feed is stable and public.
    """
    print(f"Fetching Ubuntu Security Notices via RSS...")

    RSS_URL = "https://ubuntu.com/security/notices/rss.xml"

    try:
        resp = requests.get(
            RSS_URL,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0 (security research)"},
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
    except Exception as e:
        print(f"  ⚠️  Ubuntu RSS fetch failed: {e}")
        return []

    records  = []
    channel  = root.find("channel")
    if channel is None:
        print("  ⚠️  Ubuntu RSS: no channel element found")
        return []

    for item in channel.findall("item"):
        title       = (item.findtext("title") or "").strip()
        description = (item.findtext("description") or "").strip()
        link        = (item.findtext("link") or "").strip()
        pub_date    = (item.findtext("pubDate") or "").strip()

        # Strip HTML tags from description if any
        description_clean = re.sub(r"<[^>]+>", " ", description).strip()

        combined = title + " " + description_clean
        cve_ids  = list(set(re.findall(r"CVE-\d{4}-\d+", combined, re.IGNORECASE)))
        cve_ids  = [c.upper() for c in cve_ids]

        if not cve_ids:
            continue

        usn_match = re.search(r"USN-[\d-]+", title)
        usn_id    = usn_match.group(0) if usn_match else ""

        records.append({
            "source":            "ubuntu_usn",
            "usn_id":            usn_id,
            "title":             title[:200],
            "description":       description_clean[:1500],
            "priority":          "",
            "published":         pub_date,
            "affected_packages": [],
            "references":        [link],
            "cves_mentioned":    cve_ids,
            "url":               link,
        })

        if len(records) >= max_notices:
            break

    print(f"  ✅ Ubuntu USN (RSS): {len(records)} notices with CVEs")
    return records


# ── 4. Debian Security Tracker ────────────────────────────────────────────────

def crawl_debian_security(max_cves: int = 500) -> list:
    """
    Fetch Debian security tracker data.
    Debian's tracker shows per-package, per-release vulnerability status
    (vulnerable / fixed / no-dsa / ignored) for every CVE tracked.
    This is NOT available in NVD and provides unique correlation signals.
    No auth required.
    """
    print("Fetching Debian Security Tracker...")

    try:
        resp = requests.get(DEBIAN_TRACKER, timeout=120)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  ⚠️  Debian security tracker failed: {e}")
        return []

    records = []
    count   = 0

    for pkg_name, cve_dict in data.items():
        if not isinstance(cve_dict, dict):
            continue

        for cve_id, cve_info in cve_dict.items():
            if not cve_id.startswith("CVE-"):
                continue
            if count >= max_cves:
                break
            if not isinstance(cve_info, dict):
                continue

            releases_affected = {}
            releases_fixed    = {}
            for release_name, release_data in cve_info.get("releases", {}).items():
                if not isinstance(release_data, dict):
                    continue
                status    = release_data.get("status", "")
                urgency   = release_data.get("urgency", "")
                fixed_ver = release_data.get("fixed_version", "")

                if status == "resolved":
                    releases_fixed[release_name] = fixed_ver
                elif status in ("open", "undetermined"):
                    releases_affected[release_name] = urgency

            records.append({
                "source":             "debian_security",
                "cve_id":             cve_id.upper(),
                "package":            pkg_name,
                "description":        cve_info.get("description", "")[:1000],
                "scope":              cve_info.get("scope", ""),
                "releases_affected":  releases_affected,
                "releases_fixed":     releases_fixed,
                "debian_bug":         cve_info.get("debianbug", ""),
                "nosupport":          cve_info.get("nosupport", False),
                "cves_mentioned":     [cve_id.upper()],
                "url":                DEBIAN_CVE_PREFIX.format(cve_id=cve_id),
            })
            count += 1

        if count >= max_cves:
            break

    print(f"  ✅ Debian: {len(records)} CVE-package records")
    return records


# ── 5. PoC-in-GitHub exploit index ────────────────────────────────────────────

def crawl_poc_in_github(max_cves: int = 200) -> list:
    """
    Query GitHub API for public PoC exploit repositories.
    Uses the GitHub search API — no auth required (rate limited).
    With GITHUB_TOKEN env var: much higher rate limits.
    """
    print("Fetching PoC-in-GitHub exploit index...")

    github_token = os.getenv("GITHUB_TOKEN", "")
    headers      = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    api_url = "https://api.github.com/search/repositories"
    queries = [
        "CVE PoC exploit in:name pushed:>2024-01-01",
        "CVE-2024 exploit proof-of-concept in:readme",
        "CVE-2023 RCE exploit in:name",
    ]

    records = []
    for query in queries:
        try:
            resp = requests.get(
                api_url,
                params={
                    "q":        query,
                    "sort":     "updated",
                    "order":    "desc",
                    "per_page": min(max_cves // len(queries), 50),
                },
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 403:
                print("  ⚠️  GitHub PoC search rate limited. Set GITHUB_TOKEN.")
                break
            resp.raise_for_status()
            items = resp.json().get("items", [])

            for repo in items:
                name        = repo.get("name", "")
                description = repo.get("description", "") or ""
                readme_text = name + " " + description

                cves = list(set(re.findall(r"CVE-\d{4}-\d+", readme_text, re.IGNORECASE)))
                cves = [c.upper() for c in cves]
                if not cves:
                    continue

                records.append({
                    "source":         "poc_github",
                    "repo":           repo.get("full_name", ""),
                    "name":           name,
                    "description":    description[:500],
                    "stars":          repo.get("stargazers_count", 0),
                    "language":       repo.get("language", ""),
                    "last_updated":   repo.get("updated_at", ""),
                    "topics":         repo.get("topics", []),
                    "cves_mentioned": cves,
                    "url":            repo.get("html_url", ""),
                })

            time.sleep(2)

        except Exception as e:
            print(f"  ⚠️  PoC GitHub search failed ({query[:40]}): {e}")

    # Deduplicate by repo
    seen_repos    = set()
    unique_records = []
    for r in records:
        if r["repo"] not in seen_repos:
            seen_repos.add(r["repo"])
            unique_records.append(r)

    print(f"  ✅ PoC-in-GitHub: {len(unique_records)} PoC repos with CVE references")
    return unique_records


# ── Main ───────────────────────────────────────────────────────────────────────

def run(out: str = "data/raw_vendor_advisories.json"):
    all_records: list = []

    print("\n🏢 Crawling vendor security advisory sources...\n")

    # 1. Cisco PSIRT (semi-closed, requires free API key)
    cisco_records = crawl_cisco_advisories(max_advisories=200)
    all_records.extend(cisco_records)
    time.sleep(2)

    # 2. Red Hat Security Data API (hydra endpoint, free, no auth)
    rh_records = crawl_redhat_advisories(days_back=180, max_cves=300)
    all_records.extend(rh_records)
    time.sleep(2)

    # 3. Ubuntu USN via RSS (fixed — JSON API was returning 422)
    ubuntu_records = crawl_ubuntu_usn(max_notices=300)
    all_records.extend(ubuntu_records)
    time.sleep(2)

    # 4. Debian Security Tracker (free, no auth, rich package-level data)
    debian_records = crawl_debian_security(max_cves=500)
    all_records.extend(debian_records)
    time.sleep(2)

    # 5. PoC-in-GitHub (GitHub token helps, rate limited without)
    poc_records = crawl_poc_in_github(max_cves=200)
    all_records.extend(poc_records)

    # Keep only records with CVE mentions
    records_with_cves = [r for r in all_records if r.get("cves_mentioned")]

    source_counts: dict = {}
    for r in records_with_cves:
        src = r.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    print(f"\n📊 Vendor Advisories Summary:")
    print(f"  Total records:          {len(all_records)}")
    print(f"  With CVE mentions:      {len(records_with_cves)}")
    print("\n  Breakdown by source:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {src:<25} {cnt:>4} records")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(records_with_cves, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved {len(records_with_cves)} vendor advisory records → {out}")


if __name__ == "__main__":
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    run()