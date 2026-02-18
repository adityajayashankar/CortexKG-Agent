"""
crawl_papers.py  (FIXED v2)
----------------------------
FIXES:
  1. OSV 400 Bad Request — uses ZIP data dumps (correct bulk method)
  2. Semantic Scholar 429 — exponential backoff retry
  3. arXiv 0 CVE matches — expanded CVE-focused queries, max_results 200
  4. Full-text enriched = 0 — improved PDF extractor with pdfminer.six + pypdf
     fallback, better error logging, proper User-Agent header

INSTALL: pip install pdfminer.six pypdf
"""

import requests
import json
import re
import time
import os
import zipfile
import io
from pathlib import Path

ARXIV_API    = "http://export.arxiv.org/api/query"
SEMANTIC_API = "https://api.semanticscholar.org/graph/v1/paper/search"


# ── Retry helper ──────────────────────────────────────────────────────────────

def with_retry(fn, max_retries=4, base_delay=5, max_delay=30):
    """
    Call fn(); on 429/5xx retry with exponential backoff capped at max_delay.
    Delays: 5s → 10s → 20s → 30s. Gives up after max_retries attempts.
    """
    for attempt in range(max_retries):
        try:
            return fn()
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response else 0
            if code in (429, 500, 502, 503) and attempt < max_retries - 1:
                delay = min(base_delay * (2 ** attempt), max_delay)
                print(f"    Rate limited ({code}). Waiting {delay}s (attempt {attempt+1}/{max_retries})...")
                time.sleep(delay)
            else:
                raise
    return None


# ── arXiv crawler ─────────────────────────────────────────────────────────────

def search_arxiv(max_results: int = 200) -> list:
    import xml.etree.ElementTree as ET

    # Expanded to 6 queries that actually surface CVE-mentioning security papers
    queries = [
        "CVE vulnerability exploit proof of concept",
        "remote code execution buffer overflow attack",
        "zero-day vulnerability disclosure",
        "SQL injection cross-site scripting attack",
        "ransomware malware analysis reverse engineering",
        "privilege escalation kernel exploit",
    ]

    all_papers = []
    per_query  = max(max_results // len(queries), 10)

    print("  (Waiting 15s before arXiv to avoid burst rate limit...)")
    time.sleep(15)

    for i, query in enumerate(queries):
        if i > 0:
            time.sleep(15)

        params = {
            "search_query": f"cat:cs.CR AND all:{query}",
            "start":        0,
            "max_results":  per_query,
            "sortBy":       "submittedDate",
            "sortOrder":    "descending"
        }
        try:
            resp = with_retry(lambda p=params: requests.get(ARXIV_API, params=p, timeout=30))
            if resp is None:
                continue
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
            ns   = {"atom": "http://www.w3.org/2005/Atom"}

            for entry in root.findall("atom:entry", ns):
                title_el   = entry.find("atom:title", ns)
                summary_el = entry.find("atom:summary", ns)
                pub_el     = entry.find("atom:published", ns)
                id_el      = entry.find("atom:id", ns)

                if None in (title_el, summary_el, pub_el, id_el):
                    continue

                title     = title_el.text.strip().replace("\n", " ")
                summary   = summary_el.text.strip()
                published = pub_el.text.strip()
                arxiv_id  = id_el.text.split("/")[-1]
                cves      = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + summary, re.IGNORECASE)))

                all_papers.append({
                    "source":         "arxiv",
                    "arxiv_id":       arxiv_id,
                    "title":          title,
                    "abstract":       summary,
                    "published":      published[:10],
                    "pdf_url":        f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                    "cves_mentioned": cves,
                })
        except Exception as e:
            print(f"  ⚠️  arXiv query '{query[:40]}' failed: {e}")

    seen, unique = set(), []
    for p in all_papers:
        aid = p["arxiv_id"]
        if aid not in seen:
            seen.add(aid)
            unique.append(p)

    print(f"  ✅ arXiv: {len(unique)} papers ({sum(1 for p in unique if p['cves_mentioned'])} with CVEs)")
    return unique


# ── Semantic Scholar crawler ──────────────────────────────────────────────────

def search_semantic_scholar(max_results: int = 80) -> list:
    print("Searching Semantic Scholar for security papers...")

    headers = {}
    api_key = os.getenv("SEMANTIC_SCHOLAR_API_KEY", "")
    if api_key:
        headers["x-api-key"] = api_key

    fields  = "title,abstract,year,externalIds,openAccessPdf"
    queries = [
        "CVE vulnerability exploit proof of concept",
        "ransomware malware attack technique analysis",
        "penetration testing vulnerability discovery",
    ]

    print("  (Waiting 20s before Semantic Scholar to avoid rate limit...)")
    time.sleep(20)

    papers = []
    for qi, query in enumerate(queries):
        if qi > 0:
            time.sleep(20)
        offset = 0
        per_query_limit = max_results // len(queries)

        while len(papers) < per_query_limit * (qi + 1):
            def do_req(q=query, o=offset):
                return requests.get(
                    SEMANTIC_API,
                    params={"query": q, "fields": fields, "limit": 25, "offset": o},
                    headers=headers,
                    timeout=30
                )
            try:
                resp = with_retry(do_req, max_retries=3, base_delay=15, max_delay=30)
                if resp is None:
                    break
                resp.raise_for_status()
                items = resp.json().get("data", [])
                if not items:
                    break

                for item in items:
                    abstract = item.get("abstract") or ""
                    title    = item.get("title") or ""
                    cves     = list(set(re.findall(r"CVE-\d{4}-\d+", abstract + " " + title, re.IGNORECASE)))
                    pdf_url  = (item.get("openAccessPdf") or {}).get("url", "")

                    papers.append({
                        "source":         "semantic_scholar",
                        "paper_id":       item.get("paperId", ""),
                        "title":          title,
                        "abstract":       abstract,
                        "published":      str(item.get("year", "")),
                        "pdf_url":        pdf_url,
                        "cves_mentioned": cves,
                    })

                offset += len(items)
                if len(items) < 25:
                    break
                time.sleep(5)
            except Exception as e:
                print(f"  ⚠️  Semantic Scholar failed: {e}")
                break
        time.sleep(3)

    seen, unique = set(), []
    for p in papers:
        pid = p.get("paper_id") or p.get("title", "")[:80]
        if pid not in seen:
            seen.add(pid)
            unique.append(p)

    print(f"  ✅ Semantic Scholar: {len(unique)} papers ({sum(1 for p in unique if p['cves_mentioned'])} with CVEs)")
    return unique


# ── OSV ecosystem ZIP crawler ─────────────────────────────────────────────────

def crawl_osv_by_ecosystem(ecosystems: list = None) -> list:
    """
    Use OSV's official ecosystem ZIP data dumps.
    The /v1/query endpoint requires a package name — use bulk ZIPs instead.
    """
    if ecosystems is None:
        ecosystems = ["PyPI", "npm", "Go", "Maven", "NuGet"]

    print(f"Downloading OSV ecosystem ZIP dumps ({len(ecosystems)} ecosystems)...")
    records = []

    for ecosystem in ecosystems:
        zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        try:
            print(f"  Fetching OSV/{ecosystem}...")
            resp = requests.get(zip_url, timeout=60, stream=True)
            if resp.status_code != 200:
                print(f"  ⚠️  OSV {ecosystem} returned {resp.status_code}")
                continue

            zf    = zipfile.ZipFile(io.BytesIO(resp.content))
            count = 0

            for fname in zf.namelist()[:300]:
                try:
                    vuln    = json.loads(zf.read(fname))
                    vuln_id = vuln.get("id", "")
                    aliases = vuln.get("aliases", [])
                    summary = vuln.get("summary", "")
                    details = vuln.get("details", "")

                    cves = [a for a in aliases if a.startswith("CVE-")]
                    if not cves:
                        cves = list(set(re.findall(r"CVE-\d{4}-\d+", details + " " + summary, re.IGNORECASE)))

                    if cves:
                        records.append({
                            "source":         "osv",
                            "osv_id":         vuln_id,
                            "ecosystem":      ecosystem,
                            "title":          summary,
                            "abstract":       details[:2000],
                            "description":    details[:2000],
                            "published":      vuln.get("published", "")[:10],
                            "cves_mentioned": cves,
                        })
                        count += 1
                except Exception:
                    continue

            print(f"    ✅ {ecosystem}: {count} records with CVEs")
            time.sleep(1)

        except Exception as e:
            print(f"  ⚠️  OSV {ecosystem} ZIP failed: {e}")

    print(f"  ✅ OSV total: {len(records)} records")
    return records


# ── PDF text extraction ───────────────────────────────────────────────────────

def extract_text_from_pdf(pdf_url: str, max_chars: int = 5000) -> str:
    """
    FIX: Extract text from a PDF URL.
    Tries pdfminer.six first (best quality), falls back to pypdf.
    Returns empty string on any failure — never raises.

    Install: pip install pdfminer.six pypdf
    """
    if not pdf_url:
        return ""

    try:
        resp = requests.get(
            pdf_url,
            timeout=30,
            headers={
                "User-Agent": "Mozilla/5.0 (research crawler; contact: security-research@example.com)",
                "Accept":     "application/pdf,*/*",
            },
            stream=True,
        )
        if resp.status_code != 200:
            return ""

        pdf_bytes = resp.content
        if len(pdf_bytes) < 1000:
            return ""  # not a real PDF

    except Exception:
        return ""

    # Try pdfminer.six (best quality — handles complex layouts)
    try:
        from pdfminer.high_level import extract_text as pdfminer_extract
        text = pdfminer_extract(io.BytesIO(pdf_bytes))
        if text and len(text.strip()) > 100:
            return text[:max_chars]
    except ImportError:
        pass  # not installed — fall through to pypdf
    except Exception:
        pass  # corrupted PDF or other error

    # Fallback: pypdf (lighter, handles most arXiv PDFs)
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        pages  = []
        for page in reader.pages[:15]:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                continue
        text = "\n".join(pages)
        if text and len(text.strip()) > 100:
            return text[:max_chars]
    except ImportError:
        pass
    except Exception:
        pass

    # Final fallback: PyPDF2 (legacy)
    try:
        from PyPDF2 import PdfReader as LegacyReader
        reader = LegacyReader(io.BytesIO(pdf_bytes))
        pages  = []
        for page in reader.pages[:15]:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                continue
        text = "\n".join(pages)
        if text and len(text.strip()) > 100:
            return text[:max_chars]
    except Exception:
        pass

    return ""


# ── Full-text enrichment ──────────────────────────────────────────────────────

def enrich_papers_with_fulltext(papers: list, max_enrich: int = 60) -> int:
    """
    Extract CVE IDs from full PDF text.
    Abstracts rarely contain CVE IDs — this is what surfaces them.
    Increased max_enrich to 60 (was 30) for better coverage.
    """
    enriched = 0
    attempted = 0

    for paper in papers:
        if attempted >= max_enrich:
            break
        if not paper.get("pdf_url") or paper.get("fulltext_extracted"):
            continue

        attempted += 1
        fulltext = extract_text_from_pdf(paper["pdf_url"])

        if fulltext:
            new_cves = list(set(re.findall(r"CVE-\d{4}-\d+", fulltext, re.IGNORECASE)))
            before   = len(paper.get("cves_mentioned", []))
            paper["cves_mentioned"]     = list(set(paper.get("cves_mentioned", []) + new_cves))
            paper["fulltext_sample"]    = fulltext[:2000]  # increased from 1000
            paper["fulltext_extracted"] = True
            if len(paper["cves_mentioned"]) > before:
                enriched += 1
        else:
            paper["fulltext_extracted"] = False

        time.sleep(1.5)

    return enriched


# ── Main ─────────────────────────────────────────────────────────────────────

def run(out: str = "data/raw_papers.json"):
    all_papers: list = []

    arxiv_papers = search_arxiv(max_results=200)
    all_papers.extend(arxiv_papers)
    time.sleep(1)

    ss_papers = search_semantic_scholar(max_results=80)
    all_papers.extend(ss_papers)
    time.sleep(1)

    osv_records = crawl_osv_by_ecosystem()
    all_papers.extend(osv_records)

    # Deduplicate by title
    seen_titles, unique_papers = set(), []
    for p in all_papers:
        key = p.get("title", "").lower().strip()[:80]
        if key and key not in seen_titles:
            seen_titles.add(key)
            unique_papers.append(p)

    print("\nEnriching open-access papers with full-text CVE extraction...")
    enriched_count = enrich_papers_with_fulltext(unique_papers, max_enrich=60)

    papers_with_cves  = [p for p in unique_papers if p.get("cves_mentioned")]
    total_cve_mentions = sum(len(p.get("cves_mentioned", [])) for p in unique_papers)

    print(f"\n📄 Total unique records:    {len(unique_papers)}")
    print(f"📄 With CVE mentions:       {len(papers_with_cves)}")
    print(f"   Full-text enriched:      {enriched_count}")
    print(f"   Total CVE mentions:      {total_cve_mentions}")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(unique_papers, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved {len(unique_papers)} research records → {out}")


if __name__ == "__main__":
    run()