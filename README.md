# Vulnerability GraphRAG Pipeline (Qdrant + Neo4j)

Complete run order from scratch on Windows PowerShell. Covers data collection, KG build, vector indexing, agent runtime, and optional fine-tuning.

## Architecture Overview

```
Data Sources (10+)                  Neo4j Knowledge Graph
  NVD / EPSS / CISA KEV               407k nodes / 6.9M relationships
  MITRE ATT&CK / CWE                  Vulnerability ↔ CWE ↔ OWASP ↔ Software
  GitHub Advisories                   CORRELATED_WITH / CO_OCCURS_WITH edges
  Blogs / Papers / Vendors  ──────►  StackProfile / CWECluster / NegativeRule
  Closed sources / ExploitDB                        │
              │                                     ▼
              ▼                       Qdrant Vector Index (bge-small-en-v1.5)
  vuln_dataset.jsonl (325k CVEs)       vuln_kg_evidence_v1 (225k vectors)
  training_pairs.jsonl (2.6M pairs)              │
              │                                  ▼
              └──────────────► LangGraph Agent (main.py)
                                multi-hop hybrid GraphRAG + HITL policy
```

## Key Script Map

| Script | Purpose |
|--------|---------|
| `run_pipeline.py` | Master orchestrator — collect → correlate → build → validate |
| `data/build_master_dataset.py` | Join all raw artifacts into one `master_vuln_context.jsonl` |
| `load_kg_master.py` | Load Neo4j KG from master JSONL (preferred) |
| `load_kg.py` | Legacy multi-file Neo4j loader |
| `scripts/maintenance/validate_kg.py` | Automated KG integrity + source-alignment checks |
| `scripts/maintenance/graphrag_embed_index_qdrant_cpu.py` | CPU-optimized streaming embed + upsert to Qdrant |
| `scripts/maintenance/graphrag_embed_local.py` | Phase 1 of two-phase ingest: embed to local JSONL cache |
| `scripts/maintenance/graphrag_upsert_cache.py` | Phase 2 of two-phase ingest: upsert cached vectors to Qdrant |
| `eval/run_graphrag_benchmark.py` | Held-out retrieval quality benchmark |
| `main.py` | Interactive agent CLI |
| `training/finetuning.py` | Fine-tune Foundation-Sec-8B (QLoRA, phase 1) |
| `training/finetuning_phase2.py` | Fine-tune continuation (phase 2) |

---

## Phase 0 — Environment Setup

### 0a) Open project and activate venv

```powershell
cd C:\Users\adity\dataset-deplai
.\.venv\Scripts\Activate.ps1
```

### 0b) Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 0c) Configure `.env`

If `.env` does not exist:

```powershell
Copy-Item .env.example .env
```

Edit `.env` or set the following in every new PowerShell session:

```powershell
# ── Qdrant Cloud ──────────────────────────────────────────────────────────────
$env:QDRANT_URL="https://<your-cluster>.cloud.qdrant.io"
$env:QDRANT_API_KEY="<your_qdrant_api_key>"
$env:QDRANT_COLLECTION="vuln_kg_evidence_v1"
$env:QDRANT_TEXT_FIELD="text"

# ── Neo4j ─────────────────────────────────────────────────────────────────────
$env:NEO4J_URI="bolt://localhost:7687"
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="<your_neo4j_password>"

# ── LLM backends (Groq → OpenRouter → Ollama fallback chain) ──────────────────
$env:GROQ_API_KEY="<your_groq_api_key>"
# $env:OPENROUTER_API_KEY="<optional>"

# ── Optional source-collection keys ───────────────────────────────────────────
# $env:GITHUB_TOKEN="<github_token>"
# $env:TAVILY_API_KEY="<tavily_key>"          # blog crawler
# $env:REDDIT_CLIENT_ID="<reddit_id>"
# $env:REDDIT_CLIENT_SECRET="<reddit_secret>"
# $env:HACKERONE_USERNAME="<h1_user>"
# $env:HACKERONE_API_TOKEN="<h1_token>"
# $env:MSRC_API_KEY="<msrc_key>"
# $env:CISCO_CLIENT_ID="<cisco_id>"
# $env:CISCO_CLIENT_SECRET="<cisco_secret>"

# ── Keep vector retrieval OFF until ingest completes ──────────────────────────
$env:GRAPHRAG_USE_VECTOR="0"
$env:AGENT_GRAPHRAG_USE_VECTOR="0"
```

---

## Phase 1 — Data Collection & Dataset Build

This phase crawls all sources, builds correlation/co-occurrence graphs, produces `vuln_dataset.jsonl` and `training_pairs.jsonl`.

### 1a) Full pipeline (collect → correlate → build → validate)

```powershell
python run_pipeline.py
```

**Pipeline stages run in order:**

| # | Stage | Key output |
|---|-------|-----------|
| 1 | Crawl NVD | `data/raw_nvd.json` (328k CVEs) |
| 2 | Crawl EPSS | `data/raw_epss.json` |
| 3 | Crawl GitHub Advisories | `data/raw_github.json` |
| 4 | Crawl Blogs (agentic) | `data/raw_blogs.json` |
| 5 | Crawl ExploitDB | `data/raw_exploitdb.json` |
| 6 | Crawl CISA KEV | `data/raw_cisa_kev.json` |
| 7 | Crawl Research Papers | `data/raw_papers.json` |
| 8 | Crawl MITRE ATT&CK | `data/raw_mitre_attack.json` |
| 9 | Crawl Vendor Advisories | `data/raw_vendor_advisories.json` |
| 10 | Crawl Closed Sources | `data/raw_closed.json` |
| 11 | Build CVE correlations | `data/raw_correlations.json` |
| 12 | Collect CWE chains | `data/raw_cwe_chains.json` |
| 13 | Cluster KEV campaigns | `data/raw_kev_clusters.json` |
| 14 | Build co-occurrence v2 | `data/raw_cooccurrence_v2.json` |
| 15 | Build dataset + pairs | `data/vuln_dataset.jsonl`, `data/training_pairs.jsonl` |
| 16 | Generate co-occurrence pairs | appended to `data/training_pairs.jsonl` |
| 17 | Generate synthetic pairs | appended to `data/training_pairs.jsonl` |
| 18 | Validate dataset | quality report to stdout |

**Useful flags:**

```powershell
# Skip all crawling (use existing raw_*.json files)
python run_pipeline.py --skip-crawl

# Skip crawl + correlation build (use existing raw_*.json + raw_correlations.json)
python run_pipeline.py --from-build

# Collect only (no build)
python run_pipeline.py --only collect

# Open sources only (no closed/semi-private APIs)
python run_pipeline.py --open-only

# Limit NVD total (faster dev runs)
python run_pipeline.py --nvd-total 50000

# Dry run (show what would run, no execution)
python run_pipeline.py --dry-run
```

### 1b) Validate dataset quality (recommended)

```powershell
python validate_dataset.py
```

Optional — fast heuristic mode without loading the tokenizer:

```powershell
python validate_dataset.py --no-tokenizer
```

Auto-fix bad examples (drop outputs <80 chars, dedup):

```powershell
python validate_dataset.py --fix
```

### 1c) Dataset statistics

```powershell
python analyze_dataset.py
```

Or run both together:

```powershell
python scripts/maintenance/run_both_scripts.py
```

---

## Phase 2 — Build Master Dataset

Joins all raw artifacts into a single enriched JSONL used by the KG loader and Qdrant indexer.

```powershell
python data/build_master_dataset.py
```

Output: `data/master_vuln_context.jsonl`

**Options:**

```powershell
# Disable enrichment from additional raw sources (only vuln_dataset + correlations + cooc)
python data/build_master_dataset.py --no-use-all-raw

# Disable negative_rules metadata row embedding
python data/build_master_dataset.py --no-embed-negative-rules

# Cap items per raw source (useful for memory-constrained environments)
python data/build_master_dataset.py --max-source-items 50000
```

---

## Phase 3 — Load Knowledge Graph (Neo4j)

**Preferred — single master file:**

```powershell
python load_kg_master.py --master-file data/master_vuln_context.jsonl
```

**Legacy — multi-file loader:**

```powershell
python load_kg.py
```

Expected graph after load:

| Metric | Value |
|--------|-------|
| Vulnerability nodes | ~326,969 |
| Total nodes | ~407,713 |
| CORRELATED_WITH edges | ~5.12M |
| CO_OCCURS_WITH edges | ~891k |
| Total relationships | ~6.9M |

---

## Phase 4 — KG Validation & Benchmark Gate

Run this before promoting the vector index.

### 4a) KG integrity validation

```powershell
python scripts/maintenance/validate_kg.py `
  --strict `
  --sample-cves 50 `
  --seed 42 `
  --output-json eval/results/kg_validation.json `
  --output-md   eval/results/kg_validation.md
```

### 4b) Held-out retrieval benchmark

```powershell
python eval/run_graphrag_benchmark.py `
  --benchmark-file  eval/heldout_cve_benchmark.jsonl `
  --ground-truth    eval/ground_truth_benchmark.jsonl `
  --max-probes 120 --top-k 20 --max-hops 2 --strict `
  --output-json eval/results/graphrag_eval.json `
  --output-csv  eval/results/graphrag_eval.csv
```

Notes:
- `eval/heldout_cve_benchmark.jsonl` is auto-generated from raw artifacts if missing.
- `eval/ground_truth_benchmark.jsonl` is the curated analyst-labeled ground truth (already present).

Expected artifacts:

```
eval/results/kg_validation.json
eval/results/kg_validation.md
eval/heldout_cve_benchmark.jsonl   ← auto-generated
eval/results/graphrag_eval.json
eval/results/graphrag_eval.csv
```

---

## Phase 5 — Vector Indexing (Qdrant)

The embedding model is `BAAI/bge-small-en-v1.5` (384-dim, CPU-optimized).
Observed throughput: ~15.6 vectors/sec on CPU → full 225k ingest ≈ 4 hours.

### 5a) Verify Qdrant connectivity

```powershell
python -c "
from qdrant_client import QdrantClient; import os
c = QdrantClient(url=os.environ['QDRANT_URL'], api_key=os.environ['QDRANT_API_KEY'])
print(c.get_collections())
"
```

### 5b) Smoke test (2k vectors)

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py `
  --max-vectors 2000 --batch-size 64 --qdrant-batch-size 256
```

### 5c) Full ingest (225k vectors, streaming)

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py `
  --max-vectors 225000 --batch-size 64 --qdrant-batch-size 256
```

### 5d) Resume if interrupted

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py `
  --resume-from <done_count> --max-vectors 225000 --batch-size 64 --qdrant-batch-size 256
```

### 5e) Alternative two-phase ingest (embed locally, then upsert)

Use this when embedding and uploading are on separate machines:

```powershell
# Phase 1 — embed to local cache
python scripts/maintenance/graphrag_embed_local.py `
  --out data/vector_cache/graphrag_vectors.jsonl.gz

# Phase 2 — upsert cache to Qdrant
python scripts/maintenance/graphrag_upsert_cache.py `
  --cache data/vector_cache/graphrag_vectors.jsonl.gz
```

### 5f) Enable vector retrieval after ingest completes

```powershell
$env:GRAPHRAG_USE_VECTOR="1"
$env:AGENT_GRAPHRAG_USE_VECTOR="1"
```

> **Troubleshooting:** If you see a dimension mismatch error, delete and recreate the Qdrant collection at 384 dims before re-running ingest.

---

## Phase 6 — Run the Agent

```powershell
python main.py
```

At the prompt, enter a CVE ID or free-text vulnerability question.

**Quick validation query:**

```
CVE-2021-28310
```

Expected: multi-step GraphRAG tool calls, `direct_evidence` list with ≥1 entry, a confidence score, and a structured final report.

**Agent tuning env vars:**

```powershell
$env:AGENT_GRAPHRAG_TOP_K="20"      # number of graph+vector candidates
$env:AGENT_GRAPHRAG_MAX_HOPS="2"    # graph traversal depth
$env:AGENT_GRAPHRAG_USE_VECTOR="1"  # enable vector retrieval (after ingest)
```

---

## Phase 7 — Fine-Tuning (Optional)

Fine-tunes `fdtn-ai/Foundation-Sec-8B` (Llama 3.1-based, 80B cyber token pre-training) using QLoRA on the generated `training_pairs.jsonl`.

Recommended hardware: A100 40 GB (fits with 4-bit QLoRA at `max_length=4096`).
On 2× T4: set `max_length=2048` and `gradient_accumulation_steps=32`.

### Phase 1 — Base SFT

```powershell
python training/finetuning.py
```

Key config (in `finetuning.py`): LoRA r=32 / alpha=64, `vulnerability_correlation` and `vulnerability_cooccurrence` layers sampled at 3×.

### Phase 2 — Continuation

```powershell
python training/finetuning_phase2.py
```

---

## Optional — Augmented Training Dataset

Generates a 1 GB augmented dataset with 5 scenario-based semantic reframings per base pair (incident response, red team, compliance, threat hunting, vuln management):

```powershell
python data/expand_training_pairs.py --target-total-mb 1024
```

Output: `data/training_pairs_augmented_1gb.jsonl`

---

## Open Items

1. ExploitDB crawler currently returns 0 records (all known mirror URLs are failing). Contributions welcome.

