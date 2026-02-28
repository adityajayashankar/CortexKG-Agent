# Vulnerability GraphRAG Pipeline (Qdrant + Neo4j)

This is the run order from scratch on Windows PowerShell, including required `$env:` variables.

## 1) Open project and activate venv

```powershell
cd C:\Users\adity\dataset-deplai
.\.venv\Scripts\Activate.ps1
```

## 2) Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## 3) Prepare environment file

If `.env` does not exist:

```powershell
Copy-Item .env.example .env
```

## 4) Set runtime environment variables (PowerShell session)

Set these each time you open a new shell (unless you permanently store them in `.env`):

```powershell
# Qdrant Cloud
$env:QDRANT_URL="https://3fc728f0-bf4b-4b27-8634-6ada5569eddc.sa-east-1-0.aws.cloud.qdrant.io"
$env:QDRANT_API_KEY="<your_qdrant_api_key>"
$env:QDRANT_COLLECTION="vuln_kg_evidence_v1"
$env:QDRANT_TEXT_FIELD="text"

# Neo4j
$env:NEO4J_URI="bolt://localhost:7687"
$env:NEO4J_USER="neo4j"
$env:NEO4J_PASSWORD="<your_neo4j_password>"

# Optional source-collection keys (set only if you use these collectors)
# $env:GITHUB_TOKEN="<github_token>"
# $env:REDDIT_CLIENT_ID="<reddit_id>"
# $env:REDDIT_CLIENT_SECRET="<reddit_secret>"
# $env:HACKERONE_USERNAME="<h1_user>"
# $env:HACKERONE_API_TOKEN="<h1_token>"
# $env:MSRC_API_KEY="<msrc_key>"

# Keep vector retrieval OFF during ingest
$env:GRAPHRAG_USE_VECTOR="0"
$env:AGENT_GRAPHRAG_USE_VECTOR="0"
```

## 5) Run data collection + dataset build

Full pipeline (collect + correlate + build + validate):

```powershell
python run_pipeline.py
```

Faster rebuild from existing raw files (skip crawling):

```powershell
python run_pipeline.py --skip-crawl
```

Build-only (if raw/correlation artifacts already exist):

```powershell
python run_pipeline.py --from-build
```

## 6) Validate dataset (recommended)

```powershell
python validate_dataset.py
```

Expected outputs after build:
- `data\vuln_dataset.jsonl`
- `data\raw_correlations.json`
- `data\raw_cooccurrence_v2.json`
- `data\training_pairs.jsonl`

## 7) Load KG into Neo4j

```powershell
python load_kg.py
```

## 8) Verify Qdrant connectivity

```powershell
python -c "from qdrant_client import QdrantClient; import os; c=QdrantClient(url=os.environ['QDRANT_URL'], api_key=os.environ['QDRANT_API_KEY']); print(c.get_collections())"
```

Expected: collection list prints (or empty list if none yet).

## 9) Smoke test ingest (small run)

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py --max-vectors 2000 --batch-size 64 --qdrant-batch-size 256
```

If this succeeds, proceed to full ingest.

## 10) Full ingest (embed + upsert, streaming)

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py --max-vectors 225000 --batch-size 64 --qdrant-batch-size 256
```

## 11) Resume ingest if interrupted

Use the processed count from logs:

```powershell
python scripts/maintenance/graphrag_embed_index_qdrant_cpu.py --resume-from <done_count> --max-vectors 225000 --batch-size 64 --qdrant-batch-size 256
```

## 12) Turn vector retrieval ON (after ingest completes)

```powershell
$env:GRAPHRAG_USE_VECTOR="1"
$env:AGENT_GRAPHRAG_USE_VECTOR="1"
```

## 13) Run the agent

```powershell
python main.py
```

## 14) Quick validation query

Use `main.py` prompt:

```text
CVE-2021-28310
```

You should now see GraphRAG tool calls and vector-backed retrieval available.

## Notes

- Primary pipeline script:
  - `scripts/maintenance/graphrag_embed_index_qdrant_cpu.py`
- This script is CPU-optimized and streams data (does not load all vectors into RAM).
- If you see dimension mismatch errors, recreate/clear the Qdrant collection to `384` dims and rerun.
