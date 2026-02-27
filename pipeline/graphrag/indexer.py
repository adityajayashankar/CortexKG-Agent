from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]


def _embed_texts(texts: list[str]) -> list[list[float]]:
    model_name = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    try:
        from fastembed import TextEmbedding

        model = TextEmbedding(model_name=model_name)
        return [[float(x) for x in vec] for vec in model.embed(texts)]
    except Exception:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        vectors = model.encode(texts, normalize_embeddings=True)
        return [[float(x) for x in row.tolist()] for row in vectors]


def _qdrant_client():
    from qdrant_client import QdrantClient

    url = os.getenv("QDRANT_URL", "").strip()
    api_key = os.getenv("QDRANT_API_KEY", "").strip() or None
    if url:
        return QdrantClient(url=url, api_key=api_key)
    path = os.getenv("QDRANT_PATH", str(Path("data") / "qdrant"))
    Path(path).mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=path)


def _safe_json(path: Path) -> Any:
    if not path.exists():
        return [] if path.suffix != ".jsonl" else []
    if path.suffix == ".jsonl":
        rows = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _kg_edges() -> list[dict[str, Any]]:
    try:
        from neo4j import GraphDatabase
    except Exception:
        return []

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "").strip()
    if not password:
        return []

    out = []
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as s:
            rows = s.run(
                """
                MATCH (a:Vulnerability)-[r:CORRELATED_WITH|CO_OCCURS_WITH]->(b:Vulnerability)
                RETURN a.vuln_id AS a_id,
                       b.vuln_id AS b_id,
                       type(r) AS rel_type,
                       coalesce(r.max_score, r.max_confidence, 0.0) AS score
                LIMIT 20000
                """
            ).data()
            out.extend(rows)
        driver.close()
    except Exception:
        return []
    return out


def build_evidence_chunks(data_dir: str | Path = "data") -> list[dict[str, Any]]:
    data_dir = Path(data_dir)
    dataset = _safe_json(data_dir / "vuln_dataset.jsonl")
    corrs = _safe_json(data_dir / "raw_correlations.json")
    coocs = _safe_json(data_dir / "raw_cooccurrence_v2.json")
    kg_edges = _kg_edges()

    chunks: list[dict[str, Any]] = []

    for row in dataset if isinstance(dataset, list) else []:
        cve_id = str(row.get("cve_id") or row.get("ghsa_id") or "").upper().strip()
        if not cve_id:
            continue
        text = (
            f"{cve_id} {row.get('vulnerability_name', '')}. "
            f"CWE: {row.get('cwe_id', '')}. "
            f"OWASP: {row.get('owasp_category', '')}. "
            f"Description: {str(row.get('description', ''))[:400]}"
        ).strip()
        chunks.append(
            {
                "id": f"dataset-{_hash(cve_id + text[:80])}",
                "text": text,
                "cve_id": cve_id,
                "source_type": "dataset",
                "rel_type": "HAS_CONTEXT",
                "signals": [row.get("cwe_id", ""), row.get("owasp_category", "")],
                "reasons": [],
            }
        )

    for row in corrs if isinstance(corrs, list) else []:
        src = str(row.get("cve_id", "")).upper().strip()
        for rel in row.get("related_vulnerabilities", [])[:20]:
            tgt = str(rel.get("cve_id", "")).upper().strip()
            if not src or not tgt:
                continue
            text = (
                f"{src} correlates with {tgt}. "
                f"Signals: {', '.join(rel.get('signals', [])[:5])}. "
                f"Score: {rel.get('correlation_score', 0.0)}."
            )
            chunks.append(
                {
                    "id": f"corr-{_hash(src + tgt + text)}",
                    "text": text,
                    "cve_id": tgt,
                    "target_cve": tgt,
                    "source_type": "raw_correlations",
                    "rel_type": "CORRELATED_WITH",
                    "signals": rel.get("signals", [])[:5],
                    "reasons": [],
                }
            )

    pairs = []
    if isinstance(coocs, dict):
        pairs = coocs.get("cooccurrence_pairs", [])
    elif isinstance(coocs, list):
        pairs = coocs

    for pair in pairs[:100000]:
        a = str(pair.get("cve_a", "")).upper().strip()
        b = str(pair.get("cve_b", "")).upper().strip()
        if not a or not b:
            continue
        text = (
            f"{a} co-occurs with {b}. "
            f"Confidence: {pair.get('confidence', 0.0)}. "
            f"Source: {pair.get('source', '')}. "
            f"Reason: {pair.get('reason', '')[:220]}"
        )
        chunks.append(
            {
                "id": f"cooc-{_hash(a + b + text)}",
                "text": text,
                "cve_id": b,
                "target_cve": b,
                "source_type": "raw_cooccurrence_v2",
                "rel_type": "CO_OCCURS_WITH",
                "signals": [pair.get("source", "")],
                "reasons": [pair.get("reason", "")],
            }
        )

    for row in kg_edges:
        a = str(row.get("a_id", "")).upper().strip()
        b = str(row.get("b_id", "")).upper().strip()
        if not a or not b:
            continue
        text = (
            f"{a} has graph edge {row.get('rel_type', '')} with {b}. "
            f"Score: {row.get('score', 0.0)}."
        )
        chunks.append(
            {
                "id": f"kg-{_hash(a + b + text)}",
                "text": text,
                "cve_id": b,
                "target_cve": b,
                "source_type": "neo4j",
                "rel_type": row.get("rel_type", "GRAPH_EDGE"),
                "signals": [row.get("rel_type", "")],
                "reasons": [],
            }
        )

    seen = set()
    deduped = []
    for ch in chunks:
        key = ch["id"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ch)
    return deduped


def upsert_qdrant(chunks: list[dict[str, Any]]) -> int:
    if not chunks:
        return 0

    from qdrant_client.models import Distance, PointStruct, VectorParams

    client = _qdrant_client()
    collection = os.getenv("QDRANT_COLLECTION", "vuln_kg_evidence_v1")

    vectors = _embed_texts([c["text"] for c in chunks])
    vector_dim = len(vectors[0])

    try:
        client.get_collection(collection_name=collection)
    except Exception:
        client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE),
        )

    points = []
    for chunk, vector in zip(chunks, vectors):
        payload = {k: v for k, v in chunk.items() if k not in {"id"}}
        points.append(PointStruct(id=chunk["id"], vector=vector, payload=payload))

    client.upsert(collection_name=collection, points=points, wait=True)
    return len(points)


def build_and_index(data_dir: str | Path = "data") -> dict[str, Any]:
    chunks = build_evidence_chunks(data_dir=data_dir)
    count = upsert_qdrant(chunks)
    return {"indexed_points": count, "collection": os.getenv("QDRANT_COLLECTION", "vuln_kg_evidence_v1")}


if __name__ == "__main__":
    result = build_and_index()
    print(json.dumps(result, indent=2))

