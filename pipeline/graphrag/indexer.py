from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

try:
    from pipeline.graphrag.embeddings import embed_texts
    from pipeline.graphrag.qdrant_conn import get_qdrant_client
except ModuleNotFoundError:
    ROOT = Path(__file__).resolve().parents[2]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from pipeline.graphrag.embeddings import embed_texts
    from pipeline.graphrag.qdrant_conn import get_qdrant_client


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)


_load_env()

CHUNK_SIZE = int(os.getenv("GRAPHRAG_CHUNK_SIZE", "900"))
CHUNK_OVERLAP = int(os.getenv("GRAPHRAG_CHUNK_OVERLAP", "120"))
EMBED_BATCH_SIZE = int(os.getenv("GRAPHRAG_EMBED_BATCH_SIZE", "512"))
UPSERT_BATCH_SIZE = int(
    os.getenv(
        "QDRANT_BATCH_SIZE",
        os.getenv("GRAPHRAG_UPSERT_BATCH_SIZE", "100"),
    )
)
MAX_DATASET_ROWS = int(os.getenv("GRAPHRAG_MAX_DATASET_ROWS", "0"))
MAX_CORR_ROWS = int(os.getenv("GRAPHRAG_MAX_CORR_ROWS", "0"))
MAX_COOC_ROWS = int(os.getenv("GRAPHRAG_MAX_COOC_ROWS", "0"))
MAX_TOTAL_CHUNKS = int(os.getenv("GRAPHRAG_MAX_TOTAL_CHUNKS", "0"))
LOG_EVERY = int(os.getenv("GRAPHRAG_LOG_EVERY", "20000"))
JSONL_LOG_EVERY = int(os.getenv("GRAPHRAG_JSONL_LOG_EVERY", "5000"))
ENABLE_CORR = os.getenv("GRAPHRAG_ENABLE_CORR", "1").strip().lower() not in {"0", "false", "no"}
ENABLE_COOC = os.getenv("GRAPHRAG_ENABLE_COOC", "1").strip().lower() not in {"0", "false", "no"}
ENABLE_DATASET = os.getenv("GRAPHRAG_ENABLE_DATASET", "1").strip().lower() not in {"0", "false", "no"}
ENABLE_KG_EDGE_CHUNKS = os.getenv("GRAPHRAG_ENABLE_KG_EDGE_CHUNKS", "0").strip().lower() not in {
    "0",
    "false",
    "no",
}

MAX_REL_PER_CVE = int(os.getenv("GRAPHRAG_MAX_REL_PER_CVE", "4"))
try:
    MIN_CORR_SCORE = float(os.getenv("GRAPHRAG_MIN_CORR_SCORE", "0.60"))
except Exception:
    MIN_CORR_SCORE = 0.60

DATASET_QUOTA = int(os.getenv("GRAPHRAG_DATASET_QUOTA", "150000"))
COOC_QUOTA = int(os.getenv("GRAPHRAG_COOC_QUOTA", "100000"))
CORR_QUOTA = int(os.getenv("GRAPHRAG_CORR_QUOTA", "50000"))
DATASET_GROUP_SIZE = max(1, int(os.getenv("GRAPHRAG_DATASET_GROUP_SIZE", "10")))

QDRANT_TEXT_FIELD = (
    os.getenv("QDRANT_TEXT_FIELD", "chunk_text").strip() or "chunk_text"
)
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "vuln_kg_evidence_v1").strip() or "vuln_kg_evidence_v1"

_QDRANT_CLIENT = None


def _log(msg: str) -> None:
    print(f"[graphrag-indexer] {msg}", flush=True)


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]


def _split_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Character-window chunking with overlap and whitespace boundary preference.
    """
    t = " ".join(str(text or "").split()).strip()
    if not t:
        return []
    if chunk_size <= 0:
        return [t]
    overlap = max(0, min(overlap, chunk_size // 2))
    if len(t) <= chunk_size:
        return [t]

    out: list[str] = []
    start = 0
    n = len(t)
    while start < n:
        end = min(start + chunk_size, n)
        if end < n:
            ws = t.rfind(" ", start + int(chunk_size * 0.65), end)
            if ws > start:
                end = ws
        chunk = t[start:end].strip()
        if chunk:
            out.append(chunk)
        if end >= n:
            break
        start = max(0, end - overlap)
    return out


def _embed_texts(texts: list[str]) -> list[list[float]]:
    return embed_texts(texts)


def _qdrant_client():
    global _QDRANT_CLIENT
    if _QDRANT_CLIENT is not None:
        return _QDRANT_CLIENT
    _QDRANT_CLIENT = get_qdrant_client(required=True)
    return _QDRANT_CLIENT


def _extract_vector_dim(collection_info: Any) -> int:
    try:
        vectors = collection_info.config.params.vectors
    except Exception:
        return 0

    # Qdrant may return either a single VectorParams or a dict of named vectors.
    if isinstance(vectors, dict):
        for _, cfg in vectors.items():
            size = getattr(cfg, "size", 0)
            if size:
                return int(size)
        return 0
    size = getattr(vectors, "size", 0)
    return int(size or 0)


def _ensure_qdrant_preflight() -> None:
    """
    Verify Qdrant collection exists and matches local embedding dimension.
    """
    client = _qdrant_client()
    collection = QDRANT_COLLECTION
    _log(f"Qdrant preflight: checking collection '{collection}'")

    probe = _embed_texts(["qdrant-dimension-probe"])
    emb_dim = len(probe[0]) if probe and probe[0] else 0
    if not emb_dim:
        raise RuntimeError("Failed to compute local embedding dimension for Qdrant preflight.")

    try:
        info = client.get_collection(collection_name=collection)
        index_dim = _extract_vector_dim(info)
        if index_dim and index_dim != emb_dim:
            raise RuntimeError(
                f"Qdrant dimension mismatch: collection={index_dim}, local_embedding={emb_dim}. "
                "Use matching embedding model or recreate collection."
            )
        _log(f"Qdrant preflight: collection exists (vectors={getattr(info, 'vectors_count', 'unknown')}, dim={index_dim or emb_dim})")
    except Exception:
        from qdrant_client.models import Distance, VectorParams

        _log(f"Qdrant preflight: creating collection '{collection}' with dim={emb_dim}")
        client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=emb_dim, distance=Distance.COSINE),
        )


def _safe_json(path: Path) -> Any:
    started = time.perf_counter()
    if not path.exists():
        _log(f"Skipping missing file: {path}")
        return [] if path.suffix != ".jsonl" else []
    _log(f"Loading {path} ({path.stat().st_size / (1024 * 1024):.1f} MB)")
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
        _log(f"Loaded {len(rows)} rows from {path} in {time.perf_counter() - started:.1f}s")
        return rows
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        extra = f"{len(data)} rows"
    elif isinstance(data, dict):
        extra = f"{len(data)} top-level keys"
    else:
        extra = f"type={type(data).__name__}"
    _log(f"Loaded {extra} from {path} in {time.perf_counter() - started:.1f}s")
    return data


def _read_jsonl_limited(path: Path, max_rows: int = 0) -> list[dict[str, Any]]:
    started = time.perf_counter()
    if not path.exists():
        _log(f"Skipping missing file: {path}")
        return []
    _log(
        f"Streaming JSONL {path} ({path.stat().st_size / (1024 * 1024):.1f} MB)"
        + (f", cap={max_rows}" if max_rows > 0 else "")
    )
    rows: list[dict[str, Any]] = []
    lines_seen = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            lines_seen += 1
            if max_rows > 0 and len(rows) >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except json.JSONDecodeError:
                continue
            if JSONL_LOG_EVERY > 0 and lines_seen % JSONL_LOG_EVERY == 0:
                _log(
                    f"JSONL parse progress: lines={lines_seen}, rows={len(rows)}, elapsed={time.perf_counter() - started:.1f}s"
                )
    _log(f"Loaded {len(rows)} JSONL rows from {path} in {time.perf_counter() - started:.1f}s")
    return rows


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


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _apply_quota(chunks: list[dict[str, Any]], label: str, quota: int) -> list[dict[str, Any]]:
    if quota > 0 and len(chunks) > quota:
        _log(f"Applying {label} quota: {len(chunks)} -> {quota}")
        return chunks[:quota]
    return chunks


def _flush_dataset_group(
    dataset_chunks: list[dict[str, Any]],
    grouped_rows: list[dict[str, Any]],
) -> None:
    if not grouped_rows:
        return

    cve_ids_raw = [str(r.get("cve_id", "")).upper().strip() for r in grouped_rows if str(r.get("cve_id", "")).strip()]
    cve_ids = list(dict.fromkeys(cve_ids_raw))[:DATASET_GROUP_SIZE]
    if not cve_ids:
        return
    primary_cve = cve_ids[0]

    cwes = [str(r.get("cwe_id", "")).strip() for r in grouped_rows if str(r.get("cwe_id", "")).strip()]
    owasp = [str(r.get("owasp_category", "")).strip() for r in grouped_rows if str(r.get("owasp_category", "")).strip()]
    signals = list(dict.fromkeys(cwes + owasp))[:8]

    joined_text = " \n ".join(str(r.get("base_text", "")).strip() for r in grouped_rows if str(r.get("base_text", "")).strip())
    if not joined_text:
        return

    for idx, text in enumerate(_split_text(joined_text)):
        dataset_chunks.append(
            {
                "id": f"dataset-{_hash(primary_cve + '|'.join(cve_ids[:DATASET_GROUP_SIZE]) + str(idx) + text[:120])}",
                "text": text,
                "cve_id": primary_cve,
                "cve_ids": cve_ids,
                "source_type": "dataset",
                "rel_type": "HAS_CONTEXT",
                "signals": signals,
                "reasons": [],
                "chunk_index": idx,
            }
        )


def _source_quota(label: str) -> int:
    if label == "dataset":
        return DATASET_QUOTA
    if label == "cooccurrence":
        return COOC_QUOTA
    if label == "correlation":
        return CORR_QUOTA
    return 0


def iter_evidence_chunks(data_dir: str | Path = "data") -> Iterator[dict[str, Any]]:
    started = time.perf_counter()
    data_dir = Path(data_dir)
    _log(f"Building evidence chunks from {data_dir.resolve()}")
    dataset = (
        _read_jsonl_limited(data_dir / "vuln_dataset.jsonl", max_rows=MAX_DATASET_ROWS)
        if ENABLE_DATASET
        else []
    )
    corrs = _safe_json(data_dir / "raw_correlations.json") if ENABLE_CORR else []
    coocs = _safe_json(data_dir / "raw_cooccurrence_v2.json") if ENABLE_COOC else []
    kg_edges = _kg_edges() if ENABLE_KG_EDGE_CHUNKS else []
    if kg_edges:
        _log(f"Loaded {len(kg_edges)} Neo4j graph edges")
    else:
        _log("No Neo4j graph edges loaded")

    source_generated = {
        "dataset": 0,
        "cooccurrence": 0,
        "correlation": 0,
        "kg": 0,
    }
    source_emitted = {
        "dataset": 0,
        "cooccurrence": 0,
        "correlation": 0,
        "kg": 0,
    }
    seen: set[str] = set()
    duplicate_count = 0
    emitted_total = 0
    capped_total = False

    def _allow_emit(chunk_id: str, label: str) -> bool:
        nonlocal duplicate_count, emitted_total, capped_total
        if MAX_TOTAL_CHUNKS > 0 and emitted_total >= MAX_TOTAL_CHUNKS:
            capped_total = True
            return False

        quota = _source_quota(label)
        if quota > 0 and source_emitted[label] >= quota:
            return False

        if chunk_id in seen:
            duplicate_count += 1
            return False

        seen.add(chunk_id)
        source_emitted[label] += 1
        emitted_total += 1
        if MAX_TOTAL_CHUNKS > 0 and emitted_total >= MAX_TOTAL_CHUNKS:
            capped_total = True
        return True

    dataset_rows = dataset if isinstance(dataset, list) else []
    _log(f"Processing dataset rows: {len(dataset_rows)} (group_size={DATASET_GROUP_SIZE})")
    grouped_rows: list[dict[str, Any]] = []
    for row_idx, row in enumerate(dataset_rows, start=1):
        if capped_total:
            break
        cve_id = str(row.get("cve_id") or row.get("ghsa_id") or "").upper().strip()
        if not cve_id:
            continue
        base_text = (
            f"{cve_id} {row.get('vulnerability_name', '')}. "
            f"CWE: {row.get('cwe_id', '')}. "
            f"OWASP: {row.get('owasp_category', '')}. "
            f"Description: {str(row.get('description', ''))}"
        ).strip()
        if not base_text:
            continue
        grouped_rows.append(
            {
                "cve_id": cve_id,
                "cwe_id": row.get("cwe_id", ""),
                "owasp_category": row.get("owasp_category", ""),
                "base_text": base_text,
            }
        )
        if len(grouped_rows) >= DATASET_GROUP_SIZE:
            group_chunks: list[dict[str, Any]] = []
            _flush_dataset_group(group_chunks, grouped_rows)
            grouped_rows = []
            for chunk in group_chunks:
                source_generated["dataset"] += 1
                if _allow_emit(chunk["id"], "dataset"):
                    yield chunk
                    if capped_total:
                        break
        if LOG_EVERY > 0 and row_idx % LOG_EVERY == 0:
            _log(
                f"Dataset progress: {row_idx}/{len(dataset_rows)} rows, emitted={source_emitted['dataset']}"
            )
    if grouped_rows and not capped_total:
        group_chunks = []
        _flush_dataset_group(group_chunks, grouped_rows)
        for chunk in group_chunks:
            source_generated["dataset"] += 1
            if _allow_emit(chunk["id"], "dataset"):
                yield chunk
                if capped_total:
                    break

    corr_rows = corrs if isinstance(corrs, list) else []
    if MAX_CORR_ROWS > 0:
        corr_rows = corr_rows[:MAX_CORR_ROWS]
        _log(f"Capping correlation rows to {len(corr_rows)} via GRAPHRAG_MAX_CORR_ROWS")
    _log(f"Processing correlation rows: {len(corr_rows)}")
    dropped_low_score = 0
    for row_idx, row in enumerate(corr_rows, start=1):
        if capped_total:
            break
        src = str(row.get("cve_id", "")).upper().strip()
        rels = row.get("related_vulnerabilities", [])
        if not isinstance(rels, list):
            continue
        if MAX_REL_PER_CVE > 0:
            rels = rels[:MAX_REL_PER_CVE]
        for rel in rels:
            if capped_total:
                break
            tgt = str(rel.get("cve_id", "")).upper().strip()
            if not src or not tgt:
                continue
            raw_score = _to_float(rel.get("correlation_score", 0.0), default=0.0)
            if raw_score < MIN_CORR_SCORE:
                dropped_low_score += 1
                continue
            base_text = (
                f"{src} correlates with {tgt}. "
                f"Signals: {', '.join(rel.get('signals', [])[:5])}. "
                f"Score: {raw_score}."
            )
            for idx, text in enumerate(_split_text(base_text)):
                chunk = {
                    "id": f"corr-{_hash(src + tgt + str(idx) + text)}",
                    "text": text,
                    "cve_id": tgt,
                    "target_cve": tgt,
                    "source_type": "raw_correlations",
                    "rel_type": "CORRELATED_WITH",
                    "signals": rel.get("signals", [])[:5],
                    "reasons": [],
                    "chunk_index": idx,
                }
                source_generated["correlation"] += 1
                if _allow_emit(chunk["id"], "correlation"):
                    yield chunk
                    if capped_total:
                        break
        if LOG_EVERY > 0 and row_idx % LOG_EVERY == 0:
            _log(
                f"Correlations progress: {row_idx}/{len(corr_rows)} rows, emitted={source_emitted['correlation']}"
            )
    _log(f"Correlations pruned by score<{MIN_CORR_SCORE}: {dropped_low_score}")

    pairs: list[dict[str, Any]] = []
    if isinstance(coocs, dict):
        pairs = coocs.get("cooccurrence_pairs", [])
    elif isinstance(coocs, list):
        pairs = coocs

    if MAX_COOC_ROWS > 0:
        pairs = pairs[:MAX_COOC_ROWS]
    _log(f"Processing cooccurrence pairs: {len(pairs)}")
    for pair_idx, pair in enumerate(pairs, start=1):
        if capped_total:
            break
        a = str(pair.get("cve_a", "")).upper().strip()
        b = str(pair.get("cve_b", "")).upper().strip()
        if not a or not b:
            continue
        base_text = (
            f"{a} co-occurs with {b}. "
            f"Confidence: {pair.get('confidence', 0.0)}. "
            f"Source: {pair.get('source', '')}. "
            f"Reason: {pair.get('reason', '')}"
        )
        for idx, text in enumerate(_split_text(base_text)):
            chunk = {
                "id": f"cooc-{_hash(a + b + str(idx) + text)}",
                "text": text,
                "cve_id": b,
                "target_cve": b,
                "source_type": "raw_cooccurrence_v2",
                "rel_type": "CO_OCCURS_WITH",
                "signals": [pair.get("source", "")],
                "reasons": [pair.get("reason", "")],
                "chunk_index": idx,
            }
            source_generated["cooccurrence"] += 1
            if _allow_emit(chunk["id"], "cooccurrence"):
                yield chunk
                if capped_total:
                    break
        if LOG_EVERY > 0 and pair_idx % LOG_EVERY == 0:
            _log(
                f"Cooccurrence progress: {pair_idx}/{len(pairs)} pairs, emitted={source_emitted['cooccurrence']}"
            )

    if ENABLE_KG_EDGE_CHUNKS:
        _log(f"Processing Neo4j rows: {len(kg_edges)}")
        for row in kg_edges:
            if capped_total:
                break
            a = str(row.get("a_id", "")).upper().strip()
            b = str(row.get("b_id", "")).upper().strip()
            if not a or not b:
                continue
            base_text = (
                f"{a} has graph edge {row.get('rel_type', '')} with {b}. "
                f"Score: {row.get('score', 0.0)}."
            )
            for idx, text in enumerate(_split_text(base_text)):
                chunk = {
                    "id": f"kg-{_hash(a + b + str(idx) + text)}",
                    "text": text,
                    "cve_id": b,
                    "target_cve": b,
                    "source_type": "neo4j",
                    "rel_type": row.get("rel_type", "GRAPH_EDGE"),
                    "signals": [row.get("rel_type", "")],
                    "reasons": [],
                    "chunk_index": idx,
                }
                source_generated["kg"] += 1
                if _allow_emit(chunk["id"], "kg"):
                    yield chunk
                    if capped_total:
                        break
    else:
        _log("Skipping Neo4j edge chunks via GRAPHRAG_ENABLE_KG_EDGE_CHUNKS=0")

    if capped_total and MAX_TOTAL_CHUNKS > 0:
        _log(f"Capping total chunks to {MAX_TOTAL_CHUNKS} via GRAPHRAG_MAX_TOTAL_CHUNKS")

    _log(
        "Chunk stream complete: "
        f"generated(dataset={source_generated['dataset']}, cooc={source_generated['cooccurrence']}, "
        f"corr={source_generated['correlation']}, kg={source_generated['kg']}) "
        f"emitted(dataset={source_emitted['dataset']}, cooc={source_emitted['cooccurrence']}, "
        f"corr={source_emitted['correlation']}, kg={source_emitted['kg']}, total={emitted_total}) "
        f"duplicates={duplicate_count} in {time.perf_counter() - started:.1f}s"
    )


def build_evidence_chunks(data_dir: str | Path = "data") -> list[dict[str, Any]]:
    return list(iter_evidence_chunks(data_dir=data_dir))


def _coerce_str_list(value: Any, max_items: int = 8) -> list[str]:
    if isinstance(value, list):
        return [str(x)[:200] for x in value[:max_items]]
    if value in (None, ""):
        return []
    return [str(value)[:200]]


def _vector_payload_metadata(chunk: dict[str, Any]) -> dict[str, Any]:
    cve_ids = _coerce_str_list(chunk.get("cve_ids", []), max_items=DATASET_GROUP_SIZE)
    if not cve_ids:
        primary = str(chunk.get("cve_id", "")).upper().strip()
        if primary:
            cve_ids = [primary]
    return {
        "chunk_id": str(chunk.get("id", "")),
        "cve_id": str(chunk.get("cve_id", "")).upper().strip(),
        "cve_ids": cve_ids,
        "target_cve": str(chunk.get("target_cve", "")).upper().strip(),
        "source_type": str(chunk.get("source_type", "vector")),
        "rel_type": str(chunk.get("rel_type", "VECTOR_SIMILARITY")),
        "signals": _coerce_str_list(chunk.get("signals", []), max_items=8),
        "reasons": _coerce_str_list(chunk.get("reasons", []), max_items=6),
        "chunk_index": int(chunk.get("chunk_index", 0) or 0),
    }


def _upsert_dense(chunks: list[dict[str, Any]]) -> int:
    if not chunks:
        return 0
    from qdrant_client.models import PointStruct

    client = _qdrant_client()
    vectors = _embed_texts([c["text"] for c in chunks])
    points = []
    for chunk, vector in zip(chunks, vectors):
        point_id = str(uuid.uuid5(uuid.NAMESPACE_URL, chunk["id"]))
        points.append(
            PointStruct(
                id=point_id,
                vector=vector,
                payload=_vector_payload_metadata(chunk) | {QDRANT_TEXT_FIELD: chunk["text"]},
            )
        )
    client.upsert(collection_name=QDRANT_COLLECTION, points=points, wait=True)
    return len(points)


def upsert_qdrant(chunks: list[dict[str, Any]]) -> int:
    if not chunks:
        _log("No chunks to upsert")
        return 0

    _log(
        f"Upserting {len(chunks)} chunks to Qdrant (collection='{QDRANT_COLLECTION}', batch={UPSERT_BATCH_SIZE})"
    )
    total = 0
    started = time.perf_counter()

    for i in range(0, len(chunks), max(1, UPSERT_BATCH_SIZE)):
        batch = chunks[i : i + max(1, UPSERT_BATCH_SIZE)]
        total += _upsert_dense(batch)

        done = min(i + len(batch), len(chunks))
        elapsed = max(1e-6, time.perf_counter() - started)
        rate = done / elapsed
        remaining = len(chunks) - done
        eta_sec = int(remaining / rate) if rate > 0 else 0
        _log(
            f"Embedded/upserted {done}/{len(chunks)} chunks "
            f"(rate={rate:.1f}/s, eta={eta_sec // 3600:02d}:{(eta_sec % 3600) // 60:02d}:{eta_sec % 60:02d})"
        )

    _log(f"Qdrant upsert complete: {total} points")
    return total


def build_and_index(data_dir: str | Path = "data") -> dict[str, Any]:
    started = time.perf_counter()
    _ensure_qdrant_preflight()
    chunks = build_evidence_chunks(data_dir=data_dir)
    count = upsert_qdrant(chunks)
    result = {
        "indexed_points": count,
        "collection": QDRANT_COLLECTION,
        "backend": "qdrant",
    }
    _log(f"Indexing complete in {time.perf_counter() - started:.1f}s")
    return result


if __name__ == "__main__":
    result = build_and_index()
    print(json.dumps(result, indent=2))
