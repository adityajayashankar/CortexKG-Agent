from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)
except Exception:
    pass

import torch
from qdrant_client import QdrantClient
from qdrant_client.http.exceptions import ResponseHandlingException, UnexpectedResponse
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer


DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"
DEFAULT_BATCH_SIZE = 64
DEFAULT_QDRANT_BATCH = 256
DEFAULT_VECTOR_DIM = 384
LOG_EVERY = 2000


@dataclass
class Quotas:
    dataset: int
    correlation: int
    cooccurrence: int
    total: int


def _log(msg: str) -> None:
    print(f"[graphrag-cpu-index] {msg}", flush=True)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def _coerce_str_list(value: Any, max_items: int = 8) -> list[str]:
    if isinstance(value, list):
        return [str(x)[:200] for x in value[:max_items]]
    if value in (None, ""):
        return []
    return [str(value)[:200]]


def _split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    normalized = " ".join(str(text or "").split()).strip()
    if not normalized:
        return []
    if chunk_size <= 0 or len(normalized) <= chunk_size:
        return [normalized]

    out: list[str] = []
    n = len(normalized)
    start = 0
    overlap = max(0, min(overlap, chunk_size // 2))
    while start < n:
        end = min(start + chunk_size, n)
        if end < n:
            ws = normalized.rfind(" ", start + int(chunk_size * 0.65), end)
            if ws > start:
                end = ws
        part = normalized[start:end].strip()
        if part:
            out.append(part)
        if end >= n:
            break
        start = max(0, end - overlap)
    return out


def _hash_id(text: str) -> str:
    import hashlib

    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]


def _chunk_metadata(chunk: dict[str, Any], text_field: str) -> dict[str, Any]:
    cve_ids = _coerce_str_list(chunk.get("cve_ids", []), max_items=12)
    if not cve_ids:
        cve_id = str(chunk.get("cve_id", "")).upper().strip()
        if cve_id:
            cve_ids = [cve_id]

    return {
        "chunk_id": str(chunk.get("id", "")),
        "cve_id": str(chunk.get("cve_id", "")).upper().strip(),
        "cve_ids": cve_ids,
        "target_cve": str(chunk.get("target_cve", "")).upper().strip(),
        "source_type": str(chunk.get("source_type", "dataset")),
        "rel_type": str(chunk.get("rel_type", "HAS_CONTEXT")),
        "signals": _coerce_str_list(chunk.get("signals", []), max_items=8),
        "reasons": _coerce_str_list(chunk.get("reasons", []), max_items=6),
        "chunk_index": int(chunk.get("chunk_index", 0) or 0),
        text_field: str(chunk.get("text", "")),
    }


def _open_qdrant_client(url: str, api_key: str | None, local_path: str | None) -> QdrantClient:
    if url:
        return QdrantClient(url=url, api_key=api_key)
    path = local_path or str(Path("data") / "qdrant")
    Path(path).mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=path)


def _ensure_collection(client: QdrantClient, collection_name: str, vector_size: int) -> None:
    try:
        info = client.get_collection(collection_name=collection_name)
        vectors = info.config.params.vectors
        existing_size = int(getattr(vectors, "size", 0) or 0)
        if existing_size and existing_size != vector_size:
            raise RuntimeError(
                f"Collection '{collection_name}' exists with dim={existing_size}, expected={vector_size}. "
                "Use a matching model or recreate the collection."
            )
    except UnexpectedResponse as exc:
        if getattr(exc, "status_code", None) != 404:
            raise
        _log(f"Creating Qdrant collection '{collection_name}' (dim={vector_size}, distance=Cosine)")
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
        )
    except ResponseHandlingException:
        raise
    except Exception as exc:
        # Local-mode "not found" errors may not be HTTP exceptions.
        if "not found" not in str(exc).lower():
            raise
        _log(f"Creating Qdrant collection '{collection_name}' (dim={vector_size}, distance=Cosine)")
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
        )


def _disable_hf_progress() -> None:
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    try:
        from huggingface_hub.utils import disable_progress_bars

        disable_progress_bars()
    except Exception:
        pass
    try:
        from transformers.utils import logging as transformers_logging

        transformers_logging.disable_progress_bar()
    except Exception:
        pass


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def _iter_cooccurrence_pairs_stream(path: Path) -> Iterator[dict[str, Any]]:
    """
    Stream parse data/raw_cooccurrence_v2.json without loading full file into RAM.
    Expects a top-level object with a large `cooccurrence_pairs` array.
    """
    if not path.exists():
        return

    decoder = json.JSONDecoder()
    key = '"cooccurrence_pairs"'
    in_array = False
    buf = ""

    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(1 << 20)  # 1 MiB
            if not chunk:
                break
            buf += chunk

            if not in_array:
                key_idx = buf.find(key)
                if key_idx < 0:
                    if len(buf) > len(key):
                        buf = buf[-len(key) :]
                    continue
                arr_idx = buf.find("[", key_idx)
                if arr_idx < 0:
                    continue
                buf = buf[arr_idx + 1 :]
                in_array = True

            while in_array:
                stripped = buf.lstrip()
                consumed = len(buf) - len(stripped)
                if consumed:
                    buf = stripped
                if not buf:
                    break
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                if buf[0] == "]":
                    return
                try:
                    obj, end = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                buf = buf[end:]
                if isinstance(obj, dict):
                    yield obj


def _stream_chunks(data_dir: Path, quotas: Quotas) -> Iterator[dict[str, Any]]:
    chunk_size = _env_int("GRAPHRAG_CHUNK_SIZE", 900)
    overlap = _env_int("GRAPHRAG_CHUNK_OVERLAP", 120)
    group_size = max(1, _env_int("GRAPHRAG_DATASET_GROUP_SIZE", 10))
    max_rel_per_cve = max(1, _env_int("GRAPHRAG_MAX_REL_PER_CVE", 4))
    min_corr_score = _env_float("GRAPHRAG_MIN_CORR_SCORE", 0.60)

    emitted = {"dataset": 0, "correlation": 0, "cooccurrence": 0, "total": 0}
    seen: set[str] = set()
    grouped: list[dict[str, Any]] = []

    def can_emit(source: str, chunk_id: str) -> bool:
        if chunk_id in seen:
            return False
        if quotas.total > 0 and emitted["total"] >= quotas.total:
            return False
        if source == "dataset" and quotas.dataset > 0 and emitted["dataset"] >= quotas.dataset:
            return False
        if source == "correlation" and quotas.correlation > 0 and emitted["correlation"] >= quotas.correlation:
            return False
        if source == "cooccurrence" and quotas.cooccurrence > 0 and emitted["cooccurrence"] >= quotas.cooccurrence:
            return False
        seen.add(chunk_id)
        emitted[source] += 1
        emitted["total"] += 1
        return True

    def flush_group() -> Iterator[dict[str, Any]]:
        nonlocal grouped
        if not grouped:
            return
        cve_ids = list(dict.fromkeys(str(r.get("cve_id", "")).upper().strip() for r in grouped if r.get("cve_id")))
        cve_ids = [c for c in cve_ids if c][:group_size]
        if not cve_ids:
            grouped = []
            return
        primary = cve_ids[0]
        cwes = [str(r.get("cwe_id", "")).strip() for r in grouped if str(r.get("cwe_id", "")).strip()]
        owasp = [str(r.get("owasp_category", "")).strip() for r in grouped if str(r.get("owasp_category", "")).strip()]
        signals = list(dict.fromkeys(cwes + owasp))[:8]
        text = " \n ".join(str(r.get("base_text", "")).strip() for r in grouped if str(r.get("base_text", "")).strip())
        grouped = []
        if not text:
            return
        for idx, part in enumerate(_split_text(text, chunk_size, overlap)):
            chunk = {
                "id": f"dataset-{_hash_id(primary + '|'.join(cve_ids) + str(idx) + part[:120])}",
                "text": part,
                "cve_id": primary,
                "cve_ids": cve_ids,
                "source_type": "dataset",
                "rel_type": "HAS_CONTEXT",
                "signals": signals,
                "reasons": [],
                "chunk_index": idx,
            }
            if can_emit("dataset", chunk["id"]):
                yield chunk

    dataset_path = data_dir / "vuln_dataset.jsonl"
    line_no = 0
    for row in _iter_jsonl(dataset_path):
        line_no += 1
        cve_id = str(row.get("cve_id") or row.get("ghsa_id") or "").upper().strip()
        if not cve_id:
            continue
        base_text = (
            f"{cve_id} {row.get('vulnerability_name', '')}. "
            f"CWE: {row.get('cwe_id', '')}. "
            f"OWASP: {row.get('owasp_category', '')}. "
            f"Description: {str(row.get('description', ''))}"
        ).strip()
        if base_text:
            grouped.append(
                {
                    "cve_id": cve_id,
                    "cwe_id": row.get("cwe_id", ""),
                    "owasp_category": row.get("owasp_category", ""),
                    "base_text": base_text,
                }
            )
            if len(grouped) >= group_size:
                for chunk in flush_group() or []:
                    yield chunk

        if quotas.correlation <= 0 or emitted["correlation"] < quotas.correlation:
            rels = row.get("related_vulnerabilities", [])
            if isinstance(rels, list):
                for rel in rels[:max_rel_per_cve]:
                    tgt = str(rel.get("cve_id", "")).upper().strip()
                    score = float(rel.get("correlation_score", 0.0) or 0.0)
                    if not tgt or score < min_corr_score:
                        continue
                    raw_text = (
                        f"{cve_id} correlates with {tgt}. "
                        f"Signals: {', '.join((rel.get('signals') or [])[:5])}. "
                        f"Score: {score}."
                    )
                    for idx, part in enumerate(_split_text(raw_text, chunk_size, overlap)):
                        corr_chunk = {
                            "id": f"corr-{_hash_id(cve_id + tgt + str(idx) + part[:120])}",
                            "text": part,
                            "cve_id": tgt,
                            "target_cve": tgt,
                            "source_type": "raw_correlations",
                            "rel_type": "CORRELATED_WITH",
                            "signals": (rel.get("signals") or [])[:5],
                            "reasons": [],
                            "chunk_index": idx,
                        }
                        if can_emit("correlation", corr_chunk["id"]):
                            yield corr_chunk
                        if quotas.total > 0 and emitted["total"] >= quotas.total:
                            break
                if quotas.total > 0 and emitted["total"] >= quotas.total:
                    break
        if quotas.total > 0 and emitted["total"] >= quotas.total:
            break

    for chunk in flush_group() or []:
        yield chunk

    if quotas.total > 0 and emitted["total"] >= quotas.total:
        return

    cooc_path = data_dir / "raw_cooccurrence_v2.json"
    pair_no = 0
    for pair in _iter_cooccurrence_pairs_stream(cooc_path):
        pair_no += 1
        if quotas.cooccurrence > 0 and emitted["cooccurrence"] >= quotas.cooccurrence:
            break
        if quotas.total > 0 and emitted["total"] >= quotas.total:
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
        for idx, part in enumerate(_split_text(base_text, chunk_size, overlap)):
            chunk = {
                "id": f"cooc-{_hash_id(a + b + str(idx) + part[:120])}",
                "text": part,
                "cve_id": b,
                "target_cve": b,
                "source_type": "raw_cooccurrence_v2",
                "rel_type": "CO_OCCURS_WITH",
                "signals": [str(pair.get("source", ""))],
                "reasons": [str(pair.get("reason", ""))],
                "chunk_index": idx,
            }
            if can_emit("cooccurrence", chunk["id"]):
                yield chunk

    _log(
        f"Chunk stream complete: dataset={emitted['dataset']} correlation={emitted['correlation']} "
        f"cooccurrence={emitted['cooccurrence']} total={emitted['total']}"
    )


def _iter_batches(rows: Iterator[dict[str, Any]], batch_size: int) -> Iterator[list[dict[str, Any]]]:
    step = max(1, batch_size)
    batch: list[dict[str, Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= step:
            yield batch
            batch = []
    if batch:
        yield batch


def _is_oom(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "out of memory" in msg or "cannot allocate" in msg or "bad alloc" in msg


def _fmt_eta(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"


def _fmt_secs(seconds: float) -> str:
    h = int(seconds) // 3600
    m = (int(seconds) % 3600) // 60
    s = int(seconds) % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _estimate_target(args_max_vectors: int, quotas: Quotas) -> int:
    if args_max_vectors > 0:
        return args_max_vectors
    if quotas.total > 0:
        return quotas.total
    parts = [v for v in (quotas.dataset, quotas.correlation, quotas.cooccurrence) if v > 0]
    return sum(parts) if parts else 0


def _estimate_bytes(dim: int, count: int) -> int:
    return dim * 4 * count


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    kib = n / 1024
    if kib < 1024:
        return f"{kib:.2f} KiB"
    mib = kib / 1024
    if mib < 1024:
        return f"{mib:.2f} MiB"
    gib = mib / 1024
    return f"{gib:.2f} GiB"


def main() -> int:
    parser = argparse.ArgumentParser(description="CPU-optimized streaming embed + Qdrant upsert for GraphRAG.")
    parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME, help=f"Embedding model (default: {DEFAULT_MODEL_NAME})")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Embedding batch size (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--collection-name", default=os.getenv("QDRANT_COLLECTION", "vuln_kg_evidence_v1"), help="Qdrant collection")
    parser.add_argument("--resume-from", type=int, default=0, help="Skip first N vectors before upsert")
    parser.add_argument("--max-vectors", type=int, default=0, help="Stop after N vectors")
    parser.add_argument("--qdrant-url", default=os.getenv("QDRANT_URL", "http://localhost:6333"), help="Qdrant URL")
    parser.add_argument("--qdrant-api-key", default=os.getenv("QDRANT_API_KEY", ""), help="Qdrant API key")
    parser.add_argument("--qdrant-path", default=os.getenv("QDRANT_PATH", ""), help="Local Qdrant path when URL empty")
    parser.add_argument("--qdrant-batch-size", type=int, default=DEFAULT_QDRANT_BATCH, help=f"Qdrant upsert chunk size (default: {DEFAULT_QDRANT_BATCH})")
    parser.add_argument("--data-dir", default="data", help="Input data directory")
    parser.add_argument("--vector-size", type=int, default=DEFAULT_VECTOR_DIM, help=f"Vector size (default: {DEFAULT_VECTOR_DIM})")
    parser.add_argument("--text-field", default=os.getenv("QDRANT_TEXT_FIELD", "text"), help="Payload text field")
    parser.add_argument("--dataset-quota", type=int, default=_env_int("GRAPHRAG_DATASET_QUOTA", 150000))
    parser.add_argument("--corr-quota", type=int, default=_env_int("GRAPHRAG_CORR_QUOTA", 50000))
    parser.add_argument("--cooc-quota", type=int, default=_env_int("GRAPHRAG_COOC_QUOTA", 70000))
    parser.add_argument("--max-total", type=int, default=_env_int("GRAPHRAG_MAX_TOTAL_CHUNKS", 0))
    args = parser.parse_args()

    cpu_threads = max(1, os.cpu_count() or 1)
    torch.set_num_threads(cpu_threads)
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    _disable_hf_progress()

    quotas = Quotas(
        dataset=max(0, args.dataset_quota),
        correlation=max(0, args.corr_quota),
        cooccurrence=max(0, args.cooc_quota),
        total=max(0, args.max_total),
    )
    target = _estimate_target(args.max_vectors, quotas)
    if target > 0:
        _log(
            f"Estimated raw vector footprint: dim({args.vector_size}) * 4 * vectors({target}) = "
            f"{_human_bytes(_estimate_bytes(args.vector_size, target))}"
        )

    _log(f"Runtime: model={args.model_name} device=cpu torch_threads={cpu_threads} interop=1")
    model = SentenceTransformer(args.model_name, device="cpu")

    url = (args.qdrant_url or "").strip()
    api_key = (args.qdrant_api_key or "").strip() or None
    local_path = (args.qdrant_path or "").strip() or None
    client = _open_qdrant_client(url=url, api_key=api_key, local_path=local_path)
    _ensure_collection(client, args.collection_name, args.vector_size)

    started = time.perf_counter()
    processed = 0
    skipped = 0
    data_dir = Path(args.data_dir)
    chunk_iter = _stream_chunks(data_dir=data_dir, quotas=quotas)

    def log_progress(force: bool = False) -> None:
        if processed <= 0:
            return
        if not force and (processed % LOG_EVERY) != 0:
            return
        elapsed = max(1e-6, time.perf_counter() - started)
        rate = processed / elapsed
        eta_text = "--:--:--"
        if target > 0 and rate > 0:
            remaining = max(0, target - processed)
            eta_text = _fmt_eta(int(remaining / rate))
        _log(
            f"processed={processed}"
            + (f"/{target}" if target > 0 else "")
            + f" embeddings/sec={rate:.2f} elapsed={_fmt_secs(elapsed)} eta={eta_text}"
        )

    try:
        for batch in _iter_batches(chunk_iter, args.batch_size):
            if args.max_vectors > 0 and processed >= args.max_vectors:
                break

            if args.resume_from > 0 and skipped < args.resume_from:
                to_skip = min(len(batch), args.resume_from - skipped)
                skipped += to_skip
                if to_skip == len(batch):
                    continue
                batch = batch[to_skip:]

            if not batch:
                continue

            queue: list[list[dict[str, Any]]] = [batch]
            while queue:
                part = queue.pop(0)
                if not part:
                    continue
                if args.max_vectors > 0 and processed >= args.max_vectors:
                    break
                if args.max_vectors > 0 and processed + len(part) > args.max_vectors:
                    part = part[: args.max_vectors - processed]

                texts = [str(c.get("text", "")) for c in part]
                try:
                    with torch.inference_mode():
                        vectors = model.encode(
                            texts,
                            batch_size=len(part),
                            normalize_embeddings=True,
                            show_progress_bar=False,
                            convert_to_tensor=True,
                        )
                except MemoryError:
                    if len(part) <= 1:
                        _log(f"MemoryError on single-row batch, skipping chunk_id={part[0].get('id', 'unknown')}")
                        continue
                    mid = max(1, len(part) // 2)
                    queue.insert(0, part[mid:])
                    queue.insert(0, part[:mid])
                    continue
                except RuntimeError as exc:
                    if _is_oom(exc) and len(part) > 1:
                        mid = max(1, len(part) // 2)
                        queue.insert(0, part[mid:])
                        queue.insert(0, part[:mid])
                        continue
                    raise

                points: list[PointStruct] = []
                for idx, chunk in enumerate(part):
                    vector = vectors[idx].tolist()
                    if len(vector) != args.vector_size:
                        raise RuntimeError(
                            f"Embedding dim mismatch: model produced {len(vector)}, expected {args.vector_size}."
                        )
                    point_id = str(uuid.uuid5(uuid.NAMESPACE_URL, str(chunk.get("id", ""))))
                    payload = _chunk_metadata(chunk, text_field=args.text_field)
                    points.append(PointStruct(id=point_id, vector=vector, payload=payload))

                for i in range(0, len(points), max(1, args.qdrant_batch_size)):
                    slice_points = points[i : i + max(1, args.qdrant_batch_size)]
                    client.upsert(collection_name=args.collection_name, points=slice_points, wait=True)

                processed += len(part)
                del vectors
                del points
                del texts
                log_progress()

            if args.max_vectors > 0 and processed >= args.max_vectors:
                break
    except MemoryError:
        _log("Fatal MemoryError: stopping gracefully.")
        return 1

    elapsed = max(1e-6, time.perf_counter() - started)
    rate = processed / elapsed
    log_progress(force=True)
    _log(
        f"Complete: processed={processed}, skipped={skipped}, elapsed={_fmt_secs(elapsed)}, "
        f"throughput={rate:.2f} embeddings/sec, collection={args.collection_name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
