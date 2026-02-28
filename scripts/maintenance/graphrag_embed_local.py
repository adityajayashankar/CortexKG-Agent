from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
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

from pipeline.graphrag.embeddings import embed_texts, embedding_runtime_info
from pipeline.graphrag.indexer import (
    COOC_QUOTA,
    CORR_QUOTA,
    DATASET_QUOTA,
    MAX_TOTAL_CHUNKS,
    PINECONE_TEXT_FIELD,
    _pinecone_metadata,
    iter_evidence_chunks,
)


DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"
DEFAULT_BATCH_SIZE = 64


def _log(msg: str) -> None:
    print(f"[graphrag-embed] {msg}", flush=True)


def _open_text_writer(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, mode="wt", encoding="utf-8")
    return path.open(mode="w", encoding="utf-8")


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


def _is_oom_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(token in msg for token in ["out of memory", "cannot allocate", "bad alloc", "memoryerror"])


def _fmt_eta(seconds: int) -> str:
    return f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"


def _fmt_bytes(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    kib = num_bytes / 1024
    if kib < 1024:
        return f"{kib:.2f} KiB"
    mib = kib / 1024
    if mib < 1024:
        return f"{mib:.2f} MiB"
    gib = mib / 1024
    return f"{gib:.2f} GiB"


def _estimate_total_vectors() -> int:
    if MAX_TOTAL_CHUNKS > 0:
        return MAX_TOTAL_CHUNKS
    total = 0
    for quota in (DATASET_QUOTA, COOC_QUOTA, CORR_QUOTA):
        if quota > 0:
            total += quota
    return total


def _embed_write_batch(
    batch: list[dict[str, Any]],
    writer,
) -> tuple[int, int]:
    """
    Embed + write a batch with OOM backoff.
    Returns (written_rows, embedding_dim).
    """
    if not batch:
        return 0, 0

    queue: list[list[dict[str, Any]]] = [batch]
    written = 0
    dim = 0

    while queue:
        part = queue.pop(0)
        try:
            vectors = embed_texts([c["text"] for c in part])
        except MemoryError as exc:
            if len(part) <= 1:
                _log(f"Skipping 1 chunk after MemoryError: {part[0].get('id', 'unknown')} ({exc})")
                continue
            half = max(1, len(part) // 2)
            _log(f"MemoryError on batch={len(part)}. Retrying with smaller chunks ({half}).")
            queue.insert(0, part[half:])
            queue.insert(0, part[:half])
            continue
        except RuntimeError as exc:
            if _is_oom_error(exc) and len(part) > 1:
                half = max(1, len(part) // 2)
                _log(f"OOM runtime error on batch={len(part)}. Retrying with smaller chunks ({half}).")
                queue.insert(0, part[half:])
                queue.insert(0, part[:half])
                continue
            raise

        if vectors and not dim:
            dim = len(vectors[0])

        for chunk, vector in zip(part, vectors):
            writer.write(
                json.dumps(
                    {
                        "id": str(chunk.get("id", "")),
                        "values": vector,
                        "metadata": _pinecone_metadata(chunk) | {PINECONE_TEXT_FIELD: chunk["text"]},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
        written += len(part)

    return written, dim


def main() -> int:
    parser = argparse.ArgumentParser(description="Build GraphRAG chunks and embed locally into a cache file.")
    parser.add_argument("--data-dir", default="data", help="Input data directory (default: data)")
    parser.add_argument(
        "--out",
        default="data/vector_cache/graphrag_vectors.jsonl.gz",
        help="Output cache file (.jsonl or .jsonl.gz)",
    )
    parser.add_argument(
        "--model-name",
        default=DEFAULT_MODEL_NAME,
        help=f"Embedding model name (default: {DEFAULT_MODEL_NAME})",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Local embedding batch size (default: {DEFAULT_BATCH_SIZE})",
    )
    args = parser.parse_args()
    os.environ["EMBEDDING_DEVICE"] = "cpu"
    os.environ["EMBEDDING_MODEL"] = args.model_name

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    info = embedding_runtime_info()
    _log(
        "Embedding runtime: "
        f"model={info['model_name']} requested_device={info['requested_device']} "
        f"resolved_device={info['resolved_device']}"
    )
    estimated_total = _estimate_total_vectors()
    if estimated_total > 0:
        _log(f"Estimated total vectors to embed: ~{estimated_total}")

    total = 0
    dim = 0
    est_footprint_logged = False

    with _open_text_writer(out_path) as f:
        streamed_chunks = iter_evidence_chunks(data_dir=args.data_dir)
        for batch in _iter_batches(streamed_chunks, args.batch_size):
            written, batch_dim = _embed_write_batch(batch, f)
            total += written
            if batch_dim and not dim:
                dim = batch_dim

            if dim and estimated_total > 0 and not est_footprint_logged:
                est_bytes = int(dim * 4 * estimated_total)
                _log(
                    f"Estimated raw vector footprint: dim({dim}) * 4 bytes * vectors({estimated_total}) = "
                    f"{_fmt_bytes(est_bytes)}"
                )
                est_footprint_logged = True

            elapsed = max(1e-6, time.perf_counter() - started)
            rate = total / elapsed
            if estimated_total > 0:
                remaining = max(0, estimated_total - total)
                eta = int(remaining / rate) if rate > 0 else 0
                _log(
                    f"Embedded {total}/{estimated_total} chunks (dim={dim}, embeddings/sec={rate:.2f}, eta={_fmt_eta(eta)})"
                )
            else:
                _log(f"Embedded {total} chunks (dim={dim}, embeddings/sec={rate:.2f})")

    elapsed = time.perf_counter() - started
    raw_bytes = int(dim * 4 * total) if dim and total else 0
    _log(
        "Embed cache complete: "
        f"rows={total}, dim={dim}, file={out_path}, elapsed={elapsed:.1f}s, "
        f"throughput={total / max(elapsed, 1e-6):.2f} embeddings/sec"
    )
    if raw_bytes > 0:
        _log(
            f"Raw vector memory footprint estimate: dim({dim}) * 4 bytes * vectors({total}) = {_fmt_bytes(raw_bytes)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
