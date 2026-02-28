from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)
except Exception:
    pass

from pipeline.graphrag.indexer import QDRANT_COLLECTION, UPSERT_BATCH_SIZE
from pipeline.graphrag.qdrant_conn import get_qdrant_client


def _log(msg: str) -> None:
    print(f"[graphrag-upsert] {msg}", flush=True)


def _open_text_reader(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8")
    return path.open(mode="r", encoding="utf-8")


def _iter_rows(path: Path) -> Iterator[dict]:
    with _open_text_reader(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("id") and isinstance(row.get("values"), list):
                yield row


def _count_rows(path: Path) -> int:
    n = 0
    for _ in _iter_rows(path):
        n += 1
    return n


def _upsert_batch(client, collection: str, rows: list[dict]) -> None:
    from qdrant_client.models import PointStruct

    points = [
        PointStruct(
            id=str(r.get("id", "")),
            vector=r.get("values", []),
            payload=r.get("metadata", {}) or {},
        )
        for r in rows
    ]
    client.upsert(collection_name=collection, points=points, wait=True)


def _extract_collection_dim(collection_info) -> int:
    try:
        vectors = collection_info.config.params.vectors
    except Exception:
        return 0
    if isinstance(vectors, dict):
        for _, cfg in vectors.items():
            size = getattr(cfg, "size", 0)
            if size:
                return int(size)
        return 0
    return int(getattr(vectors, "size", 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Upsert precomputed vector cache into Qdrant.")
    parser.add_argument(
        "--in",
        dest="in_path",
        default="data/vector_cache/graphrag_vectors.jsonl.gz",
        help="Input vector cache (.jsonl or .jsonl.gz)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=UPSERT_BATCH_SIZE,
        help=f"Upsert batch size (default: {UPSERT_BATCH_SIZE})",
    )
    parser.add_argument("--collection", default=QDRANT_COLLECTION, help="Qdrant collection")
    parser.add_argument("--limit", type=int, default=0, help="Optional row limit for smoke runs")
    args = parser.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        _log(f"Input cache file not found: {in_path}")
        return 1

    client = get_qdrant_client(required=True)
    collection = (args.collection or QDRANT_COLLECTION).strip() or QDRANT_COLLECTION

    probe_dim = 0
    for row in _iter_rows(in_path):
        probe_dim = len(row.get("values", []) or [])
        break
    if probe_dim <= 0:
        _log("No vectors found in cache file.")
        return 1

    try:
        info = client.get_collection(collection_name=collection)
        index_dim = _extract_collection_dim(info)
        if index_dim and index_dim != probe_dim:
            _log(
                f"Dimension mismatch: collection={index_dim}, cache_vectors={probe_dim}. "
                "Use a matching collection or regenerate vectors with matching model."
            )
            return 1
    except Exception:
        from qdrant_client.models import Distance, VectorParams

        _log(f"Collection '{collection}' not found. Creating with dim={probe_dim}")
        client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=probe_dim, distance=Distance.COSINE),
        )

    total_rows = _count_rows(in_path)
    if args.limit > 0:
        total_rows = min(total_rows, args.limit)
    _log(f"Upserting vectors from {in_path} to collection='{collection}' (rows={total_rows}, batch={args.batch_size})")

    started = time.perf_counter()
    upserted = 0
    batch: list[dict] = []
    for row in _iter_rows(in_path):
        if args.limit > 0 and upserted >= args.limit:
            break
        batch.append(row)
        if len(batch) >= max(1, args.batch_size):
            _upsert_batch(client, collection, batch)
            upserted += len(batch)
            batch = []
            elapsed = max(1e-6, time.perf_counter() - started)
            rate = upserted / elapsed
            remaining = max(0, total_rows - upserted)
            eta = int(remaining / rate) if rate > 0 else 0
            _log(
                f"Upserted {upserted}/{total_rows} vectors (rate={rate:.1f}/s, "
                f"eta={eta // 3600:02d}:{(eta % 3600) // 60:02d}:{eta % 60:02d})"
            )

    if batch:
        _upsert_batch(client, collection, batch)
        upserted += len(batch)

    elapsed = time.perf_counter() - started
    _log(f"Upsert complete: {upserted} vectors in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
