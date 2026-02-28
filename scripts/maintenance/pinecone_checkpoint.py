from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)
except Exception:
    pass

from pipeline.graphrag.pinecone_client import get_pinecone_index


def _to_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        try:
            data = obj.to_dict()
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    if hasattr(obj, "model_dump"):
        try:
            data = obj.model_dump()
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def main() -> int:
    api_key = os.getenv("PINECONE_API_KEY", "").strip()
    host = os.getenv("PINECONE_HOST", "").strip()
    namespace = os.getenv("PINECONE_NAMESPACE", "default").strip() or "default"
    if not api_key or not host:
        print("Missing PINECONE_API_KEY or PINECONE_HOST")
        return 1

    index = get_pinecone_index(required=False)
    if index is None:
        print("Unable to initialize Pinecone client (SDK or HTTP fallback).")
        return 1

    stats = _to_dict(index.describe_index_stats())
    ns = (stats.get("namespaces") or {}).get(namespace, {})
    record_count = ns.get("record_count", ns.get("vector_count", 0))
    print(json.dumps({"namespace": namespace, "record_count": record_count, "host": host}, indent=2))

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        from pipeline.graphrag.retriever import retrieve_hybrid

        payload = retrieve_hybrid(
            query=query,
            entity=None,
            top_k=10,
            max_hops=2,
            use_vector=True,
        )
        print(json.dumps(payload.get("confidence_summary", {}), indent=2))
        print(f"direct={len(payload.get('direct_evidence', []))} inferred={len(payload.get('inferred_candidates', []))}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
