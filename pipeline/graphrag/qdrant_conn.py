from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def get_qdrant_client(required: bool = False) -> Any | None:
    try:
        from qdrant_client import QdrantClient
    except Exception:
        if required:
            raise RuntimeError("qdrant-client is not installed. Add `qdrant-client` to requirements.")
        return None

    url = os.getenv("QDRANT_URL", "").strip()
    api_key = os.getenv("QDRANT_API_KEY", "").strip() or None
    if url:
        return QdrantClient(url=url, api_key=api_key)

    path = os.getenv("QDRANT_PATH", str(Path("data") / "qdrant"))
    Path(path).mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=path)
