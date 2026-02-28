from __future__ import annotations

import os
from typing import Any

import requests


class PineconeHTTPIndex:
    """
    Minimal Pinecone HTTP fallback used when the official SDK is unavailable.
    """

    def __init__(self, host: str, api_key: str):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self._session = requests.Session()
        # Ignore broken proxy env in local shells unless explicitly handled by caller.
        self._session.trust_env = False

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.host}{path}"
        headers = {
            "Api-Key": self.api_key,
            "Content-Type": "application/json",
        }
        resp = self._session.request(method=method, url=url, headers=headers, json=payload, timeout=120)
        if resp.status_code >= 400:
            raise RuntimeError(f"Pinecone HTTP {resp.status_code}: {resp.text[:300]}")
        if not resp.text:
            return {}
        try:
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def describe_index_stats(self) -> dict[str, Any]:
        # Legacy/stat endpoint compatibility.
        try:
            return self._request("POST", "/describe_index_stats", payload={})
        except Exception:
            return self._request("GET", "/describe_index_stats", payload=None)

    def upsert_records(self, namespace: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        path = f"/records/namespaces/{namespace}/upsert"
        if isinstance(records, dict):
            return self._request("POST", path, payload=records)
        upserted = 0
        for record in records:
            self._request("POST", path, payload=record)
            upserted += 1
        return {"upserted_count": upserted}

    def search_records(self, namespace: str, query: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/records/namespaces/{namespace}/search",
            payload={"query": query},
        )

    def upsert(self, vectors: list[dict[str, Any]], namespace: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"vectors": vectors}
        if namespace:
            body["namespace"] = namespace
        return self._request("POST", "/vectors/upsert", payload=body)

    def query(
        self,
        *,
        namespace: str | None,
        vector: list[float],
        top_k: int,
        include_metadata: bool,
    ) -> dict[str, Any]:
        # Try legacy body shape first.
        body_legacy: dict[str, Any] = {
            "vector": vector,
            "topK": top_k,
            "includeMetadata": include_metadata,
        }
        if namespace:
            body_legacy["namespace"] = namespace
        try:
            return self._request("POST", "/query", payload=body_legacy)
        except Exception:
            body_modern: dict[str, Any] = {
                "vector": vector,
                "top_k": top_k,
                "include_metadata": include_metadata,
            }
            if namespace:
                body_modern["namespace"] = namespace
            return self._request("POST", "/query", payload=body_modern)


def get_pinecone_index(required: bool = False) -> Any | None:
    api_key = os.getenv("PINECONE_API_KEY", "").strip()
    host = os.getenv("PINECONE_HOST", "").strip()
    if not api_key or not host:
        if required:
            missing = []
            if not api_key:
                missing.append("PINECONE_API_KEY")
            if not host:
                missing.append("PINECONE_HOST")
            raise RuntimeError(f"Missing required Pinecone env: {', '.join(missing)}")
        return None

    # Preferred path: official SDK
    try:
        from pinecone import Pinecone

        pc = Pinecone(api_key=api_key)
        return pc.Index(host=host)
    except Exception:
        # Fallback path: direct HTTP API client
        return PineconeHTTPIndex(host=host, api_key=api_key)
