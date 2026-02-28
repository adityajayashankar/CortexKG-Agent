from __future__ import annotations

import os
from typing import Any

_EMBEDDER: Any | None = None
_EMBEDDER_MODEL = ""


def _resolve_hf_embeddings_class():
    try:
        from langchain_huggingface import HuggingFaceEmbeddings

        return HuggingFaceEmbeddings
    except Exception:
        pass

    try:
        from langchain_community.embeddings import HuggingFaceEmbeddings

        return HuggingFaceEmbeddings
    except Exception:
        pass

    try:
        from langchain.embeddings import HuggingFaceEmbeddings

        return HuggingFaceEmbeddings
    except Exception:
        return None


def _model_name() -> str:
    requested = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5").strip()
    return requested or "BAAI/bge-small-en-v1.5"


def resolve_embedding_device() -> str:
    # CPU-only pipeline by design for predictable memory/throughput on constrained machines.
    return "cpu"


def embedding_runtime_info() -> dict[str, Any]:
    requested = os.getenv("EMBEDDING_DEVICE", "cpu").strip().lower() or "cpu"
    return {
        "model_name": _model_name(),
        "requested_device": requested,
        "resolved_device": resolve_embedding_device(),
    }


def download_embeddings():
    model_name = _model_name()
    device = resolve_embedding_device()
    HuggingFaceEmbeddings = _resolve_hf_embeddings_class()
    if HuggingFaceEmbeddings is not None:
        return HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": device},
            encode_kwargs={"normalize_embeddings": True},
        )

    class _SentenceTransformerAdapter:
        def __init__(self, name: str, run_device: str):
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(name, device=run_device)

        def embed_documents(self, texts: list[str]) -> list[list[float]]:
            vectors = self._model.encode(texts, normalize_embeddings=True)
            return [[float(x) for x in row.tolist()] for row in vectors]

        def embed_query(self, text: str) -> list[float]:
            return self.embed_documents([text])[0]

    return _SentenceTransformerAdapter(model_name, device)


def _get_embedder():
    global _EMBEDDER, _EMBEDDER_MODEL
    model_name = _model_name()
    if _EMBEDDER is None or _EMBEDDER_MODEL != model_name:
        _EMBEDDER = download_embeddings()
        _EMBEDDER_MODEL = model_name
    return _EMBEDDER


def embed_texts(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    model = _get_embedder()
    vectors = model.embed_documents([str(t or "") for t in texts])
    return [[float(x) for x in row] for row in vectors]


def embed_query(text: str) -> list[float]:
    model = _get_embedder()
    vector = model.embed_query(str(text or ""))
    return [float(x) for x in vector]
