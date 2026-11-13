"""Embedding models. The rest of the code only needs:
    name, embed_documents(list[str]) -> ndarray, embed_query(str) -> ndarray
so a hosted embedding service can replace the local model later."""
from __future__ import annotations

from rag import DEFAULT_EMBEDDING_MODEL


class SentenceTransformerEmbedder:
    """Small local model (about 130 MB). Embeddings are L2-normalised, so a dot
    product equals cosine similarity."""

    def __init__(self, model_name: str = DEFAULT_EMBEDDING_MODEL, batch_size: int = 32,
                 device: str = "cpu",
                 query_prefix: str = "Represent this sentence for searching relevant passages: "):
        from sentence_transformers import SentenceTransformer   # imported lazily (slow)
        self.name = model_name
        self.batch_size = batch_size
        self.query_prefix = query_prefix
        self.model = SentenceTransformer(model_name, device=device)
        self.model.max_seq_length = 512

    def embed_documents(self, texts):
        return self.model.encode(list(texts), batch_size=self.batch_size, convert_to_numpy=True,
                                 normalize_embeddings=True, show_progress_bar=True)

    def embed_query(self, text):
        return self.model.encode([self.query_prefix + text], convert_to_numpy=True,
                                 normalize_embeddings=True, show_progress_bar=False)[0]
