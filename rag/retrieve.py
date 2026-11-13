from __future__ import annotations

from dataclasses import dataclass

from rag.index import VectorIndex


@dataclass
class Hit:
    rank: int
    score: float
    chunk: dict

    @property
    def chunk_id(self) -> str:
        return self.chunk["chunk_id"]


class Retriever:
    def __init__(self, index: VectorIndex, chunks: list[dict], embedder):
        self.index, self.embedder = index, embedder
        self.by_id = {c["chunk_id"]: c for c in chunks}
        missing = [i for i in index.ids if i not in self.by_id]
        if missing:
            raise ValueError(f"{len(missing)} indexed chunk ids are missing from the chunk file "
                             f"(e.g. {missing[0]}) - rebuild the index")

    def retrieve(self, question: str, k: int = 5) -> list[Hit]:
        qvec = self.embedder.embed_query(question)
        return [Hit(rank=r, score=s, chunk=self.by_id[self.index.ids[row]])
                for r, (row, s) in enumerate(self.index.search(qvec, k), start=1)]
