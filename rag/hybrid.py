"""Hybrid retrieval (Milestone 8): meaning search + keyword search + identifier lookup.

Four modes, so every claim can be measured against the others (see rag/compare.py):

    dense       Milestone 7 behaviour: embeddings only
    bm25        keyword search only (needs no embedding model)
    hybrid      dense and BM25 merged with Reciprocal Rank Fusion (RRF)
    hybrid_ids  hybrid + a lookup tier for identifiers written in the question

Reciprocal Rank Fusion: every ranked list gives a chunk  weight / (rrf_k + rank)  points;
points are added up across lists.  A chunk that is high in BOTH lists wins, and the raw
scores (cosine vs BM25) never have to be put on a common scale.

Keyword weight (8.1): if the question names a CVE or technique id, BM25 votes id_weight (3x)
as strongly, because embeddings are blind to identifiers.

Identifier tier (hybrid_ids): if the question contains CVE-2024-3400, T1059.001 or
AA20-302A, chunks whose structured fields (cve_ids / technique_ids / doc_id) contain that
identifier receive a bonus larger than anything RRF can award, so they are listed first.
Within the bonus group the normal fused order decides.  If the identifier is not in any
chunk, nothing happens and the result equals plain `hybrid`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np

from rag.bm25 import BM25Index
from rag.index import VectorIndex
from rag.retrieve import Hit

MODES = ("dense", "bm25", "hybrid", "hybrid_ids")

_CVE_Q = re.compile(r"(?<![A-Za-z0-9])CVE[-\u2010-\u2015\u2212]\d{4}[-\u2010-\u2015\u2212]\d{4,7}(?![0-9])", re.I)
_TECH_Q = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9])", re.I)
_ADV_Q = re.compile(r"(?<![A-Za-z0-9])AA\d{2}[-\u2010-\u2015\u2212]\d{3}[A-Z](?![A-Za-z0-9])", re.I)
_ADV_DOC = re.compile(r"aa\d{2}-\d{3}[a-z]")
_DASH = re.compile("[\u2010-\u2015\u2212]")


def extract_identifiers(question: str) -> dict[str, list[str]]:
    """Identifiers written in a question: CVE / technique ids upper-case, advisory ids lower-case."""
    def uniq(items):
        return list(dict.fromkeys(items))
    q = _DASH.sub("-", question or "")
    return {"cve": uniq(m.group(0).upper() for m in _CVE_Q.finditer(q)),
            "technique": uniq(m.group(0).upper() for m in _TECH_Q.finditer(q)),
            "advisory": uniq(m.group(0).lower() for m in _ADV_Q.finditer(q))}


@dataclass
class HybridHit(Hit):
    """A Hit that also says HOW it was found (shown by ask.py)."""
    dense_rank: int | None = None
    bm25_rank: int | None = None
    id_matches: list[str] = field(default_factory=list)

    @property
    def via(self) -> str:
        parts = []
        if self.dense_rank:
            parts.append(f"dense#{self.dense_rank}")
        if self.bm25_rank:
            parts.append(f"bm25#{self.bm25_rank}")
        if self.id_matches:
            parts.append("id:" + ",".join(self.id_matches))
        return " ".join(parts) or "-"


class HybridRetriever:
    """Same interface as rag.retrieve.Retriever: retrieve(question, k) -> list[Hit]."""

    def __init__(self, index: VectorIndex, chunks: list[dict], embedder=None, mode: str = "hybrid_ids",
                 rrf_k: int = 60, depth: int = 100, w_dense: float = 1.0, w_bm25: float = 1.0,
                 exact_boost: float = 0.10, related_boost: float = 0.05, id_weight: float = 3.0):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if mode in ("dense", "hybrid", "hybrid_ids") and embedder is None:
            raise ValueError(f"mode '{mode}' needs an embedder")
        self.index, self.embedder, self.mode = index, embedder, mode
        self.rrf_k, self.depth, self.w_dense, self.w_bm25 = rrf_k, depth, w_dense, w_bm25
        self.exact_boost, self.related_boost = exact_boost, related_boost
        self.id_weight = id_weight
        self.by_id = {c["chunk_id"]: c for c in chunks}
        missing = [i for i in index.ids if i not in self.by_id]
        if missing:
            raise ValueError(f"{len(missing)} indexed chunk ids are missing from the chunk file "
                             f"(e.g. {missing[0]}) - rebuild the index")
        self.rows = [self.by_id[i] for i in index.ids]        # row r of the index -> chunk
        self._bm25: BM25Index | None = None
        self._id_maps = None
        self._qcache: dict[str, np.ndarray] = {}

    # ----- lazily built helpers ------------------------------------------------------
    @property
    def bm25(self) -> BM25Index:
        if self._bm25 is None:
            self._bm25 = BM25Index([c.get("embedding_text") or c.get("text", "") for c in self.rows])
        return self._bm25

    def _maps(self):
        if self._id_maps is None:
            cve, tech, child, adv = {}, {}, {}, {}
            for r, c in enumerate(self.rows):
                for x in c.get("cve_ids") or []:
                    cve.setdefault(x.upper(), []).append(r)
                for x in c.get("technique_ids") or []:
                    x = x.upper()
                    tech.setdefault(x, []).append(r)
                    if "." in x:
                        child.setdefault(x.split(".")[0], []).append(r)
                for a in set(_ADV_DOC.findall((c.get("doc_id") or "").lower())):
                    adv.setdefault(a, []).append(r)
            self._id_maps = (cve, tech, child, adv)
        return self._id_maps

    def _qvec(self, question: str) -> np.ndarray:
        if question not in self._qcache:
            v = np.asarray(self.embedder.embed_query(question), dtype=np.float32)
            n = float(np.linalg.norm(v))
            self._qcache[question] = v / n if n else v
        return self._qcache[question]

    def id_bonuses(self, question: str) -> dict[int, tuple[float, list[str]]]:
        """row -> (bonus, [identifiers that caused it]) for identifiers found in the question."""
        ids = extract_identifiers(question)
        cve, tech, child, adv = self._maps()
        out: dict[int, tuple[float, list[str]]] = {}

        def give(rows, bonus, label):
            for r in rows:
                b, labels = out.get(r, (0.0, []))
                out[r] = (b + bonus, labels + [label])
        for x in ids["cve"]:
            give(cve.get(x, []), self.exact_boost, x)
        for x in ids["technique"]:
            give(tech.get(x, []), self.exact_boost, x)
            if "." in x:                                   # sub-technique -> its parent is related
                give(tech.get(x.split(".")[0], []), self.related_boost, x.split(".")[0] + "~")
            else:                                          # parent -> its sub-techniques are related
                give(child.get(x, []), self.related_boost, x + ".*~")
        for x in ids["advisory"]:
            give(adv.get(x, []), self.related_boost, x.upper())
        return out

    # ----- main entry ----------------------------------------------------------------
    def retrieve(self, question: str, k: int = 5) -> list[Hit]:
        n = len(self.rows)
        k = max(1, min(k, n))
        if self.mode == "dense":
            return [HybridHit(rank=r, score=s, chunk=self.rows[row], dense_rank=r)
                    for r, (row, s) in enumerate(self.index.search(self._qvec(question), k), start=1)]
        if self.mode == "bm25":
            return [HybridHit(rank=r, score=s, chunk=self.rows[row], bm25_rank=r)
                    for r, (row, s) in enumerate(self.bm25.search(question, k), start=1)]

        depth = max(self.depth, k)
        dense_rank, bm25_rank = {}, {}
        for r, (row, _) in enumerate(self.index.search(self._qvec(question), depth), start=1):
            dense_rank[row] = r
        for r, (row, _) in enumerate(self.bm25.search(question, depth), start=1):
            bm25_rank[row] = r
        # Milestone 8.1: when the question names a CVE or technique id, the embedding search is
        # blind to it (it measured 0.025 doc-hit@1 on technique ids) so the keyword list gets
        # id_weight times the voting power. Advisory ids alone do not change the weights.
        ids = extract_identifiers(question)
        w_bm25 = self.w_bm25 * (self.id_weight if (ids["cve"] or ids["technique"]) else 1.0)
        fused: dict[int, float] = {}
        for row, r in dense_rank.items():
            fused[row] = fused.get(row, 0.0) + self.w_dense / (self.rrf_k + r)
        for row, r in bm25_rank.items():
            fused[row] = fused.get(row, 0.0) + w_bm25 / (self.rrf_k + r)
        bonuses = self.id_bonuses(question) if self.mode == "hybrid_ids" else {}
        for row, (b, _) in bonuses.items():
            # a bonus row may be outside both depth lists; it still enters the pool
            fused[row] = fused.get(row, 0.0) + b
        order = sorted(fused, key=lambda r: (-fused[r], r))[:k]
        return [HybridHit(rank=i, score=fused[row], chunk=self.rows[row],
                          dense_rank=dense_rank.get(row), bm25_rank=bm25_rank.get(row),
                          id_matches=bonuses.get(row, (0.0, []))[1])
                for i, row in enumerate(order, start=1)]
