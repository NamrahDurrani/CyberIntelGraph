"""BM25 keyword search (Milestone 8) - pure Python + NumPy, no new install.

Why a custom tokenizer?  Ordinary tokenizers split "CVE-2024-3400" into "cve", "2024",
"3400" and "T1059.001" into "t1059", "001", which destroys the very identifiers we want
to match exactly.  This tokenizer keeps every identifier as ONE token:

    CVE-2024-3400   -> "cve-2024-3400"
    CWE-79          -> "cwe-79"
    T1059.001       -> "t1059.001" and also its parent "t1059"
    AA20-302A       -> "aa20-302a"

The index is rebuilt in memory from the chunk file on start-up (about a second for a few
thousand chunks), so there is no second index file that could go stale.
"""
from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np

# Different Unicode dashes occasionally appear inside identifiers in scraped HTML.
_DASHES = re.compile("[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]")

_ID_TOKEN = re.compile(
    r"(?<![a-z0-9])(?:"
    r"cve-\d{4}-\d{4,7}(?![0-9])"          # CVE
    r"|cwe-\d{1,5}(?![0-9])"                # CWE
    r"|aa\d{2}-\d{3}[a-z](?![a-z0-9])"      # CISA advisory id such as aa20-302a
    r"|t\d{4}(?:\.\d{3})?(?![a-z0-9])"      # ATT&CK technique / sub-technique
    r")"
)
_WORD = re.compile(r"[a-z0-9]+")

STOPWORDS = frozenset("""a an and are as at be by for from has have in is it its of on or that the
this to was were which what who whom with about does did do used use""".split())


def normalise_text(text: str) -> str:
    return _DASHES.sub("-", text or "").lower()


def tokenize(text: str) -> list[str]:
    """Identifier-preserving tokens (lower-case). Stop-words are removed."""
    t = normalise_text(text)
    tokens: list[str] = []
    for m in _ID_TOKEN.finditer(t):
        tok = m.group(0)
        tokens.append(tok)
        if tok.startswith("t") and "." in tok:        # t1059.001 also counts as t1059
            tokens.append(tok.split(".")[0])
    rest = _ID_TOKEN.sub(" ", t)        # identifiers are NOT also split into loose pieces
    tokens.extend(w for w in _WORD.findall(rest) if w not in STOPWORDS)
    return tokens


class BM25Index:
    """Okapi BM25.  rows are 0..N-1 in the order of the texts given to the constructor."""

    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.n = len(texts)
        self.postings: dict[str, list[tuple[int, int]]] = {}
        lengths = np.zeros(self.n, dtype=np.float32)
        for row, text in enumerate(texts):
            counts = Counter(tokenize(text))
            lengths[row] = sum(counts.values())
            for term, tf in counts.items():
                self.postings.setdefault(term, []).append((row, tf))
        self.lengths = lengths
        self.avgdl = float(lengths.mean()) if self.n else 0.0
        self.idf = {term: math.log(1.0 + (self.n - len(p) + 0.5) / (len(p) + 0.5))
                    for term, p in self.postings.items()}

    def __len__(self):
        return self.n

    def scores(self, query: str) -> np.ndarray:
        """BM25 score of every row for the query (0 where no query term occurs)."""
        out = np.zeros(self.n, dtype=np.float32)
        if not self.n or not self.avgdl:
            return out
        for term in set(tokenize(query)):
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf[term]
            for row, tf in postings:
                norm = tf + self.k1 * (1.0 - self.b + self.b * self.lengths[row] / self.avgdl)
                out[row] += idf * tf * (self.k1 + 1.0) / norm
        return out

    def search(self, query: str, k: int = 5) -> list[tuple[int, float]]:
        """Top-k (row, score) with score > 0, best first; ties are broken by row."""
        s = self.scores(query)
        order = np.lexsort((np.arange(self.n), -s))[:max(1, k)]
        return [(int(i), float(s[i])) for i in order if s[i] > 0]
