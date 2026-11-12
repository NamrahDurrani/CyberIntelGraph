"""Parser-independent chunker.

A parser (Docling today, anything else tomorrow) turns a document into a flat
list of Blocks. This module turns Blocks into Chunks. It knows nothing about
Docling, HTML or files, so it is deterministic and easy to test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
SENT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")


@dataclass
class Block:
    kind: str                 # heading | text | table
    text: str
    level: int = 0            # headings only: 0 = title, 1.. = section depth
    page: int | None = None


@dataclass
class Chunk:
    index: int
    heading_path: list[str]
    text: str
    page_start: int | None = None
    page_end: int | None = None
    kinds: list[str] = field(default_factory=list)

    @property
    def words(self) -> int:
        return len(self.text.split())


def words(text: str) -> int:
    return len(text.split())


def split_long_text(text: str, max_words: int) -> list[str]:
    """Split on sentence boundaries; a single over-long sentence is split by words."""
    if words(text) <= max_words:
        return [text]
    out, cur, cur_w = [], [], 0
    for sent in SENT_RE.split(text):
        sw = words(sent)
        if sw > max_words:                      # pathological sentence
            if cur:
                out.append(" ".join(cur)); cur, cur_w = [], 0
            toks = sent.split()
            for i in range(0, len(toks), max_words):
                out.append(" ".join(toks[i:i + max_words]))
            continue
        if cur_w + sw > max_words and cur:
            out.append(" ".join(cur)); cur, cur_w = [], 0
        cur.append(sent); cur_w += sw
    if cur:
        out.append(" ".join(cur))
    return out


def split_table(md: str, max_words: int) -> list[str]:
    """Split a markdown table by rows, repeating the header row in every piece."""
    if words(md) <= max_words:
        return [md]
    lines = [ln for ln in md.splitlines() if ln.strip()]
    if len(lines) < 3:
        return split_long_text(md, max_words)
    head, rows = lines[:2], lines[2:]
    out, cur = [], []
    budget = max_words - words("\n".join(head))
    cur_w = 0
    for row in rows:
        rw = words(row)
        if cur and cur_w + rw > budget:
            out.append("\n".join(head + cur)); cur, cur_w = [], 0
        cur.append(row); cur_w += rw
    if cur:
        out.append("\n".join(head + cur))
    return out


def chunk_blocks(blocks: list[Block], max_words: int = 250, min_words: int = 8
                 ) -> tuple[list[Chunk], dict]:
    """Group blocks into chunks that never cross a heading and never exceed max_words
    (a table row or sentence limit aside). Chunks under min_words are dropped unless
    they mention a CVE or ATT&CK technique id. Returns (chunks, stats)."""
    stats = {"dropped_tiny": 0, "split_long_blocks": 0, "tables": 0}
    stack: list[tuple[int, str]] = []        # (level, heading text)
    chunks: list[Chunk] = []
    cur_text: list[str] = []
    cur_pages: list[int] = []
    cur_kinds: list[str] = []
    cur_path: list[str] = []

    def path() -> list[str]:
        return [h for _, h in stack]

    def flush():
        nonlocal cur_text, cur_pages, cur_kinds
        if not cur_text:
            return
        text = "\n\n".join(cur_text).strip()
        keep = words(text) >= min_words or CVE_RE.search(text) or TECH_RE.search(text)
        if keep and text:
            chunks.append(Chunk(index=0, heading_path=list(cur_path), text=text,
                                page_start=min(cur_pages) if cur_pages else None,
                                page_end=max(cur_pages) if cur_pages else None,
                                kinds=sorted(set(cur_kinds))))
        else:
            stats["dropped_tiny"] += 1
        cur_text, cur_pages, cur_kinds = [], [], []

    def add(piece: str, kind: str, page: int | None):
        nonlocal cur_path
        if not cur_text:
            cur_path = path()
        if cur_text and words("\n\n".join(cur_text + [piece])) > max_words:
            flush()
            cur_path = path()
        cur_text.append(piece)
        cur_kinds.append(kind)
        if page is not None:
            cur_pages.append(page)

    for b in blocks:
        text = (b.text or "").strip()
        if not text:
            continue
        if b.kind == "heading":
            flush()
            while stack and stack[-1][0] >= b.level:
                stack.pop()
            stack.append((b.level, text))
            continue
        if b.kind == "table":
            stats["tables"] += 1
            flush()
            for piece in split_table(text, max_words):
                add(piece, "table", b.page)
                flush()
            continue
        pieces = split_long_text(text, max_words)
        if len(pieces) > 1:
            stats["split_long_blocks"] += 1
        for piece in pieces:
            add(piece, "text", b.page)
    flush()
    for i, c in enumerate(chunks, start=1):
        c.index = i
    return chunks, stats


def embedding_text(heading_path: list[str], text: str) -> str:
    """Text to embed: the heading path gives each chunk its context."""
    return (" > ".join(heading_path) + "\n" + text) if heading_path else text
