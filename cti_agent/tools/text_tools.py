"""Document-passage retrieval.

The project already has a hybrid retriever from Milestones 7-8. Because this
module cannot assume its function name, it supports two ways to connect it:

1. Set RAG_RETRIEVER=package.module:function in .env. The function is called
   as fn(question, top_k=N) (or fn(question, N) / fn(question)) and may return
   dicts, tuples or objects with text / chunk_id / doc_id / score.
2. If it is not set, a fallback searches TextUnit nodes inside Neo4j.

Run scripts/probe_rag_api.py to list the retrieval functions in your rag package.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ..schema_map import Runner, SchemaMap
from . import graph_tools

TEXT_KEYS = ("text", "chunk_text", "content", "page_content", "body")
ID_KEYS = ("chunk_id", "id", "chunk")
DOC_KEYS = ("doc_id", "document_id", "source", "doc", "title", "url")
SCORE_KEYS = ("score", "rrf_score", "bm25", "similarity", "distance")


@dataclass
class TextHit:
    text: str
    chunk_id: str = ""
    doc_id: str = ""
    score: float | None = None


class TextRetriever(Protocol):
    name: str

    def retrieve(self, question: str, top_k: int) -> list[TextHit]: ...


def _get(obj: Any, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if isinstance(obj, dict):
            if obj.get(key) not in (None, ""):
                return obj[key]
        elif getattr(obj, key, None) not in (None, ""):
            return getattr(obj, key)
    return None


def normalize_hits(raw: Any, top_k: int) -> list[TextHit]:
    hits: list[TextHit] = []
    for item in list(raw or [])[:top_k]:
        if isinstance(item, tuple) and item:
            # (hit, score) or (score, hit)
            first, second = item[0], item[1] if len(item) > 1 else None
            if isinstance(first, (int, float)) and second is not None:
                item, score = second, float(first)
            else:
                item, score = first, (float(second) if isinstance(second, (int, float)) else None)
        else:
            score = None
        if isinstance(item, str):
            hits.append(TextHit(text=item, score=score))
            continue
        text = _get(item, TEXT_KEYS)
        if not text:
            continue
        raw_score = _get(item, SCORE_KEYS)
        hits.append(TextHit(
            text=str(text),
            chunk_id=str(_get(item, ID_KEYS) or ""),
            doc_id=str(_get(item, DOC_KEYS) or ""),
            score=score if score is not None else (float(raw_score) if isinstance(raw_score, (int, float)) else None),
        ))
    return hits


class FunctionRetriever:
    def __init__(self, fn: Callable[..., Any], name: str):
        self._fn = fn
        self.name = name

    def retrieve(self, question: str, top_k: int) -> list[TextHit]:
        last_error: Exception | None = None
        for call in (lambda: self._fn(question, top_k=top_k),
                     lambda: self._fn(question, top_k),
                     lambda: self._fn(question)):
            try:
                return normalize_hits(call(), top_k)
            except TypeError as exc:
                last_error = exc
        raise RuntimeError(f"Could not call {self.name}: {last_error}")


class Neo4jTextUnitRetriever:
    """Fallback: keyword search over TextUnit nodes stored in the graph."""

    name = "neo4j-textunit-fallback"

    def __init__(self, runner: Runner, schema: SchemaMap):
        self._runner, self._schema = runner, schema

    def retrieve(self, question: str, top_k: int) -> list[TextHit]:
        words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-\.]{3,}", question)]
        rows = graph_tools.textunits_matching(self._runner, self._schema, words[:8], limit=top_k)
        hits = []
        for row in rows:
            props = row.get("props") or {}
            text = next((str(props[k]) for k in self._schema.text_props if props.get(k)), "")
            if text:
                hits.append(TextHit(text=text, chunk_id=str(props.get("id") or props.get("chunk_id") or row.get("eid", "")),
                                    doc_id=str(props.get("doc_id") or props.get("document_id") or "")))
        return hits


class NullRetriever:
    name = "none"

    def retrieve(self, question: str, top_k: int) -> list[TextHit]:
        return []


def load_retriever(spec: str, runner: Runner | None = None, schema: SchemaMap | None = None) -> TextRetriever:
    if spec:
        module_name, _, func_name = spec.partition(":")
        if not module_name or not func_name:
            raise ValueError("RAG_RETRIEVER must look like package.module:function")
        module = importlib.import_module(module_name)
        return FunctionRetriever(getattr(module, func_name), spec)
    if runner is not None and schema is not None and schema.textunit_label:
        return Neo4jTextUnitRetriever(runner, schema)
    return NullRetriever()
