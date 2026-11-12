"""Parsers: turn one document file into a flat list of Blocks.

DoclingParser is the production parser (Milestone 6). The chunker only needs the
small interface  parse(path) -> list[Block]  so another parser can be swapped in.
"""
from __future__ import annotations

import importlib.metadata
import logging
from collections import Counter

from documents.chunking import Block

TEXT_LABELS = {"text", "paragraph", "list_item", "caption", "code"}
SKIP_LABELS = {"page_header", "page_footer", "footnote", "picture", "formula",
               "checkbox_selected", "checkbox_unselected", "reference"}


def _label(item) -> str:
    lab = getattr(item, "label", "")
    return str(getattr(lab, "value", lab)).lower()


def _page(item):
    prov = getattr(item, "prov", None)
    if prov:
        return getattr(prov[0], "page_no", None)
    return None


def _table_markdown(item, doc) -> str:
    try:
        return item.export_to_markdown(doc=doc)
    except TypeError:                       # older docling-core signature
        return item.export_to_markdown()


def docling_to_blocks(doc) -> tuple[list[Block], Counter]:
    """Convert a DoclingDocument into Blocks (reading order). Returns (blocks, skipped)."""
    blocks: list[Block] = []
    skipped: Counter = Counter()
    for entry in doc.iterate_items():
        item = entry[0] if isinstance(entry, tuple) else entry
        label = _label(item)
        text = (getattr(item, "text", "") or "").strip()
        if label == "title":
            blocks.append(Block("heading", text, 0, _page(item)))
        elif label == "section_header":
            level = int(getattr(item, "level", 1) or 1)
            blocks.append(Block("heading", text, max(level, 1), _page(item)))
        elif label == "table":
            blocks.append(Block("table", _table_markdown(item, doc).strip(), 0, _page(item)))
        elif label in TEXT_LABELS:
            if label == "list_item":
                text = "- " + text
            blocks.append(Block("text", text, 0, _page(item)))
        else:
            skipped[label or "group"] += 1
    return blocks, skipped


class DoclingParser:
    """HTML-only Docling converter: no layout or table AI models are loaded or
    downloaded, which keeps the install small (decision 0007)."""
    name = "docling"

    def __init__(self):
        logging.getLogger("docling").setLevel(logging.WARNING)
        from docling.datamodel.base_models import InputFormat
        from docling.document_converter import DocumentConverter
        self._converter = DocumentConverter(allowed_formats=[InputFormat.HTML])
        self.version = importlib.metadata.version("docling")
        self.last_skipped: Counter = Counter()

    def parse(self, path) -> list[Block]:
        result = self._converter.convert(str(path))
        blocks, self.last_skipped = docling_to_blocks(result.document)
        return blocks
