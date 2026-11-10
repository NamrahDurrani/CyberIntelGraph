"""Stable, deterministic canonical ids. Same input -> same id, every run."""
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def slug(text: str) -> str:
    """'Palo Alto Networks' and 'paloaltonetworks' both -> 'paloaltonetworks'."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def norm_cve(value: str) -> str:
    return value.strip().upper()


def norm_cwe(value) -> str | None:
    s = str(value).strip()
    if s.isdigit():
        return f"CWE-{int(s)}"
    m = CWE_RE.search(s)
    return m.group(0).upper() if m else None


def make_id(entity_type: str, key: str) -> str:
    return f"{entity_type}:{key}"


def software_key(vendor: str, product: str) -> str:
    return f"{slug(vendor)}/{slug(product)}"


def rel_id(rel_type: str, source_id: str, target_id: str) -> str:
    return f"{rel_type}|{source_id}|{target_id}"
