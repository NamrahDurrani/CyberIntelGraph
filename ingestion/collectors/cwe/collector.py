"""CWE (Common Weakness Enumeration) collector - official XML download.

What it does
------------
1. Downloads the official catalog zip (cwec_latest.xml.zip) from cwe.mitre.org.
2. Saves the zip UNCHANGED to data/raw/cwe/ with a .meta.json sidecar (URL, time, size, SHA-256).
   An identical zip that is already on disk is reused, not stored twice.
3. Reads the single XML file inside the zip IN MEMORY (nothing is extracted to disk), validates it and
   normalizes weaknesses, categories and views into data/processed/cwe_normalized.json.
4. Writes data/processed/cwe_initial_subset.json: the CWE ids that our NVD and CISA KEV records reference,
   plus their ancestors in the Research Concepts view (view 1000).
5. Writes a validation report to outputs/reports/ and a log to logs/.

Run from the project root (venv active):
    python ingestion\\collectors\\cwe\\collector.py

Dependencies: requests (everything else is the Python standard library).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import re
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:  # usually the virtual environment is not active
    sys.stderr.write("ERROR: the 'requests' package is not available in this Python (" + sys.executable + ").\n"
                     "Activate the project environment first (type: cig   or run: .\\.venv\\Scripts\\Activate.ps1 in the project folder),\n"
                     "or install the package with: python -m pip install -r requirements.txt\n")
    raise SystemExit(2)

# --------------------------------------------------------------------------- constants
SOURCE_NAME = "CWE - Common Weakness Enumeration (MITRE)"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DOWNLOADS_PAGE = "https://cwe.mitre.org/data/downloads.html"
DEFINITION_URL = "https://cwe.mitre.org/data/definitions/{}.html"
COLLECTION_METHOD = "official XML download (zip) via HTTP GET, parsed in memory with xml.etree"
ORIGINAL_FORMAT = "xml (zip)"

# collector.py lives in <root>/ingestion/collectors/cwe/ -> root is 3 levels up
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "cwe"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
NORMALIZED = PROCESSED_DIR / "cwe_normalized.json"
SUBSET = PROCESSED_DIR / "cwe_initial_subset.json"
NVD_NORMALIZED = PROCESSED_DIR / "nvd_normalized.json"
KEV_NORMALIZED = PROCESSED_DIR / "cisa_kev_normalized.json"
REPORT_DIR = PROJECT_ROOT / "outputs" / "reports"
LOG_FILE = PROJECT_ROOT / "logs" / "cwe_collector.log"

MAX_XML_BYTES = 300 * 1024 * 1024      # refuse absurdly large archives (zip-bomb guard)
RESEARCH_VIEW = "1000"                  # "Research Concepts" view: the weakness hierarchy
RETRY_STATUS = {429, 500, 502, 503, 504}
PLACEHOLDER_PREFIX = "NVD-CWE-"         # NVD placeholders such as NVD-CWE-Other / NVD-CWE-noinfo

log = logging.getLogger("cwe_collector")


# --------------------------------------------------------------------------- result object
@dataclass
class IngestionResult:
    """Consistent result returned by every collector in this project."""
    source_name: str = SOURCE_NAME
    source_url: str = CWE_URL
    success: bool = False
    retrieved_at: str = ""
    catalog_name: str = ""
    catalog_version: str = ""
    catalog_date: str = ""
    xml_member: str = ""
    raw_file: str = ""
    raw_saved_new: bool = False
    raw_sha256: str = ""
    raw_bytes: int = 0
    weaknesses: int = 0
    categories: int = 0
    views: int = 0
    other_kinds: dict = field(default_factory=dict)       # entry kinds other than weakness / category / view
    catalog_sections: dict = field(default_factory=dict)  # what the XML really contains: {section: {element: count}}
    by_status: dict = field(default_factory=dict)
    by_abstraction: dict = field(default_factory=dict)
    referenced_ids_total: int = 0
    referenced_ids_found: int = 0
    referenced_ids_missing: list[str] = field(default_factory=list)
    nvd_placeholders_seen: dict = field(default_factory=dict)
    subset_records: int = 0
    processed_file: str = ""
    subset_file: str = ""
    report_file: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Raised when the catalog cannot be retrieved or read."""


# --------------------------------------------------------------------------- helpers
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%SZ")


def setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for handler in (logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE, encoding="utf-8")):
        handler.setFormatter(fmt)
        log.addHandler(handler)


def rel(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def write_json_atomic(path: Path, data: object, indent: int | None = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=indent)
        fh.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- 1. fetch + raw storage
def fetch(url: str, timeout: float, retries: int, user_agent: str) -> requests.Response:
    headers = {"User-Agent": user_agent}
    last_error = "unknown error"
    for attempt in range(1, retries + 1):
        wait = min(2 ** attempt, 30)
        try:
            log.info("GET %s (attempt %d/%d)", url, attempt, retries)
            resp = requests.get(url, headers=headers, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.warning("Network problem: %s", last_error)
        else:
            if resp.status_code == 200:
                return resp
            last_error = f"HTTP {resp.status_code} {resp.reason}"
            if resp.status_code not in RETRY_STATUS:
                raise CollectionError(f"{last_error} (not retryable) from {url}")
            retry_after = resp.headers.get("Retry-After", "")
            if retry_after.isdigit():
                wait = min(int(retry_after), 60)
            log.warning("%s - will retry", last_error)
        if attempt < retries:
            log.info("Waiting %ds before retry", wait)
            time.sleep(wait)
    raise CollectionError(f"Giving up after {retries} attempts. Last error: {last_error}")


def save_raw(resp: requests.Response, url: str, retrieved_at: datetime) -> tuple[Path, str, bool]:
    """Save the zip bytes untouched; never overwrite; reuse an identical earlier file."""
    content = resp.content
    sha = hashlib.sha256(content).hexdigest()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for meta_path in sorted(RAW_DIR.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        existing = RAW_DIR / str(meta.get("raw_file", ""))
        if meta.get("sha256") == sha and existing.is_file():
            log.info("Catalog unchanged since earlier download; reusing %s", rel(existing))
            return existing, sha, False
    path = RAW_DIR / f"cwec_latest__{stamp(retrieved_at)}.zip"
    counter = 1
    while path.exists():
        counter += 1
        path = RAW_DIR / f"cwec_latest__{stamp(retrieved_at)}_{counter}.zip"
    with open(path, "xb") as fh:
        fh.write(content)
    meta = {"source_name": SOURCE_NAME, "source_url": url, "retrieved_at": retrieved_at.isoformat(),
            "http_status": resp.status_code, "content_type": resp.headers.get("Content-Type", ""),
            "etag": resp.headers.get("ETag", ""), "last_modified_header": resp.headers.get("Last-Modified", ""),
            "bytes": len(content), "sha256": sha, "raw_file": path.name, "original_format": ORIGINAL_FORMAT,
            "collection_method": COLLECTION_METHOD}
    write_json_atomic(path.with_suffix(".meta.json"), meta)
    log.info("Saved raw catalog: %s (%d bytes, sha256 %s...)", rel(path), len(content), sha[:12])
    return path, sha, True


def read_xml_from_zip(content: bytes) -> tuple[str, bytes]:
    """Return (member name, xml bytes). The zip is opened in memory; nothing is written to disk."""
    if not zipfile.is_zipfile(io.BytesIO(content)):
        raise CollectionError("downloaded file is not a zip archive (got an error page instead?)")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        xml_members = [i for i in archive.infolist() if i.filename.lower().endswith(".xml") and not i.is_dir()]
        if not xml_members:
            raise CollectionError(f"zip contains no .xml file (members: {archive.namelist()[:5]})")
        preferred = [i for i in xml_members if Path(i.filename).name.lower().startswith("cwec")]
        member = (preferred or xml_members)[0]
        if member.file_size > MAX_XML_BYTES:
            raise CollectionError(f"XML member {member.filename} is {member.file_size} bytes (limit {MAX_XML_BYTES})")
        return member.filename, archive.read(member)


# --------------------------------------------------------------------------- 2. XML helpers
def localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def children(el: ET.Element | None, name: str) -> list[ET.Element]:
    return [c for c in el if localname(c.tag) == name] if el is not None else []


def child(el: ET.Element | None, name: str) -> ET.Element | None:
    found = children(el, name)
    return found[0] if found else None


def text_of(el: ET.Element | None) -> str:
    """All text inside an element (including nested XHTML), whitespace collapsed."""
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def first_text(el: ET.Element, *names: str) -> str:
    """Text of the first of these child elements that exists and is not empty."""
    for name in names:
        found = text_of(child(el, name))
        if found:
            return found
    return ""


def cwe_id_of(raw: object) -> str | None:
    raw = str(raw or "").strip()
    return f"CWE-{int(raw)}" if raw.isdigit() else None


# --------------------------------------------------------------------------- 3. parse + normalize
def parse_catalog(xml_bytes: bytes, ctx: dict, result: IngestionResult) -> tuple[list[dict], list[dict]]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        result.errors.append(f"XML is not well-formed: {exc}")
        return [], []
    if localname(root.tag) != "Weakness_Catalog":
        result.errors.append(f"unexpected XML root element {localname(root.tag)!r} (expected Weakness_Catalog)")
        return [], []
    result.catalog_name = root.attrib.get("Name", "")
    result.catalog_version = root.attrib.get("Version", "")
    result.catalog_date = root.attrib.get("Date", "")
    if not result.catalog_version:
        result.warnings.append("catalog has no Version attribute")

    # Structure-agnostic: every element two levels down (root > section > element) that carries ID and Name is an entry.
    # This finds weaknesses, categories and views whatever the sections are called, and reports what it saw.
    records: list[dict] = []
    views: list[dict] = []
    sections: dict[str, Counter] = {}
    for section in root:
        section_name = localname(section.tag)
        if section_name == "External_References":
            continue
        for el in section:
            if "ID" not in el.attrib or "Name" not in el.attrib:
                continue
            tag = localname(el.tag)
            sections.setdefault(section_name, Counter())[tag] += 1
            if tag == "View":
                views.append(normalize_view(el, ctx, result))
            else:
                records.append(normalize_entry(el, tag.lower(), ctx, result))
    result.catalog_sections = {name: dict(counter) for name, counter in sections.items()}
    records = [r for r in records if r is not None]
    views = [v for v in views if v is not None]

    seen: set[str] = set()
    for rec in records + views:
        if rec["cwe_id"] in seen:
            result.errors.append(f"duplicate id {rec['cwe_id']}")
        seen.add(rec["cwe_id"])
    result.weaknesses = sum(1 for r in records if r["element_type"] == "weakness")
    result.categories = sum(1 for r in records if r["element_type"] == "category")
    result.views = len(views)
    result.other_kinds = dict(Counter(r["element_type"] for r in records if r["element_type"] not in ("weakness", "category")))
    if result.categories == 0 and not result.other_kinds:
        result.warnings.append("no Category entries and no other entry kinds found, but real CWE catalogs list hundreds of grouping "
                               f"entries (many NVD records reference them). Sections seen in the XML: {result.catalog_sections}")
    elif result.categories == 0:
        result.warnings.append(f"this file has no elements named Category; other entry kinds were found and kept as written: {result.other_kinds}")
    result.by_status = dict(Counter(r["status"] for r in records))
    result.by_abstraction = dict(Counter(r["abstraction"] for r in records if r["element_type"] == "weakness"))

    known = {r["cwe_id"] for r in records}
    dangling = Counter()
    for rec in records:
        for rw in rec["related_weaknesses"]:
            if rw["cwe_id"] and rw["cwe_id"] not in known:
                dangling[rw["cwe_id"]] += 1
    if dangling:
        result.warnings.append(f"{len(dangling)} related-weakness target(s) not in this catalog "
                               f"(e.g. {', '.join(sorted(dangling)[:3])}); kept as written")
    if not records:
        result.errors.append("catalog contains no weaknesses or categories")
    return records, views


def provenance(ctx: dict, record_id: str, published: str | None, modified: str | None) -> dict:
    return {"source_name": SOURCE_NAME, "source_url": ctx["source_url"], "source_record_id": record_id,
            "retrieved_at": ctx["retrieved_at"], "published_at": published, "last_modified_at": modified,
            "original_format": ORIGINAL_FORMAT, "raw_file_reference": ctx["raw_ref"],
            "collection_method": COLLECTION_METHOD, "catalog_version": ctx["version"],
            "evidence_type": "structured_authoritative_record"}


def content_dates(el: ET.Element) -> tuple[str | None, str | None]:
    history = child(el, "Content_History")
    submission = child(child(history, "Submission"), "Submission_Date")
    mods = [text_of(child(m, "Modification_Date")) for m in children(history, "Modification")]
    mods = [m for m in mods if m]
    return (text_of(submission) or None), (max(mods) if mods else None)


def mapping_notes(el: ET.Element) -> dict | None:
    notes = child(el, "Mapping_Notes")
    if notes is None:
        return None
    return {"usage": text_of(child(notes, "Usage")), "rationale": text_of(child(notes, "Rationale")),
            "comments": text_of(child(notes, "Comments"))}


def normalize_entry(el: ET.Element, kind: str, ctx: dict, result: IngestionResult) -> dict | None:
    cwe_id = cwe_id_of(el.attrib.get("ID"))
    name = (el.attrib.get("Name") or "").strip()
    if cwe_id is None or not name:
        result.errors.append(f"{kind} with bad ID or empty name: ID={el.attrib.get('ID')!r} Name={name!r}")
        return None
    status = el.attrib.get("Status", "")
    if not status:
        result.warnings.append(f"{cwe_id}: no Status")
    submitted, modified = content_dates(el)
    related = [{"nature": r.attrib.get("Nature"), "cwe_id": cwe_id_of(r.attrib.get("CWE_ID")),
                "view_id": r.attrib.get("View_ID"), "ordinal": r.attrib.get("Ordinal")}
               for r in children(child(el, "Related_Weaknesses"), "Related_Weakness")]
    members = [{"cwe_id": cwe_id_of(m.attrib.get("CWE_ID")), "view_id": m.attrib.get("View_ID")}
               for m in children(child(el, "Relationships"), "Has_Member")]
    platforms_el = child(el, "Applicable_Platforms")
    platforms = [{"kind": localname(p.tag), "name": p.attrib.get("Name"), "class": p.attrib.get("Class"),
                  "prevalence": p.attrib.get("Prevalence")} for p in (list(platforms_el) if platforms_el is not None else [])]
    capec = [f"CAPEC-{a.attrib['CAPEC_ID']}" for a in children(child(el, "Related_Attack_Patterns"), "Related_Attack_Pattern")
             if a.attrib.get("CAPEC_ID")]
    taxonomy = [{"taxonomy_name": t.attrib.get("Taxonomy_Name"), "entry_id": text_of(child(t, "Entry_ID")),
                 "entry_name": text_of(child(t, "Entry_Name"))} for t in children(child(el, "Taxonomy_Mappings"), "Taxonomy_Mapping")]
    number = cwe_id.split("-")[1]
    record = {
        "record_id": f"cwe:{cwe_id}", "cwe_id": cwe_id, "element_type": kind, "name": name,
        "abstraction": el.attrib.get("Abstraction", ""),
        "structure": el.attrib.get("Structure", ""),
        "status": status,
        "description": first_text(el, "Description", "Summary"),
        "extended_description": text_of(child(el, "Extended_Description")),
        "related_weaknesses": related, "members": members, "applicable_platforms": platforms,
        "related_attack_patterns": capec, "taxonomy_mappings": taxonomy, "mapping_notes": mapping_notes(el),
        "submission_date": submitted, "last_modified": modified,
        "definition_url": DEFINITION_URL.format(number),
        "referenced_by_nvd_records": 0, "referenced_by_kev_records": 0,
    }
    record.update(provenance(ctx, cwe_id, submitted, modified))
    return record


def normalize_view(el: ET.Element, ctx: dict, result: IngestionResult) -> dict | None:
    cwe_id = cwe_id_of(el.attrib.get("ID"))
    name = (el.attrib.get("Name") or "").strip()
    if cwe_id is None or not name:
        result.errors.append(f"view with bad ID or empty name: ID={el.attrib.get('ID')!r}")
        return None
    rec = {"record_id": f"cwe:{cwe_id}", "cwe_id": cwe_id, "element_type": "view", "name": name,
           "view_type": el.attrib.get("Type", ""), "status": el.attrib.get("Status", ""),
           "objective": text_of(child(el, "Objective")), "definition_url": DEFINITION_URL.format(cwe_id.split("-")[1])}
    rec.update(provenance(ctx, cwe_id, None, None))
    return rec


# --------------------------------------------------------------------------- 4. references from our own data + subset
def load_referenced_ids(result: IngestionResult) -> tuple[Counter, Counter]:
    """CWE ids used by our NVD records and KEV records (per record, so one record counts once)."""
    nvd_counts: Counter = Counter()
    kev_counts: Counter = Counter()
    placeholders: Counter = Counter()
    if NVD_NORMALIZED.is_file():
        for rec in json.loads(NVD_NORMALIZED.read_text(encoding="utf-8"))["records"]:
            for cwe in {w["cwe_id"] for w in rec.get("weaknesses", []) if w.get("cwe_id")}:
                if cwe.startswith(PLACEHOLDER_PREFIX):
                    placeholders[cwe] += 1
                else:
                    nvd_counts[cwe] += 1
    else:
        result.warnings.append(f"{rel(NVD_NORMALIZED)} not found: NVD references not counted")
    if KEV_NORMALIZED.is_file():
        for rec in json.loads(KEV_NORMALIZED.read_text(encoding="utf-8"))["records"]:
            for cwe in {str(c).strip() for c in rec.get("cwes", []) if str(c).strip()}:
                kev_counts[cwe] += 1
    else:
        result.warnings.append(f"{rel(KEV_NORMALIZED)} not found: KEV references not counted")
    result.nvd_placeholders_seen = dict(placeholders)
    return nvd_counts, kev_counts


def select_subset(records: list[dict], nvd_counts: Counter, kev_counts: Counter, result: IngestionResult) -> tuple[list[dict], str]:
    """Referenced ids + all ancestors reachable through ChildOf in the Research Concepts view."""
    rule = ("CWE ids referenced by our NVD or CISA KEV records, plus their ancestors through 'ChildOf' "
            f"relationships in view {RESEARCH_VIEW} (Research Concepts)")
    by_id = {r["cwe_id"]: r for r in records}
    referenced = set(nvd_counts) | set(kev_counts)
    result.referenced_ids_total = len(referenced)
    result.referenced_ids_missing = sorted(i for i in referenced if i not in by_id)
    result.referenced_ids_found = len(referenced) - len(result.referenced_ids_missing)
    if result.referenced_ids_missing:
        result.warnings.append(f"{len(result.referenced_ids_missing)} referenced CWE id(s) not in the catalog: "
                               f"{', '.join(result.referenced_ids_missing[:5])}")
    selected: set[str] = set()
    stack = [i for i in referenced if i in by_id]
    while stack:
        current = stack.pop()
        if current in selected:
            continue
        selected.add(current)
        for rw in by_id[current]["related_weaknesses"]:
            if rw["nature"] == "ChildOf" and rw["view_id"] == RESEARCH_VIEW and rw["cwe_id"] in by_id:
                stack.append(rw["cwe_id"])
    return sorted((by_id[i] for i in selected), key=lambda r: int(r["cwe_id"].split("-")[1])), rule


# --------------------------------------------------------------------------- orchestration
def run(args: argparse.Namespace) -> IngestionResult:
    result = IngestionResult(source_url=args.url)
    retrieved_at = utc_now()
    result.retrieved_at = retrieved_at.isoformat()
    user_agent = os.environ.get("USER_AGENT", "CyberIntelGraph/0.1 (research project)")

    try:
        resp = fetch(args.url, args.timeout, args.retries, user_agent)
    except CollectionError as exc:
        result.errors.append(str(exc))
        log.error("%s", exc)
        return result
    raw_path, sha, saved_new = save_raw(resp, args.url, retrieved_at)
    result.raw_file, result.raw_sha256, result.raw_saved_new, result.raw_bytes = rel(raw_path), sha, saved_new, len(resp.content)

    try:
        member, xml_bytes = read_xml_from_zip(resp.content)
    except (CollectionError, zipfile.BadZipFile) as exc:
        result.errors.append(f"{exc} (raw file kept for inspection)")
        log.error("%s", result.errors[-1])
        return result
    result.xml_member = member

    ctx = {"source_url": args.url, "retrieved_at": result.retrieved_at, "raw_ref": result.raw_file, "version": ""}
    # version is only known after parsing the root element: parse once to read it, then fill the context
    try:
        root_attrs = ET.fromstring(xml_bytes).attrib
        ctx["version"] = root_attrs.get("Version", "")
    except ET.ParseError:
        pass
    records, views = parse_catalog(xml_bytes, ctx, result)
    if not records:
        return result

    nvd_counts, kev_counts = load_referenced_ids(result)
    for rec in records:
        rec["referenced_by_nvd_records"] = nvd_counts.get(rec["cwe_id"], 0)
        rec["referenced_by_kev_records"] = kev_counts.get(rec["cwe_id"], 0)
    subset, rule = select_subset(records, nvd_counts, kev_counts, result)
    result.subset_records = len(subset)

    meta = {"source_name": SOURCE_NAME, "source_url": args.url, "downloads_page": DOWNLOADS_PAGE,
            "retrieved_at": result.retrieved_at, "generated_at": utc_now().isoformat(),
            "catalog_name": result.catalog_name, "catalog_version": result.catalog_version,
            "catalog_date": result.catalog_date, "xml_member": member, "raw_file_reference": result.raw_file,
            "raw_sha256": sha, "collection_method": COLLECTION_METHOD}
    write_json_atomic(NORMALIZED, {"metadata": {**meta, "weaknesses": result.weaknesses, "categories": result.categories,
                                                 "views": result.views, "record_count": len(records)},
                                   "records": records, "views": views})
    result.processed_file = rel(NORMALIZED)
    if subset:
        write_json_atomic(SUBSET, {"metadata": {**meta, "record_count": len(subset), "selection_rule": rule,
                                                 "referenced_ids": result.referenced_ids_total}, "records": subset})
        result.subset_file = rel(SUBSET)
    log.info("Wrote %s (%d weaknesses, %d categories, %d views) and subset of %d",
             result.processed_file, result.weaknesses, result.categories, result.views, len(subset))
    result.success = not result.errors and len(records) > 0
    return result


def write_report(result: IngestionResult) -> None:
    path = REPORT_DIR / f"cwe_validation_{stamp(utc_now())}.json"
    result.report_file = rel(path)
    write_json_atomic(path, asdict(result))


def print_summary(result: IngestionResult) -> None:
    line = lambda label, value: print(f"  {label:<30}: {value}")
    print("\n=== CWE collection summary ===")
    line("Status", "SUCCESS" if result.success else "FAILED")
    line("Catalog", f"{result.catalog_name or '-'} v{result.catalog_version or '-'} ({result.catalog_date or '-'})")
    line("Raw file", (result.raw_file or "-") + ("" if result.raw_saved_new or not result.raw_file else "  (reused, unchanged)"))
    line("XML inside zip", result.xml_member or "-")
    line("Weaknesses", result.weaknesses)
    line("Categories", result.categories)
    line("Views", result.views)
    if result.other_kinds:
        line("Other entry kinds", result.other_kinds)
    line("XML sections", result.catalog_sections)
    line("Status values", result.by_status)
    line("Abstraction (weaknesses)", result.by_abstraction)
    line("CWE ids used by NVD/KEV", f"{result.referenced_ids_found} found of {result.referenced_ids_total}")
    line("NVD placeholders seen", result.nvd_placeholders_seen or "none")
    line("Initial subset records", result.subset_records)
    line("Normalized file", result.processed_file or "-")
    line("Subset file", result.subset_file or "-")
    line("Validation report", result.report_file or "-")
    line("Warnings", len(result.warnings))
    line("Errors", len(result.errors))
    for message in result.warnings[:10]:
        print(f"  WARNING: {message}")
    for message in result.errors[:20]:
        print(f"  ERROR: {message}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the official CWE catalog (XML zip).")
    parser.add_argument("--url", default=CWE_URL, help="catalog zip URL (default: official latest)")
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args(argv)

    setup_logging()
    try:
        result = run(args)
    except Exception as exc:  # last-resort guard
        log.exception("Unexpected failure")
        result = IngestionResult(source_url=args.url, retrieved_at=utc_now().isoformat())
        result.errors.append(f"Unexpected {type(exc).__name__}: {exc} (details in {rel(LOG_FILE)})")
    write_report(result)
    print_summary(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
