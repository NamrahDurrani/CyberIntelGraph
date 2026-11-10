"""CISA Known Exploited Vulnerabilities (KEV) collector.

What it does
------------
1. Downloads the official KEV JSON catalog from CISA (one HTTP GET, with retries).
2. Saves the response bytes UNCHANGED to data/raw/cisa_kev/ (plus a .meta.json sidecar
   with source URL, retrieval time, HTTP info and SHA-256).
3. Validates the envelope and every record (required fields, CVE-ID format, dates, duplicates).
4. Writes a normalized copy to data/processed/ (separate from the raw file).
5. Writes a small initial subset (default 75 records) for the first controlled dataset.
6. Writes a validation report to outputs/reports/ and a log to logs/.

Run from the project root (venv active):
    python ingestion\\collectors\\cisa_kev\\collector.py

Dependencies: requests (everything else is the Python standard library).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
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
SOURCE_NAME = "CISA Known Exploited Vulnerabilities (KEV)"
SOURCE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
COLLECTION_METHOD = "official JSON catalog, HTTP GET via requests"

# collector.py lives in <root>/ingestion/collectors/cisa_kev/ -> root is 3 levels up
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "cisa_kev"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "outputs" / "reports"
LOG_FILE = PROJECT_ROOT / "logs" / "cisa_kev_collector.log"

ENVELOPE_REQUIRED = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
# A record without these cannot be used at all -> error, record is rejected.
RECORD_REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded")
# Expected but not fatal -> warning, record is kept.
RECORD_EXPECTED = ("shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RETRY_STATUS = {429, 500, 502, 503, 504}

log = logging.getLogger("cisa_kev_collector")


# --------------------------------------------------------------------------- result object
@dataclass
class IngestionResult:
    """Consistent result returned by every collector in this project."""
    source_name: str = SOURCE_NAME
    source_url: str = SOURCE_URL
    success: bool = False
    retrieved_at: str = ""
    catalog_version: str = ""
    catalog_date_released: str = ""
    declared_count: int | None = None
    records_in_file: int = 0
    records_valid: int = 0
    records_rejected: int = 0
    duplicate_cve_ids: int = 0
    raw_file: str = ""
    raw_saved_new: bool = False
    raw_sha256: str = ""
    processed_file: str = ""
    subset_file: str = ""
    report_file: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Raised when the catalog cannot be retrieved."""


# --------------------------------------------------------------------------- helpers
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for handler in (logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE, encoding="utf-8")):
        handler.setFormatter(fmt)
        log.addHandler(handler)


def rel(path: Path) -> str:
    """Project-relative path with forward slashes (stable across machines)."""
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def write_json_atomic(path: Path, data: object) -> None:
    """Write JSON via a temp file so a crash never leaves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def parse_date(value: object) -> str | None:
    """Return an ISO date (YYYY-MM-DD) or None if the value is not a valid date."""
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date().isoformat()
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- 1. fetch
def fetch_catalog(url: str, timeout: float, retries: int, user_agent: str) -> requests.Response:
    """GET the catalog. Retries timeouts, connection errors, 429 and 5xx with backoff."""
    headers = {"User-Agent": user_agent, "Accept": "application/json"}
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


# --------------------------------------------------------------------------- 2. raw storage
def save_raw(resp: requests.Response, url: str, retrieved_at: datetime) -> tuple[Path, str, bool]:
    """Save response bytes untouched. Never overwrites. Reuses an identical earlier file.

    Returns (raw_path, sha256, saved_new).
    """
    content = resp.content
    sha = hashlib.sha256(content).hexdigest()
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    for meta_path in sorted(RAW_DIR.glob("*.meta.json")):  # avoid storing duplicates
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        existing = RAW_DIR / str(meta.get("raw_file", ""))
        if meta.get("sha256") == sha and existing.is_file():
            log.info("Catalog unchanged since earlier download; reusing %s", rel(existing))
            return existing, sha, False

    stamp = retrieved_at.strftime("%Y%m%dT%H%M%SZ")
    raw_path = RAW_DIR / f"kev_raw_{stamp}.json"
    counter = 1
    while raw_path.exists():  # two different downloads in the same second: never overwrite
        counter += 1
        raw_path = RAW_DIR / f"kev_raw_{stamp}_{counter}.json"
    with open(raw_path, "xb") as fh:  # 'x' = fail if it already exists (raw is never overwritten)
        fh.write(content)
    meta = {
        "source_name": SOURCE_NAME,
        "source_url": url,
        "retrieved_at": retrieved_at.isoformat(),
        "http_status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "etag": resp.headers.get("ETag", ""),
        "last_modified_header": resp.headers.get("Last-Modified", ""),
        "bytes": len(content),
        "sha256": sha,
        "raw_file": raw_path.name,
        "original_format": "json",
        "collection_method": COLLECTION_METHOD,
    }
    write_json_atomic(raw_path.with_suffix(".meta.json"), meta)
    log.info("Saved raw catalog: %s (%d bytes, sha256 %s...)", rel(raw_path), len(content), sha[:12])
    return raw_path, sha, True


# --------------------------------------------------------------------------- 3. validate + 4. normalize
def validate_envelope(doc: object) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(doc, dict):
        return ["Top level of the file is not a JSON object"], warnings
    for key in ENVELOPE_REQUIRED:
        if key not in doc:
            errors.append(f"Envelope is missing required key '{key}'")
    if "title" not in doc:
        warnings.append("Envelope has no 'title' key (not fatal)")
    if "vulnerabilities" in doc and not isinstance(doc["vulnerabilities"], list):
        errors.append("'vulnerabilities' is not a list")
    if isinstance(doc.get("vulnerabilities"), list) and "count" in doc:
        try:
            declared = int(doc["count"])
        except (TypeError, ValueError):
            errors.append(f"'count' is not an integer: {doc['count']!r}")
        else:
            actual = len(doc["vulnerabilities"])
            if declared != actual:
                errors.append(f"Declared count ({declared}) != records in file ({actual})")
    if isinstance(doc.get("vulnerabilities"), list) and not doc["vulnerabilities"]:
        errors.append("Catalog contains zero vulnerabilities")
    return errors, warnings


def normalize_record(item: dict, cve_id: str, date_added: str, ctx: dict) -> dict:
    """Map one raw KEV entry to the project's flat, source-attributed shape."""
    def text(key: str) -> str:
        value = item.get(key)
        return value.strip() if isinstance(value, str) else ""

    ransomware_raw = text("knownRansomwareCampaignUse")
    cwes = item.get("cwes")
    cwes = [str(c).strip() for c in cwes] if isinstance(cwes, list) else []
    due = parse_date(item.get("dueDate"))
    return {
        "record_id": f"kev:{cve_id}",
        "cve_id": cve_id,
        "vendor_project": text("vendorProject"),
        "product": text("product"),
        "vulnerability_name": text("vulnerabilityName"),
        "date_added": date_added,
        "short_description": text("shortDescription"),
        "required_action": text("requiredAction"),
        "due_date": due,
        "known_ransomware_campaign_use_raw": ransomware_raw,
        "known_ransomware_campaign_use": {"Known": True, "Unknown": False}.get(ransomware_raw),
        "notes": text("notes"),
        "cwes": cwes,
        # --- provenance (project-wide metadata fields) ---
        "source_name": SOURCE_NAME,
        "source_url": ctx["source_url"],
        "source_record_id": cve_id,
        "retrieved_at": ctx["retrieved_at"],
        "published_at": date_added,        # = date CISA ADDED it to KEV (not the CVE publish date)
        "last_modified_at": None,          # KEV records carry no per-record modified date
        "original_format": "json",
        "raw_file_reference": ctx["raw_ref"],
        "collection_method": COLLECTION_METHOD,
    }


def validate_and_normalize(vulns: list, ctx: dict) -> tuple[list[dict], list[str], list[str], int]:
    """Validate every record. Returns (valid_records, errors, warnings, duplicate_count)."""
    records: list[dict] = []
    errors: list[str] = []
    seen: set[str] = set()
    duplicates = 0
    soft: dict[str, list[str]] = defaultdict(list)  # warning text -> example CVE IDs

    for index, item in enumerate(vulns):
        where = f"record #{index}"
        if not isinstance(item, dict):
            errors.append(f"{where}: not a JSON object")
            continue
        missing = [k for k in RECORD_REQUIRED if not str(item.get(k, "")).strip()]
        if missing:
            errors.append(f"{where} ({item.get('cveID', '?')}): missing/empty required field(s) {missing}")
            continue
        cve_id = str(item["cveID"]).strip().upper()
        if not CVE_RE.match(cve_id):
            errors.append(f"{where}: invalid CVE ID format {item['cveID']!r}")
            continue
        date_added = parse_date(item["dateAdded"])
        if date_added is None:
            errors.append(f"{where} ({cve_id}): dateAdded {item['dateAdded']!r} is not YYYY-MM-DD")
            continue
        if cve_id in seen:
            duplicates += 1
            errors.append(f"{where}: duplicate CVE ID {cve_id} (first occurrence kept)")
            continue
        seen.add(cve_id)

        for key in RECORD_EXPECTED:
            if not str(item.get(key, "")).strip():
                soft[f"missing or empty '{key}'"].append(cve_id)
        if str(item.get("dueDate", "")).strip() and parse_date(item.get("dueDate")) is None:
            soft["dueDate is not YYYY-MM-DD"].append(cve_id)
        if item.get("knownRansomwareCampaignUse") not in (None, "", "Known", "Unknown"):
            soft["unexpected knownRansomwareCampaignUse value"].append(cve_id)
        records.append(normalize_record(item, cve_id, date_added, ctx))

    warnings = [f"{len(ids)} record(s) with {msg} (e.g. {', '.join(ids[:3])})" for msg, ids in soft.items()]
    return records, errors, warnings, duplicates


def select_subset(records: list[dict], size: int) -> tuple[list[dict], str]:
    """Initial controlled dataset: ransomware-linked first, newest first, then newest others."""
    rule = (f"up to {size} records: entries with knownRansomwareCampaignUse='Known' first, "
            "then all others; each group sorted by date_added (newest first), then CVE ID")
    if size <= 0:
        return [], rule
    key = lambda r: (r["date_added"], r["cve_id"])
    known = sorted((r for r in records if r["known_ransomware_campaign_use"] is True), key=key, reverse=True)
    others = sorted((r for r in records if r["known_ransomware_campaign_use"] is not True), key=key, reverse=True)
    return (known + others)[:size], rule


# --------------------------------------------------------------------------- orchestration
def run(url: str, timeout: float, retries: int, user_agent: str, subset_size: int) -> IngestionResult:
    result = IngestionResult(source_url=url)
    retrieved_at = utc_now()
    result.retrieved_at = retrieved_at.isoformat()

    try:
        resp = fetch_catalog(url, timeout, retries, user_agent)
    except CollectionError as exc:
        result.errors.append(str(exc))
        log.error("%s", exc)
        return result

    raw_path, sha, saved_new = save_raw(resp, url, retrieved_at)
    result.raw_file, result.raw_sha256, result.raw_saved_new = rel(raw_path), sha, saved_new

    try:
        doc = json.loads(resp.content)
    except ValueError as exc:
        result.errors.append(f"Response is not valid JSON: {exc} (raw file kept for inspection)")
        log.error("%s", result.errors[-1])
        return result

    env_errors, env_warnings = validate_envelope(doc)
    result.errors += env_errors
    result.warnings += env_warnings
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        return result

    result.catalog_version = str(doc.get("catalogVersion", ""))
    result.catalog_date_released = str(doc.get("dateReleased", ""))
    try:
        result.declared_count = int(doc.get("count"))
    except (TypeError, ValueError):
        result.declared_count = None
    result.records_in_file = len(doc["vulnerabilities"])

    ctx = {"source_url": url, "retrieved_at": result.retrieved_at, "raw_ref": result.raw_file}
    records, rec_errors, rec_warnings, dupes = validate_and_normalize(doc["vulnerabilities"], ctx)
    result.errors += rec_errors
    result.warnings += rec_warnings
    result.records_valid = len(records)
    result.records_rejected = result.records_in_file - len(records)
    result.duplicate_cve_ids = dupes

    envelope_meta = {
        "source_name": SOURCE_NAME,
        "source_url": url,
        "catalog_page": CATALOG_PAGE,
        "retrieved_at": result.retrieved_at,
        "catalog_version": result.catalog_version,
        "catalog_date_released": result.catalog_date_released,
        "declared_count": result.declared_count,
        "raw_file_reference": result.raw_file,
        "raw_sha256": sha,
        "collection_method": COLLECTION_METHOD,
        "normalization_note": "Strings stripped; CVE IDs upper-cased; invalid records excluded (see validation report).",
    }
    processed = PROCESSED_DIR / "cisa_kev_normalized.json"
    write_json_atomic(processed, {"metadata": {**envelope_meta, "record_count": len(records)}, "records": records})
    result.processed_file = rel(processed)
    log.info("Wrote normalized copy: %s (%d records)", result.processed_file, len(records))

    subset, rule = select_subset(records, subset_size)
    if subset:
        subset_path = PROCESSED_DIR / "cisa_kev_initial_subset.json"
        write_json_atomic(subset_path, {"metadata": {**envelope_meta, "record_count": len(subset),
                                                       "selection_rule": rule}, "records": subset})
        result.subset_file = rel(subset_path)
        log.info("Wrote initial subset: %s (%d records)", result.subset_file, len(subset))

    result.success = not result.errors and result.records_valid > 0
    return result


def write_report(result: IngestionResult) -> None:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"cisa_kev_validation_{stamp}.json"
    result.report_file = rel(path) if path.is_relative_to(PROJECT_ROOT) else str(path)
    write_json_atomic(path, asdict(result))


def print_summary(result: IngestionResult) -> None:
    line = lambda label, value: print(f"  {label:<22}: {value}")
    print("\n=== CISA KEV collection summary ===")
    line("Status", "SUCCESS" if result.success else "FAILED")
    line("Catalog version", result.catalog_version or "-")
    line("Catalog released", result.catalog_date_released or "-")
    line("Declared count", result.declared_count)
    line("Records in file", result.records_in_file)
    line("Valid records", result.records_valid)
    line("Rejected records", result.records_rejected)
    line("Duplicate CVE IDs", result.duplicate_cve_ids)
    line("Raw file", f"{result.raw_file or '-'}" + ("" if result.raw_saved_new or not result.raw_file else "  (reused, unchanged)"))
    line("Normalized file", result.processed_file or "-")
    line("Initial subset file", result.subset_file or "-")
    line("Validation report", result.report_file or "-")
    line("Warnings", len(result.warnings))
    line("Errors", len(result.errors))
    for message in result.warnings:
        print(f"  WARNING: {message}")
    for message in result.errors[:20]:
        print(f"  ERROR: {message}")
    if len(result.errors) > 20:
        print(f"  ... and {len(result.errors) - 20} more errors (see validation report)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the official CISA KEV catalog.")
    parser.add_argument("--url", default=SOURCE_URL, help="Catalog URL (default: official CISA feed)")
    parser.add_argument("--subset-size", type=int, default=75, help="Initial subset size, 0 to disable (default 75)")
    parser.add_argument("--retries", type=int, default=4, help="Max download attempts (default 4)")
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args(argv)

    setup_logging()
    user_agent = os.environ.get("USER_AGENT", "CyberIntelGraph/0.1 (research project)")
    try:
        result = run(args.url, args.timeout, args.retries, user_agent, args.subset_size)
    except Exception as exc:  # last-resort guard: report clearly instead of a raw traceback
        log.exception("Unexpected failure")
        result = IngestionResult(source_url=args.url, retrieved_at=utc_now().isoformat())
        result.errors.append(f"Unexpected {type(exc).__name__}: {exc} (details in {rel(LOG_FILE)})")
    write_report(result)
    print_summary(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
