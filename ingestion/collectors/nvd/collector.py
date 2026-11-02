"""NVD (National Vulnerability Database) collector - CVE API 2.0.

What it does
------------
1. Builds a list of CVE IDs: by default the top N entries of the CISA KEV catalog (same ordering rule as
   the KEV initial subset, see docs/decisions/0002), plus any --cve-id you pass.
2. Downloads each CVE from the official NVD REST API (one GET per CVE, polite rate limiting, retries).
3. Saves every API response UNCHANGED to data/raw/nvd/ and appends a line to data/raw/nvd/manifest.jsonl
   (CVE, file, time, HTTP status, SHA-256). Already-downloaded CVEs are skipped, so an interrupted run resumes.
4. Validates each response and normalizes it to data/processed/nvd_normalized.json (separate from raw).
5. Writes a validation report to outputs/reports/ and a log to logs/.

Important: an NVD record does NOT prove a vulnerability is exploited in the wild. Use CISA KEV for that.
An API error is reported as an error - never as "this CVE does not exist".

Run from the project root (venv active):
    python ingestion\\collectors\\nvd\\collector.py --limit 3        (small first test)
    python ingestion\\collectors\\nvd\\collector.py                  (default: 150 CVEs)

Optional free API key (10x faster): put NVD_API_KEY=... in the .env file in the project root.
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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

# --------------------------------------------------------------------------- constants
SOURCE_NAME = "NVD - National Vulnerability Database (CVE API 2.0)"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COLLECTION_METHOD = "NVD CVE API 2.0 (REST GET, one request per cveId)"

# collector.py lives in <root>/ingestion/collectors/nvd/ -> root is 3 levels up
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "nvd"
MANIFEST = RAW_DIR / "manifest.jsonl"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
KEV_NORMALIZED = PROCESSED_DIR / "cisa_kev_normalized.json"
NORMALIZED = PROCESSED_DIR / "nvd_normalized.json"
REPORT_DIR = PROJECT_ROOT / "outputs" / "reports"
LOG_FILE = PROJECT_ROOT / "logs" / "nvd_collector.log"
ENV_FILE = PROJECT_ROOT / ".env"

ENVELOPE_REQUIRED = ("resultsPerPage", "startIndex", "totalResults", "format", "version", "timestamp", "vulnerabilities")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# NVD's firewall can answer 403/429 when the rate limit is exceeded, so those are retried (slowly).
RETRY_STATUS = {403, 429, 500, 502, 503, 504}
RATE_LIMIT_STATUS = {403, 429}
CVSS_ORDER = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))

log = logging.getLogger("nvd_collector")


# --------------------------------------------------------------------------- result object
@dataclass
class IngestionResult:
    """Consistent result returned by every collector in this project."""
    source_name: str = SOURCE_NAME
    source_url: str = API_URL
    success: bool = False
    interrupted: bool = False
    started_at: str = ""
    api_key_used: bool = False
    cves_requested: int = 0
    downloaded_new: int = 0
    reused_existing: int = 0
    no_record_returned: list[str] = field(default_factory=list)   # HTTP 200 but NVD returned 0 records
    failed: dict[str, str] = field(default_factory=dict)          # cve -> error (request/validation failed)
    records_normalized: int = 0
    with_cvss: int = 0
    with_weakness: int = 0
    with_affected_products: int = 0
    rejected_status: list[str] = field(default_factory=list)      # vulnStatus == Rejected
    processed_file: str = ""
    manifest_file: str = ""
    report_file: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Raised when one CVE cannot be retrieved."""


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


def load_env_file(path: Path) -> None:
    """Tiny .env reader (KEY=VALUE lines). Real environment variables win. Empty values are ignored."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def write_json_atomic(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- 1. which CVEs?
def kev_cve_ids(limit: int) -> list[str]:
    """Top `limit` KEV CVEs: ransomware-linked first, newest first, then others (same rule as KEV subset)."""
    if limit <= 0:
        return []
    if not KEV_NORMALIZED.is_file():
        raise FileNotFoundError(f"{rel(KEV_NORMALIZED)} not found - run the CISA KEV collector first "
                                "(or use --no-kev with --cve-id)")
    records = json.loads(KEV_NORMALIZED.read_text(encoding="utf-8"))["records"]
    key = lambda r: (r["date_added"], r["cve_id"])
    known = sorted((r for r in records if r["known_ransomware_campaign_use"] is True), key=key, reverse=True)
    others = sorted((r for r in records if r["known_ransomware_campaign_use"] is not True), key=key, reverse=True)
    return [r["cve_id"] for r in (known + others)[:limit]]


def build_target_list(limit: int, extra: list[str], use_kev: bool) -> tuple[list[str], list[str]]:
    """Returns (ordered unique valid CVE IDs, invalid inputs)."""
    candidates = (kev_cve_ids(limit) if use_kev else []) + [c.strip().upper() for c in extra]
    targets, invalid, seen = [], [], set()
    for cve in candidates:
        if not CVE_RE.match(cve):
            invalid.append(cve)
        elif cve not in seen:
            seen.add(cve)
            targets.append(cve)
    return targets, invalid


# --------------------------------------------------------------------------- 2. manifest + fetch + raw save
def read_manifest() -> list[dict]:
    entries: list[dict] = []
    if MANIFEST.is_file():
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                log.warning("Skipping unreadable manifest line: %.80s", line)
    return entries


def latest_ok_by_cve(entries: list[dict]) -> dict[str, dict]:
    """Latest successful download per CVE whose raw file still exists."""
    latest: dict[str, dict] = {}
    for entry in entries:
        if entry.get("outcome") == "ok" and (RAW_DIR / entry.get("raw_file", "")).is_file():
            latest[entry["cve_id"]] = entry  # later lines win
    return latest


def append_manifest(entry: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def fetch_cve(session: requests.Session, base_url: str, cve_id: str, timeout: float, retries: int) -> requests.Response:
    """GET one CVE. Retries timeouts, connection errors, 403/429 (rate limit) and 5xx with backoff."""
    last_error = "unknown error"
    for attempt in range(1, retries + 1):
        wait = min(2 ** attempt, 30)
        try:
            resp = session.get(base_url, params={"cveId": cve_id}, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.warning("%s: network problem: %s", cve_id, last_error)
        else:
            if resp.status_code == 200:
                return resp
            last_error = f"HTTP {resp.status_code} {resp.reason}"
            if resp.status_code not in RETRY_STATUS:
                raise CollectionError(f"{last_error} (not retryable)")
            if resp.status_code in RATE_LIMIT_STATUS:
                wait = 35  # NVD's window is 30 s
            retry_after = resp.headers.get("Retry-After", "")
            if retry_after.isdigit():
                wait = min(int(retry_after), 120)
            log.warning("%s: %s - will retry", cve_id, last_error)
        if attempt < retries:
            log.info("%s: waiting %ds before retry %d/%d", cve_id, wait, attempt + 1, retries)
            time.sleep(wait)
    raise CollectionError(f"Giving up after {retries} attempts. Last error: {last_error}")


def save_raw(content: bytes, cve_id: str, retrieved_at: datetime) -> Path:
    """Write the response bytes untouched; never overwrite an existing raw file."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    path = RAW_DIR / f"{cve_id}__{stamp(retrieved_at)}.json"
    counter = 1
    while path.exists():
        counter += 1
        path = RAW_DIR / f"{cve_id}__{stamp(retrieved_at)}_{counter}.json"
    with open(path, "xb") as fh:
        fh.write(content)
    return path


# --------------------------------------------------------------------------- 3. validate
def validate_response(doc: object, cve_id: str) -> tuple[str, dict | None, list[str], list[str]]:
    """Returns (outcome, cve_object, errors, warnings); outcome is 'ok' | 'no_record' | 'invalid'."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(doc, dict):
        return "invalid", None, ["response is not a JSON object"], warnings
    for key in ENVELOPE_REQUIRED:
        if key not in doc:
            errors.append(f"envelope missing '{key}'")
    if errors:
        return "invalid", None, errors, warnings
    if doc["format"] != "NVD_CVE":
        warnings.append(f"unexpected format {doc['format']!r} (expected 'NVD_CVE')")
    if str(doc["version"]) != "2.0":
        warnings.append(f"unexpected API version {doc['version']!r} (expected '2.0')")
    vulns = doc["vulnerabilities"]
    if not isinstance(vulns, list):
        return "invalid", None, ["'vulnerabilities' is not a list"], warnings
    if doc["totalResults"] == 0 or not vulns:
        return "no_record", None, errors, warnings
    if len(vulns) != 1:
        return "invalid", None, [f"expected 1 record for a cveId query, got {len(vulns)}"], warnings
    cve = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    if not isinstance(cve, dict):
        return "invalid", None, ["record has no 'cve' object"], warnings
    if str(cve.get("id", "")).upper() != cve_id:
        return "invalid", None, [f"returned id {cve.get('id')!r} != requested {cve_id}"], warnings
    for key in ("published", "lastModified", "descriptions"):
        if not cve.get(key):
            errors.append(f"cve is missing '{key}'")
    if errors:
        return "invalid", None, errors, warnings
    if not any(d.get("lang") == "en" for d in cve["descriptions"] if isinstance(d, dict)):
        warnings.append("no English description")
    if not cve.get("vulnStatus"):
        warnings.append("no vulnStatus")
    return "ok", cve, errors, warnings


# --------------------------------------------------------------------------- 4. normalize
def split_cpe(criteria: str) -> list[str]:
    """Split a CPE 2.3 string on unescaped colons."""
    return re.split(r"(?<!\\):", criteria)


def normalize_cvss(metrics: dict) -> tuple[list[dict], dict | None]:
    entries: list[dict] = []
    for key, version in CVSS_ORDER:
        for item in metrics.get(key, []) or []:
            data = item.get("cvssData", {}) if isinstance(item, dict) else {}
            entries.append({
                "version": data.get("version", version),
                "source": item.get("source"),
                "type": item.get("type"),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or item.get("baseSeverity"),  # v2 keeps severity on the item
                "vector_string": data.get("vectorString"),
            })
    primary = None
    for _, version in CVSS_ORDER:  # newest version first; prefer a 'Primary' entry within that version
        same = [e for e in entries if str(e["version"]) == version]
        if same:
            primary = next((e for e in same if e["type"] == "Primary"), same[0])
            break
    return entries, primary


def normalize_weaknesses(weaknesses: list) -> list[dict]:
    out, seen = [], set()
    for w in weaknesses or []:
        for d in w.get("description", []) if isinstance(w, dict) else []:
            if d.get("lang") == "en" and (d.get("value"), w.get("source")) not in seen:
                seen.add((d.get("value"), w.get("source")))
                out.append({"cwe_id": d.get("value"), "source": w.get("source"), "type": w.get("type")})
    return out


def normalize_affected(configurations: list) -> list[dict]:
    out, seen = [], set()
    for config in configurations or []:
        for node in config.get("nodes", []) if isinstance(config, dict) else []:
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue  # 'running on' context entries stay in the raw file only
                parts = split_cpe(match.get("criteria", ""))
                row = {
                    "cpe_criteria": match.get("criteria"),
                    "vendor": parts[3] if len(parts) > 3 else None,
                    "product": parts[4] if len(parts) > 4 else None,
                    "version": parts[5] if len(parts) > 5 else None,
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                    "match_criteria_id": match.get("matchCriteriaId"),
                }
                key = tuple(row.values())
                if key not in seen:
                    seen.add(key)
                    out.append(row)
    return out


def normalize_record(cve: dict, entry: dict) -> dict:
    description = next((d["value"].strip() for d in cve["descriptions"] if d.get("lang") == "en"), "")
    cvss_all, cvss_primary = normalize_cvss(cve.get("metrics") or {})
    return {
        "record_id": f"nvd:{cve['id']}",
        "cve_id": cve["id"].upper(),
        "description_en": description,
        "vuln_status": cve.get("vulnStatus"),
        "source_identifier": cve.get("sourceIdentifier"),
        "cvss_primary": cvss_primary,            # newest CVSS version available (4.0 > 3.1 > 3.0 > 2.0)
        "cvss_metrics_all": cvss_all,            # nothing is dropped
        "weaknesses": normalize_weaknesses(cve.get("weaknesses")),
        "affected_products": normalize_affected(cve.get("configurations")),
        "references": [{"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])}
                       for r in cve.get("references", []) if isinstance(r, dict)],
        # NVD may carry CISA KEV fields on a record; passed through only as a cross-check.
        # The authoritative 'exploited in the wild' status is the KEV catalog, not NVD.
        "nvd_cisa_fields": {k: v for k, v in cve.items() if k.startswith("cisa")},
        # --- provenance ---
        "source_name": SOURCE_NAME,
        "source_url": entry["request_url"],
        "source_record_id": cve["id"].upper(),
        "retrieved_at": entry["retrieved_at"],
        "published_at": cve.get("published"),
        "last_modified_at": cve.get("lastModified"),
        "original_format": "json",
        "raw_file_reference": f"data/raw/nvd/{entry['raw_file']}",
        "collection_method": COLLECTION_METHOD,
    }


# --------------------------------------------------------------------------- orchestration
def download_all(targets: list[str], result: IngestionResult, args: argparse.Namespace, api_key: str) -> None:
    existing = latest_ok_by_cve(read_manifest())
    session = requests.Session()
    session.headers.update({"User-Agent": os.environ.get("USER_AGENT", "CyberIntelGraph/0.1 (research project)"),
                            "Accept": "application/json"})
    if api_key:
        session.headers["apiKey"] = api_key  # sent as a header, never put in the URL or the logs
    delay = args.delay if args.delay is not None else (0.7 if api_key else 6.5)
    log.info("API key: %s | %.1fs between requests | %d CVE(s) to consider",
             "present (50 requests/30s)" if api_key else "not set (5 requests/30s)", delay, len(targets))

    first_request = True
    for position, cve_id in enumerate(targets, start=1):
        if cve_id in existing and not args.refresh:
            result.reused_existing += 1
            continue
        if not first_request:
            time.sleep(delay)
        first_request = False
        retrieved_at = utc_now()
        try:
            resp = fetch_cve(session, args.base_url, cve_id, args.timeout, args.retries)
        except CollectionError as exc:
            result.failed[cve_id] = str(exc)
            log.error("[%d/%d] %s FAILED: %s", position, len(targets), cve_id, exc)
            continue
        raw_path = save_raw(resp.content, cve_id, retrieved_at)
        sha = hashlib.sha256(resp.content).hexdigest()
        try:
            outcome, _, errs, _ = validate_response(json.loads(resp.content), cve_id)
        except ValueError:
            outcome, errs = "invalid", ["response is not valid JSON"]
        entry = {"cve_id": cve_id, "raw_file": raw_path.name, "retrieved_at": retrieved_at.isoformat(),
                 "request_url": f"{args.base_url}?cveId={cve_id}", "http_status": resp.status_code,
                 "bytes": len(resp.content), "sha256": sha, "outcome": outcome}
        append_manifest(entry)
        if outcome == "ok":
            result.downloaded_new += 1
            log.info("[%d/%d] %s saved (%d bytes)", position, len(targets), cve_id, len(resp.content))
        elif outcome == "no_record":
            result.no_record_returned.append(cve_id)
            log.warning("[%d/%d] %s: NVD answered but returned 0 records (raw response kept)", position, len(targets), cve_id)
        else:
            result.failed[cve_id] = "; ".join(errs)
            log.error("[%d/%d] %s INVALID response: %s (raw kept)", position, len(targets), cve_id, "; ".join(errs))


def normalize_all(result: IngestionResult) -> None:
    latest = latest_ok_by_cve(read_manifest())
    records: list[dict] = []
    for cve_id in sorted(latest):
        entry = latest[cve_id]
        try:
            doc = json.loads((RAW_DIR / entry["raw_file"]).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            result.failed[cve_id] = f"cannot re-read raw file {entry['raw_file']}: {exc}"
            continue
        outcome, cve, errs, warns = validate_response(doc, cve_id)
        if outcome != "ok" or cve is None:
            result.failed[cve_id] = "; ".join(errs) or outcome
            continue
        for w in warns:
            result.warnings.append(f"{cve_id}: {w}")
        record = normalize_record(cve, entry)
        if record["vuln_status"] == "Rejected":
            result.rejected_status.append(cve_id)
        records.append(record)

    result.records_normalized = len(records)
    result.with_cvss = sum(1 for r in records if r["cvss_primary"])
    result.with_weakness = sum(1 for r in records if r["weaknesses"])
    result.with_affected_products = sum(1 for r in records if r["affected_products"])
    if result.rejected_status:
        result.warnings.append(f"{len(result.rejected_status)} CVE(s) have vulnStatus 'Rejected' "
                               f"(e.g. {', '.join(result.rejected_status[:3])})")
    if not records:
        return
    write_json_atomic(NORMALIZED, {
        "metadata": {
            "source_name": SOURCE_NAME, "source_url": API_URL, "generated_at": utc_now().isoformat(),
            "record_count": len(records), "manifest_file": rel(MANIFEST),
            "collection_method": COLLECTION_METHOD,
            "normalization_note": ("Built from the latest successful raw download per CVE. cvss_primary = newest CVSS "
                                   "version available (all metrics kept in cvss_metrics_all). affected_products lists "
                                   "only CPE matches flagged vulnerable=true. NVD does not establish exploitation in the wild."),
        },
        "records": records,
    })
    result.processed_file = rel(NORMALIZED)
    log.info("Wrote normalized copy: %s (%d records)", result.processed_file, len(records))


def write_report(result: IngestionResult) -> None:
    path = REPORT_DIR / f"nvd_validation_{stamp(utc_now())}.json"
    result.report_file = rel(path)
    write_json_atomic(path, asdict(result))


def print_summary(result: IngestionResult) -> None:
    line = lambda label, value: print(f"  {label:<26}: {value}")
    print("\n=== NVD collection summary ===")
    line("Status", "SUCCESS" if result.success else ("INTERRUPTED" if result.interrupted else "FAILED / INCOMPLETE"))
    line("API key used", "yes" if result.api_key_used else "no")
    line("CVEs requested", result.cves_requested)
    line("Downloaded now", result.downloaded_new)
    line("Reused (already on disk)", result.reused_existing)
    line("Answered with 0 records", len(result.no_record_returned))
    line("Failed", len(result.failed))
    line("Normalized records", result.records_normalized)
    line("  with CVSS", result.with_cvss)
    line("  with weakness (CWE)", result.with_weakness)
    line("  with affected products", result.with_affected_products)
    line("Normalized file", result.processed_file or "-")
    line("Manifest", result.manifest_file or "-")
    line("Validation report", result.report_file or "-")
    for message in result.warnings[:10]:
        print(f"  WARNING: {message}")
    if len(result.warnings) > 10:
        print(f"  ... and {len(result.warnings) - 10} more warnings (see validation report)")
    for cve in result.no_record_returned[:10]:
        print(f"  NO RECORD: {cve} (NVD returned 0 records; this is NOT proof the CVE does not exist)")
    for cve, message in list(result.failed.items())[:10]:
        print(f"  FAILED: {cve}: {message}")
    for message in result.errors:
        print(f"  ERROR: {message}")


def run(args: argparse.Namespace) -> IngestionResult:
    result = IngestionResult(source_url=args.base_url, started_at=utc_now().isoformat())
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    result.api_key_used = bool(api_key)
    try:
        targets, invalid = build_target_list(args.limit, args.cve_id or [], not args.no_kev)
    except FileNotFoundError as exc:
        result.errors.append(str(exc))
        log.error("%s", exc)
        return result
    for bad in invalid:
        result.warnings.append(f"ignored invalid CVE ID {bad!r}")
    result.cves_requested = len(targets)
    if not targets:
        result.errors.append("No CVE IDs to collect (check --limit / --cve-id / --no-kev)")
        return result
    try:
        download_all(targets, result, args, api_key)
    except KeyboardInterrupt:
        result.interrupted = True
        log.warning("Interrupted - progress is saved; run again to resume")
    normalize_all(result)
    result.manifest_file = rel(MANIFEST) if MANIFEST.is_file() else ""
    result.success = (not result.interrupted and not result.failed and not result.errors
                      and result.records_normalized > 0)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect CVE records from the official NVD CVE API 2.0.")
    parser.add_argument("--limit", type=int, default=150,
                        help="how many CVEs to take from the KEV ordering (default 150; use 3 for a first test)")
    parser.add_argument("--cve-id", action="append", metavar="CVE-YYYY-NNNN",
                        help="extra CVE ID to fetch (repeatable)")
    parser.add_argument("--no-kev", action="store_true", help="do not read the KEV catalog; only fetch --cve-id values")
    parser.add_argument("--refresh", action="store_true", help="download again even if a raw copy exists")
    parser.add_argument("--delay", type=float, default=None, help="seconds between requests (default 0.7 with key, 6.5 without)")
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--base-url", default=API_URL, help="API endpoint (default: official NVD)")
    args = parser.parse_args(argv)

    load_env_file(ENV_FILE)
    if args.timeout is None:
        args.timeout = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "30"))
    setup_logging()
    try:
        result = run(args)
    except Exception as exc:  # last-resort guard: clear message instead of a raw traceback
        log.exception("Unexpected failure")
        result = IngestionResult(source_url=args.base_url, started_at=utc_now().isoformat())
        result.errors.append(f"Unexpected {type(exc).__name__}: {exc} (details in {rel(LOG_FILE)})")
    write_report(result)
    print_summary(result)
    return 0 if result.success else (130 if result.interrupted else 1)


if __name__ == "__main__":
    sys.exit(main())
