"""MITRE ATT&CK collector (Enterprise domain, STIX 2.1 JSON).

What it does
------------
1. Downloads the collection index (index.json) from the official repository
   github.com/mitre-attack/attack-stix-data and picks the latest Enterprise ATT&CK release
   (or the one you pin with --version).
2. Downloads that ONE versioned bundle (for example enterprise-attack-20.0.json, tens of MB).
   Mobile and ICS domains are not downloaded.
3. Saves both files UNCHANGED to data/raw/mitre_attack/ with .meta.json sidecars (URL, time, SHA-256, version).
   A release that is already on disk is not downloaded again (a release file never changes).
4. Validates the bundle and normalizes the objects we need into data/processed/:
     attack_objects_normalized.json        techniques, tactics, groups, malware, tools, campaigns, mitigations
     attack_relationships_normalized.json  uses / mitigates / subtechnique-of / attributed-to
   Revoked and deprecated objects stay in the raw file but are left out of the normalized files.
5. Writes a validation report to outputs/reports/ and a log to logs/.

Not touched here: x-mitre-analytic, x-mitre-detection-strategy, x-mitre-data-source, x-mitre-data-component
(detection content). They remain in the raw file if we need them later.

Run from the project root (venv active):
    python ingestion\\collectors\\mitre_attack\\collector.py

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
SOURCE_NAME = "MITRE ATT&CK (Enterprise, STIX 2.1)"
REPO_URL = "https://github.com/mitre-attack/attack-stix-data"
INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTION_NAME = "Enterprise ATT&CK"
COLLECTION_METHOD = "official STIX 2.1 collection bundle (versioned release) via HTTP GET (requests)"

# collector.py lives in <root>/ingestion/collectors/mitre_attack/ -> root is 3 levels up
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "mitre_attack"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OBJECTS_FILE = PROCESSED_DIR / "attack_objects_normalized.json"
RELATIONSHIPS_FILE = PROCESSED_DIR / "attack_relationships_normalized.json"
REPORT_DIR = PROJECT_ROOT / "outputs" / "reports"
LOG_FILE = PROJECT_ROOT / "logs" / "mitre_attack_collector.log"

KEEP_TYPES = ("attack-pattern", "x-mitre-tactic", "intrusion-set", "malware", "tool", "campaign", "course-of-action")
KEEP_REL_TYPES = ("uses", "mitigates", "subtechnique-of", "attributed-to")
ID_PATTERNS = {  # ATT&CK external id format per STIX type
    "attack-pattern": re.compile(r"^T\d{4}(\.\d{3})?$"),
    "x-mitre-tactic": re.compile(r"^TA\d{4}$"),
    "intrusion-set": re.compile(r"^G\d{4}$"),
    "malware": re.compile(r"^S\d{4}$"),
    "tool": re.compile(r"^S\d{4}$"),
    "campaign": re.compile(r"^C\d{4}$"),
    "course-of-action": re.compile(r"^M\d{4}$"),
}
RETRY_STATUS = {429, 500, 502, 503, 504}

log = logging.getLogger("mitre_attack_collector")


# --------------------------------------------------------------------------- result object
@dataclass
class IngestionResult:
    """Consistent result returned by every collector in this project."""
    source_name: str = SOURCE_NAME
    source_url: str = INDEX_URL
    success: bool = False
    retrieved_at: str = ""
    attack_version: str = ""
    bundle_url: str = ""
    bundle_bytes: int = 0
    bundle_reused: bool = False
    index_file: str = ""
    bundle_file: str = ""
    bundle_sha256: str = ""
    objects_in_bundle: int = 0
    objects_by_type_in_bundle: dict = field(default_factory=dict)
    excluded_revoked_or_deprecated: int = 0
    objects_normalized: int = 0
    objects_by_type: dict = field(default_factory=dict)
    relationships_in_bundle: int = 0
    relationships_normalized: int = 0
    relationships_by_type: dict = field(default_factory=dict)
    relationships_excluded: dict = field(default_factory=dict)
    objects_file: str = ""
    relationships_file: str = ""
    report_file: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Raised when a file cannot be retrieved."""


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
        json.dump(data, fh, ensure_ascii=False, indent=indent,
                  separators=None if indent else (",", ":"))
        fh.write("\n")
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in str(version).split("."))


# --------------------------------------------------------------------------- 1. fetch
def fetch(url: str, timeout: float, retries: int, user_agent: str) -> requests.Response:
    """GET with retries on timeouts, connection errors, 429 and 5xx."""
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


# --------------------------------------------------------------------------- 2. raw storage
def save_raw(content: bytes, prefix: str, kind: str, url: str, retrieved_at: datetime,
             resp: requests.Response, extra: dict | None = None) -> tuple[Path, str, bool]:
    """Save bytes untouched, never overwrite; reuse an earlier file with identical bytes."""
    sha = hashlib.sha256(content).hexdigest()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for meta_path in sorted(RAW_DIR.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        existing = RAW_DIR / str(meta.get("raw_file", ""))
        if meta.get("sha256") == sha and meta.get("kind") == kind and existing.is_file():
            log.info("Identical %s already on disk; reusing %s", kind, rel(existing))
            return existing, sha, False
    path = RAW_DIR / f"{prefix}__{stamp(retrieved_at)}.json"
    counter = 1
    while path.exists():
        counter += 1
        path = RAW_DIR / f"{prefix}__{stamp(retrieved_at)}_{counter}.json"
    with open(path, "xb") as fh:
        fh.write(content)
    meta = {"source_name": SOURCE_NAME, "kind": kind, "source_url": url, "retrieved_at": retrieved_at.isoformat(),
            "http_status": resp.status_code, "content_type": resp.headers.get("Content-Type", ""),
            "etag": resp.headers.get("ETag", ""), "bytes": len(content), "sha256": sha, "raw_file": path.name,
            "original_format": "json", "collection_method": COLLECTION_METHOD, **(extra or {})}
    write_json_atomic(path.with_suffix(".meta.json"), meta)
    log.info("Saved raw %s: %s (%d bytes, sha256 %s...)", kind, rel(path), len(content), sha[:12])
    return path, sha, True


def find_bundle_on_disk(version: str) -> tuple[Path, str] | None:
    """A versioned release never changes, so a verified copy on disk means no download is needed."""
    for meta_path in sorted(RAW_DIR.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        path = RAW_DIR / str(meta.get("raw_file", ""))
        if meta.get("kind") == "bundle" and str(meta.get("attack_version")) == version and path.is_file():
            if sha256_file(path) != meta.get("sha256"):
                raise CollectionError(f"{rel(path)} no longer matches its recorded SHA-256 (file was changed). "
                                      "Raw files must never be edited: restore or delete it, then run again.")
            return path, meta["sha256"]
    return None


# --------------------------------------------------------------------------- 3. choose release
def choose_release(index: dict, collection_name: str, pin: str | None) -> tuple[str, str]:
    """Return (version, bundle_url) from index.json."""
    if not isinstance(index, dict) or not isinstance(index.get("collections"), list):
        raise CollectionError("index.json has no 'collections' list")
    collection = next((c for c in index["collections"] if c.get("name") == collection_name), None)
    if collection is None:
        names = [c.get("name") for c in index["collections"]]
        raise CollectionError(f"collection {collection_name!r} not in index.json (found {names})")
    versions = [v for v in collection.get("versions", []) if v.get("version") and v.get("url")]
    if not versions:
        raise CollectionError(f"collection {collection_name!r} lists no downloadable versions")
    if pin:
        match = next((v for v in versions if str(v["version"]) == pin), None)
        if match is None:
            raise CollectionError(f"version {pin!r} not found; available: {[v['version'] for v in versions][:8]} ...")
        return str(match["version"]), match["url"]
    best = max(versions, key=lambda v: version_key(v["version"]))
    return str(best["version"]), best["url"]


# --------------------------------------------------------------------------- 4. validate + normalize
def is_active(obj: dict) -> bool:
    return obj.get("revoked") is not True and obj.get("x_mitre_deprecated") is not True


def attack_ref(obj: dict) -> dict | None:
    """The external reference that carries the ATT&CK ID (source_name 'mitre-attack')."""
    return next((r for r in obj.get("external_references", [])
                 if isinstance(r, dict) and r.get("source_name") == "mitre-attack" and r.get("external_id")), None)


def clean_refs(refs: list) -> list[dict]:
    return [{"source_name": r.get("source_name"), "external_id": r.get("external_id"),
             "url": r.get("url"), "description": r.get("description")}
            for r in refs or [] if isinstance(r, dict)]


def validate_bundle(doc: object) -> tuple[list[dict], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(doc, dict) or doc.get("type") != "bundle":
        return [], ["file is not a STIX bundle (type != 'bundle')"], warnings
    objects = doc.get("objects")
    if not isinstance(objects, list) or not objects:
        return [], ["bundle has no 'objects' list"], warnings
    seen: set[str] = set()
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict) or not obj.get("id") or not obj.get("type"):
            errors.append(f"object #{i} has no id/type")
            continue
        if obj["id"] in seen:
            errors.append(f"duplicate STIX id {obj['id']}")
        seen.add(obj["id"])
        if not str(obj["id"]).startswith(f"{obj['type']}--"):
            errors.append(f"object #{i}: id {obj['id']} does not match type {obj['type']}")
    return objects, errors, warnings


def normalize_object(obj: dict, ctx: dict) -> dict:
    ref = attack_ref(obj)
    attack_id = ref["external_id"]
    stix_type = obj["type"]
    record = {
        "record_id": f"attack:{attack_id}",
        "stix_id": obj["id"],
        "stix_type": stix_type,
        "attack_id": attack_id,
        "name": obj.get("name", "").strip(),
        "description": (obj.get("description") or "").strip(),
        "attack_url": ref.get("url"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "object_version": obj.get("x_mitre_version"),
        "domains": obj.get("x_mitre_domains", []),
        "aliases": obj.get("aliases") or obj.get("x_mitre_aliases") or [],
        "platforms": obj.get("x_mitre_platforms", []),
        "external_references": clean_refs(obj.get("external_references")),
    }
    if stix_type == "attack-pattern":
        record["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
        record["tactics"] = [k["phase_name"] for k in obj.get("kill_chain_phases", [])
                             if k.get("kill_chain_name") == "mitre-attack"]
        record["parent_attack_id"] = None  # filled in from 'subtechnique-of' relationships
    elif stix_type == "x-mitre-tactic":
        record["shortname"] = obj.get("x_mitre_shortname")
    elif stix_type == "malware":
        record["is_family"] = obj.get("is_family")
    elif stix_type == "campaign":
        record["first_seen"] = obj.get("first_seen")
        record["last_seen"] = obj.get("last_seen")
    record.update({  # provenance
        "source_name": SOURCE_NAME, "source_url": ctx["bundle_url"], "source_record_id": attack_id,
        "retrieved_at": ctx["retrieved_at"], "published_at": obj.get("created"), "last_modified_at": obj.get("modified"),
        "original_format": "stix-2.1-json", "raw_file_reference": ctx["raw_ref"], "collection_method": COLLECTION_METHOD,
        "attack_version": ctx["version"], "evidence_type": "structured_authoritative_record",
    })
    return record


def normalize(objects: list[dict], ctx: dict, result: IngestionResult) -> tuple[list[dict], list[dict]]:
    by_id = {o["id"]: o for o in objects if isinstance(o, dict) and "id" in o}
    result.objects_in_bundle = len(objects)
    result.objects_by_type_in_bundle = dict(Counter(o["type"] for o in objects if "type" in o))
    result.relationships_in_bundle = result.objects_by_type_in_bundle.get("relationship", 0)

    kept: dict[str, dict] = {}
    seen_attack_ids: set[tuple[str, str]] = set()
    for obj in objects:
        if obj.get("type") not in KEEP_TYPES:
            continue
        if not is_active(obj):
            result.excluded_revoked_or_deprecated += 1
            continue
        ref = attack_ref(obj)
        if ref is None:
            result.errors.append(f"{obj['id']} ({obj.get('name')}): no 'mitre-attack' external id")
            continue
        if not ID_PATTERNS[obj["type"]].match(ref["external_id"]):
            result.errors.append(f"{obj['id']}: unexpected ATT&CK id format {ref['external_id']!r} for {obj['type']}")
            continue
        key = (obj["type"], ref["external_id"])
        if key in seen_attack_ids:
            result.errors.append(f"duplicate ATT&CK id {ref['external_id']} for {obj['type']}")
            continue
        seen_attack_ids.add(key)
        kept[obj["id"]] = normalize_object(obj, ctx)

    excluded = Counter()
    relationships: list[dict] = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rtype = obj.get("relationship_type")
        src, dst = obj.get("source_ref"), obj.get("target_ref")
        if src not in by_id or dst not in by_id:
            result.errors.append(f"relationship {obj.get('id')}: endpoint missing from bundle ({src} -> {dst})")
            continue
        if not is_active(obj):
            excluded["relationship revoked/deprecated"] += 1
        elif rtype == "revoked-by":
            excluded["revoked-by (replacement pointer)"] += 1
        elif rtype not in KEEP_REL_TYPES:
            excluded[f"type '{rtype}' not in scope (e.g. detection content)"] += 1
        elif by_id[src]["type"] not in KEEP_TYPES or by_id[dst]["type"] not in KEEP_TYPES:
            excluded["endpoint object type not in scope"] += 1
        elif src not in kept or dst not in kept:
            excluded["endpoint is revoked/deprecated"] += 1
        else:
            relationships.append({
                "record_id": f"attack-rel:{obj['id']}",
                "stix_id": obj["id"],
                "relationship_type": rtype,
                "source_stix_id": src, "source_stix_type": by_id[src]["type"], "source_attack_id": kept[src]["attack_id"],
                "target_stix_id": dst, "target_stix_type": by_id[dst]["type"], "target_attack_id": kept[dst]["attack_id"],
                "description": (obj.get("description") or "").strip(),
                "created": obj.get("created"), "modified": obj.get("modified"),
                "external_references": clean_refs(obj.get("external_references")),
                "source_name": SOURCE_NAME, "source_url": ctx["bundle_url"], "source_record_id": obj["id"],
                "retrieved_at": ctx["retrieved_at"], "published_at": obj.get("created"),
                "last_modified_at": obj.get("modified"), "original_format": "stix-2.1-json",
                "raw_file_reference": ctx["raw_ref"], "collection_method": COLLECTION_METHOD,
                "attack_version": ctx["version"], "evidence_type": "structured_authoritative_record",
            })
    result.relationships_excluded = dict(excluded)

    # sub-technique -> parent technique (from relationships), exactly one parent expected
    parents: dict[str, list[str]] = {}
    for r in relationships:
        if r["relationship_type"] == "subtechnique-of":
            parents.setdefault(r["source_stix_id"], []).append(r["target_attack_id"])
    for stix_id, rec in kept.items():
        if rec["stix_type"] == "attack-pattern" and rec["is_subtechnique"]:
            found = parents.get(stix_id, [])
            if len(found) == 1:
                rec["parent_attack_id"] = found[0]
            else:
                result.errors.append(f"sub-technique {rec['attack_id']} has {len(found)} parent(s), expected 1")

    shortnames = {r["shortname"] for r in kept.values() if r["stix_type"] == "x-mitre-tactic"}
    for rec in kept.values():
        if rec["stix_type"] == "attack-pattern":
            unknown = [t for t in rec["tactics"] if t not in shortnames]
            if unknown:
                result.errors.append(f"technique {rec['attack_id']}: unknown tactic(s) {unknown}")
            if not rec["tactics"]:
                result.warnings.append(f"technique {rec['attack_id']} has no tactic")

    records = sorted(kept.values(), key=lambda r: (r["stix_type"], r["attack_id"]))
    relationships.sort(key=lambda r: (r["relationship_type"], r["source_attack_id"], r["target_attack_id"], r["stix_id"]))
    result.objects_normalized = len(records)
    result.objects_by_type = dict(Counter(r["stix_type"] for r in records))
    result.relationships_normalized = len(relationships)
    result.relationships_by_type = dict(Counter(r["relationship_type"] for r in relationships))
    return records, relationships


# --------------------------------------------------------------------------- orchestration
def run(args: argparse.Namespace) -> IngestionResult:
    result = IngestionResult(source_url=args.index_url)
    retrieved_at = utc_now()
    result.retrieved_at = retrieved_at.isoformat()
    user_agent = os.environ.get("USER_AGENT", "CyberIntelGraph/0.1 (research project)")

    try:
        resp = fetch(args.index_url, args.timeout, args.retries, user_agent)
        index_path, _, _ = save_raw(resp.content, "index", "index", args.index_url, retrieved_at, resp)
        result.index_file = rel(index_path)
        version, bundle_url = choose_release(json.loads(resp.content), COLLECTION_NAME, args.version)
        if args.bundle_url:
            bundle_url = args.bundle_url
    except (CollectionError, ValueError) as exc:
        result.errors.append(str(exc))
        log.error("%s", exc)
        return result
    result.attack_version, result.bundle_url = version, bundle_url
    log.info("Selected release: %s %s", COLLECTION_NAME, version)

    try:
        on_disk = None if args.refresh else find_bundle_on_disk(version)
        if on_disk:
            bundle_path, sha = on_disk
            result.bundle_reused = True
            log.info("Release %s already downloaded and verified; reusing %s", version, rel(bundle_path))
            content = bundle_path.read_bytes()
        else:
            resp = fetch(bundle_url, args.bundle_timeout, args.retries, user_agent)
            content = resp.content
            bundle_path, sha, saved_new = save_raw(content, f"enterprise-attack-{version}", "bundle", bundle_url,
                                                   retrieved_at, resp, {"attack_version": version})
            result.bundle_reused = not saved_new
    except CollectionError as exc:
        result.errors.append(str(exc))
        log.error("%s", exc)
        return result
    result.bundle_file, result.bundle_sha256, result.bundle_bytes = rel(bundle_path), sha, len(content)

    try:
        doc = json.loads(content)
    except ValueError as exc:
        result.errors.append(f"Bundle is not valid JSON: {exc} (raw file kept for inspection)")
        log.error("%s", result.errors[-1])
        return result
    objects, errors, warnings = validate_bundle(doc)
    result.errors += errors
    result.warnings += warnings
    if not objects:
        return result

    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), None)
    if collection and str(collection.get("x_mitre_version")) != version:
        result.warnings.append(f"bundle says version {collection.get('x_mitre_version')!r} but index said {version!r}")
    if collection is None:
        result.warnings.append("bundle has no x-mitre-collection object (version could not be cross-checked)")

    ctx = {"bundle_url": bundle_url, "retrieved_at": result.retrieved_at, "raw_ref": result.bundle_file, "version": version}
    records, relationships = normalize(objects, ctx, result)

    meta = {"source_name": SOURCE_NAME, "repository": REPO_URL, "attack_version": version, "bundle_url": bundle_url,
            "generated_at": utc_now().isoformat(), "retrieved_at": result.retrieved_at,
            "raw_file_reference": result.bundle_file, "raw_sha256": sha, "collection_method": COLLECTION_METHOD,
            "normalization_note": ("Only active (not revoked, not deprecated) objects of types " + ", ".join(KEEP_TYPES)
                                   + " are kept; STIX direction is preserved (e.g. campaign attributed-to intrusion-set).")}
    write_json_atomic(OBJECTS_FILE, {"metadata": {**meta, "record_count": len(records),
                                                  "records_by_type": result.objects_by_type}, "records": records})
    write_json_atomic(RELATIONSHIPS_FILE, {"metadata": {**meta, "record_count": len(relationships),
                                                        "records_by_type": result.relationships_by_type},
                                           "records": relationships}, indent=None)
    result.objects_file, result.relationships_file = rel(OBJECTS_FILE), rel(RELATIONSHIPS_FILE)
    log.info("Wrote %s (%d objects) and %s (%d relationships)", result.objects_file, len(records),
             result.relationships_file, len(relationships))
    result.success = not result.errors and len(records) > 0
    return result


def write_report(result: IngestionResult) -> None:
    path = REPORT_DIR / f"mitre_attack_validation_{stamp(utc_now())}.json"
    result.report_file = rel(path)
    write_json_atomic(path, asdict(result))


def print_summary(result: IngestionResult) -> None:
    line = lambda label, value: print(f"  {label:<30}: {value}")
    print("\n=== MITRE ATT&CK collection summary ===")
    line("Status", "SUCCESS" if result.success else "FAILED")
    line("Release", f"{COLLECTION_NAME} {result.attack_version or '-'}")
    line("Bundle file", (result.bundle_file or "-") + ("  (reused, already on disk)" if result.bundle_reused else ""))
    line("Bundle size (bytes)", result.bundle_bytes)
    line("Objects in bundle", result.objects_in_bundle)
    line("Excluded revoked/deprecated", result.excluded_revoked_or_deprecated)
    line("Objects normalized", result.objects_normalized)
    for k, v in sorted(result.objects_by_type.items()):
        line(f"   {k}", v)
    line("Relationships in bundle", result.relationships_in_bundle)
    line("Relationships normalized", result.relationships_normalized)
    for k, v in sorted(result.relationships_by_type.items()):
        line(f"   {k}", v)
    for k, v in sorted(result.relationships_excluded.items()):
        line(f"   excluded: {k}", v)
    line("Objects file", result.objects_file or "-")
    line("Relationships file", result.relationships_file or "-")
    line("Validation report", result.report_file or "-")
    line("Warnings", len(result.warnings))
    line("Errors", len(result.errors))
    for message in result.warnings[:10]:
        print(f"  WARNING: {message}")
    for message in result.errors[:20]:
        print(f"  ERROR: {message}")
    if len(result.errors) > 20:
        print(f"  ... and {len(result.errors) - 20} more errors (see validation report)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect MITRE ATT&CK Enterprise (STIX 2.1) from the official repository.")
    parser.add_argument("--version", default=None, help="pin a release, e.g. 20.0 (default: latest in index.json)")
    parser.add_argument("--refresh", action="store_true", help="download the release again even if it is on disk")
    parser.add_argument("--index-url", default=INDEX_URL)
    parser.add_argument("--bundle-url", default=None, help="override the bundle URL taken from index.json (testing)")
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--bundle-timeout", type=float, default=180.0, help="timeout for the large bundle (default 180 s)")
    args = parser.parse_args(argv)

    setup_logging()
    try:
        result = run(args)
    except Exception as exc:  # last-resort guard
        log.exception("Unexpected failure")
        result = IngestionResult(source_url=args.index_url, retrieved_at=utc_now().isoformat())
        result.errors.append(f"Unexpected {type(exc).__name__}: {exc} (details in {rel(LOG_FILE)})")
    write_report(result)
    print_summary(result)
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
