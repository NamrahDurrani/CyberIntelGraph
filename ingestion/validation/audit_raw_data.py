"""Milestone 4: combined raw data audit (validation and storage).

One command that audits ALL five sources together and answers: is the raw data complete, untouched, fresh,
properly stored, consistent across sources, and well documented?

What it checks
--------------
1. Raw inventory per source: every file listed in a .meta.json sidecar or manifest exists, matches its SHA-256 and size;
   orphan files (on disk, recorded nowhere); duplicate content; read-only protection.
2. Freshness: age of the newest download, plus what each source says about itself (catalog version / date).
3. Processed data: record counts per source (re-read from disk).
4. Dataset targets (config/dataset_targets.json): met, below or above.
5. Cross-source integrity: NVD vs KEV, CWE ids vs the CWE catalog, advisory mentions vs KEV / NVD / ATT&CK / CWE,
   NVD's embedded CISA dates vs the KEV catalog.
6. Field inventory: which fields really occur in the raw data, which our normalizers use, which are ignored.
7. Storage hygiene: nothing from data/, outputs/, logs/ or .env is tracked by Git.
8. The five independent check scripts (the Milestone 3 gate).
9. Documentation: data dictionary pages exist and are not still marked "not verified".

Output: console summary, outputs/reports/raw_data_audit_<time>.json, and (with --write-doc) the Git-tracked
docs/data_dictionary/RAW_DATA_AUDIT.md. Exit code 1 only if there is a FAIL finding (integrity, storage, checks);
WARN findings (targets, freshness, unknown mentions) do not fail.

Run from the project root (venv active):
    python ingestion\\validation\\audit_raw_data.py --write-doc
Options: --fast (skip the heavy field inventory of the ATT&CK bundle and CWE XML), --skip-checks, --max-age-days 30
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2}

SOURCES = {
    "kev": {"label": "CISA KEV", "raw": "data/raw/cisa_kev", "index": "sidecar", "check": "check_kev_output.py",
            "processed": ["data/processed/cisa_kev_normalized.json", "data/processed/cisa_kev_initial_subset.json"],
            "doc": "cisa_kev.md", "collector": "python ingestion\\collectors\\cisa_kev\\collector.py"},
    "nvd": {"label": "NVD", "raw": "data/raw/nvd", "index": "manifest", "check": "check_nvd_output.py",
            "processed": ["data/processed/nvd_normalized.json"], "doc": "nvd.md",
            "collector": "python ingestion\\collectors\\nvd\\collector.py"},
    "attack": {"label": "MITRE ATT&CK", "raw": "data/raw/mitre_attack", "index": "sidecar", "check": "check_attack_output.py",
               "processed": ["data/processed/attack_objects_normalized.json", "data/processed/attack_relationships_normalized.json"],
               "doc": "mitre_attack.md", "collector": "python ingestion\\collectors\\mitre_attack\\collector.py"},
    "cwe": {"label": "CWE", "raw": "data/raw/cwe", "index": "sidecar", "check": "check_cwe_output.py",
            "processed": ["data/processed/cwe_normalized.json", "data/processed/cwe_initial_subset.json"], "doc": "cwe.md",
            "collector": "python ingestion\\collectors\\cwe\\collector.py"},
    "advisories": {"label": "CISA advisories", "raw": "data/raw/advisories", "index": "manifest", "check": "check_advisories_output.py",
                   "processed": ["data/processed/advisories_normalized.json"], "doc": "advisories.md",
                   "collector": "python ingestion\\collectors\\advisories\\collector.py"},
}

# fields our normalizers read (everything else in the raw data is ignored on purpose or not yet used)
CONSUMED = {
    "kev": {"record": {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
                       "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes"},
            "envelope": {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"}},
    "nvd": {"cve": {"id", "sourceIdentifier", "published", "lastModified", "vulnStatus", "descriptions", "metrics",
                    "weaknesses", "configurations", "references"}},   # plus every key that starts with 'cisa'
    "attack": {"common": {"id", "type", "name", "description", "external_references", "created", "modified", "x_mitre_version",
                          "x_mitre_domains", "aliases", "x_mitre_aliases", "x_mitre_platforms", "revoked", "x_mitre_deprecated"},
               "attack-pattern": {"kill_chain_phases", "x_mitre_is_subtechnique"}, "x-mitre-tactic": {"x_mitre_shortname"},
               "malware": {"is_family"}, "campaign": {"first_seen", "last_seen"}},
    "cwe": {"attributes": {"ID", "Name", "Abstraction", "Structure", "Status"},
            "children": {"Description", "Summary", "Extended_Description", "Related_Weaknesses", "Applicable_Platforms",
                         "Related_Attack_Patterns", "Taxonomy_Mappings", "Mapping_Notes", "Content_History", "Relationships",
                         "Objective"}},
}
ATTACK_KEEP = ("attack-pattern", "x-mitre-tactic", "intrusion-set", "malware", "tool", "campaign", "course-of-action")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ICS_ID = re.compile(r"^T08\d{2}$")  # ATT&CK for ICS technique ids


# --------------------------------------------------------------------------- small helpers
class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, severity: str, area: str, message: str) -> None:
        self.items.append({"severity": severity, "area": area, "message": message})

    def count(self, severity: str) -> int:
        return sum(1 for f in self.items if f["severity"] == severity)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_iso(value: str | None) -> datetime | None:
    try:
        parsed = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_read_only(path: Path) -> bool:
    return not (path.stat().st_mode & stat.S_IWRITE)


# --------------------------------------------------------------------------- 1. raw inventory
def load_entries(root: Path, key: str) -> list[dict]:
    """Everything the collectors recorded about downloaded files for one source (sidecars and/or manifest)."""
    spec = SOURCES[key]
    raw_dir = root / spec["raw"]
    entries: list[dict] = []
    if not raw_dir.is_dir():
        return entries
    sidecar_glob = "feed__*.meta.json" if spec["index"] == "manifest" else "*.meta.json"
    for meta_path in sorted(raw_dir.glob(sidecar_glob)):
        meta = load_json(meta_path)
        if isinstance(meta, dict) and meta.get("raw_file"):
            entries.append({"raw_file": meta["raw_file"], "sha256": meta.get("sha256"), "bytes": meta.get("bytes"),
                            "retrieved_at": meta.get("retrieved_at"), "kind": meta.get("kind", "file"),
                            "attack_version": meta.get("attack_version")})
    manifest = raw_dir / "manifest.jsonl"
    if spec["index"] == "manifest" and manifest.is_file():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("raw_file"):
                entries.append({"raw_file": row["raw_file"], "sha256": row.get("sha256"), "bytes": row.get("bytes"),
                                "retrieved_at": row.get("retrieved_at"), "kind": row.get("outcome", "file"),
                                "url": row.get("url") or row.get("cve_id")})
    return entries


def audit_files(root: Path, key: str, findings: Findings) -> dict:
    spec = SOURCES[key]
    raw_dir = root / spec["raw"]
    entries = load_entries(root, key)
    result = {"label": spec["label"], "entries": len(entries), "files_on_disk": 0, "bytes": 0, "verified_ok": 0,
              "missing": [], "mismatched": [], "orphans": [], "duplicate_content": [], "read_only_files": 0,
              "newest_retrieved_at": None, "oldest_retrieved_at": None, "age_days": None}
    if not entries:
        findings.add("FAIL" if raw_dir.is_dir() and any(raw_dir.iterdir()) else "WARN", spec["label"],
                     f"no recorded downloads found in {spec['raw']} (run: {spec['collector']})")
        return result
    referenced, by_hash = set(), {}
    for e in entries:
        path = raw_dir / e["raw_file"]
        referenced.add(e["raw_file"])
        if not path.is_file():
            result["missing"].append(e["raw_file"])
            continue
        actual = sha256_file(path)
        size = path.stat().st_size
        if (e["sha256"] and actual != e["sha256"]) or (e["bytes"] and size != e["bytes"]):
            result["mismatched"].append(e["raw_file"])
            continue
        result["verified_ok"] += 1
        result["bytes"] += size
        by_hash.setdefault(actual, set()).add(e["raw_file"])
        result["read_only_files"] += int(is_read_only(path))
    ignore = {".gitkeep", "manifest.jsonl"}
    for path in sorted(raw_dir.iterdir()):
        if path.is_file() and path.name not in ignore and not path.name.endswith((".meta.json", ".tmp")) and path.name not in referenced:
            result["orphans"].append(path.name)
    result["files_on_disk"] = sum(1 for p in raw_dir.iterdir() if p.is_file() and p.name not in ignore and not p.name.endswith((".meta.json", ".tmp")))
    result["duplicate_content"] = sorted(sorted(v) for v in by_hash.values() if len(v) > 1)
    times = sorted(t for t in (parse_iso(e["retrieved_at"]) for e in entries) if t)
    if times:
        result["oldest_retrieved_at"], result["newest_retrieved_at"] = times[0].isoformat(), times[-1].isoformat()
        result["age_days"] = round((datetime.now(timezone.utc) - times[-1]).total_seconds() / 86400, 1)

    label = spec["label"]
    if result["missing"]:
        findings.add("FAIL", label, f"{len(result['missing'])} recorded raw file(s) are missing, e.g. {result['missing'][:3]}")
    if result["mismatched"]:
        findings.add("FAIL", label, f"{len(result['mismatched'])} raw file(s) no longer match their SHA-256/size (changed after download), e.g. {result['mismatched'][:3]}")
    if result["orphans"]:
        findings.add("WARN", label, f"{len(result['orphans'])} file(s) in {spec['raw']} are recorded nowhere, e.g. {result['orphans'][:3]}")
    if result["duplicate_content"]:
        findings.add("INFO", label, f"{len(result['duplicate_content'])} group(s) of raw files with identical content, e.g. {result['duplicate_content'][0]}")
    if not result["missing"] and not result["mismatched"]:
        findings.add("INFO", label, f"{result['verified_ok']} raw file(s) verified against their SHA-256 ({result['bytes']:,} bytes)")
    return result


# --------------------------------------------------------------------------- 2/3. processed data + freshness
def processed_stats(root: Path, findings: Findings) -> dict:
    stats: dict[str, dict] = {}
    kev, subset = load_json(root / SOURCES["kev"]["processed"][0]), load_json(root / SOURCES["kev"]["processed"][1])
    if kev:
        stats["kev"] = {"records": len(kev["records"]), "initial_subset_records": len(subset["records"]) if subset else 0,
                        "catalog_version": kev["metadata"].get("catalog_version"), "source_date": kev["metadata"].get("catalog_date_released")}
    nvd = load_json(root / SOURCES["nvd"]["processed"][0])
    if nvd:
        modified = [r["last_modified_at"] for r in nvd["records"] if r.get("last_modified_at")]
        stats["nvd"] = {"records": len(nvd["records"]), "source_date": max(modified) if modified else None}
    objs, rels = (load_json(root / p) for p in SOURCES["attack"]["processed"])
    if objs and rels:
        stats["attack"] = {"objects": len(objs["records"]), "relationships": len(rels["records"]),
                           "catalog_version": objs["metadata"].get("attack_version"), "source_date": None}
    cwe, cwe_subset = (load_json(root / p) for p in SOURCES["cwe"]["processed"])
    if cwe:
        stats["cwe"] = {"records": len(cwe["records"]), "weaknesses": sum(1 for r in cwe["records"] if r["element_type"] == "weakness"),
                        "categories": sum(1 for r in cwe["records"] if r["element_type"] == "category"),
                        "other_entries": sum(1 for r in cwe["records"] if r["element_type"] not in ("weakness", "category")), "views": len(cwe["views"]),
                        "initial_subset_records": len(cwe_subset["records"]) if cwe_subset else 0,
                        "catalog_version": cwe["metadata"].get("catalog_version"), "source_date": cwe["metadata"].get("catalog_date")}
    adv = load_json(root / SOURCES["advisories"]["processed"][0])
    if adv:
        dates = sorted(r["published_at"] for r in adv["records"] if r.get("published_at"))
        stats["advisories"] = {"documents": len(adv["records"]), "source_date": dates[-1] if dates else None,
                               "words": sum(r["word_count"] for r in adv["records"])}
    for key, spec in SOURCES.items():
        if key not in stats and (root / spec["raw"]).is_dir() and load_entries(root, key):
            findings.add("FAIL", spec["label"], f"raw data exists but the processed file is missing ({spec['processed'][0]}); run: {spec['collector']}")
    return stats


def freshness_findings(files: dict, max_age_days: float, findings: Findings) -> None:
    for key, info in files.items():
        if info.get("age_days") is not None and info["age_days"] > max_age_days:
            findings.add("WARN", info["label"], f"newest download is {info['age_days']} days old (limit {max_age_days}); "
                                                 f"run the collector again to refresh")


# --------------------------------------------------------------------------- 4. targets
def evaluate_targets(targets: list[dict], stats: dict) -> list[dict]:
    rows = []
    for t in targets:
        value = stats.get(t["source"], {}).get(t["metric"])
        if value is None:
            status = "NO DATA"
        elif value < t["min"]:
            status = "BELOW"
        elif t.get("max") is not None and value > t["max"]:
            status = "ABOVE"
        else:
            status = "MET"
        rows.append({**t, "actual": value, "status": status})
    return rows


# --------------------------------------------------------------------------- 5. cross-source integrity
def cross_checks(data: dict) -> dict:
    """data holds plain sets/dicts loaded from the processed files; returns findings-ready numbers."""
    out: dict = {}
    kev_ids, nvd_ids = data["kev_ids"], data["nvd_ids"]
    if kev_ids and nvd_ids:
        out["nvd_in_kev"] = {"matched": len(nvd_ids & kev_ids), "total": len(nvd_ids)}
        subset = data["kev_subset_ids"]
        out["kev_subset_in_nvd"] = {"matched": len(subset & nvd_ids), "total": len(subset)}
    cwe_ids = data["cwe_ids"]
    if cwe_ids:
        for name, ids in (("nvd_cwe_in_catalog", data["nvd_cwe_ids"]), ("kev_cwe_in_catalog", data["kev_cwe_ids"]),
                          ("advisory_cwe_in_catalog", data["adv_cwe_ids"])):
            missing = sorted(ids - cwe_ids)
            out[name] = {"matched": len(ids) - len(missing), "total": len(ids), "missing": missing[:15]}
    adv_cves = data["adv_cve_ids"]
    if adv_cves:
        in_kev, in_nvd = adv_cves & kev_ids, adv_cves & nvd_ids
        out["advisory_cves"] = {"total": len(adv_cves), "in_kev": len(in_kev), "in_nvd_set": len(in_nvd),
                                "in_neither": len(adv_cves - kev_ids - nvd_ids), "not_in_kev_examples": sorted(adv_cves - kev_ids)[:10]}
    if data["attack_technique_ids"] and data["adv_attack_ids"]:
        not_active = sorted(data["adv_attack_ids"] - data["attack_technique_ids"])
        ics = [i for i in not_active if ICS_ID.match(i)]          # T0800-T0899 belong to the ICS matrix, which we do not collect
        unknown = [i for i in not_active if not ICS_ID.match(i)]
        out["advisory_attack_ids"] = {"total": len(data["adv_attack_ids"]), "known": len(data["adv_attack_ids"]) - len(not_active),
                                      "ics_matrix": ics[:20], "ics_matrix_count": len(ics), "unknown": unknown[:15], "unknown_count": len(unknown)}
    pairs = data["nvd_cisa_vs_kev"]  # list of (cve, nvd_exploit_add, kev_date_added, nvd_action_due, kev_due)
    if pairs:
        has = [p for p in pairs if p[1]]
        out["nvd_cisa_dates"] = {"compared": len(has), "records_without_field": len(pairs) - len(has),
                                 "added_mismatch": [(p[0], p[1], p[2]) for p in has if p[1] != p[2]][:10],
                                 "due_mismatch": [(p[0], p[3], p[4]) for p in has if p[3] and p[4] and p[3] != p[4]][:10]}
    return out


def collect_cross_data(root: Path) -> dict:
    kev = load_json(root / SOURCES["kev"]["processed"][0])
    kev_subset = load_json(root / SOURCES["kev"]["processed"][1])
    nvd = load_json(root / SOURCES["nvd"]["processed"][0])
    cwe = load_json(root / SOURCES["cwe"]["processed"][0])
    adv = load_json(root / SOURCES["advisories"]["processed"][0])
    objs = load_json(root / SOURCES["attack"]["processed"][0])
    kev_by_id = {r["cve_id"]: r for r in kev["records"]} if kev else {}
    pairs = []
    for r in (nvd["records"] if nvd else []):
        fields, k = r.get("nvd_cisa_fields") or {}, kev_by_id.get(r["cve_id"])
        if k is not None:
            pairs.append((r["cve_id"], fields.get("cisaExploitAdd"), k.get("date_added"), fields.get("cisaActionDue"), k.get("due_date")))
    return {
        "kev_ids": set(kev_by_id), "kev_subset_ids": {r["cve_id"] for r in kev_subset["records"]} if kev_subset else set(),
        "nvd_ids": {r["cve_id"] for r in nvd["records"]} if nvd else set(),
        "cwe_ids": {r["cwe_id"] for r in cwe["records"]} if cwe else set(),
        "nvd_cwe_ids": {w["cwe_id"] for r in (nvd["records"] if nvd else []) for w in r.get("weaknesses", [])
                        if w.get("cwe_id", "").startswith("CWE-")},
        "kev_cwe_ids": {str(c).strip() for r in (kev["records"] if kev else []) for c in r.get("cwes", []) if str(c).strip()},
        "adv_cwe_ids": {c for r in (adv["records"] if adv else []) for c in r.get("mentioned_cwe_ids", [])},
        "adv_cve_ids": {c for r in (adv["records"] if adv else []) for c in r.get("mentioned_cve_ids", [])},
        "adv_attack_ids": {c for r in (adv["records"] if adv else []) for c in r.get("mentioned_attack_ids", [])},
        "attack_technique_ids": {r["attack_id"] for r in (objs["records"] if objs else []) if r["stix_type"] == "attack-pattern"},
        "nvd_cisa_vs_kev": pairs,
    }


def cross_findings(cross: dict, findings: Findings) -> None:
    if "nvd_in_kev" in cross:
        c = cross["nvd_in_kev"]
        findings.add("INFO", "Cross-source", f"{c['matched']}/{c['total']} NVD records are also in KEV (the default NVD set is built from KEV)")
    if "kev_subset_in_nvd" in cross and cross["kev_subset_in_nvd"]["matched"] < cross["kev_subset_in_nvd"]["total"]:
        c = cross["kev_subset_in_nvd"]
        findings.add("WARN", "Cross-source", f"only {c['matched']}/{c['total']} KEV subset CVEs have an NVD record")
    for name, label in (("nvd_cwe_in_catalog", "NVD"), ("kev_cwe_in_catalog", "KEV"), ("advisory_cwe_in_catalog", "advisory")):
        if name in cross and cross[name]["missing"]:
            c = cross[name]
            findings.add("WARN", "Cross-source", f"{len(c['missing'])} CWE id(s) used by {label} data are not in the CWE catalog: {c['missing'][:6]}")
    if "advisory_cves" in cross:
        c = cross["advisory_cves"]
        findings.add("INFO", "Cross-source", f"advisories mention {c['total']} distinct CVEs: {c['in_kev']} in KEV, {c['in_nvd_set']} in our NVD set, {c['in_neither']} in neither")
    if "advisory_attack_ids" in cross:
        c = cross["advisory_attack_ids"]
        if c["ics_matrix_count"]:
            findings.add("INFO", "Cross-source", f"{c['ics_matrix_count']} technique id(s) in advisory text belong to the ATT&CK for ICS matrix "
                                                  f"(T08xx), which is not collected (decision 0003, Enterprise only): {c['ics_matrix'][:6]}")
        if c["unknown_count"]:
            findings.add("WARN", "Cross-source", f"{c['unknown_count']} ATT&CK-style id(s) in advisory text are neither active Enterprise techniques nor ICS ids "
                                                  f"(retired, Mobile, or not really ATT&CK ids): {c['unknown'][:6]}")
    if "nvd_cisa_dates" in cross:
        c = cross["nvd_cisa_dates"]
        if c["added_mismatch"]:
            findings.add("WARN", "Cross-source", f"{len(c['added_mismatch'])} NVD record(s) carry a CISA 'exploit added' date that differs from KEV, e.g. {c['added_mismatch'][:2]}")
        elif c["compared"]:
            findings.add("INFO", "Cross-source", f"NVD's embedded CISA 'exploit added' dates agree with KEV for all {c['compared']} compared records")
        else:
            findings.add("INFO", "Cross-source", "NVD records carry no embedded CISA exploit-added field to compare")


# --------------------------------------------------------------------------- 6. field inventory
def diff_fields(observed: Counter, consumed: set, extra_consumed_prefix: str | None = None) -> dict:
    def used(name: str) -> bool:
        return name in consumed or bool(extra_consumed_prefix and name.startswith(extra_consumed_prefix))
    return {"observed": dict(observed.most_common()),
            "used": sorted(n for n in observed if used(n)),
            "ignored": {n: c for n, c in observed.most_common() if not used(n)},
            "used_but_never_seen": sorted(n for n in consumed if n not in observed)}


def never_seen(consumed: set, observed: set, prefix: str | None = None) -> list[str]:
    """Fields our normalizer reads that occur NOWHERE in the source (per-kind differences are normal and not reported)."""
    return sorted(n for n in consumed if n not in observed)


def latest_entry(root: Path, key: str, kind: str | None = None) -> dict | None:
    entries = [e for e in load_entries(root, key) if (kind is None or e["kind"] == kind) and (root / SOURCES[key]["raw"] / e["raw_file"]).is_file()]
    entries.sort(key=lambda e: e.get("retrieved_at") or "")
    return entries[-1] if entries else None


def inventory_kev(root: Path) -> dict | None:
    entry = latest_entry(root, "kev")
    if not entry:
        return None
    doc = json.loads((root / SOURCES["kev"]["raw"] / entry["raw_file"]).read_bytes())
    record_keys = Counter(k for r in doc.get("vulnerabilities", []) for k in r)
    envelope = diff_fields(Counter(doc.keys()), CONSUMED["kev"]["envelope"])
    record = diff_fields(record_keys, CONSUMED["kev"]["record"])
    return {"records": len(doc.get("vulnerabilities", [])), "envelope": envelope, "record": record,
            "never_seen_anywhere": sorted(set(envelope["used_but_never_seen"]) | set(record["used_but_never_seen"]))}


def inventory_nvd(root: Path) -> dict | None:
    latest: dict[str, dict] = {}
    for e in load_entries(root, "nvd"):
        if e["kind"] == "ok" and (root / SOURCES["nvd"]["raw"] / e["raw_file"]).is_file():
            latest[e["url"]] = e
    if not latest:
        return None
    keys, metric_keys = Counter(), Counter()
    for e in latest.values():
        cve = json.loads((root / SOURCES["nvd"]["raw"] / e["raw_file"]).read_bytes())["vulnerabilities"][0]["cve"]
        keys.update(cve.keys())
        metric_keys.update((cve.get("metrics") or {}).keys())
    cve = diff_fields(keys, CONSUMED["nvd"]["cve"], "cisa")
    return {"records": len(latest), "cve": cve, "metrics_versions_seen": dict(metric_keys.most_common()),
            "never_seen_anywhere": cve["used_but_never_seen"]}


def inventory_attack(root: Path) -> dict | None:
    entry = latest_entry(root, "attack", "bundle")
    if not entry:
        return None
    doc = json.loads((root / SOURCES["attack"]["raw"] / entry["raw_file"]).read_bytes())
    per_type: dict[str, Counter] = {}
    for obj in doc["objects"]:
        t = obj.get("type")
        if t in ATTACK_KEEP and obj.get("revoked") is not True and obj.get("x_mitre_deprecated") is not True:
            per_type.setdefault(t, Counter()).update(obj.keys())
    consumed_union = set(CONSUMED["attack"]["common"]).union(*(v for k, v in CONSUMED["attack"].items() if k != "common"))
    observed_union = set().union(*per_type.values()) if per_type else set()
    return {"version": entry.get("attack_version"),
            "types": {t: diff_fields(c, CONSUMED["attack"]["common"] | CONSUMED["attack"].get(t, set())) for t, c in per_type.items()},
            "never_seen_anywhere": never_seen(consumed_union, observed_union)}


def inventory_cwe(root: Path) -> dict | None:
    entry = latest_entry(root, "cwe")
    if not entry:
        return None
    with zipfile.ZipFile(root / SOURCES["cwe"]["raw"] / entry["raw_file"]) as z:
        member = next(n for n in z.namelist() if n.lower().endswith(".xml"))
        xml_root = ET.fromstring(z.read(member))
    attrs: dict[str, Counter] = {}
    kids: dict[str, Counter] = {}
    for section in xml_root:
        for el in section:
            if "ID" in el.attrib and "Name" in el.attrib:
                tag = el.tag.rsplit("}", 1)[-1]
                attrs.setdefault(tag, Counter()).update(el.attrib.keys())
                kids.setdefault(tag, Counter()).update(c.tag.rsplit("}", 1)[-1] for c in el)
    seen_attrs = set().union(*attrs.values()) if attrs else set()
    seen_kids = set().union(*kids.values()) if kids else set()
    return {"kinds": {t: {"attributes": diff_fields(attrs[t], CONSUMED["cwe"]["attributes"]),
                          "children": diff_fields(kids[t], CONSUMED["cwe"]["children"])} for t in attrs},
            "never_seen_anywhere": never_seen(CONSUMED["cwe"]["attributes"], seen_attrs) + never_seen(CONSUMED["cwe"]["children"], seen_kids)}


def inventory_advisories(root: Path) -> dict | None:
    adv = load_json(root / SOURCES["advisories"]["processed"][0])
    if not adv:
        return None
    records, n = adv["records"], len(adv["records"])
    fields = ("release_date", "last_revised", "alert_code", "advisory_type", "archived", "published_at", "attachments",
              "mentioned_cve_ids", "mentioned_attack_ids", "mentioned_cwe_ids")
    return {"documents": n, "filled": {f: sum(1 for r in records if r.get(f)) for f in fields},
            "derived_dates": sum(1 for r in records if r.get("published_at_is_derived")), "never_seen_anywhere": []}


# --------------------------------------------------------------------------- 7. storage hygiene, 8. checks, 9. docs
def git_hygiene(root: Path, findings: Findings) -> dict:
    info = {"git_repository": (root / ".git").exists(), "tracked_data_files": [], "env_ignored": None}
    if not info["git_repository"]:
        findings.add("INFO", "Storage", "not a Git repository here: tracked-file check skipped")
        return info
    try:
        listed = subprocess.run(["git", "-C", str(root), "ls-files", "data", "outputs", "logs", ".env", ".venv"],
                                capture_output=True, text=True, check=True).stdout.splitlines()
        ignored = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", ".env"], capture_output=True).returncode == 0
    except (OSError, subprocess.CalledProcessError) as exc:
        findings.add("INFO", "Storage", f"git could not be queried ({exc}); tracked-file check skipped")
        return info
    info["tracked_data_files"] = [f for f in listed if not f.endswith(".gitkeep")]
    info["env_ignored"] = ignored
    if info["tracked_data_files"]:
        findings.add("FAIL", "Storage", f"{len(info['tracked_data_files'])} file(s) from data/, outputs/, logs/ or .env are tracked by Git, "
                                        f"e.g. {info['tracked_data_files'][:3]}. Remove them with 'git rm --cached' and check .gitignore")
    else:
        findings.add("INFO", "Storage", "no files from data/, outputs/, logs/, .env or .venv are tracked by Git (only .gitkeep placeholders)")
    if not ignored:
        findings.add("FAIL", "Storage", ".env is not ignored by Git: secrets could be committed")
    return info


def storage_protection(files: dict, findings: Findings) -> None:
    total = sum(f["verified_ok"] for f in files.values())
    protected = sum(f["read_only_files"] for f in files.values())
    if total and protected < total:
        findings.add("INFO", "Storage", f"{protected}/{total} raw files are read-only. Optional protection: .\\scripts\\protect_raw_data.ps1")


def run_check_scripts(root: Path, findings: Findings) -> dict:
    results = {}
    for key, spec in SOURCES.items():
        script = root / "scripts" / spec["check"]
        if not script.is_file():
            results[key] = "script missing"
            findings.add("FAIL", spec["label"], f"check script missing: scripts/{spec['check']}")
            continue
        proc = subprocess.run([sys.executable, str(script)], cwd=root, capture_output=True, text=True)
        passed = proc.returncode == 0 and "ALL CHECKS PASSED" in proc.stdout
        results[key] = "PASS" if passed else "FAIL"
        if not passed:
            first = next((ln.strip() for ln in proc.stdout.splitlines() if "[FAIL]" in ln), "see the script's own output")
            findings.add("FAIL", spec["label"], f"check script failed: {first}")
    return results


def docs_status(root: Path, findings: Findings) -> dict:
    status = {}
    for key, spec in SOURCES.items():
        page = root / "docs" / "data_dictionary" / spec["doc"]
        if not page.is_file():
            status[key] = "missing"
            findings.add("WARN", spec["label"], f"data dictionary page missing: docs/data_dictionary/{spec['doc']}")
            continue
        text = page.read_text(encoding="utf-8")
        not_verified = bool(re.search(r"Verified[^|\n]*\|\s*\*\*NO", text))
        status[key] = "not verified" if not_verified else "ok"
        if not_verified:
            findings.add("WARN", spec["label"], f"docs/data_dictionary/{spec['doc']} is still marked 'not verified on your PC'")
    return status


# --------------------------------------------------------------------------- report writers
def render_markdown(report: dict) -> str:
    L = ["# Raw Data Audit (generated)", "",
         f"*Generated {report['generated_at']} by `ingestion/validation/audit_raw_data.py`. Do not edit by hand: run the audit again.*", "",
         f"**Result:** {report['summary']['fail']} FAIL, {report['summary']['warn']} WARN, {report['summary']['info']} INFO", "",
         "## 1. Raw files per source", "",
         "| Source | Recorded downloads | Verified (SHA-256) | Missing | Changed | Orphans | Bytes | Newest download | Age (days) |",
         "|---|---:|---:|---:|---:|---:|---:|---|---:|"]
    for info in report["files"].values():
        L.append(f"| {info['label']} | {info['entries']} | {info['verified_ok']} | {len(info['missing'])} | {len(info['mismatched'])} | "
                 f"{len(info['orphans'])} | {info['bytes']:,} | {info['newest_retrieved_at'] or '-'} | {info['age_days'] if info['age_days'] is not None else '-'} |")
    L += ["", "## 2. Processed data", "", "| Source | Numbers (re-read from disk) | Source's own version / date |", "|---|---|---|"]
    for key, st in report["processed"].items():
        nums = ", ".join(f"{k} {v:,}" for k, v in st.items() if isinstance(v, int))
        L.append(f"| {SOURCES[key]['label']} | {nums} | {st.get('catalog_version') or '-'} / {st.get('source_date') or '-'} |")
    L += ["", "## 3. Dataset targets", "", "| Source | Metric | Target | Actual | Status |", "|---|---|---|---:|---|"]
    for t in report["targets"]:
        rng = f"{t['min']}" + (f"-{t['max']}" if t.get("max") is not None else "+")
        L.append(f"| {SOURCES[t['source']]['label']} | {t['metric']} | {rng} | {t['actual'] if t['actual'] is not None else '-'} | {t['status']} |")
    L += ["", "Targets are initial targets, not permanent limits (see the master prompt and decision records 0002-0004).", "",
          "## 4. Cross-source checks", ""]
    for name, value in report["cross"].items():
        L.append(f"- **{name}**: `{json.dumps(value, ensure_ascii=False)}`")
    L += ["", "## 5. Field inventory (what really occurs in the raw data)", "",
          "For each source: fields we **use**, fields that occur but are **ignored** (with how often), and fields we expect but never saw.", ""]
    for key, inv in report["fields"].items():
        L.append(f"### {SOURCES[key]['label']}")
        L.append("")
        L.append(render_inventory(key, inv))
        L.append("")
    L += ["## 6. Check scripts (Milestone 3 gate)", ""] + [f"- {SOURCES[k]['label']}: **{v}**" for k, v in report["check_scripts"].items()]
    L += ["", "## 7. Storage hygiene", "", f"- Git repository: {report['storage'].get('git_repository')}",
          f"- Tracked files from data/outputs/logs/.env: {len(report['storage'].get('tracked_data_files', []))}",
          f"- .env ignored by Git: {report['storage'].get('env_ignored')}", "", "## 8. Findings", "",
          "| Severity | Area | Finding |", "|---|---|---|"]
    for f in sorted(report["findings"], key=lambda x: (SEVERITY_ORDER[x["severity"]], x["area"])):
        L.append(f"| {f['severity']} | {f['area']} | {f['message'].replace('|', '/')} |")
    return "\n".join(L) + "\n"


def render_inventory(key: str, inv: dict) -> str:
    def block(title: str, d: dict) -> list[str]:
        out = [f"**{title}**", f"- used ({len(d['used'])}): {', '.join(d['used']) or '-'}"]
        out.append("- ignored: " + (", ".join(f"{n} ({c})" for n, c in list(d["ignored"].items())[:25]) or "none"))
        return out
    lines: list[str] = []
    if key == "kev":
        lines += [f"{inv['records']} records."] + block("Envelope", inv["envelope"]) + block("Record fields", inv["record"])
    elif key == "nvd":
        lines += [f"{inv['records']} CVE records; CVSS metric versions seen: {inv['metrics_versions_seen']}."] + block("cve object", inv["cve"])
    elif key == "attack":
        lines.append(f"Release {inv['version']}.")
        for t, d in inv["types"].items():
            lines += block(t, d)
    elif key == "cwe":
        for kind, parts in inv["kinds"].items():
            lines += block(f"{kind}: attributes", parts["attributes"]) + block(f"{kind}: child elements", parts["children"])
    elif key == "advisories":
        lines.append(f"{inv['documents']} documents; non-empty fields: {inv['filled']}; dates derived from alert codes: {inv['derived_dates']}.")
    missing = inv.get("never_seen_anywhere") or []
    lines.append("")
    lines.append(f"**Fields we read that occur nowhere in this source:** {', '.join(missing) if missing else 'none'}")
    return "\n".join(lines)


def print_summary(report: dict) -> None:
    print("\n=== Milestone 4: raw data audit ===")
    print(f"  {'Source':<16} {'files':>6} {'verified':>9} {'missing':>8} {'changed':>8} {'orphans':>8} {'age(d)':>7}  check")
    for key, info in report["files"].items():
        print(f"  {info['label']:<16} {info['entries']:>6} {info['verified_ok']:>9} {len(info['missing']):>8} {len(info['mismatched']):>8} "
              f"{len(info['orphans']):>8} {str(info['age_days'] if info['age_days'] is not None else '-'):>7}  {report['check_scripts'].get(key, 'skipped')}")
    print("\n  Dataset targets")
    for t in report["targets"]:
        print(f"    {SOURCES[t['source']]['label']:<16} {t['metric']:<24} target {t['min']}{'-' + str(t['max']) if t.get('max') is not None else '+'}  actual {t['actual']}  -> {t['status']}")
    print("\n  Findings")
    for f in sorted(report["findings"], key=lambda x: (SEVERITY_ORDER[x["severity"]], x["area"])):
        print(f"    [{f['severity']}] {f['area']}: {f['message']}")
    s = report["summary"]
    print(f"\nAUDIT RESULT: {s['fail']} FAIL, {s['warn']} WARN, {s['info']} INFO -> {'PASSED' if s['fail'] == 0 else 'NOT PASSED'}")


# --------------------------------------------------------------------------- orchestration
def run_audit(root: Path, max_age_days: float = 30.0, fast: bool = False, skip_checks: bool = False) -> dict:
    findings = Findings()
    files = {key: audit_files(root, key, findings) for key in SOURCES}
    stats = processed_stats(root, findings)
    freshness_findings(files, max_age_days, findings)
    targets_doc = load_json(root / "config" / "dataset_targets.json") or {"targets": []}
    targets = evaluate_targets(targets_doc["targets"], stats)
    for t in targets:
        if t["status"] in ("BELOW", "NO DATA"):
            findings.add("WARN", SOURCES[t["source"]]["label"], f"target not met: {t['note']} (target {t['min']}+, actual {t['actual']}) -> {t['status']}")
        elif t["status"] == "ABOVE":
            findings.add("INFO", SOURCES[t["source"]]["label"], f"above the initial target: {t['note']} (actual {t['actual']}); targets are not permanent limits")
    cross = cross_checks(collect_cross_data(root))
    cross_findings(cross, findings)

    fields: dict = {}
    for key, fn in (("kev", inventory_kev), ("nvd", inventory_nvd), ("advisories", inventory_advisories)):
        inv = fn(root) if files[key]["verified_ok"] or key == "advisories" else None
        if inv:
            fields[key] = inv
    if not fast:
        for key, fn in (("attack", inventory_attack), ("cwe", inventory_cwe)):
            inv = fn(root) if files[key]["verified_ok"] else None
            if inv:
                fields[key] = inv
    for key, inv in fields.items():
        if inv.get("never_seen_anywhere"):
            findings.add("WARN", SOURCES[key]["label"], f"fields our normalizer reads but that occur nowhere in the raw data: {inv['never_seen_anywhere']}")

    storage = git_hygiene(root, findings)
    storage_protection(files, findings)
    check_scripts = {} if skip_checks else run_check_scripts(root, findings)
    docs = docs_status(root, findings)
    summary = {"fail": findings.count("FAIL"), "warn": findings.count("WARN"), "info": findings.count("INFO")}
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "root": str(root), "summary": summary,
            "files": files, "processed": stats, "targets": targets, "cross": cross, "fields": fields, "storage": storage,
            "check_scripts": check_scripts, "docs": docs, "findings": findings.items}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Combined raw data audit for all five sources.")
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="project root (default: this project)")
    parser.add_argument("--max-age-days", type=float, default=30.0, help="warn if the newest download is older (default 30)")
    parser.add_argument("--fast", action="store_true", help="skip the field inventory of the ATT&CK bundle and the CWE XML")
    parser.add_argument("--skip-checks", action="store_true", help="do not run the five check scripts")
    parser.add_argument("--write-doc", action="store_true", help="write docs/data_dictionary/RAW_DATA_AUDIT.md")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    report = run_audit(root, args.max_age_days, args.fast, args.skip_checks)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = root / "outputs" / "reports" / f"raw_data_audit_{stamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print_summary(report)
    print(f"\n  JSON report : {report_path.relative_to(root).as_posix()}")
    if args.write_doc:
        doc_path = root / "docs" / "data_dictionary" / "RAW_DATA_AUDIT.md"
        doc_path.parent.mkdir(parents=True, exist_ok=True)
        doc_path.write_text(render_markdown(report), encoding="utf-8")
        print(f"  Markdown doc: {doc_path.relative_to(root).as_posix()} (tracked by Git: commit it)")
    return 0 if report["summary"]["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
