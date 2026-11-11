"""Build the canonical entity/relationship files from data/processed/*.json.

Run from the project root:
    python canonical\\build.py
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pydantic import ValidationError  # noqa: E402

from canonical import SCHEMA_VERSION  # noqa: E402
from canonical.ids import (CVE_RE, TECH_RE, make_id, norm_cve, norm_cwe,  # noqa: E402
                           rel_id, slug, software_key)
from canonical.mappings import (ALIASES, ALLOWED, CWE_PLACEHOLDERS,  # noqa: E402
                                STIX_REL, STIX_TO_ENTITY)
from canonical.models import (ENTITY_CLASSES, Evidence, EvidenceType,  # noqa: E402
                              Relationship)

AUTH = EvidenceType.STRUCTURED_AUTHORITATIVE
STATED = EvidenceType.STATED_IN_SOURCE


def pick(rec: dict, names, default=None):
    for n in names:
        if n in rec and rec[n] not in (None, ""):
            return rec[n]
    return default


def txt(value):
    """Coerce a loosely typed source value to str (or None) for text fields."""
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else str(value)


def pick_bool_or_text(rec: dict, names):
    for n in names:
        if n in rec and rec[n] is not None and rec[n] != "":
            v = rec[n]
            return v if isinstance(v, (bool, str)) else str(v)
    return None


def load_records(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return data.get("records", [])
    return data


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Builder:
    def __init__(self):
        self.entities: dict[str, object] = {}
        self.rels: dict[str, Relationship] = {}
        self.unresolved: list[dict] = []
        self._unresolved_seen: set = set()
        self.skipped = Counter()
        self.stix_to_cid: dict[str, str] = {}
        self.tactic_by_short: dict[str, str] = {}
        self.attack_active_ids: set[str] = set()

    # ---------- entity / relationship helpers ----------
    def add_entity(self, etype: str, key: str, name: str, source: str,
                   evidence: Evidence, **fields):
        cid = make_id(etype, key)
        cls = ENTITY_CLASSES[etype]
        if cid in self.entities:
            ent = self.entities[cid]
            if source not in ent.sources:
                ent.sources.append(source)
            ent.evidence.append(evidence)
            for k, v in fields.items():           # fill gaps, never overwrite
                cur = getattr(ent, k, None)
                if v not in (None, "", [], False) and cur in (None, "", [], False):
                    setattr(ent, k, v)
            if name and name != ent.name and name not in ent.aliases:
                ent.aliases.append(name)
            return ent
        ent = cls(canonical_id=cid, name=name or key, sources=[source],
                  evidence=[evidence], **fields)
        self.entities[cid] = ent
        return ent

    def add_rel(self, rel_type: str, src: str, tgt: str, ev: Evidence,
                etype: EvidenceType, **props):
        st, tt = src.split(":", 1)[0], tgt.split(":", 1)[0]
        if (st, rel_type, tt) not in ALLOWED:
            self.skipped[f"disallowed:{st}-{rel_type}->{tt}"] += 1
            return
        rid = rel_id(rel_type, src, tgt)
        if rid in self.rels:
            self.rels[rid].evidence.append(ev)
            return
        self.rels[rid] = Relationship(rel_id=rid, rel_type=rel_type, source_id=src,
                                      target_id=tgt, evidence_type=etype,
                                      evidence=[ev], properties=props)

    @staticmethod
    def ev(source, etype, rec_ref, rec: dict | None = None):
        rec = rec or {}
        return Evidence(source=source, evidence_type=etype, record_ref=txt(rec_ref),
                        raw_file_reference=txt(rec.get("raw_file_reference")),
                        source_url=txt(rec.get("source_url")),
                        retrieved_at=txt(rec.get("retrieved_at")))

    # ---------- sources ----------
    def from_cwe(self, recs):
        for r in recs:
            cwe = norm_cwe(pick(r, ALIASES["cwe_id"], ""))
            if not cwe:
                self.skipped["cwe:no_id"] += 1
                continue
            e = self.ev("cwe", AUTH, cwe, r)
            self.add_entity("Weakness", cwe, txt(r.get("name")) or cwe, "cwe", e,
                            cwe_id=cwe, element_type=txt(r.get("element_type")),
                            abstraction=txt(r.get("abstraction")),
                            status=txt(r.get("status")),
                            description=txt(r.get("description")))
        for r in recs:                           # second pass: hierarchy
            cwe = norm_cwe(pick(r, ALIASES["cwe_id"], ""))
            for rel in pick(r, ALIASES["cwe_rels"], []) or []:
                if not isinstance(rel, dict):
                    continue
                nature = str(rel.get("nature", "")).lower()
                tgt = norm_cwe(rel.get("cwe_id") or rel.get("id") or rel.get("target") or "")
                if nature != "childof" or not tgt or not cwe:
                    self.skipped["cwe:rel_not_childof_or_unparsed"] += 1
                    continue
                if make_id("Weakness", tgt) not in self.entities:
                    self.skipped["cwe:parent_not_in_catalog"] += 1
                    continue
                self.add_rel("CHILD_OF", make_id("Weakness", cwe),
                             make_id("Weakness", tgt),
                             self.ev("cwe", AUTH, cwe, r), AUTH)

    def _software(self, vendor, product, source, ev):
        if not vendor or not product:
            return None
        s = self.add_entity("Software", software_key(vendor, product),
                            f"{vendor} {product}", source, ev,
                            vendor=slug(vendor), product=slug(product))
        for alias in (f"{vendor} {product}",):
            if alias != s.name and alias not in s.aliases:
                s.aliases.append(alias)
        return s.canonical_id

    # ---------- Milestone 5.1: one shared CWE linker for NVD and KEV ----------
    @staticmethod
    def _cwe_tokens(raw) -> list[str]:
        """Turn a CWE field (list, comma string, dicts, None) into raw tokens."""
        if raw is None:
            return []
        if isinstance(raw, dict):
            raw = raw.get("cwe_id") or raw.get("id")
        if isinstance(raw, (list, tuple, set)):
            out = []
            for item in raw:
                out.extend(Builder._cwe_tokens(item))
            return out
        text = str(raw).strip()
        if not text:
            return []
        return [t for t in re.split(r"[,;|\s]+", text) if t]

    def _note_unresolved(self, entry: dict):
        key = (entry["kind"], entry["id"], entry["from"])
        if key not in self._unresolved_seen:
            self._unresolved_seen.add(key)
            self.unresolved.append(entry)

    def _link_weaknesses(self, vid: str, raw, ev: Evidence, tag: str):
        """Create Vulnerability -HAS_WEAKNESS-> Weakness edges for one record.

        tag is 'nvd' or 'kev' (used only for the skipped-counter names).
        - placeholders (NVD-CWE-noinfo / -Other): counted, no edge
        - unparsable tokens: counted, no edge
        - CWE ids missing from the catalog: logged as unresolved, no edge
        - same CWE from both sources: add_rel merges into ONE edge, two evidence
        """
        for tok in self._cwe_tokens(raw):
            if tok in CWE_PLACEHOLDERS:
                self.skipped[f"{tag}:placeholder_{tok}"] += 1
                continue
            cwe = norm_cwe(tok)
            if not cwe:
                self.skipped[f"{tag}:cwe_unparsable"] += 1
                continue
            wid = make_id("Weakness", cwe)
            if wid not in self.entities:
                self._note_unresolved({"kind": "cwe_not_in_catalog", "id": cwe,
                                       "from": vid})
                continue
            self.add_rel("HAS_WEAKNESS", vid, wid, ev, AUTH)

    def from_kev(self, recs):
        for r in recs:
            cve = norm_cve(r.get("cve_id", ""))
            if not cve:
                self.skipped["kev:no_cve"] += 1
                continue
            e = self.ev("cisa_kev", AUTH, cve, r)
            v = self.add_entity(
                "Vulnerability", cve, cve, "cisa_kev", e, cve_id=cve, in_kev=True,
                description=txt(r.get("short_description") or r.get("description")),
                kev_date_added=txt(r.get("date_added")),
                kev_required_action=txt(r.get("required_action")),
                kev_ransomware_use=pick_bool_or_text(r, ALIASES["kev_ransomware"]))
            sid = self._software(r.get("vendor_project"), r.get("product"),
                                 "cisa_kev", e)
            if sid:
                self.add_rel("AFFECTS", v.canonical_id, sid, e, AUTH)
            self._link_weaknesses(v.canonical_id, pick(r, ALIASES["kev_cwes"], []),
                                  e, "kev")

    def from_nvd(self, recs):
        for r in recs:
            cve = norm_cve(r.get("cve_id", ""))
            if not cve:
                self.skipped["nvd:no_cve"] += 1
                continue
            e = self.ev("nvd", AUTH, cve, r)
            cvss = r.get("cvss_primary")
            sev = r.get("severity") or (cvss.get("severity") if isinstance(cvss, dict) else None)
            v = self.add_entity("Vulnerability", cve, cve, "nvd", e, cve_id=cve,
                                description=txt(r.get("description")),
                                cvss_primary=cvss, severity=txt(sev))
            if r.get("description"):          # NVD text is richer than KEV's blurb
                v.description = txt(r["description"])
            vid = v.canonical_id
            self._link_weaknesses(vid, pick(r, ALIASES["nvd_cwes"], []), e, "nvd")
            for p in pick(r, ALIASES["nvd_products"], []) or []:
                if isinstance(p, dict):
                    sid = self._software(p.get("vendor"), p.get("product"), "nvd", e)
                    if sid:
                        self.add_rel("AFFECTS", vid, sid, e, AUTH)

    def from_attack_objects(self, recs):
        for r in recs:
            etype = STIX_TO_ENTITY.get(r.get("stix_type"))
            if not etype:
                self.skipped[f"attack:unmapped_type:{r.get('stix_type')}"] += 1
                continue
            stix = pick(r, ALIASES["stix_id"], "")
            aid = r.get("attack_id")
            short = r.get("shortname") or r.get("short_name")
            key = aid or short or stix
            if not key:
                self.skipped["attack:no_key"] += 1
                continue
            e = self.ev("mitre_attack", AUTH, aid or stix, r)
            extra = {"attack_id": aid, "stix_id": stix or None,
                     "description": txt(r.get("description"))}
            if etype == "AttackTechnique":
                extra.update(is_subtechnique=bool(r.get("is_subtechnique")),
                             tactics=list(r.get("tactics") or []))
            if etype == "AttackTactic":
                extra["shortname"] = short
            ent = self.add_entity(etype, key, txt(r.get("name")) or key, "mitre_attack",
                                  e, **extra)
            if stix:
                self.stix_to_cid[stix] = ent.canonical_id
            if etype == "AttackTactic" and short:
                self.tactic_by_short[short] = ent.canonical_id
            if etype == "AttackTechnique" and aid:
                self.attack_active_ids.add(aid)
        for ent in list(self.entities.values()):     # technique -> tactic
            if ent.entity_type == "AttackTechnique":
                for t in ent.tactics:
                    tid = self.tactic_by_short.get(t)
                    if tid:
                        self.add_rel("PART_OF_TACTIC", ent.canonical_id, tid,
                                     ent.evidence[0], AUTH)
                    else:
                        self._note_unresolved({"kind": "tactic_shortname_unknown",
                                               "id": t, "from": ent.canonical_id})

    def from_attack_relationships(self, recs):
        for r in recs:
            kind = pick(r, ALIASES["rel_type"], "")
            if kind not in STIX_REL:
                self.skipped[f"attack_rel:unmapped:{kind}"] += 1
                continue
            canon, reverse = STIX_REL[kind]
            s = self.stix_to_cid.get(pick(r, ALIASES["rel_source"], ""))
            t = self.stix_to_cid.get(pick(r, ALIASES["rel_target"], ""))
            if not s or not t:
                self.skipped["attack_rel:endpoint_not_active"] += 1
                continue
            if reverse:
                s, t = t, s
            self.add_rel(canon, s, t, self.ev("mitre_attack", AUTH, kind, r), AUTH)

    def from_advisories(self, recs):
        for i, r in enumerate(recs):
            doc = str(pick(r, ALIASES["doc_id"], f"advisory-{i:04d}"))
            e = self.ev("advisories", STATED, doc, r)
            rep = self.add_entity("IntelligenceReport", slug(doc) or f"doc{i}",
                                  txt(r.get("title")) or doc, "advisories", e,
                                  url=txt(r.get("url") or r.get("source_url")),
                                  published=txt(r.get("published") or r.get("published_date")))
            text = json.dumps(r, ensure_ascii=False)
            for cve in sorted({norm_cve(m) for m in CVE_RE.findall(text)}):
                cid = make_id("Vulnerability", cve)
                if cid not in self.entities:        # advisory-only CVE -> stub
                    self.add_entity("Vulnerability", cve, cve, "advisories", e,
                                    cve_id=cve, stub=True)
                self.add_rel("MENTIONS", rep.canonical_id, cid, e, STATED)
            for tid in sorted(set(TECH_RE.findall(text))):
                cid = make_id("AttackTechnique", tid)
                if cid in self.entities:
                    self.add_rel("MENTIONS", rep.canonical_id, cid, e, STATED)
                else:
                    reason = ("ics_matrix_not_collected" if tid.startswith("T08")
                              else "not_active_enterprise_technique")
                    self._note_unresolved({"kind": "technique_reference", "id": tid,
                                           "reason": reason, "from": rep.canonical_id})


SOURCES = [
    ("cwe", "cwe_normalized.json", "from_cwe"),
    ("cisa_kev", "cisa_kev_normalized.json", "from_kev"),
    ("nvd", "nvd_normalized.json", "from_nvd"),
    ("mitre_attack", "attack_objects_normalized.json", "from_attack_objects"),
    ("mitre_attack_rel", "attack_relationships_normalized.json", "from_attack_relationships"),
]


def build(processed_dir: str, out_dir: str, report_dir: str | None = None) -> dict:
    b = Builder()
    inputs, missing = {}, []
    for name, fname, method in SOURCES:        # order matters: CWE before NVD, objects before relationships
        path = os.path.join(processed_dir, fname)
        if not os.path.exists(path):
            missing.append(fname)
            continue
        try:
            getattr(b, method)(load_records(path))
        except ValidationError as ex:      # a field in the real data has an unexpected type
            print(f"\nFAILED while reading {fname}:\n{ex}\n"
                  "Run scripts\\inspect_processed_schema.py and send the output "
                  "for this file so the model can be adjusted.")
            sys.exit(2)
        inputs[fname] = {"sha256": sha256(path)}
    adv = sorted(glob.glob(os.path.join(processed_dir, "*advis*normalized*.json")))
    if adv:
        b.from_advisories(load_records(adv[0]))
        inputs[os.path.basename(adv[0])] = {"sha256": sha256(adv[0])}
    else:
        missing.append("advisories_normalized.json (glob *advis*normalized*.json)")

    os.makedirs(out_dir, exist_ok=True)
    ents = [e.model_dump(mode="json") for _, e in sorted(b.entities.items())]
    rels = [r.model_dump(mode="json") for _, r in sorted(b.rels.items())]
    unresolved = sorted(b.unresolved, key=lambda u: (u["kind"], u["id"], u["from"]))
    meta = {"schema_version": SCHEMA_VERSION, "builder_revision": "5.1", "inputs": inputs,
            "generated_at": datetime.now(timezone.utc).isoformat()}
    for fname, key, rows in (("entities.json", "entity_count", ents),
                             ("relationships.json", "relationship_count", rels),
                             ("unresolved_references.json", "unresolved_count", unresolved)):
        with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as fh:
            json.dump({"metadata": {**meta, key: len(rows)}, "records": rows}, fh,
                      indent=1, ensure_ascii=False)
    prov = Counter()
    for r in rels:
        if r["rel_type"] == "HAS_WEAKNESS":
            srcs = {x["source"] for x in r["evidence"]}
            prov["both" if {"cisa_kev", "nvd"} <= srcs else
                 "kev_only" if srcs == {"cisa_kev"} else "nvd_only"] += 1
    summary = {
        "has_weakness_provenance": {"total": sum(prov.values()), **dict(prov)},
        "status": "SUCCESS" if not missing else "PARTIAL",
        "missing_inputs": missing,
        "entities_by_type": dict(Counter(e["entity_type"] for e in ents)),
        "relationships_by_type": dict(Counter(r["rel_type"] for r in rels)),
        "unresolved_by_kind": dict(Counter(u["kind"] + ":" + u.get("reason", "") for u in unresolved)),
        "skipped": dict(b.skipped),
        "advisory_only_vulnerability_stubs": sum(1 for e in ents if e.get("stub")),
    }
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        with open(os.path.join(report_dir, f"canonical_build_{ts}.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(summary, fh, indent=1)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--out-dir", default="data/canonical")
    ap.add_argument("--report-dir", default="outputs/reports")
    a = ap.parse_args()
    s = build(a.processed_dir, a.out_dir, a.report_dir)
    print("=== Milestone 5: canonical build ===")
    print(json.dumps(s, indent=2))
    sys.exit(0 if s["status"] == "SUCCESS" else 1)


if __name__ == "__main__":
    main()
