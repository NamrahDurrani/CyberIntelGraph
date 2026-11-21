"""The two Milestone 14 workflow steps, attached to the M13 agent through hooks."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Callable

from cti_agent.config import project_root
from cti_agent.deps import Deps
from cti_agent.evidence import EvidenceBook, EvidenceStatus

from .fresh import CVE_RE, FetchError, LiveSources
from .settings import VerifySettings

NodeFn = Callable[[dict], dict]
FRESH_WORDS = ("latest", "recent", "newest", "newly", "current", "currently", "today", "right now", "still",
               "updated", "this week", "this month", "just added")
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GRAPH_MODIFIED_KEYS = ("last_modified", "lastmodified", "modified", "last_modified_date")
GRAPH_CVSS_KEYS = ("cvss_score", "cvss", "base_score", "cvss_base_score", "cvss_v3_score")


def wants_fresh(question: str) -> bool:
    q = question.lower()
    return any(w in q for w in FRESH_WORDS)


def _profile_fields(profile: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in profile.splitlines():
        key, sep, value = line.partition(": ")
        if sep:
            fields[key.strip().lower()] = value.strip()
    return fields


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _stale_note(cached) -> str:
    return f" [cached copy from {cached.retrieved_at}; the live download failed]" if cached.stale else ""


def make_fresh_node(deps: Deps) -> NodeFn:
    vs: VerifySettings = deps.extras.get("verify_settings") or VerifySettings.from_env()
    sources = deps.extras.get("fresh_sources") or LiveSources(
        vs, project_root() / vs.cache_dir, deps.extras.get("fresh_fetcher"),
        deps.extras.get("fresh_now"), deps.extras.get("fresh_sleep") or time.sleep)

    def fresh_lookup(state: dict) -> dict:
        if not vs.fresh_enabled:
            return {}
        fresh = dict(state.get("fresh") or {"checked": [], "errors": [], "discrepancies": [], "notes": []})
        question = state.get("question", "")
        wanted = list(state.get("identifiers", {}).get("cve", []))
        for ref in state.get("resolved", []):
            wanted += [v.upper() for v in ref.get("ids", {}).values() if CVE_IN_TEXT.fullmatch(str(v))]
        cves = [c for c in dict.fromkeys(w.upper() for w in wanted) if c not in fresh["checked"]][: vs.max_fresh_cves]
        q = question.lower()
        want_recent = (not cves and wants_fresh(question) and ("kev" in q or "exploited" in q)
                       and "recent_kev" not in fresh["checked"])
        if not cves and not want_recent:
            return {"fresh": fresh} if fresh["checked"] else {}

        book = EvidenceBook(state.get("evidence", []))
        warnings: list[str] = []          # 'warnings' is append-only in the graph: return only NEW ones
        catalog = None
        try:
            catalog = sources.kev_catalog()
            fresh["kev_catalog_version"] = catalog.payload.get("catalogVersion")
            fresh["kev_retrieved_at"] = catalog.retrieved_at
            fresh["kev_stale"] = catalog.stale
        except FetchError as exc:
            fresh["errors"].append(f"CISA KEV: {exc}")
            warnings.append(f"Live CISA KEV check failed ({exc}); this was NOT treated as 'not listed'.")

        if want_recent:
            fresh["checked"].append("recent_kev")
            if catalog:
                rows = LiveSources.kev_recent(catalog, vs.recent_kev_count)
                lines = [f"- {r['cveID']} ({r.get('vendorProject', '')} {r.get('product', '')}), added {r.get('dateAdded')}, "
                         f"ransomware use: {r.get('knownRansomwareCampaignUse', 'Unknown')}" for r in rows]
                book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "fresh_kev_recent",
                         f"Most recently added CISA KEV entries (live, catalog {fresh['kev_catalog_version']}, "
                         f"retrieved {catalog.retrieved_at}){_stale_note(catalog)}",
                         text="\n".join(lines), source=f"{vs.kev_url} sha256={catalog.sha256[:12]}",
                         meta={"sha256": catalog.sha256})
            else:
                book.add(EvidenceStatus.UNABLE_TO_VERIFY, "fresh_kev_recent",
                         "Could not download the live CISA KEV catalog", source=vs.kev_url)

        for cve in cves:
            fresh["checked"].append(cve)
            if not CVE_RE.match(cve):
                continue
            if catalog:
                entry = LiveSources.kev_entry(catalog, cve)
                stamp = f"live, catalog {fresh['kev_catalog_version']}, retrieved {catalog.retrieved_at}"
                if entry:
                    book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "fresh_kev",
                             f"{cve} is listed in the CISA KEV catalog ({stamp}){_stale_note(catalog)}: "
                             f"{entry.get('vendorProject', '')} {entry.get('product', '')}, added {entry.get('dateAdded')}, "
                             f"known ransomware campaign use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}, "
                             f"remediation due {entry.get('dueDate')}",
                             text=f"{entry.get('shortDescription', '')} Required action: {entry.get('requiredAction', '')}",
                             source=f"{vs.kev_url} sha256={catalog.sha256[:12]}", entities=[cve],
                             meta={"sha256": catalog.sha256, "date_added": entry.get("dateAdded")})
                else:
                    book.add(EvidenceStatus.NOT_FOUND, "fresh_kev",
                             f"{cve} is not listed in the CISA KEV catalog ({stamp}){_stale_note(catalog)}",
                             text="Not being in KEV means CISA has not recorded exploitation in its catalog; "
                                  "it does not prove the vulnerability is not exploited.",
                             source=vs.kev_url, entities=[cve])
            else:
                book.add(EvidenceStatus.UNABLE_TO_VERIFY, "fresh_kev",
                         f"Could not check live CISA KEV status for {cve}", source=vs.kev_url, entities=[cve])

            try:
                cached, nvd = sources.nvd_record(cve)
            except FetchError as exc:
                fresh["errors"].append(f"NVD {cve}: {exc}")
                warnings.append(f"Live NVD check for {cve} failed ({exc}); NOT treated as 'no record'.")
                book.add(EvidenceStatus.UNABLE_TO_VERIFY, "fresh_nvd", f"Could not fetch the live NVD record for {cve}",
                         text=str(exc), source=vs.nvd_url, entities=[cve])
                continue
            if nvd is None:
                book.add(EvidenceStatus.NOT_FOUND, "fresh_nvd",
                         f"NVD returned no record for {cve} (live, retrieved {cached.retrieved_at})",
                         text="A very new CVE may not be published in NVD yet.", source=vs.nvd_url, entities=[cve])
                continue
            book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "fresh_nvd",
                     f"NVD record for {cve} (live, retrieved {cached.retrieved_at}){_stale_note(cached)}: status {nvd['status']}, "
                     f"CVSS {nvd['cvss_score']} {nvd['cvss_severity'] or ''}, last modified {nvd['last_modified']}",
                     text=f"{nvd['description']}\nCWE: {', '.join(nvd['cwes']) or 'none listed'}\n"
                          f"published: {nvd['published']}; references: {nvd['reference_count']}; vector: {nvd['cvss_vector']}",
                     source=f"{vs.nvd_url}?cveId={cve} sha256={cached.sha256[:12]}", entities=[cve],
                     meta={"sha256": cached.sha256, "last_modified": nvd["last_modified"], "cvss": nvd["cvss_score"]})

            # compare with the graph copy, if the graph has comparable fields
            graph_ref = next((r for r in state.get("resolved", []) if cve in [str(v).upper() for v in r.get("ids", {}).values()]), None)
            if graph_ref:
                fields = _profile_fields(graph_ref.get("profile", ""))
                notes_before = len(fresh["discrepancies"])
                g_mod = next((fields[k] for k in GRAPH_MODIFIED_KEYS if k in fields), None)
                live_mod, graph_mod = _parse_time(nvd["last_modified"] or ""), _parse_time(g_mod or "")
                if live_mod and graph_mod and live_mod > graph_mod:
                    fresh["discrepancies"].append(f"{cve}: NVD modified {nvd['last_modified']} is newer than the graph copy ({g_mod})")
                g_cvss = next((fields[k] for k in GRAPH_CVSS_KEYS if k in fields), None)
                try:
                    if g_cvss is not None and nvd["cvss_score"] is not None and abs(float(g_cvss) - float(nvd["cvss_score"])) > 0.05:
                        fresh["discrepancies"].append(f"{cve}: CVSS in the graph is {g_cvss}, live NVD says {nvd['cvss_score']}")
                except ValueError:
                    pass
                if g_mod is None and g_cvss is None:
                    fresh["notes"].append(f"{cve}: the graph record has no last-modified or CVSS field to compare with the live record")
                if len(fresh["discrepancies"]) > notes_before:
                    book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "freshness_check",
                             f"The graph copy of {cve} may be outdated",
                             text="\n".join(fresh["discrepancies"][notes_before:]),
                             source="comparison of the graph with live NVD", entities=[cve])
        return {"evidence": book.to_dicts(), "fresh": fresh, "warnings": warnings}

    return fresh_lookup
