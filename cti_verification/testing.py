"""Test doubles for Milestone 14: a scripted fetcher and sample KEV / NVD payloads."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .fresh import FetchError, FetchResult
from .settings import KEV_URL, NVD_URL


def kev_payload(entries: list[dict] | None = None, version: str = "2026.11.19") -> dict:
    entries = entries if entries is not None else [kev_entry("CVE-2024-3400")]
    return {"title": "CISA KEV", "catalogVersion": version, "dateReleased": "2026-11-19T00:00:00Z",
            "count": len(entries), "vulnerabilities": entries}


def kev_entry(cve: str, added: str = "2024-04-12", ransomware: str = "Unknown", product: str = "PAN-OS") -> dict:
    return {"cveID": cve, "vendorProject": "Palo Alto Networks", "product": product,
            "vulnerabilityName": f"{product} Command Injection", "dateAdded": added,
            "shortDescription": f"{product} contains a command injection vulnerability.",
            "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": ransomware, "cwes": ["CWE-77"]}


def nvd_payload(cve: str = "CVE-2024-3400", score: float = 10.0, modified: str = "2026-11-01T10:00:00.000",
                cwe: str = "CWE-77") -> dict:
    return {"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": {
        "id": cve, "vulnStatus": "Analyzed", "published": "2024-04-12T08:15:00.000", "lastModified": modified,
        "descriptions": [{"lang": "en", "value": "A command injection in GlobalProtect of PAN-OS."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL",
                                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
        "references": [{"url": "https://example.test/1"}, {"url": "https://example.test/2"}]}}]}


class FakeFetcher:
    def __init__(self, kev: dict | None = None, nvd: dict[str, dict] | None = None, fail: set[str] | None = None,
                 clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.kev = kev if kev is not None else kev_payload()
        self.nvd = nvd if nvd is not None else {"CVE-2024-3400": nvd_payload()}
        self.fail = fail or set()      # "kev" and/or "nvd"
        self.calls: list[str] = []

    def get_json(self, url, params=None, headers=None) -> FetchResult:
        stamp = self.clock().isoformat()
        if url == KEV_URL:
            self.calls.append("kev")
            if "kev" in self.fail:
                raise FetchError("simulated KEV outage")
            payload = self.kev
        elif url == NVD_URL:
            cve = params["cveId"]
            self.calls.append(f"nvd:{cve}")
            if "nvd" in self.fail:
                raise FetchError("simulated NVD outage")
            payload = self.nvd.get(cve, {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})
        else:
            raise FetchError(f"unexpected url {url}")
        return FetchResult(payload, hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(), url, stamp)


class FakeCollection:
    def __init__(self, fail: bool = False):
        self.docs: list[dict] = []
        self.fail = fail
        self.indexes: list = []

    def create_index(self, spec, **kw):
        self.indexes.append((spec, kw))

    def update_one(self, flt, update, upsert=False):
        if self.fail:
            raise RuntimeError("simulated MongoDB outage")
        for d in self.docs:
            if all(d.get(k) == v for k, v in flt.items()):
                d.update(update["$set"])
                return
        if upsert:
            self.docs.append({**flt, **update["$set"]})

    def _match(self, flt):
        return [d for d in self.docs if all(d.get(k) == v for k, v in flt.items())]

    def find_one(self, flt, proj=None):
        found = self._match(flt)
        return dict(found[0]) if found else None

    def find(self, flt, proj=None):
        return FakeCursor([dict(d) for d in self._match(flt)])


class FakeCursor(list):
    def sort(self, key, direction):
        return FakeCursor(sorted(self, key=lambda d: str(d.get(key)), reverse=direction < 0))

    def limit(self, n):
        return FakeCursor(self[:n])


class FakeMongoDb(dict):
    def __init__(self, fail: bool = False):
        super().__init__()
        self.fail = fail

    def __getitem__(self, name):
        if name not in self:
            self[name] = FakeCollection(self.fail)
        return dict.__getitem__(self, name)
