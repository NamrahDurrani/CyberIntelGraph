"""CISA Cybersecurity Advisories collector (RSS + HTML pages).

What it does
------------
1. Builds a list of advisory page URLs from (in this order): URLs you pass with --url / --urls-file,
   the official CISA advisories RSS feed, links found on listing pages you name with --discover, and an optional
   seed list (config/advisory_seed_urls.txt).
   Only pages on www.cisa.gov are accepted. Duplicates are removed. At most --limit pages are fetched (default 75).
2. Checks robots.txt, then downloads each page politely (default 2 seconds between requests, retries on 429/5xx).
   It never tries to get around a refusal: HTTP 403 is reported, not bypassed.
3. Saves every page UNCHANGED to data/raw/advisories/ and appends a line to manifest.jsonl (url, file, time,
   status, SHA-256). Pages already downloaded are skipped, so an interrupted run resumes.
4. Extracts the readable text with BeautifulSoup (title, dates, alert code, sections, attachments, CVE / ATT&CK / CWE
   ids that are MENTIONED in the text) and writes data/processed/advisories_normalized.json.
5. Writes a validation report to outputs/reports/ and a log to logs/.

PDF / DOCX attachments are only listed here; they are processed with Docling in Milestone 6.
Mentions of CVE ids etc. are lexical matches, NOT relationships: two things appearing in one document is not a relationship.

Run from the project root (venv active):
    python ingestion\\collectors\\advisories\\collector.py --limit 3      (small first test)
    python ingestion\\collectors\\advisories\\collector.py                (default: up to 75 pages)

Dependencies: requests, beautifulsoup4 (everything else is the Python standard library).
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
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

try:
    import requests
    from bs4 import BeautifulSoup, Comment, NavigableString
except ImportError:  # usually the virtual environment is not active
    sys.stderr.write("ERROR: 'requests' or 'beautifulsoup4' is not available in this Python (" + sys.executable + ").\n"
                     "Activate the project environment first (type: cig   or run: .\\.venv\\Scripts\\Activate.ps1 in the project folder),\n"
                     "or install the packages with: python -m pip install -r requirements.txt\n")
    raise SystemExit(2)

# --------------------------------------------------------------------------- constants
SOURCE_NAME = "CISA Cybersecurity Advisories"
FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
ALLOWED_HOST = "www.cisa.gov"
COLLECTION_METHOD = "RSS feed + HTML pages via HTTP GET (requests), text extraction with BeautifulSoup"

# collector.py lives in <root>/ingestion/collectors/advisories/ -> root is 3 levels up
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "advisories"
MANIFEST = RAW_DIR / "manifest.jsonl"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
NORMALIZED = PROCESSED_DIR / "advisories_normalized.json"
REPORT_DIR = PROJECT_ROOT / "outputs" / "reports"
LOG_FILE = PROJECT_ROOT / "logs" / "advisories_collector.log"
DEFAULT_SEED_FILE = PROJECT_ROOT / "config" / "advisory_seed_urls.txt"

RETRY_STATUS = {429, 500, 502, 503, 504}
MIN_TEXT_CHARS = 500                     # shorter pages are flagged (blocked / JavaScript-only / wrong page?)
ATTACHMENT_EXT = (".pdf", ".json", ".xml", ".csv", ".docx", ".xlsx", ".zip", ".txt")
BLOCK_TAGS = ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "pre", "tr", "blockquote")
REMOVE_ALWAYS = ("script", "style", "noscript", "svg", "iframe", "form", "button", "nav", "aside")
LABELS = {"release date": "release_date", "last revised": "last_revised", "alert code": "alert_code"}
KNOWN_TYPES = {"cybersecurity advisory", "joint cybersecurity advisory", "alert", "analysis report",
               "malware analysis report", "ics advisory", "ics medical advisory"}
# listing-page links we follow when discovering advisories: Cybersecurity Advisories (AAyy-ddd?) and Analysis Reports (ARyy-ddd?)
DISCOVER_PATH_RE = re.compile(r"^/news-events/(cybersecurity-advisories/aa\d{2}-\d{3}[a-z]|analysis-reports/ar\d{2}-\d{3}[a-z](-\d{3})?)$", re.I)
ALERT_CODE_RE = re.compile(r"\bAA\d{2}-\d{3}[A-Z]\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.I)

log = logging.getLogger("advisories_collector")


# --------------------------------------------------------------------------- result object
@dataclass
class IngestionResult:
    """Consistent result returned by every collector in this project."""
    source_name: str = SOURCE_NAME
    source_url: str = FEED_URL
    status: str = "FAILED"               # SUCCESS | PARTIAL | FAILED
    success: bool = False
    retrieved_at: str = ""
    robots_status: str = ""
    feed_status: str = ""
    feed_file: str = ""
    feed_items: int = 0
    candidates: int = 0
    requested: int = 0
    downloaded_new: int = 0
    reused_existing: int = 0
    discovered_links: int = 0
    skipped_robots: list[str] = field(default_factory=list)
    skipped_not_html: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    records_normalized: int = 0
    with_release_date: int = 0
    with_alert_code: int = 0
    with_derived_date: int = 0
    archived_documents: int = 0
    label_code_mismatches: list[str] = field(default_factory=list)
    documents_without_any_date: list[str] = field(default_factory=list)
    short_pages: list[str] = field(default_factory=list)
    total_words: int = 0
    documents_mentioning_cves: int = 0
    distinct_cves_mentioned: int = 0
    processed_file: str = ""
    manifest_file: str = ""
    report_file: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CollectionError(Exception):
    """Raised when one URL cannot be retrieved."""


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


def parse_any_date(value: object) -> str | None:
    """Return an ISO date (YYYY-MM-DD) from the date formats seen on CISA pages, feeds and meta tags, else None."""
    text = " ".join(str(value or "").split()).strip(" .,")
    if not text:
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y", "%b. %d, %Y", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text).date().isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def date_from_alert_code(code: str | None) -> str | None:
    """CISA alert codes follow AAyy-dddX: yy = year, ddd = day of the year of the FIRST release. Derived, not stated."""
    match = re.fullmatch(r"AA(\d{2})-(\d{3})[A-Z]", (code or "").strip().upper())
    if not match:
        return None
    year, day = 2000 + int(match.group(1)), int(match.group(2))
    if day < 1:
        return None
    try:
        derived = date(year, 1, 1) + timedelta(days=day - 1)
    except (ValueError, OverflowError):
        return None
    return derived.isoformat() if derived.year == year else None


def extract_links(html: bytes, base_url: str, allowed_host: str) -> list[str]:
    """Advisory / analysis-report links found on a listing page (canonical, unique, in page order)."""
    soup = BeautifulSoup(html, "html.parser")
    found, seen = [], set()
    for a in soup.find_all("a", href=True):
        canon = canonical_url(urljoin(base_url, a["href"]), allowed_host)
        if canon and DISCOVER_PATH_RE.match(urlparse(canon).path) and canon not in seen:
            seen.add(canon)
            found.append(canon)
    return found


def canonical_url(url: str, allowed_host: str) -> str | None:
    """Normalize a URL; return None if it is not on the allowed host (CISA only)."""
    try:
        parts = urlparse(url.strip())
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host or parts.scheme not in ("http", "https"):
        return None
    if allowed_host == ALLOWED_HOST:
        if host not in ("cisa.gov", ALLOWED_HOST):
            return None
        scheme, netloc = "https", ALLOWED_HOST
    else:  # non-default host: only used by the local test setup
        if parts.netloc.lower() != allowed_host.lower():
            return None
        scheme, netloc = parts.scheme, parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    return f"{scheme}://{netloc}{path}"


def slug_of(url: str) -> str:
    return (urlparse(url).path.rstrip("/").rsplit("/", 1)[-1] or "index").lower()


# --------------------------------------------------------------------------- 1. fetch
def fetch(session: requests.Session, url: str, timeout: float, retries: int) -> requests.Response:
    """GET with retries on timeouts, connection errors, 429 and 5xx. 403 and other 4xx are NOT retried or bypassed."""
    last_error = "unknown error"
    for attempt in range(1, retries + 1):
        wait = min(2 ** attempt, 30)
        try:
            log.info("GET %s (attempt %d/%d)", url, attempt, retries)
            resp = session.get(url, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.warning("Network problem: %s", last_error)
        else:
            if resp.status_code == 200:
                return resp
            last_error = f"HTTP {resp.status_code} {resp.reason}"
            if resp.status_code == 403:
                raise CollectionError(f"{last_error}: the site refused this request. Open the URL in a browser; "
                                      "this collector does not try to bypass access controls (use --url / --urls-file "
                                      "with pages you can open, or try again later)")
            if resp.status_code not in RETRY_STATUS:
                raise CollectionError(f"{last_error} (not retryable)")
            retry_after = resp.headers.get("Retry-After", "")
            if retry_after.isdigit():
                wait = min(int(retry_after), 120)
            log.warning("%s - will retry", last_error)
        if attempt < retries:
            log.info("Waiting %ds before retry", wait)
            time.sleep(wait)
    raise CollectionError(f"Giving up after {retries} attempts. Last error: {last_error}")


class Robots:
    """robots.txt gate. Loads robots.txt once per site. A refusal is respected, never bypassed."""

    def __init__(self, session: requests.Session, user_agent: str, timeout: float):
        self.session, self.ua, self.timeout = session, user_agent, timeout
        self.parsers: dict[str, RobotFileParser | None] = {}
        self.notes: dict[str, str] = {}

    def allowed(self, url: str) -> bool:
        parts = urlparse(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self.parsers:
            self.parsers[origin], self.notes[origin] = self._load(origin)
        parser = self.parsers[origin]
        return True if parser is None else parser.can_fetch(self.ua, url)

    def _load(self, origin: str) -> tuple[RobotFileParser | None, str]:
        try:
            resp = self.session.get(f"{origin}/robots.txt", timeout=self.timeout)
        except requests.RequestException as exc:
            return None, f"robots.txt not retrievable ({type(exc).__name__}); proceeding slowly, explicit pages only"
        if resp.status_code == 200:
            parser = RobotFileParser()
            parser.parse(resp.text.splitlines())
            return parser, "robots.txt loaded and applied"
        if resp.status_code == 404:
            return None, "no robots.txt (HTTP 404)"
        return None, f"robots.txt not retrievable (HTTP {resp.status_code}); proceeding slowly, explicit pages only"

    def status(self) -> str:
        return "; ".join(f"{o}: {n}" for o, n in self.notes.items()) or "not checked"


# --------------------------------------------------------------------------- 2. candidate URLs
def parse_feed(content: bytes) -> list[dict]:
    """RSS 2.0 items -> dicts. Raises ValueError if the content is not a usable RSS document."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"feed is not well-formed XML: {exc}") from exc
    items = []
    for item in root.iter("item"):
        def get(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "").strip() if el is not None and el.text else ""
        link = get("link") or get("guid")
        if not link:
            continue
        items.append({"title": get("title"), "link": link, "pub_date": parse_any_date(get("pubDate")),
                      "categories": [(c.text or "").strip() for c in item.findall("category") if c.text],
                      "guid": get("guid")})
    if not items and root.tag.lower().rsplit("}", 1)[-1] != "rss":
        raise ValueError(f"feed has no <item> elements and root is <{root.tag}>")
    return items


def read_url_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    urls = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            urls.append(line)
    return urls


def build_candidates(manual: list[str], feed_items: list[dict], seed: list[str], allowed_host: str,
                     limit: int, discovered: list[str] | None = None) -> tuple[list[dict], list[str]]:
    """Ordered unique candidates (manual, feed newest first, discovered, seed), at most `limit`; plus rejected inputs."""
    ordered: list[tuple[str, str, dict]] = [(u, "manual", {}) for u in manual]
    for item in sorted(feed_items, key=lambda i: i["pub_date"] or "", reverse=True):
        ordered.append((item["link"], "feed", item))
    ordered += [(u, "discovered", {}) for u in (discovered or [])]
    ordered += [(u, "seed", {}) for u in seed]
    result, rejected, seen = [], [], set()
    for url, source, item in ordered:
        canon = canonical_url(url, allowed_host)
        if canon is None:
            rejected.append(url)
        elif canon not in seen:
            seen.add(canon)
            result.append({"url": canon, "source": source, "feed_title": item.get("title", ""),
                           "feed_pub_date": item.get("pub_date"), "feed_categories": item.get("categories", [])})
    return result[:limit], rejected


# --------------------------------------------------------------------------- 3. raw storage + manifest
def read_manifest() -> list[dict]:
    entries: list[dict] = []
    if MANIFEST.is_file():
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                log.warning("Skipping unreadable manifest line: %.80s", line)
    return entries


def latest_ok_by_url(entries: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for entry in entries:
        if entry.get("outcome") == "ok" and (RAW_DIR / entry.get("raw_file", "")).is_file():
            latest[entry["url"]] = entry  # later lines win
    return latest


def append_manifest(entry: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def save_raw(content: bytes, prefix: str, ext: str, retrieved_at: datetime) -> Path:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    path = RAW_DIR / f"{prefix}__{stamp(retrieved_at)}.{ext}"
    counter = 1
    while path.exists():  # never overwrite a raw file
        counter += 1
        path = RAW_DIR / f"{prefix}__{stamp(retrieved_at)}_{counter}.{ext}"
    with open(path, "xb") as fh:
        fh.write(content)
    return path


# --------------------------------------------------------------------------- 4. extraction
def own_text(el) -> str:
    """Text of an element without the text of nested block elements (those are visited separately)."""
    parts = []
    for node in el.children:
        if isinstance(node, Comment):
            continue
        if isinstance(node, NavigableString):
            parts.append(str(node))
        elif node.name in BLOCK_TAGS or node.name in ("ul", "ol", "table", "tbody", "thead"):
            continue  # visited as separate blocks
        elif node.name in ("div", "section") and node.find(BLOCK_TAGS + ("div", "section", "ul", "ol", "table")):
            continue  # a wrapper: its own blocks are visited separately
        else:
            parts.append(node.get_text(" "))
    return " ".join(" ".join(parts).split())


def meta_content(soup: BeautifulSoup, *names: str) -> str:
    for name in names:
        tag = soup.find("meta", attrs={"property": name}) or soup.find("meta", attrs={"name": name})
        if tag and tag.get("content"):
            return tag["content"].strip()
    return ""


def extract_page(html: bytes, url: str, feed_title: str = "", feed_pub_date: str | None = None) -> dict:
    """Pure function: HTML bytes -> extracted fields. Problems are returned in 'problems' / 'warnings'."""
    soup = BeautifulSoup(html, "html.parser")
    problems: list[str] = []
    warnings: list[str] = []

    title = meta_content(soup, "og:title", "twitter:title")
    main = soup.find("main") or soup.find("article") or soup.find(id="main-content")
    main_found = main is not None
    if main is None:
        main = soup.body or soup
    remove = list(REMOVE_ALWAYS) + ([] if main_found else ["header", "footer"])
    for tag in main.find_all(remove):
        tag.decompose()
    if not title:
        h1 = main.find("h1")
        title = h1.get_text(" ", strip=True) if h1 else (soup.title.get_text(" ", strip=True) if soup.title else "")
    title = re.sub(r"\s*\|\s*CISA.*$", "", " ".join(title.split()))
    if not title:
        problems.append("no title found (og:title, h1 and <title> are all missing)")

    # labelled metadata ("Release Date", "Last Revised", "Alert Code") from the visible lines
    lines = [ln.strip() for ln in main.get_text("\n").splitlines() if ln.strip()]
    labelled: dict[str, str] = {}
    for i, line in enumerate(lines):
        low = line.lower().rstrip(":").strip()
        for label, key in LABELS.items():
            if key in labelled:
                continue
            if low == label and i + 1 < len(lines) and lines[i + 1].lower().rstrip(":") not in LABELS:
                labelled[key] = lines[i + 1]
            elif low.startswith(label + ":") and len(line) > len(label) + 1:
                labelled[key] = line.split(":", 1)[1].strip()

    archived = any(ln.lower().rstrip(":").strip() == "archived content" for ln in lines)
    advisory_type = next((ln for ln in lines[:10] if ln.lower().strip() in KNOWN_TYPES), "")
    release_date = parse_any_date(labelled.get("release_date"))
    meta_published = parse_any_date(meta_content(soup, "article:published_time", "dcterms.date", "date"))
    last_revised = parse_any_date(labelled.get("last_revised")) or parse_any_date(
        meta_content(soup, "article:modified_time", "og:updated_time", "dcterms.modified"))

    # readable text, section by section. The metadata lines (labels, their values, the "Archived Content" banner and the
    # advisory type) are stored as fields, so each is left out of the text once.
    to_skip: Counter = Counter(label for label in LABELS)
    to_skip.update(v.lower().strip() for v in labelled.values())
    if archived:
        to_skip["archived content"] += 1
    if advisory_type:
        to_skip[advisory_type.lower().strip()] += 1
    sections: list[dict] = [{"heading": None, "level": 0, "lines": []}]
    for el in main.find_all(BLOCK_TAGS + ("div",)):
        if el.name != "tr" and el.find_parent("table") is not None:
            continue  # table cells are handled through their row
        if el.name == "div":
            # only plain text-bearing leaf divs count as blocks, and not when a parent block already includes them
            if el.find(BLOCK_TAGS + ("div", "section", "ul", "ol", "table")) or el.find_parent(BLOCK_TAGS):
                continue
        if el.name == "tr":
            cells = [c.get_text(" ", strip=True) for c in el.find_all(["th", "td"])]
            text = "| " + " | ".join(cells) + " |" if any(cells) else ""
        else:
            text = own_text(el)
        if not text:
            continue
        skip_key = text.lower().rstrip(":").strip()
        if to_skip.get(skip_key, 0) > 0:
            to_skip[skip_key] -= 1
            continue
        if el.name[0] == "h" and el.name[1:].isdigit():
            sections.append({"heading": text, "level": int(el.name[1:]), "lines": []})
        else:
            sections[-1]["lines"].append(("- " + text) if el.name == "li" else text)
    out_sections, text_parts = [], []
    for sec in sections:
        body = "\n".join(sec["lines"])
        if sec["heading"] is None and not body:
            continue
        out_sections.append({"heading": sec["heading"], "level": sec["level"], "text": body})
        if sec["heading"]:
            text_parts.append("#" * max(sec["level"], 1) + " " + sec["heading"])
        if body:
            text_parts.append(body)
    text = "\n\n".join(text_parts).strip()

    alert_code = (labelled.get("alert_code") or "").strip().upper()
    if not ALERT_CODE_RE.fullmatch(alert_code):
        found = ALERT_CODE_RE.search(f"{url} {title}") or ALERT_CODE_RE.search(text)
        alert_code = found.group(0).upper() if found else ""

    derived_date = date_from_alert_code(alert_code)
    is_derived = False
    if release_date:
        published_at, published_source = release_date, "page label 'Release Date'"
    elif meta_published:
        published_at, published_source = meta_published, "page meta tag"
    elif feed_pub_date:
        published_at, published_source = feed_pub_date, "RSS pubDate"
    elif derived_date:
        published_at, is_derived = derived_date, True
        published_source = f"DERIVED from alert code {alert_code} (year and day-of-year convention), not stated on the page"
    else:
        published_at, published_source = None, ""
        warnings.append("no publication date found on the page, in the feed, or derivable from an alert code")
    matches_code = (release_date == derived_date) if (release_date and derived_date) else None
    if matches_code is False:
        warnings.append(f"Release Date label {release_date} differs from the date implied by alert code {alert_code} ({derived_date})")

    attachments, seen = [], set()
    for a in main.find_all("a", href=True):
        target = urljoin(url, a["href"]).split("#", 1)[0]
        if urlparse(target).path.lower().endswith(ATTACHMENT_EXT) and target not in seen:
            seen.add(target)
            attachments.append({"url": target, "text": a.get_text(" ", strip=True)})

    haystack = f"{title}\n{text}"
    if len(text) < MIN_TEXT_CHARS:
        warnings.append(f"very little text ({len(text)} characters): blocked, JavaScript-only or wrong page?")
    return {
        "title": title or feed_title, "alert_code": alert_code, "published_at": published_at,
        "published_at_source": published_source, "published_at_is_derived": is_derived,
        "release_date": release_date, "last_revised": last_revised, "release_date_from_alert_code": derived_date,
        "release_date_matches_alert_code": matches_code, "archived": archived, "advisory_type": advisory_type,
        "text": text, "sections": out_sections, "word_count": len(text.split()), "attachments": attachments,
        "mentioned_cve_ids": sorted({m.upper() for m in CVE_RE.findall(haystack)}),
        "mentioned_attack_ids": sorted(set(ATTACK_RE.findall(haystack))),
        "mentioned_cwe_ids": sorted({m.upper() for m in CWE_RE.findall(haystack)}),
        "problems": problems, "warnings": warnings,
    }


def normalize_record(extracted: dict, entry: dict) -> dict:
    slug = slug_of(entry["url"])
    record = {
        "record_id": f"cisa-advisory:{slug}", "doc_id": f"cisa-advisory:{slug}", "slug": slug,
        "url": entry["url"], "final_url": entry.get("final_url", entry["url"]),
        "title": extracted["title"], "alert_code": extracted["alert_code"], "advisory_type": extracted["advisory_type"],
        "archived": extracted["archived"],
        "release_date": extracted["release_date"], "last_revised": extracted["last_revised"],
        "release_date_from_alert_code": extracted["release_date_from_alert_code"],
        "release_date_matches_alert_code": extracted["release_date_matches_alert_code"],
        "feed_title": entry.get("feed_title", ""), "feed_pub_date": entry.get("feed_pub_date"),
        "feed_categories": entry.get("feed_categories", []),
        "text": extracted["text"], "sections": extracted["sections"], "word_count": extracted["word_count"],
        "attachments": extracted["attachments"],
        "mentioned_cve_ids": extracted["mentioned_cve_ids"],
        "mentioned_attack_ids": extracted["mentioned_attack_ids"],
        "mentioned_cwe_ids": extracted["mentioned_cwe_ids"],
        "mentions_note": "lexical matches in the text, NOT verified relationships",
        # --- provenance ---
        "source_name": SOURCE_NAME, "source_url": entry["url"], "source_record_id": slug,
        "retrieved_at": entry["retrieved_at"], "published_at": extracted["published_at"],
        "published_at_source": extracted["published_at_source"],
        "published_at_is_derived": extracted["published_at_is_derived"], "last_modified_at": extracted["last_revised"],
        "original_format": "html", "raw_file_reference": f"data/raw/advisories/{entry['raw_file']}",
        "raw_sha256": entry["sha256"], "collection_method": COLLECTION_METHOD,
        "evidence_type": "stated_in_source",
    }
    return record


# --------------------------------------------------------------------------- orchestration
def make_session(user_agent: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5"})
    return session


def collect_feed(session: requests.Session, args: argparse.Namespace, result: IngestionResult) -> list[dict]:
    if args.no_feed:
        result.feed_status = "skipped (--no-feed)"
        return []
    try:
        resp = fetch(session, args.feed_url, args.timeout, args.retries)
        items = parse_feed(resp.content)
    except (CollectionError, ValueError) as exc:
        result.feed_status = f"unavailable: {exc}"
        result.warnings.append(f"RSS feed not used: {exc}")
        log.warning("RSS feed not used: %s", exc)
        return []
    retrieved_at = utc_now()
    sha = hashlib.sha256(resp.content).hexdigest()
    for meta_path in sorted(RAW_DIR.glob("feed__*.meta.json")):  # an identical feed is not stored twice
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if meta.get("sha256") == sha and (RAW_DIR / str(meta.get("raw_file", ""))).is_file():
            result.feed_file, result.feed_items = rel(RAW_DIR / meta["raw_file"]), len(items)
            result.feed_status = f"ok ({len(items)} items, unchanged since an earlier download)"
            log.info("Feed unchanged; reusing %s", result.feed_file)
            return items
    path = save_raw(resp.content, "feed", "xml", retrieved_at)
    write_json_atomic(path.with_suffix(".meta.json"), {
        "source_name": SOURCE_NAME, "source_url": args.feed_url, "retrieved_at": retrieved_at.isoformat(),
        "http_status": resp.status_code, "bytes": len(resp.content), "sha256": sha,
        "raw_file": path.name, "original_format": "xml (RSS)", "collection_method": COLLECTION_METHOD})
    result.feed_file, result.feed_items, result.feed_status = rel(path), len(items), f"ok ({len(items)} items)"
    log.info("Feed saved: %s (%d items)", rel(path), len(items))
    return items


def discover_links(session: requests.Session, robots: Robots, args: argparse.Namespace, result: IngestionResult) -> list[str]:
    """Follow CISA listing pages (--discover) and collect advisory links from them. Listing pages are saved raw too."""
    links: list[str] = []
    first = True
    for base in args.discover or []:
        if canonical_url(base, args.allowed_host) is None:
            result.warnings.append(f"ignored --discover URL outside {args.allowed_host}: {base}")
            continue
        for index in range(max(args.discover_pages, 1)):
            url = base if index == 0 else f"{base}{'&' if '?' in base else '?'}page={index}"
            if not robots.allowed(url):
                result.warnings.append(f"listing page skipped (robots.txt): {url}")
                break
            if not first:
                time.sleep(args.delay)
            first = False
            retrieved_at = utc_now()
            try:
                resp = fetch(session, url, args.timeout, args.retries)
            except CollectionError as exc:
                result.warnings.append(f"listing page not used: {url}: {exc}")
                break
            if "html" not in resp.headers.get("Content-Type", "").lower():
                result.warnings.append(f"listing page is not HTML: {url}")
                break
            raw_path = save_raw(resp.content, f"listing-{slug_of(base)}-p{index}", "html", retrieved_at)
            append_manifest({"url": url, "raw_file": raw_path.name, "retrieved_at": retrieved_at.isoformat(),
                             "http_status": resp.status_code, "bytes": len(resp.content),
                             "sha256": hashlib.sha256(resp.content).hexdigest(), "outcome": "listing"})
            found = extract_links(resp.content, resp.url, args.allowed_host)
            new = [u for u in found if u not in links]
            log.info("Listing %s: %d advisory link(s), %d new", url, len(found), len(new))
            links += new
            if index > 0 and not new:
                break  # a page with nothing new means we ran past the end
    return links


def download_pages(candidates: list[dict], session: requests.Session, robots: Robots,
                   result: IngestionResult, args: argparse.Namespace) -> None:
    existing = latest_ok_by_url(read_manifest())
    first = True
    for position, cand in enumerate(candidates, start=1):
        url = cand["url"]
        if url in existing and not args.refresh:
            result.reused_existing += 1
            continue
        if not robots.allowed(url):
            result.skipped_robots.append(url)
            log.warning("[%d/%d] %s skipped: disallowed by robots.txt", position, len(candidates), url)
            continue
        if not first:
            time.sleep(args.delay)
        first = False
        retrieved_at = utc_now()
        try:
            resp = fetch(session, url, args.timeout, args.retries)
        except CollectionError as exc:
            result.failed[url] = str(exc)
            log.error("[%d/%d] %s FAILED: %s", position, len(candidates), url, exc)
            continue
        final = canonical_url(resp.url, args.allowed_host)
        if final is None:
            result.failed[url] = f"redirected outside the allowed site: {resp.url}"
            log.error("[%d/%d] %s", position, len(candidates), result.failed[url])
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            result.skipped_not_html.append(f"{url} ({ctype or 'unknown type'})")
            log.warning("[%d/%d] %s is not HTML (%s): skipped; documents are handled in Milestone 6", position, len(candidates), url, ctype)
            continue
        raw_path = save_raw(resp.content, slug_of(final), "html", retrieved_at)
        entry = {"url": url, "final_url": final, "slug": slug_of(final), "raw_file": raw_path.name,
                 "retrieved_at": retrieved_at.isoformat(), "http_status": resp.status_code, "content_type": ctype,
                 "bytes": len(resp.content), "sha256": hashlib.sha256(resp.content).hexdigest(), "outcome": "ok",
                 "source": cand["source"], "feed_title": cand["feed_title"], "feed_pub_date": cand["feed_pub_date"],
                 "feed_categories": cand["feed_categories"]}
        append_manifest(entry)
        result.downloaded_new += 1
        log.info("[%d/%d] %s saved (%d bytes)", position, len(candidates), url, len(resp.content))


def normalize_all(result: IngestionResult) -> None:
    latest = latest_ok_by_url(read_manifest())
    records: list[dict] = []
    slugs: Counter = Counter()
    for url, entry in latest.items():
        html = (RAW_DIR / entry["raw_file"]).read_bytes()
        if hashlib.sha256(html).hexdigest() != entry["sha256"]:
            result.failed[url] = f"raw file {entry['raw_file']} no longer matches its recorded SHA-256 (it was changed)"
            continue
        extracted = extract_page(html, entry["final_url"], entry.get("feed_title", ""), entry.get("feed_pub_date"))
        if extracted["problems"]:
            result.failed[url] = "extraction: " + "; ".join(extracted["problems"])
            continue
        for w in extracted["warnings"]:
            result.warnings.append(f"{slug_of(url)}: {w}")
        if len(extracted["text"]) < MIN_TEXT_CHARS:
            result.short_pages.append(url)
        record = normalize_record(extracted, entry)
        slugs[record["slug"]] += 1
        records.append(record)
    for slug, n in slugs.items():
        if n > 1:
            result.errors.append(f"duplicate document slug {slug!r} ({n} pages)")
    records.sort(key=lambda r: (r["published_at"] or "", r["slug"]), reverse=True)

    result.records_normalized = len(records)
    result.with_release_date = sum(1 for r in records if r["release_date"])
    result.with_alert_code = sum(1 for r in records if r["alert_code"])
    result.with_derived_date = sum(1 for r in records if r["published_at_is_derived"])
    result.archived_documents = sum(1 for r in records if r["archived"])
    result.label_code_mismatches = [r["slug"] for r in records if r["release_date_matches_alert_code"] is False]
    result.documents_without_any_date = [r["slug"] for r in records if not r["published_at"]]
    result.total_words = sum(r["word_count"] for r in records)
    result.documents_mentioning_cves = sum(1 for r in records if r["mentioned_cve_ids"])
    result.distinct_cves_mentioned = len({c for r in records for c in r["mentioned_cve_ids"]})
    if records:
        write_json_atomic(NORMALIZED, {"metadata": {
            "source_name": SOURCE_NAME, "feed_url": FEED_URL, "generated_at": utc_now().isoformat(),
            "record_count": len(records), "manifest_file": rel(MANIFEST), "collection_method": COLLECTION_METHOD,
            "normalization_note": ("Built from the latest successful raw download per URL. 'text' keeps headings (#) and "
                                   "list items (-). mentioned_* lists are lexical matches, not relationships. "
                                   "PDF/DOCX attachments are listed but not downloaded (Milestone 6)."),
        }, "records": records})
        result.processed_file = rel(NORMALIZED)
        log.info("Wrote normalized copy: %s (%d records)", result.processed_file, len(records))


def write_report(result: IngestionResult) -> None:
    path = REPORT_DIR / f"advisories_validation_{stamp(utc_now())}.json"
    result.report_file = rel(path)
    write_json_atomic(path, asdict(result))


def print_summary(result: IngestionResult) -> None:
    line = lambda label, value: print(f"  {label:<28}: {value}")
    print("\n=== CISA advisories collection summary ===")
    line("Status", result.status)
    line("robots.txt", result.robots_status or "-")
    line("RSS feed", result.feed_status or "-")
    line("Links found on listings", result.discovered_links)
    line("Candidate pages", result.candidates)
    line("Downloaded now", result.downloaded_new)
    line("Reused (already on disk)", result.reused_existing)
    line("Skipped by robots.txt", len(result.skipped_robots))
    line("Skipped (not HTML)", len(result.skipped_not_html))
    line("Failed", len(result.failed))
    line("Normalized documents", result.records_normalized)
    line("  with release date", result.with_release_date)
    line("  with alert code", result.with_alert_code)
    line("  date derived from code", result.with_derived_date)
    line("  no date at all", len(result.documents_without_any_date))
    line("  marked 'Archived'", result.archived_documents)
    line("  label vs code mismatch", len(result.label_code_mismatches))
    line("  very short (<500 chars)", len(result.short_pages))
    line("Total words", result.total_words)
    line("Docs mentioning CVE ids", result.documents_mentioning_cves)
    line("Distinct CVE ids mentioned", result.distinct_cves_mentioned)
    line("Normalized file", result.processed_file or "-")
    line("Manifest", result.manifest_file or "-")
    line("Validation report", result.report_file or "-")
    for message in result.warnings[:10]:
        print(f"  WARNING: {message}")
    if len(result.warnings) > 10:
        print(f"  ... and {len(result.warnings) - 10} more warnings (see validation report)")
    for url, message in list(result.failed.items())[:15]:
        print(f"  FAILED: {url}: {message}")
    if len(result.failed) > 15:
        print(f"  ... and {len(result.failed) - 15} more failures (see validation report)")
    for url in result.skipped_robots[:5]:
        print(f"  SKIPPED (robots.txt): {url}")
    for message in result.errors:
        print(f"  ERROR: {message}")


def run(args: argparse.Namespace) -> IngestionResult:
    result = IngestionResult(source_url=args.feed_url, retrieved_at=utc_now().isoformat())
    user_agent = os.environ.get("USER_AGENT", "CyberIntelGraph/0.1 (research project)")
    session = make_session(user_agent)

    manual = list(args.url or [])
    for path in args.urls_file or []:
        manual += read_url_file(Path(path))
    feed_items = collect_feed(session, args, result)
    seed = [] if args.no_seed else read_url_file(Path(args.seed_file))
    robots = Robots(session, user_agent, args.timeout)
    discovered = discover_links(session, robots, args, result)
    result.discovered_links = len(discovered)
    candidates, rejected = build_candidates(manual, feed_items, seed, args.allowed_host, args.limit, discovered)
    for url in rejected:
        result.warnings.append(f"ignored URL outside {args.allowed_host}: {url}")
    result.candidates = len(candidates)
    if not candidates:
        result.errors.append("No advisory URLs to collect. The RSS feed gave nothing and no --discover / --url / --urls-file / "
                             "seed file was usable. Open an advisory page in your browser and pass its address with --url.")
        return result

    try:
        download_pages(candidates, session, robots, result, args)
    except KeyboardInterrupt:
        result.warnings.append("interrupted by the user; progress is saved, run again to resume")
        log.warning("Interrupted - progress is saved; run again to resume")
    result.robots_status = robots.status()
    result.requested = len(candidates)
    normalize_all(result)
    result.manifest_file = rel(MANIFEST) if MANIFEST.is_file() else ""
    if result.records_normalized > 0 and not result.errors:
        result.status = "SUCCESS" if not result.failed and not result.skipped_robots else "PARTIAL"
    result.success = result.status == "SUCCESS"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect CISA cybersecurity advisories (RSS + HTML).")
    parser.add_argument("--limit", type=int, default=75, help="max pages to consider this run (default 75; use 3 for a first test)")
    parser.add_argument("--url", action="append", metavar="URL", help="an advisory page to fetch (repeatable)")
    parser.add_argument("--urls-file", action="append", metavar="FILE", help="text file with one advisory URL per line")
    parser.add_argument("--discover", action="append", metavar="URL",
                        help="a CISA listing page to read advisory links from, e.g. https://www.cisa.gov/news-events/cybersecurity-advisories (repeatable)")
    parser.add_argument("--discover-pages", type=int, default=1, help="how many listing pages to read per --discover URL (default 1)")
    parser.add_argument("--feed-url", default=FEED_URL)
    parser.add_argument("--no-feed", action="store_true", help="do not read the RSS feed")
    parser.add_argument("--seed-file", default=str(DEFAULT_SEED_FILE), help="optional seed list (default config/advisory_seed_urls.txt)")
    parser.add_argument("--no-seed", action="store_true", help="do not read the seed list")
    parser.add_argument("--refresh", action="store_true", help="download again even if a raw copy exists")
    parser.add_argument("--delay", type=float, default=2.0, help="seconds between page requests (default 2.0)")
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("HTTP_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--allowed-host", default=ALLOWED_HOST, help=argparse.SUPPRESS)  # local testing only
    args = parser.parse_args(argv)

    setup_logging()
    try:
        result = run(args)
    except Exception as exc:  # last-resort guard
        log.exception("Unexpected failure")
        result = IngestionResult(source_url=args.feed_url, retrieved_at=utc_now().isoformat())
        result.errors.append(f"Unexpected {type(exc).__name__}: {exc} (details in {rel(LOG_FILE)})")
    write_report(result)
    print_summary(result)
    return 0 if result.success else (130 if any("interrupted" in w for w in result.warnings) else 1)


if __name__ == "__main__":
    sys.exit(main())
