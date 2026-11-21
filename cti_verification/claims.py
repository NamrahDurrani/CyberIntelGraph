"""Split a written answer into individual claims (sentences) with their citations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cti_agent.nlp import ID_PATTERNS

CITE = re.compile(r"\[(E\d+(?:\s*,\s*E\d+)*|E\?)\]")
SENTENCE_END = re.compile(r"(?<=[.!?])(?=\s+[A-Z\[(*\-\u2022\d])")
META_START = re.compile(r"^(limitations?|note|verification|evidence found|confirmed|reported|candidate|inferred|"
                        r"not found|unable)\b[^.]{0,40}:", re.IGNORECASE)
NO_INFO = re.compile(r"\b(could not find|cannot find|can't find|not found|no (?:matching|supporting|information|evidence)|"
                     r"unable to verify|does not prove|not proof)\b", re.IGNORECASE)


@dataclass
class Claim:
    text: str                       # sentence as written, without trailing citations
    cited: list[str] = field(default_factory=list)
    start: int = 0                  # offsets of the whole sentence (incl. citations) in the answer
    end: int = 0
    is_claim: bool = True


def _cited_ids(text: str) -> list[str]:
    ids: list[str] = []
    for m in CITE.finditer(text):
        ids += [i.strip() for i in m.group(1).split(",") if i.strip() != "E?"]
    return list(dict.fromkeys(ids))


def split_claims(answer: str) -> list[Claim]:
    claims: list[Claim] = []
    pos = 0
    for line in answer.split("\n"):
        line_start = pos
        pos += len(line) + 1
        if not line.strip():
            continue
        bullet = re.match(r"^\s*(?:[-*\u2022]|\d+[.)])\s+", line)
        offset = bullet.end() if bullet else 0
        body = line[offset:]
        bounds = [0] + [m.start() for m in SENTENCE_END.finditer(body)] + [len(body)]
        for a, b in zip(bounds, bounds[1:]):
            raw = body[a:b]
            stripped = raw.strip()
            if not stripped:
                continue
            start = line_start + offset + a + (len(raw) - len(raw.lstrip()))
            end = line_start + offset + a + len(raw.rstrip())
            # a bare "[E3]" sentence belongs to the previous claim
            if CITE.sub("", stripped).strip(" .") == "" and claims and claims[-1].end <= start:
                claims[-1].cited = list(dict.fromkeys(claims[-1].cited + _cited_ids(stripped)))
                claims[-1].end = end
                continue
            text = re.sub(r"\s+([.,;:!?])", r"\1", re.sub(r"\s{2,}", " ", CITE.sub("", stripped))).strip()
            words = re.findall(r"[A-Za-z0-9]+", text)
            has_anchor = bool(CITE.search(stripped)) or any(p.search(text) for p in ID_PATTERNS.values())
            meta = bool(META_START.match(text)) or bool(NO_INFO.search(text)) or text.endswith(":") \
                or (len(words) < 4 and not has_anchor)
            claims.append(Claim(text=text, cited=_cited_ids(stripped), start=start, end=end, is_claim=not meta))
    return claims
