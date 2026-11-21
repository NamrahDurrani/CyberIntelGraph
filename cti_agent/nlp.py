"""Question understanding helpers: identifiers, entity-name extraction, intent.
No database or LLM needed - these are plain, testable functions."""

from __future__ import annotations

import re

ID_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "cwe": re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE),
    "technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "group": re.compile(r"\bG\d{4}\b"),
    "software": re.compile(r"\bS\d{4}\b"),
}

STOPWORDS = {
    "what", "which", "who", "whom", "whose", "when", "where", "why", "how", "does", "did", "do",
    "show", "tell", "give", "list", "find", "investigate", "explain", "describe", "summarize",
    "the", "this", "that", "these", "those", "and", "for", "with", "from", "about", "into",
    "are", "was", "were", "has", "have", "had", "been", "any", "all", "some", "there", "their",
    "its", "evidence", "vulnerabilities", "vulnerability", "techniques", "technique", "software",
    "weakness", "weaknesses", "attack", "attacks", "associated", "related", "used", "uses", "use",
    "exploited", "affected", "ransomware", "group", "groups", "malware", "threat", "actor", "actors",
    "please", "can", "could", "would", "should", "know", "known", "support", "supports", "report",
    "reports", "advisory", "advisories", "campaign", "campaigns", "tools", "tool", "mitre", "cisa",
    "also", "other", "more", "most", "many", "much", "between", "connected", "connection",
    "is", "are", "will", "was", "be", "a", "an", "of", "in", "on", "to", "by", "or", "if", "it", "as", "at",
    "provide", "identify", "compare", "explore", "check", "look", "name", "get", "summarise", "analyse",
    "analyze", "whether", "linked", "link", "relate", "relates", "related", "exploit", "exploits",
    "run", "ran", "using", "used", "than", "then", "so", "not", "no", "yes", "our", "your", "my",
}

INTENT_KEYWORDS = [
    ("affected_software", ("software", "affects", "affected product", "which products", "product")),
    ("weakness", ("weakness", "cwe")),
    ("techniques", ("technique", "ttp", "tactic", "att&ck", "attack pattern")),
    ("vulnerability", ("vulnerab", "cve", "exploit", "kev")),
]

# Relations that the question is about are shown first (used for ordering only).
INTENT_RELS = {
    "affected_software": ["AFFECTS"],
    "weakness": ["HAS_WEAKNESS"],
    "techniques": ["USES", "SUBTECHNIQUE_OF", "PART_OF_TACTIC"],
}


def extract_identifiers(question: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for kind, pattern in ID_PATTERNS.items():
        values = list(dict.fromkeys(m.group(0).upper() for m in pattern.finditer(question)))
        if values:
            found[kind] = values
    return found


def matching_intents(question: str) -> list[str]:
    q = question.lower()
    return [intent for intent, words in INTENT_KEYWORDS if any(w in q for w in words)]


def classify_intent(question: str) -> str:
    found = matching_intents(question)
    return found[0] if found else "general"


def heuristic_terms(question: str, identifiers: dict[str, list[str]]) -> list[str]:
    text = question
    for values in identifiers.values():
        for v in values:
            text = re.sub(re.escape(v), " ", text, flags=re.IGNORECASE)
    terms: list[str] = [m.strip() for m in re.findall(r'["\u201c]([^"\u201d]+)["\u201d]', text) if m.strip()]
    text = re.sub(r'["\u201c][^"\u201d]+["\u201d]', " ", text)

    tokens = list(re.finditer(r"[A-Za-z][A-Za-z0-9\-\.]*[A-Za-z0-9]|[A-Za-z]", text))
    run: list[str] = []
    last_end = -1

    def flush() -> None:
        if run:
            terms.append(" ".join(run))
            run.clear()

    for m in tokens:
        word = m.group(0).strip(".-")
        entity_like = (word[:1].isupper() or any(c.isdigit() for c in word)
                       or (any(c.isupper() for c in word[1:]))) and word.lower() not in STOPWORDS
        if entity_like:
            if run and m.start() - last_end > 1:
                flush()
            run.append(word)
            last_end = m.end()
        else:
            flush()
    flush()

    if not terms and not identifiers:  # lower-case question: fall back to content words
        words = [w for w in re.findall(r"[a-z0-9][a-z0-9\-]{3,}", question.lower()) if w not in STOPWORDS]
        terms = words[-3:]
    return list(dict.fromkeys(t for t in terms if len(t) > 1))[:8]


