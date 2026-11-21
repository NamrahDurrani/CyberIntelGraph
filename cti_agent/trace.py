"""Save each investigation as a JSON file (question, evidence, answer, warnings).
These records are the raw material for the Milestone 17 evaluation."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_trace(final: dict[str, Any], directory: Path) -> Path | None:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^a-z0-9]+", "-", final.get("question", "question").lower()).strip("-")[:50] or "question"
        path = directory / f"{stamp}-{slug}.json"
        path.write_text(json.dumps(final, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return path
    except OSError:
        return None
