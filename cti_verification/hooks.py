"""Registers the Milestone 14 steps with the Milestone 13 agent (see cti_agent/hooks.py)."""

from __future__ import annotations

from .nodes import make_fresh_node
from .persistence import make_persist_node
from .verify_node import make_verify_node


def get_hooks() -> dict[str, list]:
    return {
        "pre_assess": [("fresh_lookup", make_fresh_node)],
        "post_generate": [("verification_agent", make_verify_node)],
        "post_finalize": [("persist_mongo", make_persist_node)],
    }
