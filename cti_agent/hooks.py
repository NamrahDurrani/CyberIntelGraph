"""Extension points. Later milestones plug extra steps into the workflow
WITHOUT editing this milestone's files.

Three hook points exist:
  pre_assess     - runs after the specialist agents have been collected, before assessment
                   (Milestone 14: live CISA KEV / NVD fallback)
  post_generate  - runs after the answer and citation check
                   (Milestone 14: independent verification agent)
  post_finalize  - runs after the final record exists and was saved to a file
                   (Milestone 14: MongoDB persistence)

A hook module exposes get_hooks() returning
  {"pre_assess": [...], "post_generate": [...], "post_finalize": [...]}  (each a list of (name, factory))
where factory(deps) returns a node function fn(state) -> partial state update.
"""

from __future__ import annotations

import importlib
from typing import Callable

HOOK_POINTS = ("pre_assess", "post_generate", "post_finalize")
HOOK_MODULES = ("cti_verification.hooks",)

NodeFactory = Callable[..., Callable[[dict], dict]]


def load_hooks(modules: tuple[str, ...] = HOOK_MODULES) -> dict[str, list[tuple[str, NodeFactory]]]:
    hooks: dict[str, list[tuple[str, NodeFactory]]] = {p: [] for p in HOOK_POINTS}
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            # Only "this hook module is not installed yet" is fine; a missing
            # dependency INSIDE the module must still be reported.
            if exc.name and module_name.startswith(exc.name):
                continue
            raise
        provided = module.get_hooks()
        for point in HOOK_POINTS:
            hooks[point].extend(provided.get(point, []))
    return hooks
