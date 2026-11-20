"""Milestone 12, stage 3: the eight application collections - their shape (validator) and their indexes.

Rules of this design
* MongoDB holds APPLICATION data only. The knowledge graph stays in Neo4j: reports and messages store
  graph ENTITY IDS (e.g. "AttackTechnique:T1059.001") and an evidence class, never a copy of the graph.
* Raw source data stays in files (data/raw). document_metadata only records where it is and its hash.
* Every document has a text `_id` such as "conv_<uuid>" made by the application (stable, easy to reference
  from other collections, and readable in logs), plus UTC `created_at`.
* Evidence classes are the same words as Milestone 11: documented | inferred | candidate.
* `additionalProperties` is left open on purpose, so later milestones can add fields without a migration;
  the validator only guards what must always be true.
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION = 1
CLAIM_CLASSES = ["documented", "inferred", "candidate", "unclassified"]
_STR = {"bsonType": "string"}
_DATE = {"bsonType": "date"}
_ID_REF = {"bsonType": "string", "minLength": 1}
_STR_LIST = {"bsonType": "array", "items": _STR}


def _s(minlen: int = 1) -> dict[str, Any]:
    return {"bsonType": "string", "minLength": minlen}


def _enum(*values: str) -> dict[str, Any]:
    return {"bsonType": "string", "enum": list(values)}


def _schema(required: list[str], props: dict[str, Any]) -> dict[str, Any]:
    base = {"_id": _s(), "created_at": _DATE, "schema_version": {"bsonType": "int", "minimum": 1}}
    return {"$jsonSchema": {"bsonType": "object", "required": ["_id", "created_at", "schema_version", *required],
                            "properties": {**base, **props}}}


_CITATION = {"bsonType": "object", "required": ["entity_id", "claim_class"],
             "properties": {"entity_id": _s(), "claim_class": _enum(*CLAIM_CLASSES), "source_url": _STR}}
_CLAIM = {"bsonType": "object", "required": ["text", "claim_class"],
          "properties": {"text": _s(), "claim_class": _enum(*CLAIM_CLASSES), "entity_ids": _STR_LIST, "evidence_refs": _STR_LIST}}

# name -> {"validator": ..., "indexes": [(name, [(field, 1|-1)...], {options})]}
COLLECTIONS: dict[str, dict[str, Any]] = {
    "users": {
        "validator": _schema(["username", "role"], {
            "username": _s(), "display_name": _STR, "role": _enum("researcher", "admin"), "updated_at": _DATE}),
        "indexes": [("users_username_unique", [("username", 1)], {"unique": True})],
    },
    "conversations": {
        "validator": _schema(["user_id", "title", "status", "updated_at"], {
            "user_id": _ID_REF, "title": _s(), "status": _enum("active", "archived"),
            "updated_at": _DATE, "last_message_at": _DATE}),
        "indexes": [("conversations_user_recent", [("user_id", 1), ("updated_at", -1)], {})],
    },
    "messages": {
        "validator": _schema(["conversation_id", "seq", "role", "content"], {
            "conversation_id": _ID_REF, "seq": {"bsonType": ["int", "long"], "minimum": 1},
            "role": _enum("user", "assistant", "system", "tool"), "content": _STR,
            "citations": {"bsonType": "array", "items": _CITATION}, "trace_id": _STR}),
        "indexes": [("messages_conversation_order_unique", [("conversation_id", 1), ("seq", 1)], {"unique": True})],
    },
    "research_jobs": {
        "validator": _schema(["user_id", "question", "status"], {
            "user_id": _ID_REF, "conversation_id": _ID_REF, "question": _s(),
            "status": _enum("queued", "running", "succeeded", "failed", "cancelled"),
            "started_at": _DATE, "finished_at": _DATE, "report_id": _ID_REF,
            "error": {"bsonType": "string", "maxLength": 2000}}),
        "indexes": [("research_jobs_status_recent", [("status", 1), ("created_at", -1)], {}),
                    ("research_jobs_user_recent", [("user_id", 1), ("created_at", -1)], {})],
    },
    "reports": {
        "validator": _schema(["job_id", "user_id", "title", "body_markdown", "version"], {
            "job_id": _ID_REF, "user_id": _ID_REF, "conversation_id": _ID_REF, "title": _s(),
            "body_markdown": _s(), "version": {"bsonType": "int", "minimum": 1},
            "claims": {"bsonType": "array", "items": _CLAIM}, "graph_entity_ids": _STR_LIST}),
        "indexes": [("reports_job_version_unique", [("job_id", 1), ("version", 1)], {"unique": True}),
                    ("reports_user_recent", [("user_id", 1), ("created_at", -1)], {})],
    },
    "document_metadata": {
        "validator": _schema(["source", "source_uri", "content_hash"], {
            "source": _enum("cisa_kev", "nvd", "mitre_attack", "cwe", "advisory", "other"),
            "source_uri": _s(), "content_hash": {"bsonType": "string", "pattern": "^[0-9a-f]{64}$"},
            "title": _STR, "fetched_at": _DATE, "record_count": {"bsonType": ["int", "long"], "minimum": 0},
            "raw_path": _STR}),
        "indexes": [("document_metadata_source_hash_unique", [("source", 1), ("content_hash", 1)], {"unique": True})],
    },
    "feedback": {
        "validator": _schema(["user_id", "rating"], {
            "user_id": _ID_REF, "message_id": _ID_REF, "report_id": _ID_REF,
            "rating": _enum("up", "down"), "comment": {"bsonType": "string", "maxLength": 4000}}),
        "indexes": [("feedback_message", [("message_id", 1)], {"sparse": True}),
                    ("feedback_report", [("report_id", 1)], {"sparse": True})],
    },
    "agent_traces": {
        "validator": _schema(["job_id", "step", "node", "status"], {
            "job_id": _ID_REF, "conversation_id": _ID_REF, "step": {"bsonType": ["int", "long"], "minimum": 0},
            "node": _s(), "tool": _STR, "status": _enum("ok", "error", "skipped"),
            "input_summary": _STR, "output_summary": _STR, "duration_ms": {"bsonType": ["int", "long", "double"], "minimum": 0}}),
        "indexes": [("agent_traces_job_step", [("job_id", 1), ("step", 1)], {})],
    },
}
