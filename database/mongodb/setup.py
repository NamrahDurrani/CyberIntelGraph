"""Create / update the collections, validators and indexes. Idempotent: running it twice changes nothing.

`plan()` only READS. `apply()` creates missing collections, refreshes validators and creates missing indexes.
It never drops anything and never touches documents.
"""
from __future__ import annotations

from typing import Any

from pymongo import IndexModel
from pymongo.errors import PyMongoError

from database.mongodb.client import MongoUnavailable
from database.mongodb.schema import COLLECTIONS

VALIDATION = {"validationLevel": "strict", "validationAction": "error"}


def _wrap(e: Exception) -> MongoUnavailable:
    return MongoUnavailable(f"{type(e).__name__}: {str(e)[:300]}")


async def plan(db) -> list[dict[str, Any]]:
    """What exists now vs. what the schema wants. Read-only."""
    try:
        existing = set(await db.list_collection_names())
        out = []
        for name, spec in COLLECTIONS.items():
            row: dict[str, Any] = {"collection": name, "exists": name in existing,
                                   "missing_indexes": [i[0] for i in spec["indexes"]], "validator_current": False}
            if name in existing:
                have = await db[name].index_information()
                row["missing_indexes"] = [i[0] for i in spec["indexes"] if i[0] not in have]
                info = await (await db.list_collections(filter={"name": name})).to_list()
                opts = (info[0].get("options") if info else {}) or {}
                row["validator_current"] = opts.get("validator") == spec["validator"] and opts.get("validationAction") == "error"
            out.append(row)
        return out
    except PyMongoError as e:
        raise _wrap(e) from None


async def apply(db) -> list[str]:
    log: list[str] = []
    try:
        for row in await plan(db):
            name, spec = row["collection"], COLLECTIONS[row["collection"]]
            if not row["exists"]:
                await db.create_collection(name, validator=spec["validator"], **VALIDATION)
                log.append(f"created collection {name}")
            elif not row["validator_current"]:
                await db.command("collMod", name, validator=spec["validator"], **VALIDATION)
                log.append(f"updated validator on {name}")
            todo = [i for i in spec["indexes"] if i[0] in row["missing_indexes"]]
            if todo:
                await db[name].create_indexes([IndexModel(keys, name=iname, **opts) for iname, keys, opts in todo])
                log.append(f"created indexes on {name}: {[i[0] for i in todo]}")
        return log
    except PyMongoError as e:
        raise _wrap(e) from None


async def validator_rejects_bad_document(db) -> bool:
    """True if the server refuses a deliberately invalid `users` document. A document that is wrongly
    ACCEPTED is deleted again (only that one _id) and False is returned."""
    from pymongo.errors import WriteError
    probe = {"_id": "schema_probe_do_not_keep", "username": "", "role": "not-a-role"}
    try:
        await db["users"].insert_one(probe)
    except WriteError as e:
        return e.code == 121                      # 121 = DocumentValidationFailure
    except PyMongoError as e:
        raise _wrap(e) from None
    await db["users"].delete_one({"_id": probe["_id"]})
    return False
