"""Milestone 12, stage 3: create the eight collections, validators and indexes in MongoDB.

    python scripts/setup_mongodb_collections.py            # dry run: only shows what WOULD change
    python scripts/setup_mongodb_collections.py --apply    # create / update, then verify
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database.mongodb import setup                                           # noqa: E402
from database.mongodb.client import MongoClientFactory, MongoUnavailable   # noqa: E402
from database.mongodb.schema import COLLECTIONS                            # noqa: E402
from database.mongodb.settings import MongoConfigError, MongoSettings       # noqa: E402


async def run(apply: bool) -> int:
    try:
        settings = MongoSettings.from_env()
    except MongoConfigError as e:
        print(f"CONFIG ERROR: {e}")
        return 1
    print(f"connecting: {settings.redacted()}  database: {settings.database}")
    try:
        async with MongoClientFactory(settings) as m:
            rows = await setup.plan(m.db)
            for r in rows:
                state = "exists" if r["exists"] else "MISSING"
                print(f"  {r['collection']:<18} {state:<8} validator {'ok' if r['validator_current'] else 'to set':<7} "
                      f"indexes to create: {r['missing_indexes'] or '-'}")
            if not apply:
                print("DRY RUN: nothing changed. Add --apply to create / update.")
                return 0
            for line in await setup.apply(m.db):
                print(f"  applied: {line}")
            after = await setup.plan(m.db)
            ok = all(r["exists"] and r["validator_current"] and not r["missing_indexes"] for r in after)
            print(f"  [{'PASS' if ok else 'FAIL'}] all {len(COLLECTIONS)} collections exist with current validators and indexes")
            rejected = await setup.validator_rejects_bad_document(m.db)
            print(f"  [{'PASS' if rejected else 'FAIL'}] the server rejects an invalid document (validator is enforced)")
            print("RESULT:", "OK" if ok and rejected else "FAILED")
            return 0 if ok and rejected else 1
    except MongoUnavailable as e:
        print(f"  [FAIL] {e}")
        return 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    sys.exit(asyncio.run(run(ap.parse_args().apply)))
