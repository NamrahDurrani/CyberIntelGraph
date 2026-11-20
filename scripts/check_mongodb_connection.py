"""Milestone 12, stage 2: can we reach MongoDB Atlas? READ-ONLY - nothing is created or written.

    python scripts/check_mongodb_connection.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database.mongodb.client import MongoClientFactory, MongoUnavailable   # noqa: E402
from database.mongodb.settings import MongoConfigError, MongoSettings       # noqa: E402


async def run() -> int:
    try:
        settings = MongoSettings.from_env()
    except MongoConfigError as e:
        print(f"CONFIG ERROR: {e}")
        return 1
    print(f"connecting: {settings.redacted()}  database: {settings.database}")
    try:
        async with MongoClientFactory(settings) as m:
            print("  [PASS] ping answered")
            info = await m.db.command("hello")
            print(f"  [PASS] server replied - replica set: {info.get('setName')}, writable primary: {info.get('isWritablePrimary')}")
            names = await m.db.list_collection_names()
            print(f"  [PASS] database '{settings.database}' readable - {len(names)} collection(s): {sorted(names)}")
    except MongoUnavailable as e:
        print(f"  [FAIL] {e}")
        print("  hints: Atlas > Network Access must allow your IP; check the user/password; the URI must be mongodb+srv://...")
        return 1
    print("RESULT: OK (nothing was written)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
