"""Milestone 12 acceptance check: a test conversation and report make a full round trip through MongoDB Atlas.

    python scripts/check_mongodb_roundtrip.py [--keep]

Writes a few clearly labelled test documents (ids contain a random run tag), reads them back, compares them
field by field, then deletes ONLY the documents it created (use --keep to leave them for inspection in Atlas).
"""
import argparse
import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database.mongodb.client import MongoClientFactory, MongoUnavailable   # noqa: E402
from database.mongodb.settings import MongoConfigError, MongoSettings       # noqa: E402
from database.repositories import DocumentRejected, DuplicateRecord, Repositories   # noqa: E402

results: list[tuple[str, str, str]] = []


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append(("PASS" if ok else "FAIL", name, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


async def run(keep: bool) -> int:
    try:
        settings = MongoSettings.from_env()
    except MongoConfigError as e:
        print(f"CONFIG ERROR: {e}")
        return 1
    tag = uuid.uuid4().hex[:8]
    created: list[tuple[object, str]] = []          # (repository, id) to clean up
    print(f"connecting: {settings.redacted()}  database: {settings.database}  run tag: {tag}")
    try:
        async with MongoClientFactory(settings) as m:
            r = Repositories(m.db)
            try:
                user = await r.users.create(f"roundtrip_{tag}", display_name="Round-trip test"); created.append((r.users, user["_id"]))
                conv = await r.conversations.create(user["_id"], f"Round-trip test {tag}"); created.append((r.conversations, conv["_id"]))
                rec("conversation round-trips", await r.conversations.get(conv["_id"]) == conv)
                cites = [{"entity_id": "ThreatActor:G0094", "claim_class": "documented", "source_url": "https://attack.mitre.org/groups/G0094/"},
                         {"entity_id": "AttackTechnique:T1059.001", "claim_class": "inferred"}]
                m1 = await r.messages.append(conv["_id"], "user", "Which techniques does Kimsuky use?"); created.append((r.messages, m1["_id"]))
                m2 = await r.messages.append(conv["_id"], "assistant", "Kimsuky uses ...", citations=cites); created.append((r.messages, m2["_id"]))
                job = await r.jobs.create(user["_id"], "Kimsuky techniques", conv["_id"]); created.append((r.jobs, job["_id"]))
                claims = [{"text": "Kimsuky uses PowerShell", "claim_class": "documented", "entity_ids": ["ThreatActor:G0094", "AttackTechnique:T1059.001"]},
                          {"text": "Possible backup abuse", "claim_class": "candidate"}]
                rep = await r.reports.save(job["_id"], user["_id"], "Kimsuky techniques", "# Report\nBody", claims=claims,
                                           graph_entity_ids=["ThreatActor:G0094"], conversation_id=conv["_id"]); created.append((r.reports, rep["_id"]))

                # ---- round trips: what we wrote must equal what we read back ----------------------------------
                rec("user round-trips", await r.users.get(user["_id"]) == user)
                hist = await r.messages.history(conv["_id"])
                rec("messages come back in order with citations intact", [h["_id"] for h in hist] == [m1["_id"], m2["_id"]] and
                    [h["seq"] for h in hist] == [1, 2] and hist[1]["citations"] == cites)
                back = await r.reports.get(rep["_id"])
                rec("report round-trips exactly (claims, evidence classes, graph ids, timestamps)", back == rep)
                rec("latest_for_job finds the report", (await r.reports.latest_for_job(job["_id"]))["_id"] == rep["_id"])
                rep2 = await r.reports.save(job["_id"], user["_id"], "Kimsuky techniques v2", "# Report\nBody 2"); created.append((r.reports, rep2["_id"]))
                rec("saving again creates version 2 and keeps version 1", rep2["version"] == 2 and (await r.reports.get(rep["_id"])) == rep)
                conv_after = await r.conversations.get(conv["_id"])
                rec("conversation records its last message time", conv_after.get("last_message_at") == m2["created_at"])
                j = await r.jobs.move_to(job["_id"], "running"); j = await r.jobs.move_to(job["_id"], "succeeded", report_id=rep["_id"])
                rec("job lifecycle queued -> running -> succeeded", j["status"] == "succeeded" and "started_at" in j and j["report_id"] == rep["_id"])

                # ---- honesty / safety ---------------------------------------------------------------------------
                rec("an unknown id is None (database answered), not an error", await r.reports.get("rep_does_not_exist") is None)
                try:
                    await r.reports.save(job["_id"], user["_id"], "bad", "x", claims=[{"text": "t", "claim_class": "certain"}]); rec("invalid evidence class is refused", False)
                except DocumentRejected:
                    rec("invalid evidence class is refused", True)
                try:
                    await r.users.insert({"username": "", "role": "root"}); rec("the server validator refuses a bad user", False)
                except DocumentRejected:
                    rec("the server validator refuses a bad user", True)
                try:
                    await r.users.create(f"roundtrip_{tag}"); rec("duplicate username is refused", False)
                except DuplicateRecord:
                    rec("duplicate username is refused", True)
                try:
                    await r.jobs.move_to(job["_id"], "running"); rec("an impossible job transition is refused", False)
                except DocumentRejected:
                    rec("an impossible job transition is refused", True)
            finally:
                if keep:
                    print("  --keep: test documents left in place (ids contain the run tag above)")
                else:
                    for repo, _id in reversed(created):
                        await repo.delete(_id)
                    left = [_id for repo, _id in created if await repo.get(_id) is not None]
                    rec("test documents cleaned up", not left, f"{len(created)} deleted")
    except MongoUnavailable as e:
        print(f"  [FAIL] {e}")
        return 1
    bad = [x for x in results if x[0] == "FAIL"]
    print("RESULT:", "ALL CHECKS PASSED" if not bad else f"{len(bad)} FAILED")
    return 0 if not bad else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--keep", action="store_true")
    sys.exit(asyncio.run(run(ap.parse_args().keep)))
