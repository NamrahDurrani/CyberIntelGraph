"""Command line for Milestone 11.   Run from C:\\CyberIntelGraph with the venv active.

  python neo4j_engine\\cli.py schema [--write] [--apply-indexes]
  python neo4j_engine\\cli.py find "apt29" [--type ThreatActor]
  python neo4j_engine\\cli.py entity T1059.001
  python neo4j_engine\\cli.py neighbors T1059.001 [--rel USES]
  python neo4j_engine\\cli.py actor-techniques "APT29" [--json]
  python neo4j_engine\\cli.py path APT29 T1059.001
  python neo4j_engine\\cli.py provenance T1059.001
  python neo4j_engine\\cli.py candidates T1059.001
  python neo4j_engine\\cli.py since 2026-01-01 [--type Vulnerability]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from neo4j_engine.connection.client import Neo4jClient, Neo4jConfigError, Neo4jSettings  # noqa: E402
from neo4j_engine.repositories.graph_repository import (  # noqa: E402
    AmbiguousEntity, CapabilityUnavailable, EntityNotFound, GraphRepository)
from neo4j_engine.schema.indexes import apply_indexes, plan_indexes  # noqa: E402
from neo4j_engine.schema.introspect import introspect  # noqa: E402
from neo4j_engine.schema.mapping import GraphMap  # noqa: E402


def _ent(e: dict) -> str:
    tag = " [CANDIDATE]" if e.get("is_candidate") else ""
    return f"{e.get('id')}  {e.get('name') or ''}  ({', '.join(e.get('types', []))}){tag}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CyberIntelGraph Neo4j retrieval (Milestone 11)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--database", help="override NEO4J_DATABASE (Aura Free databases are normally named 'neo4j')")
    common.add_argument("--json", action="store_true", help="print JSON instead of text")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add = sub.add_parser
    sub.add_parser = lambda *a, **k: _add(*a, parents=[common], **k)  # every subcommand accepts --json / --database
    s = sub.add_parser("schema"); s.add_argument("--write", action="store_true"); s.add_argument("--apply-indexes", action="store_true")
    f = sub.add_parser("find"); f.add_argument("text"); f.add_argument("--type", action="append"); f.add_argument("--no-candidates", action="store_true"); f.add_argument("--limit", type=int, default=10)
    e = sub.add_parser("entity"); e.add_argument("ref")
    n = sub.add_parser("neighbors"); n.add_argument("ref"); n.add_argument("--rel", action="append"); n.add_argument("--candidates", action="store_true"); n.add_argument("--limit", type=int, default=50)
    a = sub.add_parser("actor-techniques"); a.add_argument("actor"); a.add_argument("--no-inferred", action="store_true"); a.add_argument("--no-candidates", action="store_true"); a.add_argument("--limit", type=int, default=500)
    t = sub.add_parser("path"); t.add_argument("a"); t.add_argument("b"); t.add_argument("--hops", type=int, default=4); t.add_argument("--rel", action="append"); t.add_argument("--candidates", action="store_true"); t.add_argument("--all", action="store_true")
    pr = sub.add_parser("provenance"); pr.add_argument("ref")
    c = sub.add_parser("candidates"); c.add_argument("ref"); c.add_argument("--limit", type=int, default=25)
    sn = sub.add_parser("since"); sn.add_argument("date", help="ISO date, e.g. 2026-01-01"); sn.add_argument("--type", action="append"); sn.add_argument("--limit", type=int, default=25)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = Neo4jSettings.from_env()
    except Neo4jConfigError as exc:
        print(f"ERROR: {exc}"); return 2
    if args.database:
        settings = Neo4jSettings(settings.uri, settings.user, settings.password, args.database, settings.ca_bundle)
    print(f"connecting: {settings.describe()}")
    try:
        with Neo4jClient(settings) as client:
            print(f"connected (trusting {client.connected_via})")
            return run(args, client)
    except (EntityNotFound, CapabilityUnavailable) as exc:
        print(f"NOT FOUND / UNAVAILABLE: {exc}"); return 1
    except AmbiguousEntity as exc:
        print(f"AMBIGUOUS: {exc}")
        for m in exc.matches: print("   ", _ent(m))
        return 1
    except Exception as exc:  # connection, auth, database name, timeouts
        print(f"ERROR: {type(exc).__name__}: {exc}")
        if "database" in str(exc).lower() and "not" in str(exc).lower():
            print("hint: set NEO4J_DATABASE=neo4j in .env (or pass --database neo4j)")
        return 3


def run(args, client) -> int:
    if args.cmd == "schema":
        rep = introspect(client)
        gm = GraphMap.from_report(rep)
        print(f"labels: {len(rep['labels'])}  relationship types: {len(rep['rel_types'])}")
        print("Entity properties: " + ", ".join(f"{k}:{'/'.join(v)}" for k, v in rep['properties'].get('Entity', {}).items()))
        print("resolved fields:", json.dumps(gm.to_dict()["node"]))
        print("not found:", gm.unresolved() or "none")
        print("indexes:", [i["name"] for i in rep["indexes"]])
        if args.write:
            out = ROOT / "outputs" / "reports" / f"neo4j_schema_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
            print(f"report: {out.relative_to(ROOT)}")
        if args.apply_indexes:
            for st in apply_indexes(client, gm): print("applied:", st)
        else:
            for st in plan_indexes(gm): print("would apply (add --apply-indexes):", st)
        return 0

    repo = GraphRepository(client, GraphMap.from_report(introspect(client)))
    if args.cmd == "find":
        res = repo.find_entities(args.text, types=args.type, include_candidates=not args.no_candidates, limit=args.limit)
        print(json.dumps(res, indent=2, default=str) if args.json else "\n".join(_ent(r) for r in res) or "no matches")
    elif args.cmd == "entity":
        e = repo.get_entity(repo.resolve_entity(args.ref)["id"])
        print(json.dumps(e, indent=2, default=str) if args.json else _ent(e) + "\n  degree: " + json.dumps(e["degree"]))
    elif args.cmd == "neighbors":
        r = repo.neighbors(repo.resolve_entity(args.ref)["id"], rel_types=args.rel, include_candidates=args.candidates, limit=args.limit)
        if args.json: print(json.dumps(r, indent=2, default=str))
        else:
            for x in r["neighbors"]: print(f"{x['direction']:>3} {x['rel_type']:<16} {_ent(x['other'])}  [{x['evidence_status']}]")
            print(f"{r['count']} shown" + (" (truncated)" if r["truncated"] else ""))
    elif args.cmd == "actor-techniques":
        r = repo.techniques_for_actor(args.actor, include_inferred=not args.no_inferred, include_candidates=not args.no_candidates, limit=args.limit)
        if args.json: print(json.dumps(r, indent=2, default=str))
        else:
            print(f"actor: {_ent(r['actor'])}\ncounts: {r['counts']}")
            for n_ in r["notes"]: print("note:", n_)
            for t_ in r["techniques"]:
                via = "; ".join(sorted({p['derivation'] + (f" via {p['via']['name']}" if p.get('via') else '') for p in t_['paths']}))
                rep = f"  reports: {len(t_.get('reports', []))}" if t_.get("reports") else ""
                print(f"  {t_['claim_class']:<10} {t_['id']}  {t_['name']}  <{via}>{rep}")
    elif args.cmd == "path":
        r = repo.find_path(args.a, args.b, max_hops=args.hops, rel_types=args.rel, include_candidates=args.candidates, all_paths=args.all)
        if args.json: print(json.dumps(r, indent=2, default=str))
        else:
            print(f"{_ent(r['from'])}  ->  {_ent(r['to'])}")
            if not r["found"]: print(f"no path within {r['max_hops']} hops")
            for p_ in r["paths"]:
                chain = p_["nodes"][0]["name"] or p_["nodes"][0]["id"]
                for rel, node in zip(p_["relationships"], p_["nodes"][1:]):
                    chain += f" -[{rel['type']}]- {node.get('name') or node['id']}"
                print(f"{p_['hops']} hop(s): {chain}")
    elif args.cmd == "provenance":
        print(json.dumps(repo.provenance(repo.resolve_entity(args.ref)["id"]), indent=2, default=str))
    elif args.cmd == "candidates":
        print(json.dumps(repo.candidate_evidence(repo.resolve_entity(args.ref)["id"], limit=args.limit), indent=2, default=str))
    elif args.cmd == "since":
        r = repo.changed_since(args.date, types=args.type, limit=args.limit)
        print(f"{len(r['entities'])} entities with {r['date_property']} >= {args.date}")
        for e in r["entities"]: print("  ", _ent(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
