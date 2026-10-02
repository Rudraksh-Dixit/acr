"""ACR command-line interface.

Commands:
    python -m acr generate [--scenario ID ...] [--seed N] [--no-reconstruct]
    python -m acr ingest <file> [--source S] [--scenario ID] [--reconstruct]
    python -m acr reconstruct [--scenario ID]
    python -m acr evaluate [--scenario ID ...] [--seed N] [--out file.json]
    python -m acr export <scenario_id> [--format json|csv] [--out FILE] [--seed N]
    python -m acr openapi [--out docs/openapi.json]
    python -m acr status
    python -m acr serve [--host H] [--port P]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Optional

from app.core.database import init_db, session_scope


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str))


def cmd_generate(args: argparse.Namespace) -> int:
    from app.scenarios import generate_scenario, scenario_catalog
    from app.services.chain_service import reconstruct
    from app.services.event_service import ingest_records, run_detection_pass_
    from app.api.scenarios import _remove_scenario_events
    from app.services.chain_service import _clear_chains

    known = {s["scenario_id"] for s in scenario_catalog()}
    ids = args.scenario or sorted(known)
    unknown = [i for i in ids if i not in known]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"available: {', '.join(sorted(known))}", file=sys.stderr)
        return 2

    with session_scope() as session:
        _clear_chains(session)
        replaced = _remove_scenario_events(session, ids)
        reports = []
        for scenario_id in ids:
            scenario = generate_scenario(scenario_id, seed=args.seed)
            report = ingest_records(
                session, scenario.events, source="cli", scenario_id=scenario_id,
                run_detection_pass=False,
            )
            reports.append({
                "scenario_id": scenario_id, "is_benign": scenario.is_benign,
                "emitted": len(scenario.events), "stored": report.stored,
                "duplicates": report.duplicates, "skipped": report.skipped,
            })
        detections = run_detection_pass_(session)
        reconstruction = reconstruct(session).to_dict() if not args.no_reconstruct else None
        _print({
            "events_replaced": replaced,
            "scenarios": reports,
            "detections": detections,
            "reconstruction": reconstruction,
        })
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from app.ingestion.csv_loader import load_csv
    from app.ingestion.json_loader import LoaderError, load_json
    from app.services.chain_service import reconstruct
    from app.services.event_service import ingest_records

    path = Path(args.file)
    try:
        records = load_csv(path) if path.suffix.lower() == ".csv" else load_json(path)
    except LoaderError as exc:
        print(f"failed to read {path}: {exc}", file=sys.stderr)
        return 2

    with session_scope() as session:
        report = ingest_records(
            session, records, source=args.source, scenario_id=args.scenario,
            run_detection_pass=True,
        )
        payload = report.to_dict()
        if args.reconstruct:
            payload["reconstruction"] = reconstruct(session, scenario_id=args.scenario).to_dict()
        _print(payload)
    return 0


def cmd_reconstruct(args: argparse.Namespace) -> int:
    from app.services.chain_service import reconstruct

    with session_scope() as session:
        report = reconstruct(session, scenario_id=args.scenario)
        _print(report.to_dict())
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from app.services.evaluation_service import run_evaluation

    with session_scope() as session:
        payload = run_evaluation(
            scenario_ids=args.scenario or None, seed=args.seed,
            session=session, persist=not args.no_persist,
        )
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"wrote {args.out}")
    metrics = payload["metrics"]
    _print({
        "scenarios_evaluated": metrics["scenarios_evaluated"],
        "technique_f1": {k: v["f1"] for k, v in metrics["technique_level"].items()},
        "event_f1": {k: v["f1"] for k, v in metrics["event_level"].items()},
        "attack_f1": {k: v["f1"] for k, v in metrics["attack_detection"].items()},
        "attack_fpr": {k: v["false_positive_rate"] for k, v in metrics["attack_detection"].items()},
        "chain_accuracy": metrics["reconstruction"]["chain_accuracy"],
        "mean_detection_latency_seconds": metrics["detection_latency_seconds"]["mean"],
        "events_per_second": metrics["performance"]["events_per_second"],
        "run_id": payload.get("run_id"),
    })
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from app.scenarios import generate_scenario, scenario_catalog

    known = {s["scenario_id"] for s in scenario_catalog()}
    if args.scenario not in known:
        print(f"unknown scenario: {args.scenario}", file=sys.stderr)
        print(f"available: {', '.join(sorted(known))}", file=sys.stderr)
        return 2

    scenario = generate_scenario(args.scenario, seed=args.seed)
    fmt = args.format
    out = Path(args.out or f"data/raw/{args.scenario}.{fmt}")
    out.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        out.write_text(json.dumps(scenario.events, indent=2, default=str), encoding="utf-8")
    else:
        fieldnames: list[str] = []
        for record in scenario.events:
            for key in record:
                if key not in fieldnames:
                    fieldnames.append(key)
        with out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for record in scenario.events:
                writer.writerow({k: ("" if record.get(k) is None else record.get(k)) for k in fieldnames})

    _print({
        "scenario_id": args.scenario,
        "is_benign": scenario.is_benign,
        "events": len(scenario.events),
        "format": fmt,
        "written": str(out),
    })
    return 0


def cmd_openapi(args: argparse.Namespace) -> int:
    from app.main import app

    spec = app.openapi()
    out = Path(args.out or "docs/openapi.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(spec, indent=2), encoding="utf-8")
    _print({
        "written": str(out),
        "openapi": spec.get("openapi"),
        "paths": len(spec.get("paths", {})),
        "operations": sum(len(v) for v in spec.get("paths", {}).values()),
        "schemas": len(spec.get("components", {}).get("schemas", {})),
    })
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from sqlalchemy import func, select

    from app.models import AttackChain, Detection, Entity, Event, EvaluationRun

    with session_scope() as session:
        def count(model: Any) -> int:
            return int(session.scalar(select(func.count()).select_from(model)) or 0)

        _print({
            "events": count(Event),
            "detections": count(Detection),
            "chains": count(AttackChain),
            "attack_chains": int(session.scalar(
                select(func.count()).select_from(AttackChain).where(AttackChain.is_attack.is_(True))
            ) or 0),
            "entities": count(Entity),
            "evaluation_runs": count(EvaluationRun),
        })
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    init_db()
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acr", description="Attack Chain Reconstruction Engine")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate", help="generate synthetic scenarios, ingest and reconstruct")
    p.add_argument("--scenario", action="append", help="scenario id (repeatable; default: all)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-reconstruct", action="store_true")
    p.set_defaults(fn=cmd_generate)

    p = sub.add_parser("ingest", help="ingest a JSON or CSV telemetry file")
    p.add_argument("file")
    p.add_argument("--source", default="cli")
    p.add_argument("--scenario", default=None)
    p.add_argument("--reconstruct", action="store_true")
    p.set_defaults(fn=cmd_ingest)

    p = sub.add_parser("reconstruct", help="run correlation + chain reconstruction")
    p.add_argument("--scenario", default=None)
    p.set_defaults(fn=cmd_reconstruct)

    p = sub.add_parser("evaluate", help="evaluate pipeline stages against ground truth")
    p.add_argument("--scenario", action="append")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=None, help="write full JSON report to this file")
    p.add_argument("--no-persist", action="store_true", help="skip saving the evaluation run")
    p.set_defaults(fn=cmd_evaluate)

    p = sub.add_parser("export", help="export a scenario's raw telemetry to JSON or CSV (no DB writes)")
    p.add_argument("scenario", help="scenario id (see: python -m acr generate --help / scenario catalog)")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--out", default=None, help="output path (default: data/raw/<scenario>.<fmt>)")
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("openapi", help="export the OpenAPI spec for frontend integration")
    p.add_argument("--out", default="docs/openapi.json")
    p.set_defaults(fn=cmd_openapi)

    p = sub.add_parser("status", help="show store counts")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("serve", help="start the REST API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(fn=cmd_serve)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command not in {"export", "openapi"}:
        init_db()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
