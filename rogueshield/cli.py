"""RogueShield v0.5 beginner-friendly, offline-only command line."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from rogueshield import __version__
from rogueshield.authz import inspect_authz
from rogueshield.baseline import compare_files, regression_at_or_above, text_comparison, write_comparison
from rogueshield.manifest import validate_scope
from rogueshield.localio import create_private
from rogueshield.offline import inspect_python, inspect_openapi, inspect_invariants, read_json
from rogueshield.reporting import assemble, html_report, sarif_report, text_report, write_report, _terminal_safe
from rogueshield.review import inspect
from rogueshield.safety import CONSENT_PHRASE, ENVIRONMENTS, LEVELS, choose_profile
from rogueshield.swarm import SwarmConfig, simulate

LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", help="Local report path")
    parser.add_argument("--format", choices=("text", "json", "html", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=tuple(LEVEL), default="high")


def _print_help() -> None:
    print("""RogueShield v0.5 — BEGIN HERE

  1. First time?  python -m rogueshield setup
  2. Review code: python -m rogueshield review ./your-project
  3. Save an understandable report:
                 python -m rogueshield review ./your-project --format html --out review.html
  4. Model 700 virtual actors safely:
                 python -m rogueshield swarm-preview --agents 700

The software does not contact websites, create live agents or modify tested services.
Review indicators require manual verification; no finding is proof that your system is secure.
""")


def _report(mode: str, findings: list[dict], fmt: str, output: str | None, threshold: str,
            *, preassembled: dict | None = None) -> int:
    report = preassembled if preassembled is not None else assemble(mode, findings)
    if output:
        write_report(report, output, fmt)
        print(f"Saved {fmt} report: {_terminal_safe(output)}")
    elif fmt in ("json", "sarif"):
        document = sarif_report(report) if fmt == "sarif" else report
        print(json.dumps(document, sort_keys=True, indent=2))
    elif fmt == "html":
        print(html_report(report))
    else:
        print(text_report(report), end="")
    return 2 if any(LEVEL.get(f.get("severity"), 0) >= LEVEL[threshold] for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RogueShield: accessible offline defensive assessment")
    parser.add_argument("--version", action="version", version=__version__)
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("static", "openapi", "invariants", "authz", "review"):
        p = subs.add_parser(name, help="Analyze local files; never contacts a target")
        p.add_argument("input")
        _add_output_options(p)
    comparison = subs.add_parser("compare", help="Compare two offline RogueShield JSON reports")
    comparison.add_argument("current", help="Current RogueShield JSON report")
    comparison.add_argument("baseline", help="Previously saved RogueShield JSON report")
    comparison.add_argument("--format", choices=("text", "json"), default="text")
    comparison.add_argument("--out", help="Private, new local output file")
    comparison.add_argument("--fail-on", choices=tuple(LEVEL), default="high")
    subs.add_parser("guide", help="Explain simple first steps")
    setup = subs.add_parser("setup", help="Choose testing level, environment and authorization")
    setup.add_argument("--level", choices=LEVELS)
    setup.add_argument("--environment", choices=ENVIRONMENTS)
    setup.add_argument("--out", default="rogueshield.local.json")
    swarm = subs.add_parser("swarm-preview", help="Run a synthetic quota-defense model offline")
    swarm.add_argument("--agents", type=int, default=700)
    swarm.add_argument("--rounds", type=int, default=10)
    swarm.add_argument("--actions-per-agent", type=int, default=4)
    swarm.add_argument("--identity-limit", type=int, default=2)
    swarm.add_argument("--origin-limit", type=int, default=30)
    swarm.add_argument("--global-limit", type=int, default=100)
    swarm.add_argument("--origin-groups", type=int, default=35)
    swarm.add_argument("--out")
    scope = subs.add_parser("scope-check", help="Validate a future engagement declaration offline")
    scope.add_argument("input")
    args = parser.parse_args(argv)
    try:
        if args.command == "guide":
            _print_help()
            return 0
        if args.command == "setup":
            lvl = args.level or input("Testing level (beginner/standard/advanced/swarm-simulation): ").strip()
            env = args.environment or input("Environment (local/isolated-staging/staging/production): ").strip()
            print("Only assess systems you own or have permission to test.")
            print("All v0.5 profiles are OFFLINE only, including production and swarm simulation.")
            accepted = input("Type exactly '" + CONSENT_PHRASE + "': ").strip()
            profile = choose_profile(lvl, env, accepted)
            output = Path(args.out)
            if output.exists() or output.is_symlink() or not output.parent.is_dir():
                raise ValueError("Profile file already exists or destination is invalid")
            create_private(output, json.dumps({"schema_version": 1, "level": profile.level,
                                          "environment": profile.environment,
                                          "execution_mode": "offline", "max_live_requests": 0,
                                          "authorization_acknowledged": True,
                                          "note": "Self-attestation is not independent proof of permission"}, indent=2) + "\n")
            print(f"Offline profile saved: {_terminal_safe(output)}")
            return 0
        if args.command == "swarm-preview":
            result = simulate(SwarmConfig(agents=args.agents, rounds=args.rounds,
                                          actions_per_agent=args.actions_per_agent,
                                          identity_limit=args.identity_limit,
                                          origin_limit=args.origin_limit,
                                          global_limit=args.global_limit,
                                          origin_groups=args.origin_groups))
            if args.out:
                output = Path(args.out)
                if output.is_symlink() or not output.parent.is_dir():
                    raise ValueError("Invalid output destination")
                create_private(output, json.dumps(result, indent=2, sort_keys=True) + "\n")
                print(f"Saved synthetic swarm model: {_terminal_safe(output)}")
            else:
                print("ROGUESHIELD • VIRTUAL SWARM MODEL (NO NETWORK TRAFFIC)")
                print(f"Virtual agents: {result['config']['agents']:,}")
                print(f"Simulated decisions: {result['modeled_attempts']:,}")
                print(f"Allowed by modeled quotas: {result['modeled_allowed']:,}")
                print(f"Blocked by modeled quotas: {result['modeled_blocked']:,}")
                print("No real load, defense testing or attack occurred. This model cannot establish real capacity.")
            return 0
        if args.command == "scope-check":
            print(json.dumps(validate_scope(read_json(args.input)), indent=2, sort_keys=True))
            return 0
        if args.command == "compare":
            result = compare_files(args.current, args.baseline)
            if args.out:
                write_comparison(result, args.out, args.format)
                print(f"Saved {args.format} comparison: {_terminal_safe(args.out)}")
            elif args.format == "json":
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                print(text_comparison(result), end="")
            return 2 if regression_at_or_above(result, args.fail_on) else 0
        if args.command == "review":
            report = inspect(args.input)
            findings = report["findings"]
            # Reuse presentation without falsely counting multiple heuristics as verified defects.
            return _report("guided-offline-review", findings, args.format, args.out, args.fail_on, preassembled=report)
        tasks = {"static": inspect_python, "openapi": inspect_openapi, "invariants": inspect_invariants, "authz": inspect_authz}
        return _report(args.command, tasks[args.command](args.input), args.format, args.out, args.fail_on)
    except (ValueError, OSError, PermissionError, EOFError, KeyboardInterrupt, json.JSONDecodeError) as exc:
        print(f"RogueShield could not complete this operation ({type(exc).__name__}). "
              "Check local paths, format, and explicit permission.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
