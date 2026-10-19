"""RogueShield command line, offline by default."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from rogueshield import __version__
from rogueshield.offline import inspect_python, inspect_openapi, inspect_invariants
from rogueshield.safety import CONSENT_PHRASE, ENVIRONMENTS, LEVELS, choose_profile, simulate_swarm

LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RogueShield offline defensive checks")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("static", "openapi", "invariants"):
        p = sub.add_parser(name)
        p.add_argument("input")
        p.add_argument("--out", help="Write JSON report")
        p.add_argument("--fail-on", choices=tuple(LEVEL), default="high")
    setup = sub.add_parser("setup", help="Select safe test level/environment and acknowledge authorization")
    setup.add_argument("--level", choices=LEVELS, help="Offline testing profile")
    setup.add_argument("--environment", choices=ENVIRONMENTS, help="Where your system runs")
    setup.add_argument("--out", default="rogueshield.local.json", help="Local profile (never commit)")
    swarm = sub.add_parser("swarm-preview", help="Model agent count offline; generates no traffic")
    swarm.add_argument("--agents", type=int, default=700)
    args = parser.parse_args(argv)
    try:
        if args.command == "setup":
            chosen_level = args.level or input("Choose test level (beginner/standard/advanced/swarm-simulation): ").strip()
            environment = args.environment or input("Environment (local/isolated-staging/staging/production): ").strip()
            print("RogueShield is authorized for defensive work only.")
            print("You must own the target or have explicit permission for the methods used.")
            print("The present edition runs OFFLINE checks only. This acknowledgment does not authorize any network test.")
            confirmation = input("Type exactly '" + CONSENT_PHRASE + "' to continue: ").strip()
            profile = choose_profile(chosen_level, environment, confirmation)
            location = Path(args.out)
            if location.is_symlink() or location.exists():
                raise ValueError("Refusing to replace an existing profile or symlink")
            result = {"version": 1, "level": profile.level,
                      "environment": profile.environment,
                      "execution_mode": profile.mode, "max_live_requests": 0,
                      "acknowledged": True,
                      "acknowledgment_text": CONSENT_PHRASE,
                      "note": "This file is not proof of target ownership or network-testing permission"}
            location.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print("Offline profile created:", location)
            print("Next: python -m rogueshield static <source-folder>")
            return 0
        if args.command == "swarm-preview":
            modeled = simulate_swarm(args.agents)
            print(json.dumps(modeled, indent=2, sort_keys=True))
            return 0
        tasks = {"static": inspect_python, "openapi": inspect_openapi, "invariants": inspect_invariants}
        findings = tasks[args.command](args.input)
        report = {"tool": "RogueShield", "version": __version__,
                  "mode": args.command, "findings": findings,
                  "summary": {"count": len(findings)}}
        result = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out:
            target = Path(args.out)
            if target.is_symlink():
                raise ValueError("Refusing to write through a symbolic link")
            target.write_text(result, encoding="utf-8")
        else:
            print(result, end="")
        return 2 if any(LEVEL[f["severity"]] >= LEVEL[args.fail_on] for f in findings) else 0
    except (ValueError, OSError, json.JSONDecodeError, PermissionError, EOFError, KeyboardInterrupt) as exc:
        print(f"RogueShield: input, permission or output error ({type(exc).__name__})", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
