"""RogueShield command line: offline, deterministic analysis by default."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from rogueshield import __version__
from rogueshield.offline import inspect_python, inspect_openapi, inspect_invariants

LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RogueShield offline defensive checks")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("static", "openapi", "invariants"):
        p = sub.add_parser(name)
        p.add_argument("input")
        p.add_argument("--out", help="Write a JSON report to this location")
        p.add_argument("--fail-on", choices=tuple(LEVEL), default="high")
    args = parser.parse_args(argv)
    try:
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
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Avoid printing exception details: file paths and input values may be sensitive.
        print(f"RogueShield: input or output error ({type(exc).__name__})", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
