"""No-network project inventory and orchestration of existing local checks."""
from __future__ import annotations

from pathlib import Path
from rogueshield.offline import MAX_INPUT, inspect_python, inspect_openapi, inspect_invariants, read_json
from rogueshield.reporting import assemble


def inspect(target: str) -> dict:
    p = Path(target)
    if p.is_symlink() or not p.exists():
        raise ValueError("Input unavailable or is a symbolic link")
    findings: list[dict] = []
    kinds: list[str] = []
    if p.is_dir():
        # Do not report a clean analysis of an unsupported/empty directory.
        py_findings, py_count = inspect_python(str(p), with_count=True)
        if py_count:
            findings.extend(py_findings)
            kinds.append("python-source")
        for name in ("openapi.json", "swagger.json"):
            spec = p / name
            if spec.is_file() and not spec.is_symlink():
                findings.extend(inspect_openapi(str(spec)))
                kinds.append("openapi")
        fixtures = p / "rogueshield-fixtures.json"
        if fixtures.is_file() and not fixtures.is_symlink():
            findings.extend(inspect_invariants(str(fixtures)))
            kinds.append("synthetic-invariants")
    elif p.is_file() and p.suffix.lower() == ".json" and p.stat().st_size <= MAX_INPUT:
        data = read_json(str(p))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        if "openapi" in data:
            findings.extend(inspect_openapi(str(p)))
            kinds.append("openapi")
        elif "transfers" in data or "replays" in data:
            findings.extend(inspect_invariants(str(p)))
            kinds.append("synthetic-invariants")
        else:
            raise ValueError("Unknown JSON format; provide OpenAPI 3 or synthetic invariants")
    else:
        raise ValueError("Provide a source directory or supported JSON file")
    if not kinds:
        raise ValueError("No supported source, API schema or synthetic fixtures found")
    report = assemble("guided-offline-review", findings, checks=len(kinds))
    report["checks_performed"] = kinds
    return report
