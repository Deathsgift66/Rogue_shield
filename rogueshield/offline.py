"""Offline static, API-schema and synthetic balance consistency checks."""
from __future__ import annotations
import ast
import os
import stat
import io
import tokenize
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
from rogueshield.localio import read_regular

MAX_INPUT = 1_000_000
MAX_SOURCE_FILES = 3000
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_DIRS = 6000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"}


def read_json(path: str) -> dict:
    try:
        value = json.loads(read_regular(path, max_bytes=MAX_INPUT).decode("utf-8"))
    except RecursionError as exc:
        raise ValueError("Excessive JSON nesting") from exc
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def finding(rule: str, severity: str, location: str, reason: str) -> dict:
    return {"rule_id": rule, "severity": severity, "location": location, "message": reason}


def inspect_python(root: str, *, with_count: bool = False) -> list[dict] | tuple[list[dict], int]:
    """Bounded local AST heuristics; do not execute inspected code.

    Files that cannot be fully inspected cause an error, rather than a false
    claim of a clean report. Generated/environment directories are excluded.
    """
    folder = Path(root)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Source folder does not exist or is a symbolic link")
    folder = folder.resolve()
    found: list[dict] = []
    total_bytes = 0
    file_count = 0
    dir_count = 0
    def on_walk_error(exc: OSError) -> None:
        raise ValueError("Source directory could not be completely traversed") from exc

    for current, dirs, files in os.walk(folder, topdown=True, followlinks=False, onerror=on_walk_error):
        dir_count += 1
        if dir_count > MAX_DIRS:
            raise ValueError("Too many directories: analysis incomplete")
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = Path(current) / name
            if path.is_symlink():
                continue
            file_count += 1
            if file_count > MAX_SOURCE_FILES:
                raise ValueError("Too many Python files: analysis incomplete")
            try:
                info = path.stat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > MAX_INPUT or total_bytes + info.st_size > MAX_SOURCE_BYTES:
                    raise ValueError("Source byte budget exceeded: analysis incomplete")
                payload = read_regular(path, max_bytes=MAX_INPUT)
                total_bytes += len(payload)
                encoding, _ = tokenize.detect_encoding(io.BytesIO(payload).readline)
                tree = ast.parse(payload.decode(encoding), filename=str(path))
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                raise ValueError("Unable to analyze every Python file") from exc
            relative = str(path.relative_to(folder))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                target = func.id if isinstance(func, ast.Name) else (
                    func.value.id + "." + func.attr if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else "")
                issue = {
                    "eval": ("PY-EVAL", "high", "Review dynamic evaluation"),
                    "exec": ("PY-EXEC", "high", "Review dynamic code execution"),
                    "os.system": ("PY-SHELL", "high", "Review command invocation"),
                    "pickle.loads": ("PY-PICKLE", "high", "Review untrusted deserialization"),
                }.get(target)
                if issue is not None:
                    rule, severity, message = issue
                    found.append(finding(rule, severity, f"{relative}:{node.lineno}", message))
                if target in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
                    if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                        found.append(finding("PY-SHELL-TRUE", "medium", f"{relative}:{node.lineno}", "Review shell=True usage"))
    return (found, file_count) if with_count else found


def inspect_openapi(path: str) -> list[dict]:
    spec = read_json(path)
    if not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("Expected OpenAPI 3.x JSON")
    found: list[dict] = []
    if not isinstance(spec.get("servers", []), list):
        raise ValueError("Invalid OpenAPI servers")
    for i, server in enumerate(spec.get("servers", [])):
        if not isinstance(server, dict):
            raise ValueError("Invalid OpenAPI server declaration")
        if str(server.get("url", "")).startswith("http://"):
            found.append(finding("API-HTTP", "medium", f"servers[{i}]", "Server URL uses plaintext HTTP"))
    if not isinstance(spec.get("paths", {}), dict):
        raise ValueError("Invalid OpenAPI paths")
    for path_name, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            raise ValueError("Invalid OpenAPI operation map")
        for method, operation in methods.items():
            if not isinstance(method, str):
                raise ValueError("Invalid OpenAPI HTTP method")
            if method.lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(operation, dict):
                continue
            if str(path_name).startswith(("/admin", "/account", "/users", "/private")):
                security = operation.get("security", spec.get("security"))
                if not security:
                    found.append(finding("API-AUTH-DOC", "medium", f"{method.upper()} {path_name}",
                                         "Sensitive operation has no declared security requirement"))
            if operation.get("deprecated") is True and method.lower() != "get":
                found.append(finding("API-OLD-MUTATION", "low", f"{method.upper()} {path_name}",
                                     "Deprecated modifying endpoint remains documented"))
    return found


def inspect_invariants(path: str) -> list[dict]:
    data = read_json(path)
    found: list[dict] = []
    transfers = data.get("transfers", [])
    replays = data.get("replays", [])
    if not isinstance(transfers, list) or not isinstance(replays, list) or len(transfers) > 5000 or len(replays) > 5000:
        raise ValueError("Invalid or over-budget invariant collection")
    for i, transfer in enumerate(transfers):
        try:
            before = [Decimal(str(x)) for x in transfer["before"].values()]
            after = [Decimal(str(x)) for x in transfer["after"].values()]
            external = Decimal(str(transfer.get("expected_external_delta", "0")))
            if not all(x.is_finite() for x in before + after + [external]):
                raise ValueError("Nonfinite amount")
        except (KeyError, AttributeError, InvalidOperation, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid synthetic transfer fixture #{i}") from exc
        if sum(after) - sum(before) != external:
            found.append(finding("INV-CONSERVATION", "high", f"transfers[{i}]",
                                 "Observed totals differ from expected external change"))
        if transfer.get("nonnegative", True) and any(x < 0 for x in after):
            found.append(finding("INV-NEGATIVE", "high", f"transfers[{i}]", "Result contains a negative balance"))
    for i, replay in enumerate(replays):
        if not isinstance(replay, dict) or "state_after_first" not in replay or "state_after_repeat" not in replay:
            raise ValueError("Invalid replay fixture")
        if replay.get("state_after_first") != replay.get("state_after_repeat"):
            found.append(finding("INV-REPLAY", "high", f"replays[{i}]",
                                 "Repeated operation differs from first result"))
    return found
