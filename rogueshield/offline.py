"""Deterministic offline checks for application security reviews."""
from __future__ import annotations

import ast
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path

MAX_INPUT = 1_000_000
MAX_SOURCE_FILES = 3000

def read_json(path: str) -> dict:
    file = Path(path)
    if not file.is_file() or file.is_symlink() or file.stat().st_size > MAX_INPUT:
        raise ValueError("Input must be an ordinary JSON file of at most 1MB")
    value = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value

def finding(rule: str, severity: str, location: str, reason: str) -> dict:
    return {"rule_id": rule, "severity": severity, "location": location, "message": reason}

def inspect_python(root: str) -> list[dict]:
    """AST-based indicators, not confirmations of exploitable vulnerabilities."""
    folder = Path(root).resolve()
    if not folder.exists() or not folder.is_dir():
        raise ValueError("Source folder does not exist")
    found: list[dict] = []
    files = sorted(p for p in folder.rglob("*.py") if p.is_file() and not p.is_symlink())
    if len(files) > MAX_SOURCE_FILES:
        raise ValueError("Too many files")
    for path in files:
        if path.stat().st_size > MAX_INPUT:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        relative = str(path.relative_to(folder))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            target = f.id if isinstance(f, ast.Name) else (
                f.value.id + "." + f.attr if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
            )
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
    return found

def inspect_openapi(path: str) -> list[dict]:
    spec = read_json(path)
    if not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("Expected OpenAPI 3.x JSON")
    found: list[dict] = []
    for i, server in enumerate(spec.get("servers", [])):
        if isinstance(server, dict) and str(server.get("url", "")).startswith("http://"):
            found.append(finding("API-HTTP", "medium", f"servers[{i}]", "Server URL uses plaintext HTTP"))
    for path_name, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
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
    for i, transfer in enumerate(data.get("transfers", [])):
        try:
            before = [Decimal(str(x)) for x in transfer["before"].values()]
            after = [Decimal(str(x)) for x in transfer["after"].values()]
            external = Decimal(str(transfer.get("expected_external_delta", "0")))
            if not all(x.is_finite() for x in before + after + [external]):
                raise ValueError("Nonfinite amount")
        except (KeyError, AttributeError, InvalidOperation, ValueError) as exc:
            raise ValueError(f"Invalid synthetic transfer fixture #{i}") from exc
        if sum(after) - sum(before) != external:
            found.append(finding("INV-CONSERVATION", "high", f"transfers[{i}]",
                                 "Observed totals differ from expected external change"))
        if transfer.get("nonnegative", True) and any(x < 0 for x in after):
            found.append(finding("INV-NEGATIVE", "high", f"transfers[{i}]",
                                 "Result contains a negative balance"))
    for i, replay in enumerate(data.get("replays", [])):
        if replay.get("state_after_first") != replay.get("state_after_repeat"):
            found.append(finding("INV-REPLAY", "high", f"replays[{i}]",
                                 "Repeated operation differs from first result"))
    return found
