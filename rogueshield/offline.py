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


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous JSON objects rather than silently taking the last key."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(token: str) -> None:
    raise ValueError("Non-standard JSON numeric constant is not permitted")


def read_json(path: str) -> dict:
    try:
        value = json.loads(
            read_regular(path, max_bytes=MAX_INPUT).decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_nonstandard_json_constant,
        )
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


SENSITIVE_API_SEGMENTS = frozenset({
    "admin", "staff", "moderation", "account", "accounts", "users",
    "private", "billing", "payments", "wallet", "inventory",
})


def _declares_required_auth(value: object) -> bool:
    """OpenAPI alternatives: an empty requirement object permits anonymous use.

    Operation-level security overrides root security, even when it is [].
    All alternatives must require at least one named scheme to require auth.
    """
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("OpenAPI security must be a bounded list")
    for requirement in value:
        if not isinstance(requirement, dict):
            raise ValueError("OpenAPI security requirements must be objects")
        for scheme, scopes in requirement.items():
            if not isinstance(scheme, str) or not scheme or not isinstance(scopes, list):
                raise ValueError("Invalid OpenAPI security scheme or scope list")
            if any(not isinstance(scope, str) for scope in scopes):
                raise ValueError("Invalid OpenAPI security scope")
    return bool(value) and all(bool(requirement) for requirement in value)


def inspect_openapi(path: str) -> list[dict]:
    spec = read_json(path)
    if not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("Expected OpenAPI 3.x JSON")
    found: list[dict] = []
    global_auth_required = _declares_required_auth(spec.get("security", []))
    servers = spec.get("servers", [])
    if not isinstance(servers, list):
        raise ValueError("Invalid OpenAPI servers")
    for i, server in enumerate(servers):
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise ValueError("Invalid OpenAPI server declaration")
        if server["url"].startswith("http://"):
            found.append(finding("API-HTTP", "medium", f"servers[{i}]", "Server URL uses plaintext HTTP"))
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("Invalid OpenAPI paths")
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    for path_name, methods in paths.items():
        if not isinstance(methods, dict) or not isinstance(path_name, str):
            raise ValueError("Invalid OpenAPI operation map")
        segments = {segment.lower() for segment in path_name.split("/") if segment}
        sensitive = bool(segments & SENSITIVE_API_SEGMENTS)
        for method, operation in methods.items():
            if not isinstance(method, str):
                raise ValueError("Invalid OpenAPI HTTP method")
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                raise ValueError("Invalid OpenAPI operation")
            operation_auth_required = (
                _declares_required_auth(operation["security"])
                if "security" in operation else global_auth_required
            )
            if sensitive and not operation_auth_required:
                found.append(finding("API-AUTH-DOC", "medium", f"{method.upper()} {path_name}",
                                     "Sensitive operation permits anonymous access in its OpenAPI security declaration"))
            if operation.get("deprecated") is True and method.lower() not in {"get", "head", "options"}:
                found.append(finding("API-OLD-MUTATION", "low", f"{method.upper()} {path_name}",
                                     "Deprecated modifying endpoint remains documented"))
    return found


def _fixture_decimal(value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("Synthetic asset amount must be numeric")
    try:
        amount = Decimal(str(value))
        if not amount.is_finite() or amount.adjusted() > 100 or amount.as_tuple().exponent < -100:
            raise ValueError("Synthetic asset amount exceeds numeric bounds")
        return amount
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Invalid synthetic asset amount") from exc


def _asset_balances(value: object) -> list[Decimal]:
    if not isinstance(value, dict) or len(value) > 5000:
        raise ValueError("Asset balances must be a bounded account map")
    if any(not isinstance(account, str) or not account or len(account) > 100 for account in value):
        raise ValueError("Invalid synthetic account identifier")
    return [_fixture_decimal(amount) for amount in value.values()]

def inspect_invariants(path: str) -> list[dict]:
    data = read_json(path)
    found: list[dict] = []
    transfers = data.get("transfers", [])
    replays = data.get("replays", [])
    asset_transfers = data.get("asset_transfers", [])
    if (not isinstance(transfers, list) or not isinstance(replays, list)
            or not isinstance(asset_transfers, list)
            or any(len(items) > 5000 for items in (transfers, replays, asset_transfers))):
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
    for i, transfer in enumerate(asset_transfers):
        if not isinstance(transfer, dict) or set(transfer) - {
            "before", "after", "expected_external_delta", "nonnegative"
        }:
            raise ValueError("Invalid synthetic asset transfer")
        before = transfer.get("before")
        after = transfer.get("after")
        external = transfer.get("expected_external_delta", {})
        if not all(isinstance(value, dict) for value in (before, after, external)):
            raise ValueError("Asset transfer states and external deltas must be objects")
        if not isinstance(transfer.get("nonnegative", True), bool):
            raise ValueError("Asset nonnegative setting must be boolean")
        assets = set(before) | set(after) | set(external)
        if not 1 <= len(assets) <= 100 or any(
            not isinstance(asset, str) or not asset or len(asset) > 80 for asset in assets
        ):
            raise ValueError("Invalid or over-budget asset identifiers")
        for asset in sorted(assets):
            before_amounts = _asset_balances(before.get(asset, {}))
            after_amounts = _asset_balances(after.get(asset, {}))
            expected_delta = _fixture_decimal(external.get(asset, "0"))
            if sum(after_amounts) - sum(before_amounts) != expected_delta:
                found.append(finding(
                    "INV-ASSET-CONSERVATION", "high", f"asset_transfers[{i}].{asset}",
                    "Asset totals differ from the explicitly expected mint/burn delta",
                ))
            if transfer.get("nonnegative", True) and any(amount < 0 for amount in after_amounts):
                found.append(finding(
                    "INV-ASSET-NEGATIVE", "high", f"asset_transfers[{i}].{asset}",
                    "An account has a negative balance for this asset",
                ))
    return found
