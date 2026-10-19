"""Strict validation of future testing scopes; no network executors in v0.3."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
import re
from urllib.parse import urlsplit

ALLOWED_ENVIRONMENTS = {"local", "isolated-staging", "staging", "production"}
SAFE_METHODS = {"GET", "HEAD"}
SCOPE_FIELDS = {"environment", "operator_acknowledgment", "engagement_id", "targets", "methods", "expires_at", "max_requests"}
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def validate_scope(scope: dict) -> dict:
    """Validate declarations; never treats the manifest as proof of permission."""
    if not isinstance(scope, dict):
        raise ValueError("Scope must be a JSON object")
    if set(scope) - SCOPE_FIELDS:
        raise ValueError("Unsupported scope fields: unknown options must not be silently ignored")
    if scope.get("environment") not in ALLOWED_ENVIRONMENTS:
        raise ValueError("Unknown environment")
    if scope.get("operator_acknowledgment") is not True:
        raise PermissionError("Authorization acknowledgment is required")
    if not isinstance(scope.get("engagement_id"), str) or not 3 <= len(scope["engagement_id"]) <= 100:
        raise ValueError("Engagement identifier required")
    targets = scope.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 10:
        raise ValueError("List one to ten explicit targets")
    for item in targets:
        if not isinstance(item, str) or len(item) > 255 or not item.isascii() or any(ch.isspace() or ord(ch) < 33 or ord(ch) == 127 for ch in item):
            raise ValueError("Invalid target")
        parsed = urlsplit(item)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("Only explicit HTTP(S) origins are accepted")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Credentials, queries and fragments forbidden in targets")
        if parsed.path not in ("", "/") or not parsed.hostname:
            raise ValueError("Targets must be exact origins, not paths")
        hostname = parsed.hostname.lower()
        if parsed.scheme != "https" and not (parsed.scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("Only HTTPS targets or explicit local HTTP are supported")
        if not HOST_PATTERN.fullmatch(hostname) and hostname != "::1":
            raise ValueError("Invalid host")
        if hostname != "::1" and any(not label or label.startswith("-") or label.endswith("-") or len(label) > 63 for label in hostname.split(".")):
            raise ValueError("Invalid host labels")
        try:
            ip = ip_address(hostname)
        except ValueError:
            ip = None
        if ip is not None and (ip.is_link_local or ip.is_multicast or ip.is_unspecified):
            raise ValueError("Forbidden target address")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid port") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid port")
    if scope.get("methods", ["GET"]) not in (["GET"], ["GET", "HEAD"], ["HEAD"]):
        raise ValueError("Only explicitly supported read methods may be declared")
    if "expires_at" not in scope:
        raise ValueError("Scope expiry is required")
    try:
        expiry = datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid expiry time") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("Scope is expired or lacks a timezone")
    if type(scope.get("max_requests", 0)) is not int or scope.get("max_requests", 0) != 0:
        raise ValueError("v0.3 does not support live network testing")
    digest = sha256(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"scope_sha256": digest, "environment": scope["environment"],
            "declared_targets": len(targets), "validated_offline_only": True,
            "warning": "This is not verification of target ownership or authorization"}
