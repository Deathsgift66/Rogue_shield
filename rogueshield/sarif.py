"""Offline SARIF 2.1.0 export for code review and CI annotation.

SARIF is a machine-readable lead list, not evidence that a defect is
exploitable. No network calls or external packages are used.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from urllib.parse import quote

from rogueshield import __version__

_PY_LOCATION = re.compile(r"(?P<path>.+\.py):(?P<line>[1-9][0-9]*)$")
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def _location(value: str) -> dict:
    location: dict = {"logicalLocations": [{"name": value or "unspecified"}]}
    match = _PY_LOCATION.fullmatch(value)
    if match is None:
        return location
    raw_path = match.group("path").replace("\\", "/")
    parts = PurePosixPath(raw_path).parts
    # Only emit repository-relative source locations. Other findings remain
    # logical locations so an untrusted path cannot escape a CI workspace.
    if raw_path.startswith("/") or re.match(r"^[A-Za-z]:", raw_path) or ".." in parts:
        return location
    location["physicalLocation"] = {
        "artifactLocation": {"uri": quote(raw_path, safe="/._-~")},
        "region": {"startLine": int(match.group("line"))},
    }
    return location


def sarif_report(report: dict) -> dict:
    """Convert RogueShield's normalized report into SARIF 2.1.0."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in report["findings"]:
        rule_id = finding["rule_id"]
        level = _SARIF_LEVEL.get(finding["severity"], "note")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding["title"]},
                "help": {"text": finding["what_to_do"]},
                "defaultConfiguration": {"level": level},
            }
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": finding["message"]},
            "locations": [_location(finding["location"])],
            "properties": {
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "remediation": finding["what_to_do"],
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RogueShield",
                "version": __version__,
                "informationUri": "https://github.com/Deathsgift66/Rogue_shield",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "reviewMode": report["mode"],
                "coverageWarning": report["coverage"]["warning"],
                "verifiedExploitability": False,
            },
        }],
    }
