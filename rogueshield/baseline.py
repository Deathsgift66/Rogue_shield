"""Deterministic, offline comparison of RogueShield JSON reports.

Fingerprints use normalized rule, location and message; severity is deliberately
excluded so a severity escalation is reported as a regression.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import unicodedata

from rogueshield.offline import read_json
from rogueshield.localio import create_private

SEVERITIES = ("info", "low", "medium", "high", "critical")
_LEVEL = {name: index for index, name in enumerate(SEVERITIES)}


def fingerprint(rule_id: str, location: str, message: str) -> str:
    payload = json.dumps(["RogueShield-fingerprint-v1", rule_id, location, message],
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256(payload).hexdigest()


def _index(report: dict) -> dict[str, list[dict]]:
    if not isinstance(report, dict) or report.get("tool") != "RogueShield" or type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ValueError("Expected a RogueShield JSON report, schema_version 1")
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > 30_000:
        raise ValueError("Invalid or over-budget report findings")
    result: dict[str, list[dict]] = defaultdict(list)
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("Invalid report finding")
        for field, limit in (("rule_id", 80), ("location", 240), ("message", 500)):
            if not isinstance(item.get(field), str) or len(item[field]) > limit:
                raise ValueError("Invalid report finding field")
        severity = item.get("severity")
        if not isinstance(severity, str) or severity not in _LEVEL:
            raise ValueError("Invalid report severity")
        digest = fingerprint(item["rule_id"], item["location"], item["message"])
        if "fingerprint" in item and item["fingerprint"] != digest:
            raise ValueError("Report finding fingerprint does not match content")
        result[digest].append({
            "fingerprint": digest, "rule_id": item["rule_id"], "severity": severity,
            "location": item["location"], "message": item["message"],
        })
    return result


def compare_reports(current: dict, baseline: dict) -> dict:
    """Compare multisets: identical findings on one line are counted separately."""
    new_index, old_index = _index(current), _index(baseline)
    changes: dict[str, list] = {"new": [], "resolved": [], "worsened": [], "improved": []}
    unchanged = 0
    for digest in sorted(new_index.keys() | old_index.keys()):
        current_by_level = {severity: [] for severity in SEVERITIES}
        old_by_level = {severity: [] for severity in SEVERITIES}
        for item in new_index.get(digest, []):
            current_by_level[item["severity"]].append(item)
        for item in old_index.get(digest, []):
            old_by_level[item["severity"]].append(item)
        for severity in SEVERITIES:
            matches = min(len(current_by_level[severity]), len(old_by_level[severity]))
            unchanged += matches
            del current_by_level[severity][:matches]
            del old_by_level[severity][:matches]
        remaining_current = [item for severity in SEVERITIES for item in current_by_level[severity]]
        remaining_old = [item for severity in SEVERITIES for item in old_by_level[severity]]
        pairs = min(len(remaining_current), len(remaining_old))
        for i in range(pairs):
            before, after = remaining_old[i], remaining_current[i]
            key = "worsened" if _LEVEL[after["severity"]] > _LEVEL[before["severity"]] else "improved"
            changes[key].append({"before": before, "after": after})
        changes["new"].extend(remaining_current[pairs:])
        changes["resolved"].extend(remaining_old[pairs:])
    return {
        "tool": "RogueShield", "schema_version": 1, "mode": "offline-baseline-comparison",
        "summary": {key: len(value) for key, value in changes.items()} | {"unchanged": unchanged},
        **changes,
        "warning": "Only changes in offline heuristic indicators are compared; no security guarantee.",
    }


def regression_at_or_above(comparison: dict, threshold: str) -> bool:
    if threshold not in _LEVEL:
        raise ValueError("Invalid severity threshold")
    candidates = comparison["new"] + [item["after"] for item in comparison["worsened"]]
    return any(_LEVEL[item["severity"]] >= _LEVEL[threshold] for item in candidates)


def text_comparison(comparison: dict) -> str:
    def safe(value: object) -> str:
        return "".join(ch if unicodedata.category(ch) not in {"Cc", "Cf", "Cs"}
                       else f"\\u{ord(ch):04x}" for ch in str(value))
    summary = comparison["summary"]
    lines = ["ROGUESHIELD • OFFLINE BASELINE COMPARISON", "=" * 40,
             f"New: {summary['new']}  Worsened: {summary['worsened']}  "
             f"Resolved: {summary['resolved']}  Improved: {summary['improved']}  "
             f"Unchanged: {summary['unchanged']}",
             "A baseline is not a security certification.", ""]
    for item in comparison["new"]:
        lines.append(f"NEW [{item['severity'].upper()}] {safe(item['rule_id'])} at {safe(item['location'])}")
    for item in comparison["worsened"]:
        after = item["after"]
        lines.append(f"WORSENED [{item['before']['severity']} -> {after['severity']}] "
                     f"{safe(after['rule_id'])} at {safe(after['location'])}")
    for item in comparison["resolved"]:
        lines.append(f"RESOLVED {safe(item['rule_id'])} at {safe(item['location'])}")
    for item in comparison["improved"]:
        after = item["after"]
        lines.append(f"IMPROVED [{item['before']['severity']} -> {after['severity']}] "
                     f"{safe(after['rule_id'])} at {safe(after['location'])}")
    return "\n".join(lines) + "\n"


def compare_files(current_path: str, baseline_path: str) -> dict:
    return compare_reports(read_json(current_path), read_json(baseline_path))


def write_comparison(comparison: dict, path: str, fmt: str) -> None:
    if fmt == "json":
        payload = json.dumps(comparison, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    elif fmt == "text":
        payload = text_comparison(comparison)
    else:
        raise ValueError("Baseline comparison supports text and json only")
    create_private(path, payload)
