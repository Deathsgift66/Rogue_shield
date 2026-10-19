"""Fixture-only access-control and report-baseline regression tests."""
from __future__ import annotations

import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from rogueshield.authz import inspect_authz
from rogueshield.baseline import compare_reports, fingerprint, regression_at_or_above
from rogueshield.cli import main
from rogueshield.reporting import assemble
from rogueshield.review import inspect
from rogueshield.sarif import sarif_report


def fixture():
    return {
        "kind": "authorization-matrix", "schema_version": 1,
        "principals": [
            {"id": "alice", "tenant": "north", "roles": ["player"]},
            {"id": "bob", "tenant": "north", "roles": ["player"]},
            {"id": "eve", "tenant": "south", "roles": ["player"]},
            {"id": "moderator", "tenant": "north", "roles": ["moderator"]},
        ],
        "resources": [{"id": "wallet-a", "type": "wallet", "owner": "alice", "tenant": "north"}],
        "policies": [{"resource_type": "wallet", "action": "read", "allow_owner": True,
                      "allow_roles": ["moderator"], "require_same_tenant": True}],
        "observations": [
            {"principal": "alice", "resource": "wallet-a", "action": "read", "decision": "allow"},
            {"principal": "bob", "resource": "wallet-a", "action": "read", "decision": "deny"},
            {"principal": "eve", "resource": "wallet-a", "action": "read", "decision": "deny"},
            {"principal": "moderator", "resource": "wallet-a", "action": "read", "decision": "allow"},
        ],
    }


class AuthzMatrix(unittest.TestCase):
    def _write(self, root, data, name="authz.json"):
        path = Path(root, name)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_clean_covered_fixture(self):
        with TemporaryDirectory() as root:
            self.assertEqual(inspect_authz(str(self._write(root, fixture()))), [])

    def test_detects_cross_owner_and_cross_tenant_access(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["observations"][1]["decision"] = "allow"
            data["observations"][2]["decision"] = "allow"
            self.assertEqual([f["rule_id"] for f in inspect_authz(str(self._write(root, data)))],
                             ["AUTHZ-BOLA", "AUTHZ-TENANT-ESCAPE"])

    def test_detects_denial_of_permitted_access(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["observations"][0]["decision"] = "deny"
            self.assertIn("AUTHZ-OVERDENY", [f["rule_id"] for f in inspect_authz(str(self._write(root, data)))])

    def test_reports_missing_test_cohorts(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["observations"] = data["observations"][:1]
            issues = inspect_authz(str(self._write(root, data)))
            self.assertEqual([f["rule_id"] for f in issues], ["AUTHZ-COVERAGE"])
            self.assertIn("cross-tenant", issues[0]["message"])

    def test_rejects_conflicting_or_duplicate_observations(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["observations"].append(dict(data["observations"][0], decision="deny"))
            with self.assertRaises(ValueError):
                inspect_authz(str(self._write(root, data)))

    def test_rejects_undeclared_policy_and_missing_owner(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["observations"][0]["action"] = "transfer"
            with self.assertRaises(ValueError):
                inspect_authz(str(self._write(root, data)))
            data = fixture()
            data["resources"][0]["owner"] = "unknown"
            with self.assertRaises(ValueError):
                inspect_authz(str(self._write(root, data)))

    def test_rejects_ambiguous_or_oversize_input(self):
        with TemporaryDirectory() as root:
            data = fixture()
            data["principals"][0]["roles"] = ["player", "player"]
            with self.assertRaises(ValueError):
                inspect_authz(str(self._write(root, data)))
            data = fixture()
            data["observations"] *= 1001
            with self.assertRaises(ValueError):
                inspect_authz(str(self._write(root, data)))

    def test_standalone_and_project_review(self):
        with TemporaryDirectory() as root:
            path = self._write(root, fixture(), "rogueshield-authz.json")
            self.assertEqual(inspect(str(path))["checks_performed"], ["synthetic-authorization"])
            self.assertEqual(inspect(root)["checks_performed"], ["synthetic-authorization"])
            self.assertEqual(main(["authz", str(path)]), 0)

    def test_cli_flags_synthetic_policy_violation_without_network(self):
        with TemporaryDirectory() as root, patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            data = fixture()
            data["observations"][1]["decision"] = "allow"
            path = self._write(root, data)
            self.assertEqual(main(["authz", str(path), "--fail-on", "high"]), 2)


class BaselineDiff(unittest.TestCase):
    def _report(self, findings):
        return assemble("static", findings)

    def _finding(self, severity="high", location="app.py:1", rule="PY-EVAL"):
        return {"rule_id": rule, "severity": severity, "location": location, "message": "Review dynamic evaluation"}

    def test_fingerprint_stable_and_sarif(self):
        report = self._report([self._finding()])
        item = report["findings"][0]
        self.assertEqual(item["fingerprint"], fingerprint("PY-EVAL", "app.py:1", "Review dynamic evaluation"))
        self.assertEqual(sarif_report(report)["runs"][0]["results"][0]["partialFingerprints"]["rogueshield/v1"],
                         item["fingerprint"])

    def test_detects_new_and_resolved(self):
        baseline = self._report([self._finding(location="old.py:1")])
        current = self._report([self._finding(location="new.py:2")])
        comparison = compare_reports(current, baseline)
        self.assertEqual(comparison["summary"]["new"], 1)
        self.assertEqual(comparison["summary"]["resolved"], 1)
        self.assertTrue(regression_at_or_above(comparison, "high"))
        self.assertFalse(regression_at_or_above(comparison, "critical"))

    def test_detects_worsened_severity_not_new(self):
        comparison = compare_reports(self._report([self._finding("critical")]),
                                     self._report([self._finding("medium")]))
        self.assertEqual(comparison["summary"]["worsened"], 1)
        self.assertEqual(comparison["summary"]["new"], 0)
        self.assertTrue(regression_at_or_above(comparison, "high"))

    def test_matches_duplicates_as_multiset(self):
        item = self._finding()
        comparison = compare_reports(self._report([item, item]), self._report([item]))
        self.assertEqual(comparison["summary"]["unchanged"], 1)
        self.assertEqual(comparison["summary"]["new"], 1)

    def test_legacy_reports_without_fingerprint(self):
        old = self._report([self._finding()])
        for item in old["findings"]:
            del item["fingerprint"]
        comparison = compare_reports(self._report([self._finding()]), old)
        self.assertEqual(comparison["summary"]["unchanged"], 1)

    def test_rejects_tampered_fingerprint(self):
        old = self._report([])
        current = self._report([self._finding()])
        current["findings"][0]["fingerprint"] = "0" * 64
        with self.assertRaises(ValueError):
            compare_reports(current, old)

    def test_cli_compare_json_and_threshold(self):
        with TemporaryDirectory() as root:
            base = Path(root, "baseline.json")
            current = Path(root, "current.json")
            output = Path(root, "comparison.json")
            base.write_text(json.dumps(self._report([])), encoding="utf-8")
            current.write_text(json.dumps(self._report([self._finding()])), encoding="utf-8")
            self.assertEqual(main(["compare", str(current), str(base), "--format", "json",
                                   "--out", str(output), "--fail-on", "high"]), 2)
            self.assertEqual(json.loads(output.read_text())["summary"]["new"], 1)
            self.assertEqual(main(["compare", str(current), str(base), "--format", "json",
                                   "--out", str(output)]), 3)
            self.assertEqual(main(["compare", str(current), str(base), "--fail-on", "critical"]), 0)


if __name__ == "__main__":
    unittest.main()
