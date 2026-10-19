"""Offline regression tests for security analysis and machine-readable reports."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from rogueshield.cli import main
from rogueshield.offline import inspect_invariants, inspect_openapi, read_json
from rogueshield.reporting import assemble, write_report
from rogueshield.review import inspect
from rogueshield.sarif import sarif_report


class HardeningRegressions(unittest.TestCase):
    def _json(self, root: str, name: str, data: object) -> Path:
        path = Path(root, name)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_duplicate_json_keys_rejected_at_all_depths(self):
        with TemporaryDirectory() as root:
            path = Path(root, "spec.json")
            for payload in (
                '{"openapi":"3.0.0","paths":{},"paths":{}}',
                '{"openapi":"3.0.0","paths":{"/admin":{"get":{},"get":{}}}}',
            ):
                path.write_text(payload, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_json(str(path))

    def test_nonstandard_json_constants_rejected(self):
        with TemporaryDirectory() as root:
            path = Path(root, "data.json")
            for token in ("NaN", "Infinity", "-Infinity"):
                path.write_text('{"transfers":[' + token + ']}', encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_json(str(path))

    def test_openapi_anonymous_alternative_overrides_protected_global(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "api.json", {
                "openapi": "3.0.3",
                "security": [{"bearerAuth": []}],
                "paths": {"/api/v1/admin/settings": {
                    "post": {"security": [{}, {"bearerAuth": []}]},
                }},
            })
            issues = inspect_openapi(str(path))
            self.assertEqual([item["rule_id"] for item in issues], ["API-AUTH-DOC"])

    def test_openapi_empty_operation_security_overrides_global(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "api.json", {
                "openapi": "3.1.0",
                "security": [{"bearerAuth": []}],
                "paths": {"/api/v1/users/{id}": {"get": {"security": []}}},
            })
            self.assertEqual(inspect_openapi(str(path))[0]["rule_id"], "API-AUTH-DOC")

    def test_openapi_protected_sensitive_route_not_flagged(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "api.json", {
                "openapi": "3.0.3",
                "security": [{"bearerAuth": []}],
                "paths": {
                    "/api/v1/admin/settings": {"post": {}},
                    "/api/v1/health": {"get": {}},
                },
            })
            self.assertEqual(inspect_openapi(str(path)), [])

    def test_openapi_options_preflight_is_not_treated_as_protected_operation(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "api.json", {
                "openapi": "3.0.3",
                "paths": {"/api/v1/admin/settings": {"options": {}, "get": {}}},
            })
            issues = inspect_openapi(str(path))
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0]["location"], "GET /api/v1/admin/settings")

    def test_openapi_malformed_security_rejected(self):
        with TemporaryDirectory() as root:
            for value in ({"bearerAuth": []}, [None], [{"bearerAuth": "scope"}]):
                path = self._json(root, "api.json", {
                    "openapi": "3.0.3",
                    "paths": {"/admin": {"post": {"security": value}}},
                })
                with self.assertRaises(ValueError):
                    inspect_openapi(str(path))

    def test_asset_swap_cannot_hide_behind_aggregate_conservation(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "ledger.json", {"asset_transfers": [{
                "before": {"gold": {"alice": "10"}, "gems": {"alice": "0"}},
                "after": {"gold": {"alice": "0"}, "gems": {"alice": "10"}},
            }]})
            issues = inspect_invariants(str(path))
            self.assertEqual(
                [item["rule_id"] for item in issues],
                ["INV-ASSET-CONSERVATION", "INV-ASSET-CONSERVATION"],
            )
            self.assertEqual(inspect(str(path))["checks_performed"], ["synthetic-invariants"])

    def test_asset_transfer_with_explicit_mint_is_consistent(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "ledger.json", {"asset_transfers": [{
                "before": {"gold": {"alice": "10", "bob": "0"}},
                "after": {"gold": {"alice": "10", "bob": "2"}},
                "expected_external_delta": {"gold": "2"},
            }]})
            self.assertEqual(inspect_invariants(str(path)), [])

    def test_large_balances_do_not_hide_one_unit_asset_creation(self):
        with TemporaryDirectory() as root:
            huge = "10000000000000000000000000000000000000000"
            path = self._json(root, "ledger.json", {"asset_transfers": [{
                "before": {"gold": {"alice": huge}},
                "after": {"gold": {"alice": str(int(huge) + 1)}},
            }]})
            self.assertEqual([f["rule_id"] for f in inspect_invariants(str(path))],
                             ["INV-ASSET-CONSERVATION"])

    def test_negative_per_asset_balance_is_detected(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "ledger.json", {"asset_transfers": [{
                "before": {"gold": {"alice": "0", "bob": "0"}},
                "after": {"gold": {"alice": "-1", "bob": "1"}},
            }]})
            self.assertEqual([f["rule_id"] for f in inspect_invariants(str(path))],
                             ["INV-ASSET-NEGATIVE"])

    def test_invalid_asset_balances_fail_closed(self):
        with TemporaryDirectory() as root:
            path = self._json(root, "ledger.json", {"asset_transfers": [{
                "before": {"gold": ["10"]},
                "after": {"gold": {"alice": "10"}},
            }]})
            with self.assertRaises(ValueError):
                inspect_invariants(str(path))

    def test_sarif_contains_rule_and_relative_python_location(self):
        report = assemble("static", [{
            "rule_id": "PY-EVAL", "severity": "high",
            "location": "src/app.py:12", "message": "Review dynamic evaluation",
        }])
        doc = sarif_report(report)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "PY-EVAL")
        result = run["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 12)
        self.assertFalse(run["properties"]["verifiedExploitability"])

    def test_sarif_does_not_emit_escaping_source_location(self):
        report = assemble("static", [{
            "rule_id": "PY-EVAL", "severity": "high",
            "location": "../secret.py:5", "message": "Synthetic finding",
        }])
        location = sarif_report(report)["runs"][0]["results"][0]["locations"][0]
        self.assertNotIn("physicalLocation", location)

    def test_sarif_file_and_cli_work_offline(self):
        with TemporaryDirectory() as root:
            Path(root, "app.py").write_text("value = eval('1')\n", encoding="utf-8")
            output = Path(root, "review.sarif")
            self.assertEqual(
                main(["static", root, "--format", "sarif", "--out", str(output)]), 2
            )
            doc = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(doc["runs"][0]["results"][0]["ruleId"], "PY-EVAL")
            with self.assertRaises(FileExistsError):
                write_report(assemble("static", []), str(output), "sarif")


if __name__ == "__main__":
    unittest.main()
