"""Offline tests use only temporary files and synthetic data."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from rogueshield.offline import inspect_python, inspect_openapi, inspect_invariants
from rogueshield.cli import main


class OfflineChecks(unittest.TestCase):
    def test_static_finds_eval(self):
        with TemporaryDirectory() as tmp:
            Path(tmp, "example.py").write_text("value = eval('1 + 1')\n")
            found = inspect_python(tmp)
            self.assertEqual(found[0]["rule_id"], "PY-EVAL")

    def test_static_no_secret_value_in_report(self):
        with TemporaryDirectory() as tmp:
            Path(tmp, "example.py").write_text("password='fictional-secret'\nvalue=eval('2')\n")
            self.assertNotIn("fictional-secret", json.dumps(inspect_python(tmp)))

    def test_static_clean(self):
        with TemporaryDirectory() as tmp:
            Path(tmp, "example.py").write_text("print('hello')\n")
            self.assertEqual(inspect_python(tmp), [])

    def test_openapi_missing_security(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "api.json")
            src.write_text(json.dumps({"openapi": "3.0.0", "paths": {
                "/admin/settings": {"get": {"responses": {}}}}}))
            self.assertTrue(any(f["rule_id"] == "API-AUTH-DOC" for f in inspect_openapi(str(src))))

    def test_openapi_inherits_global_security(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "api.json")
            src.write_text(json.dumps({"openapi": "3.0.0",
                                       "security": [{"bearerAuth": []}],
                                       "paths": {"/admin/settings": {"get": {}}}}))
            self.assertEqual(inspect_openapi(str(src)), [])

    def test_invariants_conservation(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "snapshots.json")
            src.write_text(json.dumps({"transfers": [
                {"before": {"A": "10", "B": "2"}, "after": {"A": "7", "B": "5"}}]}))
            self.assertEqual(inspect_invariants(str(src)), [])

    def test_invariants_mismatch(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "snapshots.json")
            src.write_text(json.dumps({"transfers": [
                {"before": {"A": "10"}, "after": {"A": "20"}}]}))
            self.assertEqual(inspect_invariants(str(src))[0]["rule_id"], "INV-CONSERVATION")

    def test_replay_mismatch(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "snapshots.json")
            src.write_text(json.dumps({"replays": [
                {"state_after_first": {"points": 10}, "state_after_repeat": {"points": 20}}]}))
            self.assertEqual(inspect_invariants(str(src))[0]["rule_id"], "INV-REPLAY")

    def test_cli_exit_status(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp, "api.json")
            report = Path(tmp, "report.json")
            src.write_text(json.dumps({"openapi": "3.0.1", "paths": {
                "/admin/test": {"get": {}}}}))
            self.assertEqual(main(["openapi", str(src), "--out", str(report), "--fail-on", "medium"]), 2)
            self.assertTrue(report.exists())


if __name__ == "__main__":
    unittest.main()
