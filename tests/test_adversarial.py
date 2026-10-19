"""Adversarial input tests: no outside network or real-world targets."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import socket
import stat
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from rogueshield.cli import main
from rogueshield.localio import create_private, read_regular
from rogueshield.offline import inspect_python, inspect_invariants, inspect_openapi, read_json
from rogueshield.manifest import validate_scope
from rogueshield.reporting import assemble, html_report, text_report, write_report
from rogueshield.review import inspect
from rogueshield.swarm import SwarmConfig, simulate


class AdversarialInput(TestCase):
    def scope(self):
        return dict(environment="isolated-staging", engagement_id="synthetic-lab",
                    operator_acknowledgment=True, targets=["https://example.invalid"],
                    methods=["GET"], max_requests=0,
                    expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat())

    def test_explicit_no_network_for_all_commands(self):
        with TemporaryDirectory() as root, patch.object(socket.socket, 'connect', side_effect=AssertionError('Unexpected network')):
            Path(root, 'app.py').write_text('ok = 1\n')
            report = Path(root, 'report.json')
            self.assertEqual(main(['review', root, '--format', 'json', '--out', str(report)]), 0)
            self.assertEqual(main(['swarm-preview', '--agents', '700', '--out', str(Path(root, 'swarm.json'))]), 0)
            self.assertEqual(main(['scope-check', str(self._save(root, 'scope.json', self.scope()))]), 0)
            self.assertEqual(main(['invariants', str(self._save(root, 'ledger.json', {'transfers': []})), '--format', 'text']), 0)

    def _save(self, root, name, value):
        target = Path(root, name)
        target.write_text(json.dumps(value), encoding='utf8')
        return target

    def test_fails_closed_on_syntax_error(self):
        with TemporaryDirectory() as root:
            Path(root, 'bad.py').write_text('def\n')
            with self.assertRaises(ValueError):
                inspect_python(root)

    def test_python_source_encoding_cookie(self):
        with TemporaryDirectory() as root:
            Path(root, 'latin.py').write_bytes(b"# coding: latin-1\nname='caf\xe9'\n")
            self.assertEqual(inspect_python(root), [])

    def test_fails_closed_on_oversize_source(self):
        with TemporaryDirectory() as root:
            Path(root, 'oversize.py').write_bytes(b'#' * 1_000_001)
            with self.assertRaises(ValueError):
                inspect_python(root)

    def test_empty_project_cannot_report_clean(self):
        with TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                inspect(root)

    def test_symlink_source_and_input_forbidden(self):
        with TemporaryDirectory() as root:
            dest = Path(root, 'real.json')
            dest.write_text('{}')
            link = Path(root, 'alias.json')
            link.symlink_to(dest)
            with self.assertRaises((OSError, ValueError)):
                read_regular(link)
            with self.assertRaises(ValueError):
                read_json(str(link)) if False else inspect(str(link))

    def test_device_file_rejected(self):
        with self.assertRaises(ValueError):
            read_regular('/dev/null')

    def test_output_private_and_exclusive(self):
        with TemporaryDirectory() as root:
            path = Path(root, 'out.json')
            report = assemble('review', [])
            write_report(report, str(path), 'json')
            self.assertFalse(path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))
            with self.assertRaises(FileExistsError):
                write_report(report, str(path), 'json')
            self.assertIn('RogueShield', path.read_text())

    def test_symlink_output_no_overwrite(self):
        with TemporaryDirectory() as root:
            existing = Path(root, 'important')
            existing.write_text('original')
            path = Path(root, 'report')
            path.symlink_to(existing)
            with self.assertRaises((OSError, ValueError)):
                create_private(path, 'different')
            self.assertEqual(existing.read_text(), 'original')

    def test_no_terminal_escape_in_findings(self):
        report = assemble('review', [{
            'rule_id': 'PY-EVAL', 'severity': 'high', 'location': 'evil\x1b[31m.py',
            'message': '\x1b]8;;https://bad.invalid\x07masked',
        }])
        output = text_report(report)
        self.assertNotIn('\x1b', output)
        self.assertNotIn('\x07', output)
        self.assertIn('\\u001b', output)
        self.assertNotIn('<script>', html_report(report))

    def test_invalid_nested_openapi_schema_fails_cleanly(self):
        with TemporaryDirectory() as root:
            spec = self._save(root, 'api.json', {'openapi': '3.1.0', 'paths': {'/foo': {2: {}}}})
            # JSON coerces object keys to strings; a malformed paths field must be rejected.
            spec.write_text(json.dumps({'openapi': '3.0.0', 'paths': []}))
            with self.assertRaises(ValueError):
                inspect_openapi(str(spec))

    def test_invalid_invariants_fail_closed(self):
        with TemporaryDirectory() as root:
            fixture = self._save(root, 'fixture.json', {'replays': [{'state_after_first': 1}]})
            with self.assertRaises(ValueError):
                inspect_invariants(str(fixture))
            fixture.write_text(json.dumps({'transfers': [None]}))
            with self.assertRaises(ValueError):
                inspect_invariants(str(fixture))

    def test_scope_rejects_unknown_and_controlled_origin(self):
        invalid_origins = [' https://example.invalid', 'https://example.invalid\n',
                           'https://user@example.invalid', 'https://bad..invalid',
                           'http://169.254.169.254', 'https://example.invalid/path',
                           'https://-invalid.test', 'https://example.invalid?token=x']
        for origin in invalid_origins:
            s = self.scope()
            s['targets'] = [origin]
            with self.assertRaises((ValueError, PermissionError), msg=origin):
                validate_scope(s)
        s = self.scope()
        s['future_bypass_flag'] = True
        with self.assertRaises(ValueError):
            validate_scope(s)
        s = self.scope()
        s['max_requests'] = False
        with self.assertRaises(ValueError):
            validate_scope(s)

    def test_swarm_bounded_and_deterministic(self):
        settings = SwarmConfig(agents=700, rounds=10, actions_per_agent=4)
        r = simulate(settings)
        self.assertEqual(r, simulate(settings))
        self.assertEqual(r['modeled_attempts'], 28_000)
        self.assertEqual(r['live_requests'], 0)
        self.assertEqual(r['real_agents'], 0)
        self.assertEqual(r['modeled_allowed'] + r['modeled_blocked'], 28_000)
        with self.assertRaises(ValueError):
            simulate(SwarmConfig(agents=1_000_000))


if __name__ == '__main__':
    import unittest
    unittest.main()
