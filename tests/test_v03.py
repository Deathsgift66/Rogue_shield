"""No network required; uses only synthetic fixtures."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from rogueshield.cli import main
from rogueshield.manifest import validate_scope
from rogueshield.offline import inspect_python, inspect_openapi, inspect_invariants
from rogueshield.reporting import assemble, html_report, text_report, write_report
from rogueshield.review import inspect
from rogueshield.safety import CONSENT_PHRASE, choose_profile, simulate_swarm
from rogueshield.swarm import SwarmConfig, simulate


class OfflineV03(unittest.TestCase):
    def test_basic_ast(self):
        with TemporaryDirectory() as d:
            Path(d, 'a.py').write_text("x=eval('1')\n", encoding='utf8')
            self.assertEqual(inspect_python(d)[0]['rule_id'], 'PY-EVAL')

    def test_clean_ast(self):
        with TemporaryDirectory() as d:
            Path(d, 'a.py').write_text('x=1\n', encoding='utf8')
            self.assertEqual(inspect_python(d), [])

    def test_openapi_auth(self):
        with TemporaryDirectory() as d:
            p = Path(d, 'openapi.json')
            p.write_text(json.dumps({'openapi': '3.0.2', 'paths': {'/admin/x': {'get': {}}}}))
            self.assertEqual(inspect_openapi(str(p))[0]['rule_id'], 'API-AUTH-DOC')
            self.assertEqual(inspect(d)['checks_performed'], ['openapi'])

    def test_invariant_conservation(self):
        with TemporaryDirectory() as d:
            p = Path(d, 'synthetic.json')
            p.write_text(json.dumps({'transfers': [{'before': {'a': 2}, 'after': {'a': 3}}]}))
            self.assertEqual(inspect_invariants(str(p))[0]['rule_id'], 'INV-CONSERVATION')

    def test_negative(self):
        with TemporaryDirectory() as d:
            p=Path(d, 'i.json');p.write_text(json.dumps({'transfers': [{'before': {'a': 0}, 'after': {'a': -1}, 'expected_external_delta': -1}]}))
            self.assertEqual(inspect_invariants(str(p))[0]['rule_id'], 'INV-NEGATIVE')

    def test_replay(self):
        with TemporaryDirectory() as d:
            p=Path(d, 'i.json');p.write_text(json.dumps({'replays': [{'state_after_first': 1, 'state_after_repeat': 2}]}))
            self.assertEqual(inspect_invariants(str(p))[0]['rule_id'], 'INV-REPLAY')

    def test_auto_detect(self):
        with TemporaryDirectory() as d:
            p=Path(d,'openapi.json');p.write_text(json.dumps({'openapi': '3.1.0', 'paths': {}}))
            self.assertEqual(inspect(str(p))['summary']['total'], 0)

    def test_html_escapes_untrusted_data(self):
        r=assemble('review', [{'rule_id': 'PY-EVAL', 'severity': 'high', 'location': '<img src=x onerror=alert(1)>', 'message': '<script>alert(1)</script>'}])
        output=html_report(r)
        self.assertNotIn('<script>alert(1)</script>',output)
        self.assertIn('&lt;script&gt;',output)
        self.assertIn('Content-Security-Policy',output)

    def test_text_actionable(self):
        r=assemble('review',[{'rule_id':'PY-EVAL','severity':'high','location':'x.py:1','message':'x'}])
        self.assertIn('Suggested action:',text_report(r))
        self.assertIn('No indicators found',text_report(assemble('review',[])))

    def test_report_write(self):
        with TemporaryDirectory() as d:
            p=Path(d,'x.html')
            write_report(assemble('review',[]),str(p),'html')
            self.assertIn('RogueShield',p.read_text())

    def test_swarm_700_synthetic(self):
        r=simulate(SwarmConfig(agents=700))
        self.assertEqual(r['modeled_attempts'], 700*10*4)
        self.assertEqual(r['modeled_attempts'], r['modeled_allowed']+r['modeled_blocked'])
        self.assertEqual(r['live_requests'],0)
        self.assertEqual(r['real_agents'],0)
        self.assertFalse(r['target_contacted'])

    def test_simulation_repeatable(self):
        a=SwarmConfig(agents=20,rounds=2)
        self.assertEqual(simulate(a),simulate(a))

    def test_simulation_limiter(self):
        r=simulate(SwarmConfig(agents=3,rounds=1,actions_per_agent=3,identity_limit=1,origin_groups=3,origin_limit=100,global_limit=100))
        self.assertEqual(r['modeled_allowed'],3)
        self.assertEqual(r['blocked_by']['identity'],6)

    def test_simulation_invalid(self):
        for n in (0,-1,100001, True):
            with self.assertRaises(ValueError):
                simulate(SwarmConfig(agents=n))

    def test_simulation_work_budget(self):
        with self.assertRaises(ValueError):
            simulate(SwarmConfig(agents=100_000,rounds=100,actions_per_agent=20))

    def test_consent_required(self):
        with self.assertRaises(PermissionError):
            choose_profile('beginner','local','yes')
        for mode in ('beginner', 'standard', 'advanced', 'swarm-simulation'):
            self.assertEqual(choose_profile(mode, 'production', CONSENT_PHRASE).max_live_requests, 0)
        self.assertEqual(simulate_swarm(700)['live_requests'], 0)

    def _scope(self):
        return {'engagement_id':'test-fixture', 'operator_acknowledgment':True, 'environment':'isolated-staging',
                'targets':['https://example.test'], 'methods':['GET'], 'max_requests':0,
                'expires_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}

    def test_scope_valid_but_offline(self):
        p=validate_scope(self._scope())
        self.assertTrue(p['validated_offline_only'])
        self.assertEqual(len(p['scope_sha256']),64)

    def test_scope_disallows_mutating(self):
        p=self._scope();p['methods']=['POST']
        with self.assertRaises(ValueError):validate_scope(p)

    def test_scope_forbids_metadata(self):
        p=self._scope();p['targets']=['http://169.254.169.254']
        with self.assertRaises(ValueError):validate_scope(p)

    def test_scope_no_live_request(self):
        p=self._scope();p['max_requests']=1
        with self.assertRaises(ValueError):validate_scope(p)

    def test_scope_expired(self):
        p=self._scope();p['expires_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        with self.assertRaises(ValueError):validate_scope(p)

    def test_scope_acknowledgment(self):
        p=self._scope();p['operator_acknowledgment']=False
        with self.assertRaises(PermissionError):validate_scope(p)

    def test_cli_guide(self):
        self.assertEqual(main(['guide']),0)

    def test_cli_swarm_preview(self):
        self.assertEqual(main(['swarm-preview','--agents','700']),0)

    def test_cli_report_output(self):
        with TemporaryDirectory() as d:
            p=Path(d,'a.py');p.write_text('a=1')
            output=Path(d,'out.html')
            self.assertEqual(main(['review',d,'--out',str(output),'--format','html']),0)
            self.assertTrue(output.exists())

    def test_cli_fail_on(self):
        with TemporaryDirectory() as d:
            Path(d,'a.py').write_text("x=eval('1')\n")
            self.assertEqual(main(['review',d,'--fail-on','high']),2)


if __name__ == '__main__':unittest.main()
