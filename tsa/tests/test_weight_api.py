import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import yaml

from tsa_core import RiskScorer, StateStore
from tsa_dashboard import DashboardData, DashboardHandler, DashboardServer
from weight_policy import read_policy, update_policy, VersionConflict


class WeightApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {'storage': {'state_db': 'state.db'},
                       'scoring': {'weights': {'posture': 0.4, 'runtime': 0.6}},
                       'runtime_rules': {'event_control': {'max_active_points_per_rule': 100}}}
        self.config_path = self.root / 'policy.yaml'
        self.config_path.write_text(yaml.safe_dump(self.config), encoding='utf-8')
        self.store = StateStore(self.root / 'state.db')
        self.addCleanup(self.store.close)
        for key, value in {'posture_score': 80, 'baseline_status': 'ok',
                           'fusion_status': 'running', 'fusion_heartbeat': time.time(),
                           'source_status': {'falco': True}}.items():
            self.store.set(key, value)
        self.store.record_event(received_time='', event_time='', source='falco',
                                rule_name='risk', status='scored', deducted_points=40,
                                event_key='test', payload={}, risk_expires_at=time.time() + 3600)
        self.token = 'test-token-' + 'x' * 40
        self.env = patch.dict(os.environ, {'TSA_WEIGHTS_API_TOKEN': self.token,
                                          'TSA_WEIGHTS_API_CLIENT': 'test-main-system'})
        self.env.start()
        self.addCleanup(self.env.stop)
        active = patch('tsa_dashboard.service_state', return_value='active')
        active.start()
        self.addCleanup(active.stop)
        self.server = DashboardServer(('127.0.0.1', 0), DashboardHandler)
        self.server.data = DashboardData(self.config_path)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def request(self, method='GET', payload=None, auth=True, headers=None, path='/systemManage/risk/weights', raw=None):
        request_headers = {'Content-Type': 'application/json'}
        if auth:
            request_headers['Authorization'] = 'Bearer ' + self.token
        request_headers.update(headers or {})
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        client = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            client.request(method, path, body=body, headers=request_headers)
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

    def update(self, **kwargs):
        return self.request('PUT', {'posture': 0.3, 'runtime': 0.7, 'expected_version': 0, **kwargs})

    def test_update_is_immediate_durable_audited_and_shared_with_collector(self):
        scorer = RiskScorer(self.config, self.store, self.root)
        self.assertEqual(scorer.final_score(), 68)
        status, initial = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(initial['data']['version'], 0)
        status, changed = self.update(reason='Main system policy change')
        self.assertEqual(status, 200)
        self.assertEqual(changed['data']['version'], 1)
        self.assertEqual(changed['data']['updated_by'], 'test-main-system')
        self.assertEqual(scorer.final_score(), 66)
        status, response = self.request(path='/systemManage/risk/score', auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(response['data']['final'], 66)
        self.assertEqual(response['data']['posture'], 80)
        self.assertEqual(response['data']['runtime'], 60)
        self.assertEqual(response['data']['weights'], changed['data'])
        restored = DashboardData(self.config_path)
        self.assertEqual(restored.scores()['final'], 66)
        self.assertEqual(restored.snapshot()['weights']['version'], 1)
        with sqlite3.connect(self.root / 'settings/weights.db') as db:
            rows = db.execute('SELECT version, posture, runtime, updated_by, reason FROM weight_revisions ORDER BY version').fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][:3], (0, 0.4, 0.6))
        self.assertEqual(rows[1][3:], ('test-main-system', 'Main system policy change'))
        self.assertNotIn(self.token, str(rows))

    def test_authentication_is_required_for_reads_and_writes(self):
        for method in ('GET', 'PUT'):
            payload = {} if method == 'PUT' else None
            status, _ = self.request(method, payload, auth=False)
            self.assertEqual(status, 401)
            status, _ = self.request(method, payload, headers={'Authorization': 'Bearer wrong'})
            self.assertEqual(status, 401)
        self.assertFalse((self.root / 'settings/weights.db').exists())

    def test_missing_token_disables_management_but_not_score_reads(self):
        with patch.dict(os.environ, {'TSA_WEIGHTS_API_TOKEN': ''}):
            self.assertEqual(self.request()[0], 503)
            self.assertEqual(self.update()[0], 503)
            self.assertEqual(self.request(path='/systemManage/risk/score', auth=False)[0], 200)

    def test_rebinding_and_browser_origins_rejected(self):
        for headers in ({'Host': 'evil.example'}, {'Origin': 'http://evil.example'},
                        {'Origin': 'http://127.0.0.1'}):
            self.assertEqual(self.request('PUT', {}, headers=headers)[0], 403)

    def test_invalid_weights_and_payloads_do_not_change_policy(self):
        for body in ({'posture': 0.2, 'runtime': 0.7, 'expected_version': 0},
                     {'posture': -0.1, 'runtime': 1.1, 'expected_version': 0},
                     {'posture': True, 'runtime': 0, 'expected_version': 0},
                     {'posture': '0.3', 'runtime': 0.7, 'expected_version': 0},
                     {'posture': float('nan'), 'runtime': 1, 'expected_version': 0},
                     {'posture': float('inf'), 'runtime': 0, 'expected_version': 0},
                     {'posture': 10**200, 'runtime': 0, 'expected_version': 0},
                     {'posture': 0.3, 'runtime': 0.7},
                     {'posture': 0.3, 'runtime': 0.7, 'expected_version': True},
                     {'posture': 0.3, 'runtime': 0.7, 'expected_version': 0, 'actor': 'spoof'},
                     {'posture': 0.3, 'runtime': 0.7, 'expected_version': 0, 'reason': 'x'*501},
                     [], None):
            with self.subTest(body=body):
                self.assertEqual(self.request('PUT', body, raw='null' if body is None else None)[0], 400)
        self.assertEqual(self.request()[1]['data']['version'], 0)

    def test_body_limits_content_type_duplicate_keys_and_malformed_json(self):
        for raw in ('x'*4097, '{bad', '{"posture":0.4,"posture":0.3,"runtime":0.7,"expected_version":0}'):
            self.assertEqual(self.request('PUT', raw=raw)[0], 400)
        self.assertEqual(self.request('PUT', {}, headers={'Content-Type': 'text/plain'})[0], 400)

    def test_stale_revision_conflicts_without_losing_winner(self):
        self.assertEqual(self.update()[0], 200)
        self.assertEqual(self.update(posture=0.8, runtime=0.2)[0], 409)
        self.assertEqual(self.request()[1]['data']['posture'], 0.3)
        self.assertEqual(self.update(posture=0.8, runtime=0.2, expected_version=1)[0], 200)

    def test_first_invalid_version_does_not_poison_default_policy(self):
        self.assertEqual(self.update(expected_version=99)[0], 409)
        self.assertEqual(self.request()[1]['data']['version'], 0)
        self.assertEqual(self.update()[0], 200)

    def test_concurrent_updates_allow_exactly_one_winner(self):
        def change(weight):
            try:
                return update_policy(self.config, self.root, posture=weight, runtime=1-weight,
                                     expected_version=0, actor='worker')['version']
            except VersionConflict:
                return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(change, (0.25, 0.75)))
        self.assertCountEqual(results, [1, 'conflict'])
        self.assertEqual(read_policy(self.config, self.root)['version'], 1)

    def test_endpoint_weights_zero_and_one_are_valid(self):
        self.assertEqual(self.update(posture=0, runtime=1)[0], 200)
        self.store.set('posture_score', None)
        self.store.set('baseline_status', 'unavailable')
        self.assertEqual(self.request(path='/systemManage/risk/score')[1]['data']['final'], 60)
        self.assertEqual(self.update(posture=1, runtime=0, expected_version=1)[0], 200)
        self.assertEqual(self.request(path='/systemManage/risk/score')[0], 503)


if __name__ == '__main__':
    unittest.main()
