import copy
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import yaml

from baseline_scoring import read_report, score_report
from tsa_core import TSAFusionAgent
from tsa_dashboard import DashboardData, DashboardHandler, DashboardServer


ROOT = Path(__file__).resolve().parents[2]
CONFIG = yaml.safe_load((ROOT / 'tsa/policy_config.yaml').read_text(encoding='utf-8'))


class BaselineScoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'lynis.dat'
        self.config = copy.deepcopy(CONFIG['baseline_lynis'])

    def report(self, body='', executed=None, skipped=''):
        executed = '|'.join(self.config['controls']) if executed is None else executed
        self.path.write_text('report_version_major=1\nlynis_version=3.0.7\n'
                             'hardening_index=59\nreport_datetime_end=2026-09-18 10:00:00\n'
                             f'tests_executed={executed}|\ntests_skipped={skipped}\n'
                             + body + '\nfinish=true\n', encoding='utf-8')
        return read_report(self.path)

    def score(self, body='', **kwargs):
        return score_report(self.report(body, **kwargs), self.config)

    def control(self, result, control):
        return next(c for c in result['controls'] if c['control'] == control)

    def test_original_index_is_metadata_not_tsa_score(self):
        result = self.score()
        self.assertEqual(result['score'], 100)
        self.assertEqual(result['hardening_index'], '59')
        self.assertEqual(self.control(result, 'SSH-7408')['status'], 'executed_no_finding')
        self.assertIn('does not prove', result['scope'])

    def test_warning_and_suggestions_for_same_control_count_once(self):
        result = self.score('warning[]=PKGS-7392|Security updates|package-a|text:review updates\n' * 3
                            + 'suggestion[]=PKGS-7392|Update packages|-|-\n')
        self.assertEqual(result['score'], 85)
        self.assertEqual(len(result['findings']), 4)
        self.assertEqual(result['findings'][0]['details'], 'package-a')
        self.assertEqual(result['findings'][0]['remediation'], 'text:review updates')
        self.assertEqual(self.control(result, 'PKGS-7392')['deducted_points'], 15)

    def test_selected_suggestion_now_scores_but_contextual_ones_do_not(self):
        for control in ('AUTH-9328', 'KRNL-5820', 'LOGG-2190', 'FIRE-4513', 'BOOT-5122', 'NEW-1234'):
            with self.subTest(control=control):
                result = self.score(f'warning[]={control}|review this\nsuggestion[]=AUTH-9262|PAM missing\n')
                self.assertEqual(result['score'], 95)
                self.assertEqual(self.control(result, control)['deducted_points'], 0)

    def test_each_explicit_warning_policy_is_applied(self):
        for control in ('AUTH-9204', 'AUTH-9283', 'AUTH-9216', 'PKGS-7392'):
            with self.subTest(control=control):
                result = self.score(f'warning[]={control}|risk\n')
                self.assertEqual(result['score'], 100 - self.config['controls'][control]['warning'])

    def test_ssh_requires_structured_field_and_exact_value(self):
        for field, value, expected in [('Port', '22', 0), ('PermitRootLogin', 'PROHIBIT-PASSWORD', 0),
                                        ('PermitRootLogin', 'YES', 15), ('StrictModes', 'NO', 15),
                                        ('IgnoreRhosts', 'NO', 0), ('PermitUserEnvironment', 'YES', 5)]:
            with self.subTest(field=field, value=value):
                result = self.score('suggestion[]=SSH-7408|Consider hardening SSH|text|-\n'
                                    f'details[]=SSH-7408|sshd|desc:sshd option;field:{field};value:{value};|\n')
                self.assertEqual(result['score'], 100 - expected)
        result = self.score('suggestion[]=SSH-7408|PermitRootLogin YES, ambiguous text|-|-\n')
        self.assertEqual(result['score'], 100)
        self.assertEqual(self.control(result, 'SSH-7408')['status'], 'finding')

    def test_rhosts_without_authentication_context_is_advisory_not_a_pass(self):
        result = self.score('details[]=SSH-7408|sshd|field:IgnoreRhosts;value:NO;|\n')
        ssh = self.control(result, 'SSH-7408')
        self.assertEqual(result['score'], 100)
        self.assertEqual(ssh['status'], 'finding')
        self.assertEqual(ssh['matched_details'][0]['points'], 0)
        self.assertIn('HostbasedAuthentication', ssh['matched_details'][0]['reason'])
        self.assertEqual(ssh['matched_details'][0]['evidence']['value'], 'NO')

    def test_protocol_suggestions_preserve_evidence_without_multiplying_penalty(self):
        result = self.score(''.join(f'suggestion[]=NETW-3200|Review {protocol}|-|-\n'
                                   for protocol in ('dccp', 'sctp', 'rds', 'tipc')))
        control = self.control(result, 'NETW-3200')
        self.assertEqual(result['score'], 100)
        self.assertEqual(control['status'], 'finding')
        self.assertEqual(len(control['findings']), 4)
        self.assertEqual(control['deducted_points'], 0)
        self.assertNotEqual(control['title'], 'NETW-3200')

    def test_many_packages_are_one_patch_management_gap_not_many_vulnerabilities(self):
        for count in (1, 396):
            with self.subTest(count=count):
                result = self.score('warning[]=PKGS-7392|Security updates|-|-\n'
                                    + ''.join(f'vulnerable_package[]=package-{n}\n' for n in range(count)))
                self.assertEqual(result['score'], 85)
                self.assertEqual(result['deducted_points'], 15)
                self.assertEqual(len(result['observations']['vulnerable_packages']), count)
                self.assertEqual(result['policy_version'], 'ubuntu-host-v3')

    def test_multiple_ssh_findings_use_peak_not_sum(self):
        result = self.score('details[]=SSH-7408|sshd|field:PermitRootLogin;value:YES;|\n'
                            'details[]=SSH-7408|sshd|field:StrictModes;value:NO;|\n')
        self.assertEqual(result['score'], 85)
        self.assertEqual(len(self.control(result, 'SSH-7408')['matched_details']), 2)

    def test_missing_required_check_skipped_and_exception_are_unavailable(self):
        for options, body in [({'executed': 'AUTH-9204|AUTH-9283'}, ''),
                               ({'skipped': 'PKGS-7392|'}, ''),
                               ({}, 'exception_event[]=PKGS-7392:1|apt-check failed|\n'),
                               ({}, 'exception_event[]=SSH-7408:1|parse failure|\n')]:
            with self.subTest(options=options, body=body):
                result = self.score(body, **options)
                self.assertIsNone(result['score'])
                self.assertEqual(result['status'], 'unavailable')
                self.assertTrue(result['errors'])

    def test_optional_ssh_skipped_is_not_marked_passed(self):
        executed = '|'.join(c for c in self.config['controls'] if c != 'SSH-7408')
        result = self.score(executed=executed, skipped='SSH-7408|')
        self.assertEqual(result['score'], 100)
        self.assertEqual(self.control(result, 'SSH-7408')['status'], 'skipped')

    def test_header_and_finish_without_execution_metadata_is_not_perfect(self):
        result = self.score(executed='')
        self.assertIsNone(result['score'])
        self.assertEqual(self.control(result, 'AUTH-9204')['status'], 'unknown')

    def test_last_finish_false_invalidates_report(self):
        self.report()
        with self.path.open('a', encoding='utf-8') as file:
            file.write('finish=false\n')
        with self.assertRaises(ValueError):
            read_report(self.path)

    def test_malformed_findings_do_not_disappear_into_perfect_score(self):
        for body in ('warning[]=AUTH-9283\n', 'suggestion[]=|missing id\n'):
            with self.assertRaises(ValueError):
                self.score(body)

    def test_lynis_own_non_numeric_findings_are_preserved(self):
        result = self.score('suggestion[]=LYNIS|This release is more than 4 months old|-|-\n')
        self.assertEqual(result['score'], 100)
        self.assertEqual(self.control(result, 'LYNIS')['findings'][0]['type'], 'SUGGESTION')

    def test_package_and_account_evidence_is_preserved_without_per_item_penalties(self):
        result = self.score('warning[]=PKGS-7392|updates\n'
                            'vulnerable_package[]=openssl\nvulnerable_package[]=openssl\n'
                            'vulnerable_package[]=curl\nuser_with_uid_zero[]=extra:0\n'
                            'account_without_password[]=demo\n')
        self.assertEqual(result['score'], 85)
        self.assertEqual(result['observations']['vulnerable_packages'], ['curl', 'openssl'])
        self.assertEqual(result['observations']['extra_uid_zero_accounts'], ['extra:0'])
        self.assertEqual(result['observations']['passwordless_accounts'], ['demo'])

    def test_total_clipping_is_explained_by_control_deductions(self):
        self.config['controls']['AUTH-9204']['warning'] = 90
        result = self.score('warning[]=AUTH-9204|a\nwarning[]=AUTH-9283|b\n')
        self.assertEqual(result['score'], 0)
        self.assertEqual(sum(c['deducted_points'] for c in result['controls']), 100)
        self.assertEqual(self.control(result, 'AUTH-9283')['risk_points'], 25)

    def test_invalid_weight_is_rejected(self):
        for bad in (-1, 101, float('nan'), True, '15'):
            self.config['controls']['PKGS-7392']['warning'] = bad
            with self.assertRaises(ValueError):
                self.score()

    def agent(self):
        config = copy.deepcopy(CONFIG)
        config['storage'] = {'state_db': 'state.db', 'report_path': 'last_scan.json'}
        config['runtime_rules']['log_path'] = 'falco.json'
        config['baseline_lynis']['report_path'] = 'lynis.dat'
        self.config_path = self.root / 'policy.yaml'
        self.config_path.write_text(yaml.safe_dump(config), encoding='utf-8')
        agent = TSAFusionAgent(str(self.config_path))
        self.addCleanup(agent.close)
        return agent

    def test_agent_persists_full_explanation_and_clears_it_when_invalid(self):
        self.report('warning[]=PKGS-7392|updates\n')
        agent = self.agent()
        self.assertEqual(agent.run_posture_scan(), 85)
        self.assertEqual(agent.store.get('baseline_details')['score'], 85)
        self.assertEqual(sum(x['deducted_points'] for x in agent.recent_lynis_hits), 15)
        agent.generate_report()
        output = json.loads((self.root / 'last_scan.json').read_text(encoding='utf-8'))
        self.assertEqual(output['baseline']['score'], output['scores']['posture'])
        self.path.write_text('partial', encoding='utf-8')
        self.assertIsNone(agent.run_posture_scan())
        self.assertTrue(agent.store.get('baseline_details')['errors'])
        self.assertEqual(agent.recent_lynis_hits, [])

    @patch('tsa_dashboard.service_state', return_value='active')
    def test_dashboard_api_and_collector_expire_baseline_without_waiting_for_rescan(self, _service):
        self.report('warning[]=PKGS-7392|updates\n')
        agent = self.agent()
        agent.run_posture_scan()
        for key, value in {'fusion_status': 'running', 'fusion_heartbeat': time.time(),
                           'source_status': {'falco': True}}.items():
            agent.store.set(key, value)
        data = DashboardData(self.config_path)
        self.assertEqual(data.scores()['posture'], 85)
        details = agent.store.get('baseline_details')
        details['expires_at'] = time.time() - 1
        agent.store.set('baseline_details', details)
        self.assertIsNone(agent.scorer.final_score())
        self.assertIsNone(data.snapshot()['scores']['posture'])
        self.assertEqual(data.baseline()['status'], 'unavailable')
        with self.assertRaises(ValueError):
            data.scores()

    def test_future_report_is_unavailable(self):
        self.report()
        os.utime(self.path, (time.time() + 1000,) * 2)
        self.assertIsNone(self.agent().run_posture_scan())

    def test_baseline_endpoint_serves_evidence_and_unavailable_status(self):
        self.report('warning[]=AUTH-9283|passwordless\n')
        agent = self.agent()
        agent.run_posture_scan()
        server = DashboardServer(('127.0.0.1', 0), DashboardHandler)
        server.data = DashboardData(self.config_path)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port)
            try:
                connection.request('GET', '/systemManage/risk/baseline')
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload['data']['score'], 75)
                self.assertEqual(payload['data']['findings'][0]['control'], 'AUTH-9283')
                self.path.write_text('partial', encoding='utf-8')
                agent.run_posture_scan()
                connection.request('GET', '/systemManage/risk/baseline')
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload['data']['status'], 'unavailable')
                self.assertIsNone(payload['data']['score'])
            finally:
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
