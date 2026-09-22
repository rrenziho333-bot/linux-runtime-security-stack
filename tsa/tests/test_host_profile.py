import copy
import importlib.util
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

from tsa_core import RiskScorer, StateStore, runtime_risk_breakdown
from tsa_dashboard import DashboardData


ROOT = Path(__file__).resolve().parents[2]
CONFIG = yaml.safe_load((ROOT / 'tsa/policy_config.yaml').read_text(encoding='utf-8'))
SPEC = importlib.util.spec_from_file_location('profile_rules', ROOT / 'falco/manage_rules.py')
RULES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RULES)


class HostProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name) / 'state.db')
        self.addCleanup(self.store.close)
        self.config = copy.deepcopy(CONFIG)
        self.scorer = RiskScorer(self.config, self.store)
        self.now = time.time()

    def event(self, rule, when=None, pid=10):
        return {'rule': rule, 'priority': 'EMERGENCY', 'tags': ['T1555'],
                'time': datetime.fromtimestamp(self.now if when is None else when, timezone.utc).isoformat(),
                'output_fields': {'proc.pid': pid, 'proc.name': 'test', 'fd.name': '/test'}}

    def emit(self, rule, when=None, received=None, pid=10):
        return self.scorer.process_falco_event(self.event(rule, when, pid),
                                              received_at=self.now if received is None else received)

    def test_exactly_thirty_enabled_rules_have_explicit_positive_scoring(self):
        bundle = RULES.load_bundle(ROOT / 'falco')
        enabled = RULES.enabled_bundle_rules(bundle)
        specific = self.config['runtime_rules']['specific_rules']
        self.assertEqual(len(enabled), 30)
        self.assertEqual(enabled, set(specific))
        self.assertEqual(sum(RULES.rule_count(v) for v in bundle.values()), 94)
        for policy in specific.values():
            self.assertGreater(policy['points'], 0)
            self.assertLessEqual(policy['points'], 20)
            self.assertGreater(policy['risk_ttl_seconds'], 0)
            self.assertTrue(policy['reason'])

    def test_all_thirty_rule_weights_ignore_priority_and_tags(self):
        for rule, policy in self.config['runtime_rules']['specific_rules'].items():
            with self.subTest(rule=rule):
                self.store.db.execute('DELETE FROM events')
                self.store.db.commit()
                result = self.emit(rule)
                self.assertEqual(result['deducted_points'], policy['points'])
                self.assertEqual(self.scorer.runtime_score, 100 - policy['points'])
                risks = runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now)
                self.assertEqual(risks[0]['reason'], policy['reason'])

    def test_repetitions_with_new_pids_or_paths_do_not_multiply_risk(self):
        rule = 'Read sensitive file untrusted'
        self.assertEqual(self.emit(rule)['deducted_points'], 5)
        for pid in range(20, 70):
            result = self.emit(rule, when=self.now + pid, received=self.now + pid, pid=pid)
            self.assertEqual(result['status'], 'risk_refreshed')
            self.assertEqual(result['deducted_points'], 0)
        self.assertEqual(self.scorer.runtime_score, 95)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 51)
        self.scorer.refresh_runtime_score(self.now + 3601)
        self.assertEqual(self.scorer.runtime_score, 95)
        self.scorer.refresh_runtime_score(self.now + 3670)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_name_environment_and_argument_only_signals_are_low_weight(self):
        rules = ('Known Cryptominer Process Executed', 'Remove Bulk Data from Disk',
                 'Polkit Local Privilege Escalation Vulnerability (CVE-2021-4034)',
                 'Potential Local Privilege Escalation via Environment Variables Misuse')
        for rule in rules:
            with self.subTest(rule=rule):
                self.store.db.execute('DELETE FROM events')
                self.store.db.commit()
                result = self.emit(rule)
                self.assertEqual(result['deducted_points'], 5)
                self.assertEqual(self.scorer.runtime_score, 95)
                self.assertEqual(self.emit(rule, pid=11)['deducted_points'], 0)
                self.assertEqual(self.scorer.runtime_score, 95)

    def test_protocol_arguments_rank_above_names_below_combined_web_shell_signal(self):
        specific = self.config['runtime_rules']['specific_rules']
        self.assertEqual(specific['Detect crypto miners using the Stratum protocol']['points'], 10)
        self.assertLess(specific['Known Cryptominer Process Executed']['points'], 10)
        self.assertEqual(specific['Reverse Shell from Web Server']['points'], 20)

    def test_lower_weights_apply_to_old_active_risk_without_rewriting_history(self):
        rule = 'Known Cryptominer Process Executed'
        old_config = copy.deepcopy(self.config)
        old_config['runtime_rules']['specific_rules'][rule]['points'] = 15
        old_scorer = RiskScorer(old_config, self.store)
        old_scorer.process_falco_event(self.event(rule), received_at=self.now)
        self.assertEqual(old_scorer.runtime_score, 85)
        updated = RiskScorer(self.config, self.store)
        updated.refresh_runtime_score(self.now)
        self.assertEqual(updated.runtime_score, 95)
        row = self.store.db.execute('SELECT deducted_points, risk_points, risk_expires_at FROM events').fetchone()
        self.assertEqual((row['deducted_points'], row['risk_points']), (15, 15))
        self.assertAlmostEqual(row['risk_expires_at'], self.now + 14400, places=5)
        data = object.__new__(DashboardData)
        data.config = self.config
        with patch('tsa_dashboard.time.time', return_value=self.now):
            scores = data._scores(self.store.db, {'posture_score': 85, 'baseline_status': 'ok'})
        self.assertEqual(scores, {'runtime': 95, 'posture': 85, 'final': 91})

    def test_documented_runtime_weights_match_deployed_configuration(self):
        text = (ROOT / 'docs/FALCO_RULES_README.md').read_text(encoding='utf-8')
        for rule, policy in CONFIG['runtime_rules']['specific_rules'].items():
            value = f'实际 0；独立验收 {policy["points"]}' if policy.get('test_only') else str(policy['points'])
            self.assertIn(f'| `{rule}` | {value} |', text)

    def test_different_rules_add_and_full_high_risk_is_not_minute_truncated(self):
        self.assertEqual(self.emit('Reverse Shell from Web Server')['deducted_points'], 20)
        self.assertEqual(self.emit('Read sensitive file untrusted')['deducted_points'], 5)
        self.assertEqual(self.scorer.runtime_score, 75)

    def test_alert_after_expiry_deducts_again(self):
        rule = 'Monitor specific file access'
        self.emit(rule)
        result = self.emit(rule, when=self.now + 901, received=self.now + 901)
        self.assertEqual(result['deducted_points'], 10)
        self.assertEqual(result['status'], 'scored')

    def test_delayed_event_uses_occurrence_time_not_ingestion_time(self):
        self.emit('Monitor specific file access', when=self.now - 890)
        self.scorer.refresh_runtime_score(self.now + 11)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_expired_backlog_is_evidence_only(self):
        result = self.emit('Monitor specific file access', when=self.now - 901)
        self.assertEqual(result['status'], 'expired')
        self.assertEqual(result['deducted_points'], 0)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_invalid_missing_naive_and_future_times_are_not_silently_scored(self):
        for timestamp in ('', 'invalid', '2026-09-18T00:00:00',
                          datetime.fromtimestamp(self.now + 301, timezone.utc).isoformat()):
            with self.subTest(timestamp=timestamp):
                event = self.event('Monitor specific file access')
                event['time'] = timestamp
                result = self.scorer.process_falco_event(event, received_at=self.now)
                self.assertEqual(result['status'], 'invalid_time')
                self.assertEqual(result['deducted_points'], 0)

    def test_small_clock_skew_cannot_extend_ttl_into_future(self):
        self.emit('Monitor specific file access', when=self.now + 100)
        self.scorer.refresh_runtime_score(self.now + 901)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_falco_nanosecond_timestamp_supported_on_python310(self):
        event = self.event('Monitor specific file access')
        event['time'] = datetime.fromtimestamp(self.now, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f') + '484Z'
        result = self.scorer.process_falco_event(event, received_at=self.now)
        self.assertEqual(result['status'], 'scored')
        self.assertEqual(result['deducted_points'], 10)

    @patch('tsa_dashboard.service_state', return_value='active')
    def test_invalid_time_marks_monitoring_unavailable_until_valid_evidence(self, _service):
        data = object.__new__(DashboardData)
        data.config = self.config
        state = {'fusion_status': 'running', 'fusion_heartbeat': self.now,
                 'source_status': {'falco': True}, 'baseline_status': 'ok', 'posture_score': 85}
        self.emit('Monitor specific file access', when=self.now + 500)
        state['runtime_time_error_at'] = self.store.get('runtime_time_error_at')
        self.assertFalse(data._availability(state)['runtime_ready'])
        self.emit('Monitor specific file access', when=self.now + 1, received=self.now + 1)
        state['runtime_valid_time_at'] = self.store.get('runtime_valid_time_at')
        self.assertTrue(data._availability(state)['runtime_ready'])

    def test_unknown_rule_is_preserved_without_priority_or_tag_fallback(self):
        result = self.emit('New unreviewed rule')
        self.assertEqual(result['status'], 'ignored')
        self.assertEqual(result['deducted_points'], 0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)

    def test_maintenance_never_renews_existing_risk(self):
        rule = 'Monitor specific file access'
        self.emit(rule)
        result = self.scorer.process_falco_event(self.event(rule, self.now + 899),
                                                received_at=self.now + 899, suppress_scoring=True)
        self.assertEqual(result['status'], 'maintenance')
        self.scorer.refresh_runtime_score(self.now + 901)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_removed_rule_history_does_not_contribute_after_upgrade(self):
        self.store.record_event(received_time='old', event_time='', source='falco',
                                rule_name='Unexpected UDP Traffic', status='scored',
                                deducted_points=20, event_key='old', payload={},
                                risk_expires_at=self.now + 100)
        self.scorer.refresh_runtime_score(self.now)
        self.assertEqual(self.scorer.runtime_score, 100)
        self.assertEqual(self.store.db.execute('SELECT deducted_points FROM events').fetchone()[0], 20)

    def test_legacy_selected_rule_history_is_capped_without_rewriting_evidence(self):
        for index in range(3):
            self.store.record_event(received_time='old', event_time='', source='falco',
                                    rule_name='Read sensitive file untrusted', status='scored',
                                    deducted_points=10, event_key=str(index), payload={},
                                    risk_expires_at=self.now + 100)
        self.scorer.refresh_runtime_score(self.now)
        self.assertEqual(self.scorer.runtime_score, 95)
        self.assertEqual(self.store.db.execute('SELECT SUM(deducted_points) FROM events').fetchone()[0], 30)

    def test_score_floor_and_historical_deltas_do_not_exceed_one_hundred(self):
        for rule in self.config['runtime_rules']['specific_rules']:
            self.emit(rule)
        self.assertEqual(self.scorer.runtime_score, 0)
        self.assertEqual(self.store.db.execute('SELECT SUM(deducted_points) FROM events').fetchone()[0], 100)
        self.assertEqual(len(runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now)), 30)

    def test_collector_restart_and_dashboard_use_same_breakdown(self):
        self.emit('Reverse Shell from Web Server')
        self.emit('Reverse Shell from Web Server', pid=11)
        self.emit('Read sensitive file untrusted')
        self.scorer.set_posture_score(85)
        restored = RiskScorer(self.config, self.store)
        self.assertEqual(restored.runtime_score, 75)
        data = object.__new__(DashboardData)
        data.config = self.config
        with patch('tsa_dashboard.time.time', return_value=self.now):
            scores = data._scores(self.store.db, {'posture_score': 85, 'baseline_status': 'ok'})
        self.assertEqual(scores, {'runtime': 75, 'posture': 85, 'final': 79})

    def test_read_only_pre_migration_database_remains_compatible(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE events(rule_name TEXT, source TEXT, status TEXT, deducted_points INTEGER, risk_expires_at REAL)')
        db.execute('INSERT INTO events VALUES (?, ?, ?, ?, ?)',
                   ('Read sensitive file untrusted', 'falco', 'scored', 10, self.now + 60))
        self.assertEqual(runtime_risk_breakdown(db, self.config['runtime_rules'], self.now)[0]['points'], 5)


if __name__ == '__main__':
    unittest.main()
