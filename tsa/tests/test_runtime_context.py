import copy
import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import yaml

from runtime_context import advisory_reason, apply_signal_budget, score_effect, validate_runtime_config
from tsa_core import RiskScorer, StateStore, runtime_risk_breakdown
from tsa_dashboard import DashboardData
from verify_runtime import RULE, SHM_RULE


ROOT = Path(__file__).resolve().parents[2]
CONFIG = yaml.safe_load((ROOT / 'tsa/policy_config.yaml').read_text(encoding='utf-8'))
NAMES = {'process':'proc.name', 'executable':'proc.exepath', 'parent':'proc.pname',
         'command':'proc.cmdline', 'file':'fd.name', 'uid':'user.uid', 'container_id':'container.id',
         'syscall':'evt.type', 'is_open_write':'evt.is_open_write', 'syscall_result':'evt.rawres'}


class ContextScoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name) / 'state.db')
        self.addCleanup(self.store.close)
        self.config = copy.deepcopy(CONFIG)
        self.scorer = RiskScorer(self.config, self.store)
        self.now = time.time()

    def emit(self, rule, evidence=None, now=None):
        fields = {NAMES[k]: v for k, v in (evidence or {}).items()}
        fields['proc.pid'] = 123
        when = self.now if now is None else now
        return self.scorer.process_falco_event({'rule':rule, 'priority':'CRITICAL',
            'time':datetime.fromtimestamp(when, timezone.utc).isoformat(), 'output_fields':fields}, received_at=when)

    def context(self, policy):
        return {**{k:v[0] for k,v in policy['match'].items()}, 'syscall':'openat',
                'is_open_write':False, 'syscall_result':3}

    def test_all_expected_contexts_are_preserved_without_scoring(self):
        for policy in self.config['runtime_rules']['context_advisories']:
            with self.subTest(reason=policy['reason']):
                result = self.emit(policy['rule'], self.context(policy))
                self.assertEqual(result['status'], 'context_advisory')
                self.assertEqual(result['deducted_points'], 0)
                self.assertEqual(result['reason'], policy['reason'])
                self.assertEqual(self.scorer.runtime_score, 100)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 4)

    def test_every_required_field_must_be_present_and_exact(self):
        runtime = self.config['runtime_rules']
        for policy in runtime['context_advisories']:
            for key in policy['match']:
                original = self.context(policy)
                for missing in (False, True):
                    evidence = dict(original)
                    if missing:
                        evidence.pop(key)
                    else:
                        evidence[key] = 1000 if key == 'uid' else 'untrusted'
                    with self.subTest(policy=policy['reason'], key=key, missing=missing):
                        self.assertIsNone(advisory_reason(policy['rule'], evidence, runtime))

    def test_write_failed_unknown_and_other_rule_are_not_exempt(self):
        runtime = self.config['runtime_rules']
        policy = runtime['context_advisories'][1]
        for patch in ({'is_open_write':True}, {'syscall_result':-13}, {'syscall_result':None},
                      {'syscall_result':True}, {'syscall':'write'}, {'uid':'0'}, {'container_id':'container123'}):
            self.assertIsNone(advisory_reason(policy['rule'], {**self.context(policy), **patch}, runtime))
        self.assertIsNone(advisory_reason('Write below binary dir', self.context(policy), runtime))

    def test_renamed_program_and_changed_target_still_score(self):
        policy = self.config['runtime_rules']['context_advisories'][1]
        evidence = self.context(policy)
        evidence.update(process='vmtoolsd', executable='/tmp/vmtoolsd')
        result = self.emit(policy['rule'], evidence)
        self.assertEqual(result['deducted_points'], 5)
        self.assertEqual(result['status'], 'scored')
        traversal = self.config['runtime_rules']['context_advisories'][0]
        evidence = self.context(traversal)
        evidence['file'] = '/etc/shadow'
        self.assertEqual(self.emit(traversal['rule'], evidence)['deducted_points'], 10)

    def test_expected_read_does_not_erase_or_renew_unrelated_risk(self):
        policy = self.config['runtime_rules']['context_advisories'][1]
        self.emit(policy['rule'], {'executable':'/tmp/reader'})
        self.emit(policy['rule'], self.context(policy), now=self.now + 3500)
        self.assertEqual(self.scorer.runtime_score, 95)
        self.scorer.refresh_runtime_score(self.now + 3601)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_historical_context_reassessment_preserves_audit_and_unknown_evidence(self):
        policy = self.config['runtime_rules']['context_advisories'][1]
        old = copy.deepcopy(self.config)
        old['runtime_rules'].pop('context_advisories')
        self.scorer = RiskScorer(old, self.store)
        self.assertEqual(self.emit(policy['rule'], self.context(policy))['deducted_points'], 5)
        history = tuple(self.store.db.execute('SELECT deducted_points,payload FROM events').fetchone())
        self.assertEqual(runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now), [])
        self.assertEqual(tuple(self.store.db.execute('SELECT deducted_points,payload FROM events').fetchone()), history)
        self.emit(policy['rule'], {'executable':'/tmp/unknown'})
        risks = runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now)
        self.assertEqual(risks[0]['points'], 5)
        self.assertEqual(risks[0]['evidence_count'], 1)

    def test_weak_budget_does_not_limit_strong_signals(self):
        budget = self.config['runtime_rules']['signal_budget']
        for rule in budget['rules']:
            self.emit(rule)
        self.assertEqual(self.scorer.runtime_score, 85)
        risks = runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now)
        self.assertEqual(sum(r['rule_points'] for r in risks), 30)
        self.assertEqual(sum(r['points'] for r in risks), 15)
        self.assertEqual(len(risks), 5)
        self.emit('Reverse Shell from Web Server')
        self.assertEqual(self.scorer.runtime_score, 65)
        self.assertEqual(self.store.db.execute('SELECT SUM(deducted_points) FROM events').fetchone()[0], 35)

    def test_budget_order_does_not_change_final_score_and_repeats_do_not_multiply(self):
        rules = self.config['runtime_rules']['signal_budget']['rules']
        for rule in reversed(rules):
            self.emit(rule)
            self.emit(rule)
        self.assertEqual(self.scorer.runtime_score, 85)
        risks = runtime_risk_breakdown(self.store.db, self.config['runtime_rules'], self.now)
        self.assertEqual(apply_signal_budget(risks, self.config['runtime_rules']), risks)
        self.scorer.refresh_runtime_score(self.now + 14401)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_two_live_examples_score_ten_each_and_repeats_only_renew(self):
        result = self.emit(RULE)
        self.assertEqual(result['status'], 'scored')
        self.assertEqual(result['deducted_points'], 10)
        self.assertEqual(self.scorer.runtime_score, 90)
        self.assertEqual(self.emit(RULE)['deducted_points'], 0)
        self.assertEqual(self.scorer.runtime_score, 90)
        self.assertEqual(self.emit(SHM_RULE)['deducted_points'], 10)
        self.assertEqual(self.scorer.runtime_score, 80)
        self.assertEqual(self.emit(SHM_RULE)['deducted_points'], 0)
        self.assertEqual(self.scorer.runtime_score, 80)
        self.scorer.refresh_runtime_score(self.now + 901)
        self.assertEqual(self.scorer.runtime_score, 90)
        self.scorer.refresh_runtime_score(self.now + 14401)
        self.assertEqual(self.scorer.runtime_score, 100)

    def test_historical_test_only_records_are_not_retroactively_charged(self):
        self.config['runtime_rules']['specific_rules'][RULE]['test_only'] = True
        self.assertEqual(self.emit(RULE)['status'], 'test_event')
        self.config['runtime_rules']['specific_rules'][RULE]['test_only'] = False
        self.scorer.refresh_runtime_score(self.now)
        self.assertEqual(self.scorer.runtime_score, 100)
        self.assertEqual(self.emit(RULE)['deducted_points'], 10)

    def test_live_examples_use_the_same_dashboard_weighted_scores(self):
        data = object.__new__(DashboardData)
        data.config = self.config
        state = {'posture_score':85, 'baseline_status':'ok'}
        weights = {'posture':0.4, 'runtime':0.6}
        for rule, runtime, final in [(None,100,94),(RULE,90,88),(RULE,90,88),
                                     (SHM_RULE,80,82),(SHM_RULE,80,82)]:
            if rule:
                self.emit(rule)
            self.assertEqual(data._scores(self.store.db,state,weights=weights),
                             {'posture':85.0,'runtime':float(runtime),'final':float(final)})

    def test_unsafe_configuration_is_rejected(self):
        runtime = copy.deepcopy(self.config['runtime_rules'])
        runtime['context_advisories'][0]['match'] = {'process':['vmtoolsd']}
        with self.assertRaises(ValueError):
            advisory_reason('Read sensitive file untrusted', {}, runtime)
        runtime = copy.deepcopy(self.config['runtime_rules'])
        runtime['context_advisories'][0]['match']['executable'] = [42]
        with self.assertRaises(ValueError):
            advisory_reason('Read sensitive file untrusted', {}, runtime)
        for cap in (0, -1, True, '15'):
            runtime['signal_budget']['max_points'] = cap
            with self.assertRaises(ValueError):
                apply_signal_budget([], runtime)

    def test_missing_host_identity_is_not_invented_during_storage(self):
        policy = self.config['runtime_rules']['context_advisories'][1]
        evidence = self.context(policy)
        evidence.pop('container_id')
        result = self.emit(policy['rule'], evidence)
        self.assertEqual(result['deducted_points'], 5)
        self.assertEqual(self.scorer.runtime_score, 95)
        stored = json.loads(self.store.db.execute('SELECT payload FROM events').fetchone()[0])
        self.assertIsNone(stored['container_id'])
        self.scorer.refresh_runtime_score(self.now + 1)
        self.assertEqual(self.scorer.runtime_score, 95)

    def test_all_advisories_are_validated_even_after_a_match(self):
        runtime = copy.deepcopy(self.config['runtime_rules'])
        runtime['context_advisories'].append({'rule':'typo', 'match':{}})
        first = runtime['context_advisories'][0]
        with self.assertRaises(ValueError):
            advisory_reason(first['rule'], self.context(first), runtime)

    def test_bad_rule_references_and_duplicates_fail_at_startup(self):
        for section in ('context_advisories', 'signal_budget'):
            cfg = copy.deepcopy(self.config)
            if section == 'context_advisories':
                cfg['runtime_rules'][section][0]['rule'] = 'misspelled rule'
            else:
                cfg['runtime_rules'][section]['rules'].append('misspelled rule')
            with self.subTest(section=section), self.assertRaises(ValueError):
                RiskScorer(cfg, self.store)
        runtime = copy.deepcopy(self.config['runtime_rules'])
        runtime['signal_budget']['rules'].append(runtime['signal_budget']['rules'][0])
        with self.assertRaises(ValueError):
            validate_runtime_config(runtime)

    def test_marginal_deduction_causes_distinguish_all_caps(self):
        for args, causes, points in [
            ((5, 5, 15, 15), ['same_rule_active'], 0),
            ((0, 5, 15, 15), ['weak_signal_budget'], 0),
            ((0, 15, 100, 115), ['runtime_score_floor'], 0),
            ((0, 10, 98, 103), ['weak_signal_budget', 'runtime_score_floor'], 2),
            ((0, 10, 0, 10), [], 10),
        ]:
            with self.subTest(args=args):
                effect = score_effect(*args)
                self.assertEqual(effect['causes'], causes)
                self.assertEqual(effect['deducted_points'], points)

    def test_zero_deduction_explanation_is_persisted(self):
        self.emit('Known Cryptominer Process Executed')
        repeated = self.emit('Known Cryptominer Process Executed')
        self.assertEqual(repeated['score_effect']['causes'], ['same_rule_active'])
        self.emit('Detect crypto miners using the Stratum protocol')
        capped = self.emit('Remove Bulk Data from Disk')
        self.assertEqual(capped['score_effect']['causes'], ['weak_signal_budget'])
        payload = json.loads(self.store.db.execute('SELECT payload FROM events ORDER BY id DESC').fetchone()[0])
        self.assertEqual(payload['score_effect'], capped['score_effect'])


if __name__ == '__main__':
    unittest.main()
