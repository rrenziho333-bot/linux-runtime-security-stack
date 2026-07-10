import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from tsa_core import (
    RiskScorer,
    RotatingLineReader,
    StateStore,
    TSAFusionAgent,
    parse_lynis_report,
)


def falco_event(
    rule: str,
    *,
    priority: str = "WARNING",
    pid: int = 100,
    path: str = "/etc/example",
    tags=None,
):
    return {
        "time": "2026-01-01T00:00:00Z",
        "rule": rule,
        "priority": priority,
        "tags": tags or [],
        "output_fields": {
            "proc.pid": pid,
            "proc.name": "test-process",
            "proc.cmdline": "test-process --check",
            "user.name": "tester",
            "fd.name": path,
            "container.id": "host",
        },
    }


class RiskScorerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.db")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def scorer(self, runtime_rules=None, scoring=None):
        return RiskScorer(
            {
                "runtime_rules": {
                    "init_score": 100,
                    "event_control": {
                        "dedup_window": 10,
                        "max_points_per_minute": 30,
                    },
                    "priority_mapping": {"WARNING": 5},
                    **(runtime_rules or {}),
                },
                "scoring": scoring or {},
            },
            self.store,
        )

    def test_explicit_zero_does_not_fall_back_to_priority(self):
        scorer = self.scorer({"specific_rules": {"Ignored Rule": 0}})
        result = scorer.process_falco_event(
            falco_event("Ignored Rule", priority="WARNING"), received_at=100
        )
        self.assertEqual(result["status"], "ignored")
        self.assertEqual(result["deducted_points"], 0)
        self.assertEqual(scorer.runtime_score, 100)

    def test_maintenance_records_event_without_scoring(self):
        scorer = self.scorer({"specific_rules": {"Sensitive Rule": 10}})
        result = scorer.process_falco_event(
            falco_event("Sensitive Rule"),
            received_at=100,
            suppress_scoring=True,
        )
        self.assertEqual(result["status"], "maintenance")
        self.assertEqual(result["deducted_points"], 0)
        self.assertEqual(scorer.runtime_score, 100)

    def test_duplicate_event_is_only_scored_once_per_window(self):
        scorer = self.scorer({"specific_rules": {"Sensitive Rule": 10}})
        first = scorer.process_falco_event(falco_event("Sensitive Rule"), received_at=100)
        second = scorer.process_falco_event(falco_event("Sensitive Rule"), received_at=105)
        third = scorer.process_falco_event(falco_event("Sensitive Rule"), received_at=111)
        self.assertEqual(first["deducted_points"], 10)
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(second["deducted_points"], 0)
        self.assertEqual(third["deducted_points"], 10)
        self.assertEqual(scorer.runtime_score, 80)

    def test_per_rule_rate_limit_caps_distinct_events(self):
        scorer = self.scorer(
            {
                "specific_rules": {
                    "Sensitive Rule": {
                        "points": 10,
                        "dedup_window": 0,
                        "max_points_per_minute": 15,
                    }
                }
            }
        )
        first = scorer.process_falco_event(
            falco_event("Sensitive Rule", pid=1), received_at=100
        )
        second = scorer.process_falco_event(
            falco_event("Sensitive Rule", pid=2), received_at=101
        )
        third = scorer.process_falco_event(
            falco_event("Sensitive Rule", pid=3), received_at=102
        )
        self.assertEqual(first["deducted_points"], 10)
        self.assertEqual(second["deducted_points"], 5)
        self.assertEqual(third["status"], "rate_limited")
        self.assertEqual(scorer.runtime_score, 85)

    def test_weighted_final_score(self):
        scorer = self.scorer(
            {"event_control": {"max_active_points_per_rule": 100}},
            scoring={"weights": {"posture": 0.25, "runtime": 0.75}},
        )
        scorer.posture_score = 80
        now = time.time()
        self.store.record_event(
            received_time="2026-01-01T00:00:00+00:00",
            event_time="",
            source="falco",
            rule_name="active-risk",
            status="scored",
            deducted_points=40,
            event_key="active-risk",
            payload={},
            risk_expires_at=now + 60,
        )
        self.assertEqual(scorer.final_score(), 65)

    def test_bpf_lsm_events_are_scored_and_deduplicated(self):
        scorer = RiskScorer(
            {
                "runtime_rules": {"init_score": 100},
                "bpf_lsm": {
                    "action_points": {"audit": 2, "deny": 8},
                    "policy_points": {1001: {"deny": 10}},
                    "event_control": {
                        "dedup_window": 10,
                        "max_points_per_minute": 30,
                    },
                },
            },
            self.store,
        )
        event = {
            "received_time": "2026-01-01T00:00:00Z",
            "source": "bpf_lsm",
            "policy_id": 1001,
            "policy_name": "protect_tmp_rzh",
            "action": "deny",
            "operation": "write",
            "result": -1,
            "pid": 123,
            "uid": 1000,
            "device": 8,
            "inode": 99,
            "command": "writer",
        }
        first = scorer.process_bpf_lsm_event(event, received_at=100)
        second = scorer.process_bpf_lsm_event(event, received_at=105)
        self.assertEqual(first["deducted_points"], 10)
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(scorer.runtime_score, 90)

    def test_runtime_score_recovers_when_event_risk_expires(self):
        scorer = self.scorer(
            {
                "specific_rules": {
                    "Sensitive Rule": {
                        "points": 10,
                        "risk_ttl_seconds": 20,
                    }
                }
            }
        )
        scorer.process_falco_event(falco_event("Sensitive Rule"), received_at=100)
        self.assertEqual(scorer.runtime_score, 90)
        self.assertEqual(scorer.maybe_recover(now=119), 0)
        self.assertEqual(scorer.maybe_recover(now=121), 10)
        self.assertEqual(scorer.runtime_score, 100)


class RotatingLineReaderTests(unittest.TestCase):
    def test_follows_append_and_rotation_without_replaying_old_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "falco.json"
            log.write_text('{"old": true}\n', encoding="utf-8")
            store = StateStore(root / "state.db")
            reader = RotatingLineReader(log, store, start_at_end=True)
            try:
                self.assertIsNone(reader.readline())
                with log.open("a", encoding="utf-8") as output:
                    output.write('{"new": 1}\n')
                self.assertEqual(json.loads(reader.readline()), {"new": 1})

                os.replace(log, root / "falco.json.1")
                log.write_text('{"rotated": true}\n', encoding="utf-8")
                self.assertIsNone(reader.readline())
                self.assertEqual(json.loads(reader.readline()), {"rotated": True})
            finally:
                reader.close()
                store.close()


class LynisParserTests(unittest.TestCase):
    def test_parses_warning_and_suggestion(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "lynis.dat"
            report.write_text(
                "warning[]=PKGS-7392|Vulnerable package.|-|-|\n"
                "suggestion[]=SSH-7408|Harden SSH.|-|-|\n",
                encoding="utf-8",
            )
            warnings, suggestions = parse_lynis_report(report)
            self.assertEqual(warnings, [("PKGS-7392", "Vulnerable package.")])
            self.assertEqual(suggestions, [("SSH-7408", "Harden SSH.")])


class TSAIntegrationTests(unittest.TestCase):
    def test_state_and_report_survive_restart_for_both_event_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            falco_log = root / "falco.json"
            bpf_log = root / "bpf.jsonl"
            falco_log.touch()
            bpf_log.touch()
            config = root / "policy.yaml"
            config.write_text(
                f"""
storage:
  state_db: state/tsa.db
  report_path: reports/report.json
maintenance:
  file: {root / "maintenance-disabled"}
scoring:
  weights: {{posture: 0.4, runtime: 0.6}}
reporting:
  interval_seconds: 60
baseline_lynis:
  enabled: false
runtime_rules:
  enabled: true
  log_path: {falco_log}
  start_at_end: false
  event_control: {{dedup_window: 10, max_points_per_minute: 30}}
  specific_rules:
    Test Falco Rule: 5
  priority_mapping: {{WARNING: 5}}
bpf_lsm:
  enabled: true
  log_path: {bpf_log}
  start_at_end: false
  action_points: {{audit: 2, deny: 8}}
  event_control: {{dedup_window: 10, max_points_per_minute: 30}}
""",
                encoding="utf-8",
            )

            agent = TSAFusionAgent(str(config))
            try:
                agent.run_posture_scan()
                falco_result = agent.process_line(
                    json.dumps(falco_event("Test Falco Rule"))
                )
                bpf_result = agent.process_bpf_lsm_line(
                    json.dumps(
                        {
                            "received_time": "2026-01-01T00:00:00Z",
                            "source": "bpf_lsm",
                            "policy_id": 1,
                            "policy_name": "test",
                            "action": "deny",
                            "operation": "write",
                            "pid": 7,
                            "uid": 1000,
                            "device": 8,
                            "inode": 9,
                        }
                    )
                )
                self.assertEqual(falco_result["deducted_points"], 5)
                self.assertEqual(bpf_result["deducted_points"], 8)
                self.assertEqual(agent.scorer.runtime_score, 87)
                agent.generate_report("test")
            finally:
                agent.close()

            report = json.loads(
                (root / "reports" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["scores"]["runtime"], 87)
            self.assertEqual(
                {item["source"] for item in report["recent_security_events"]},
                {"falco", "bpf_lsm"},
            )

            restarted = TSAFusionAgent(str(config))
            try:
                self.assertEqual(restarted.scorer.runtime_score, 87)
            finally:
                restarted.close()


if __name__ == "__main__":
    unittest.main()
