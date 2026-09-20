import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tsa_core import StateStore
from tsa_dashboard import DashboardData


class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db_path = self.root / "state.db"
        store = StateStore(self.db_path)
        store.set("posture_score", 80)
        store.set("baseline_status", "ok")
        store.set("fusion_status", "running")
        store.set("fusion_heartbeat", time.time())
        store.set("source_status", {"falco": True})
        store.close()
        self.config = self.root / "tsa.yaml"
        self.config.write_text(
            """
storage:
  state_db: state.db
scoring:
  weights: {posture: 0.4, runtime: 0.6}
runtime_rules:
  event_control:
    max_active_points_per_rule: 20
""",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def insert_event(
        self,
        *,
        source,
        rule,
        payload,
        received_time="2026-01-01T00:00:00+00:00",
        points=0,
        status="scored",
        expires=None,
        event_time=None,
    ):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                """
                INSERT INTO events(
                    received_time, event_time, source, rule_name, status,
                    deducted_points, event_key, payload, risk_expires_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    received_time,
                    received_time if event_time is None else event_time,
                    source,
                    rule,
                    status,
                    points,
                    f"{source}:{rule}:{received_time}",
                    json.dumps(payload),
                    expires,
                ),
            )

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_snapshot_calculates_live_scores_and_component_status(self, _service):
        self.insert_event(
            source="falco",
            rule="Sensitive Rule",
            payload={"pid": 5, "process": "writer"},
            points=10,
            expires=time.time() + 60,
        )
        snapshot = DashboardData(self.config).snapshot()
        self.assertEqual(
            snapshot["scores"],
            {"final": 86.0, "posture": 80.0, "runtime": 90.0},
        )
        self.assertEqual([s["name"] for s in snapshot["pipeline"]], ["Falco", "Lynis", "TSA", "看板"])
        self.assertTrue(all(stage["active"] for stage in snapshot["pipeline"]))


    @patch("tsa_dashboard.service_state", return_value="active")
    def test_source_time_is_separate_from_ingestion_time(self, _service):
        source_time = "2026-09-12T11:17:26.971567484Z"
        received = "2026-09-12T11:17:28+00:00"
        self.insert_event(source="falco", rule="proxy", payload={"process": "curl"},
                          event_time=source_time, received_time=received)
        snapshot = DashboardData(self.config).snapshot()
        incident = snapshot["incidents"][0]
        self.assertEqual(incident["display_time"], source_time)
        self.assertEqual(incident["received_time"], received)
        self.assertEqual(incident["time"], received)
        self.assertEqual(incident["time_kind"], "falco_event")
        self.assertEqual(snapshot["event_window"]["records"], 1)
        self.assertFalse(snapshot["event_window"]["has_more"])

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_missing_source_time_is_labeled_as_ingestion_not_occurrence(self, _service):
        for source in ("falco",):
            self.insert_event(source=source, rule=source, payload={}, event_time="invalid")
        incidents = DashboardData(self.config).snapshot()["incidents"]
        self.assertEqual(len(incidents), 1)
        for incident in incidents:
            self.assertEqual(incident["time_kind"], "tsa_received")
            self.assertEqual(incident["display_time"], incident["received_time"])

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_repeated_rule_events_remain_identifiable_records(self, _service):
        for second in (1, 2):
            self.insert_event(source="falco", rule="proxy", payload={"process": "curl"},
                              received_time=f"2026-01-01T00:00:0{second}+00:00",
                              status="duplicate" if second == 2 else "scored",
                              points=0 if second == 2 else 2)
        incidents = DashboardData(self.config).snapshot()["incidents"]
        self.assertEqual([item["id"] for item in incidents], ["falco:2", "falco:1"])
        self.assertEqual([item["deducted_points"] for item in incidents], [0, 2])




    @patch("tsa_dashboard.service_state", return_value="active")
    def test_zero_weights_use_default_weights(self, _service):
        data = DashboardData(self.config)
        data.config["scoring"] = {"weights": {"posture": 0, "runtime": 0}}
        self.assertEqual(data.scores()["final"], 92)

    def test_similar_activity_summary_retains_all_evidence_and_zero_reasons(self):
        for n in range(1, 6):
            self.insert_event(source="falco", rule="Read sensitive file untrusted",
                              payload={"process": "gdm-session-wor", "file": f"/etc/pam.d/file{n}"},
                              received_time=f"2026-01-01T00:00:0{n}+00:00",
                              status="scored" if n <= 2 else "rate_limited", points=5 if n <= 2 else 0)
        data = DashboardData(self.config)
        with data._connect() as db:
            incidents = data._incidents(data._events(db))
        groups = data._summaries(incidents)
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group["record_count"], 5)
        self.assertEqual(group["deducted_points"], 10)
        self.assertEqual(group["status_counts"], {"rate_limited": 3, "scored": 2})
        self.assertEqual(len(group["targets"]), 5)
        self.assertEqual({m["id"] for m in group["members"]}, {f"falco:{i}" for i in range(1, 6)})
        self.assertEqual(group["id"], "falco:1")

    def test_summary_does_not_merge_different_identity_or_time_window(self):
        for pid, when in [(1, "00:00:00"), (2, "00:00:01"), (1, "00:01:00")]:
            self.insert_event(source="falco", rule="test", payload={"pid": pid}, received_time=f"2026-01-01T{when}+00:00")
        data = DashboardData(self.config)
        with data._connect() as db:
            self.assertEqual(len(data._summaries(data._incidents(data._events(db)))), 3)


    @patch("tsa_dashboard.service_state", return_value="active")
    def test_pagination_and_server_search_reach_events_beyond_first_page(self, _service):
        self.insert_event(source="falco", rule="target", payload={"pid": 77, "command": "unique-test"})
        for n in range(205):
            self.insert_event(source="falco", rule="noise", payload={"pid": 88})
        data = DashboardData(self.config)
        first = data.snapshot()
        self.assertEqual(len(first["incidents"]), 200)
        self.assertTrue(first["event_window"]["has_more"])
        second = data.snapshot(before=first["event_window"]["next_before"])
        self.assertEqual(len(second["incidents"]), 6)
        self.assertFalse(second["event_window"]["has_more"])
        self.assertEqual(len(data.snapshot(pid=77)["incidents"]), 1)
        self.assertEqual(len(data.snapshot(query="unique-test")["incidents"]), 1)
        self.assertEqual(len(data.snapshot(pid=77, after=1)["incidents"]), 0)
        self.assertEqual(len(data.snapshot(query="' OR 1=1 --")["incidents"]), 0)

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_legacy_enforcement_records_are_retained_but_not_scored_or_shown(self, _service):
        self.insert_event(source="bpf_lsm", rule="legacy", payload={}, points=20, expires=time.time() + 60)
        self.insert_event(source="falco", rule="current", payload={}, points=5, expires=time.time() + 60)
        data = DashboardData(self.config)
        snapshot = data.snapshot()
        self.assertEqual(snapshot["scores"]["runtime"], 95)
        self.assertEqual(snapshot["event_window"]["records"], 1)
        self.assertEqual(snapshot["incidents"][0]["sources"], ["falco"])
        store = StateStore(self.db_path)
        try:
            self.assertEqual(store.active_risk_points(time.time(), 20), 5)
            self.assertEqual(len(store.recent_events()), 1)
            self.assertEqual(store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)
        finally:
            store.close()
        self.assertFalse(any("bpf-lsm-controller" in str(call) for call in _service.call_args_list))

    def test_payload_cannot_override_evidence_identity(self):
        self.insert_event(source="falco", rule="real", payload={"id": 999, "source": "bpf_lsm", "deducted_points": 999})
        data = DashboardData(self.config)
        with data._connect() as db:
            event = data._events(db)[0]
        self.assertEqual((event["id"], event["source"], event["deducted_points"]), (1, "falco", 0))

    def test_processing_steps_do_not_confuse_historical_and_current_deductions(self):
        event = {'status':'scored', 'deducted_points':10}
        self.assertIn('历史新增扣分 10', DashboardData._tsa_step(event))
        event['current_policy_note'] = '已匹配只读系统上下文'
        self.assertIn('当前策略不计风险', DashboardData._tsa_step(event))
        self.assertIn('历史扣分 10', DashboardData._tsa_step(event))
        self.assertIn('旧记录未保存', DashboardData._tsa_step({'status':'risk_refreshed'}))
        self.assertIn('测试封顶原因', DashboardData._tsa_step({
            'status':'risk_refreshed', 'score_effect':{'explanation':'测试封顶原因'}}))

    def test_expired_evidence_keeps_history_but_explains_current_exclusion(self):
        self.insert_event(source='falco', rule='test', payload={}, points=10, expires=time.time() - 1)
        data = DashboardData(self.config)
        with data._connect() as db:
            event = data._events(db)[0]
        self.assertEqual(event['deducted_points'], 10)
        self.assertEqual(event['status'], 'scored')
        self.assertIn('不代表风险已经处置', event['current_policy_note'])


if __name__ == "__main__":
    unittest.main()
