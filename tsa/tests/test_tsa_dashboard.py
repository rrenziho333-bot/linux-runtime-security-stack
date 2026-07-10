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
        self.policy = self.root / "bpf.yaml"
        self.policy.write_text(
            """
version: 1
policies:
  - id: 1001
    name: protect_test
    mode: audit
    paths: [/etc/test]
    allowed_uids: []
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
                    received_time,
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
    def test_snapshot_calculates_live_scores_and_loads_policy(self, _service):
        self.insert_event(
            source="falco",
            rule="Sensitive Rule",
            payload={"pid": 5, "process": "writer"},
            points=10,
            expires=time.time() + 60,
        )
        snapshot = DashboardData(self.config, self.policy).snapshot()
        self.assertEqual(
            snapshot["scores"],
            {"final": 86.0, "posture": 80.0, "runtime": 90.0},
        )
        self.assertEqual(snapshot["policies"][0]["mode"], "audit")
        self.assertTrue(all(stage["active"] for stage in snapshot["pipeline"]))

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_bpf_and_falco_events_form_one_evidence_chain(self, _service):
        self.insert_event(
            source="falco",
            rule="Write below etc",
            payload={"pid": 77, "process": "tee"},
            received_time="2026-01-01T00:00:01+00:00",
            points=10,
            expires=time.time() + 60,
        )
        self.insert_event(
            source="bpf_lsm",
            rule="bpf_lsm:protect_test:audit",
            payload={
                "pid": 77,
                "command": "tee",
                "action": "audit",
                "operation": "write",
                "policy_name": "protect_test",
            },
            received_time="2026-01-01T00:00:02+00:00",
            points=2,
            expires=time.time() + 60,
        )
        incidents = DashboardData(self.config, self.policy).snapshot()["incidents"]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["decision"], "审计放行")
        self.assertIn("falco", incidents[0]["evidence"])
        self.assertIn("操作继续执行", " ".join(incidents[0]["steps"]))

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_missing_falco_pid_falls_back_to_process_path_and_time(self, _service):
        self.insert_event(
            source="falco",
            rule="Write below etc",
            payload={"pid": "", "process": "tee", "file": "/etc/test"},
            received_time="2026-01-01T00:00:01+00:00",
        )
        self.insert_event(
            source="bpf_lsm",
            rule="bpf_lsm:protect_test:audit",
            payload={
                "pid": 77,
                "command": "tee",
                "action": "audit",
                "operation": "write",
                "policy_name": "protect_test",
            },
            received_time="2026-01-01T00:00:02+00:00",
        )
        incident = DashboardData(self.config, self.policy).snapshot()["incidents"][0]
        self.assertIn("进程名 + 保护路径 + 时间", " ".join(incident["steps"]))
        self.assertIn("falco", incident["evidence"])

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_deny_is_described_as_kernel_block(self, _service):
        self.insert_event(
            source="bpf_lsm",
            rule="bpf_lsm:protect_test:deny",
            payload={
                "pid": 88,
                "command": "writer",
                "action": "deny",
                "operation": "unlink",
                "policy_name": "protect_test",
            },
            points=8,
            expires=time.time() + 60,
        )
        incident = DashboardData(self.config, self.policy).snapshot()["incidents"][0]
        self.assertEqual(incident["decision"], "已拦截")
        self.assertIn("-EPERM", " ".join(incident["steps"]))


if __name__ == "__main__":
    unittest.main()
