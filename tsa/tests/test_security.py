import json
import itertools
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import yaml

from tsa_core import RiskScorer, RotatingLineReader, StateStore, TSAFusionAgent
from tsa_dashboard import DashboardData, DashboardHandler, DashboardServer


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "config.yaml"
        self.config = {
            "storage": {"state_db": "state.db", "report_path": "report.json"},
            "maintenance": {"file": "maintenance"},
            "baseline_lynis": {"enabled": True, "report_path": "lynis.dat"},
            "runtime_rules": {"enabled": True, "log_path": "falco.json",
                              "start_at_end": False, "specific_rules": {"test": 5}},
            "bpf_lsm": {"enabled": False, "log_path": "bpf.jsonl"},
        }
        self.write_config()
        self.event = {"rule": "test", "priority": "WARNING", "output_fields": {"proc.pid": 42}}

    def write_config(self):
        self.config_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")

    def agent(self, **kwargs):
        agent = TSAFusionAgent(str(self.config_path), **kwargs)
        self.addCleanup(agent.close)
        return agent

    def mark_ready(self, store):
        store.set("posture_score", 80)
        store.set("baseline_status", "ok")
        store.set("fusion_status", "running")
        store.set("fusion_heartbeat", time.time())
        store.set("source_status", {"falco": True, "bpf_lsm": True})

    def test_scoring_transaction_rolls_back_dedup_after_insert_failure(self):
        agent = self.agent()
        with patch.object(agent.store, "record_event", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                agent.process_line(json.dumps(self.event))
        self.assertEqual(agent.store.db.execute("SELECT COUNT(*) FROM dedup_windows").fetchone()[0], 0)
        self.assertEqual(agent.process_line(json.dumps(self.event))["deducted_points"], 5)

    def test_unacknowledged_event_is_replayed_after_restart(self):
        (self.root / "falco.json").write_text(json.dumps(self.event) + "\n", encoding="utf-8")
        agent = self.agent()
        reader = agent.readers[0][1]
        line = reader.readline()
        self.assertEqual(agent.store.get("falco_log.offset"), 0)
        reader.close()
        restarted = RotatingLineReader(reader.path, agent.store, start_at_end=False)
        self.addCleanup(restarted.close)
        self.assertEqual(restarted.readline(), line)
        with agent.store.transaction():
            agent.process_line(line)
            restarted.acknowledge()
        self.assertGreater(agent.store.get("falco_log.offset"), 0)

    def test_cursor_and_event_rollback_together(self):
        (self.root / "falco.json").write_text(json.dumps(self.event) + "\n", encoding="utf-8")
        agent = self.agent()
        reader = agent.readers[0][1]
        line = reader.readline()
        with self.assertRaises(RuntimeError):
            with agent.store.transaction():
                agent.process_line(line)
                reader.acknowledge()
                raise RuntimeError("simulated failure before commit")
        self.assertEqual(agent.store.get("falco_log.offset"), 0)
        self.assertEqual(agent.store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_copytruncate_reads_from_start(self):
        path = self.root / "falco.json"
        path.write_text("long original record\n", encoding="utf-8")
        agent = self.agent()
        reader = agent.readers[0][1]
        reader.readline()
        reader.acknowledge()
        path.write_text("new\n", encoding="utf-8")
        self.assertIsNone(reader.readline())
        self.assertEqual(reader.readline(), "new\n")

    @unittest.skipIf(os.name == "nt", "POSIX rotation semantics")
    def test_rotation_after_partial_line_does_not_stall(self):
        path = self.root / "falco.json"
        path.write_text("partial", encoding="utf-8")
        agent = self.agent()
        reader = agent.readers[0][1]
        self.assertIsNone(reader.readline())
        path.rename(self.root / "old.json")
        path.write_text("new\n", encoding="utf-8")
        self.assertIsNone(reader.readline())
        self.assertEqual(reader.readline(), "new\n")

    def test_oversized_event_is_bounded_and_next_event_is_read(self):
        path = self.root / "falco.json"
        path.write_text("x" * 40 + "\nnext\n", encoding="utf-8")
        reader = self.agent().readers[0][1]
        reader.MAX_LINE_LENGTH = 10
        for _ in range(3):
            self.assertIsNone(reader.readline())
        self.assertEqual(reader.readline(), "")
        reader.acknowledge()
        self.assertEqual(reader.readline(), "next\n")

    def test_missing_empty_or_stale_baseline_never_scores_100(self):
        agent = self.agent()
        path = self.root / "lynis.dat"
        for case in ("missing", "empty", "invalid", "partial", "stale"):
            with self.subTest(case=case):
                if case != "missing":
                    body = "report_version_major=1\n" if case in ("stale", "partial") else ("" if case == "empty" else "junk\n")
                    path.write_text(body, encoding="utf-8")
                    if case == "stale":
                        os.utime(path, (1, 1))
                self.assertIsNone(agent.run_posture_scan())
                self.assertIsNone(agent.scorer.final_score())
                self.assertEqual(agent.store.get("baseline_status"), "unavailable")

    def test_valid_baseline_is_scored(self):
        (self.root / "lynis.dat").write_text("report_version_major=1\nwarning[]=TEST-1|example\nfinish=true\n", encoding="utf-8")
        self.config["baseline_lynis"]["default_deduct"] = {"warning": 10}
        self.write_config()
        agent = self.agent()
        self.assertEqual(agent.run_posture_scan(), 90)
        self.assertEqual(agent.store.get("baseline_status"), "ok")

    def test_failed_lynis_execution_does_not_use_old_report(self):
        self.config["baseline_lynis"]["run_lynis"] = True
        self.write_config()
        agent = self.agent()
        with patch("tsa_core.subprocess.run", side_effect=TimeoutError("scan timed out")):
            self.assertIsNone(agent.run_posture_scan())

    def test_bpf_mode_override_does_not_mutate_config(self):
        original = self.config_path.read_bytes()
        agent = self.agent(bpf_lsm_enabled=True)
        self.assertEqual([name for name, _ in agent.readers], ["falco", "bpf_lsm"])
        self.assertEqual(self.config_path.read_bytes(), original)

    def test_runtime_disabled_is_respected(self):
        self.config["runtime_rules"]["enabled"] = False
        self.write_config()
        self.assertEqual(self.agent().readers, [])

    def test_malformed_event_types_do_not_crash(self):
        agent = self.agent()
        self.assertIsNone(agent.process_bpf_lsm_line('{"source":"bpf_lsm","policy_id":[]}'))
        self.event["tags"] = [{"unhashable": True}]
        self.assertEqual(agent.process_line(json.dumps(self.event))["deducted_points"], 5)
        self.assertIsNone(agent.process_line("[" * 2000 + "]" * 2000))

    def test_busy_input_does_not_starve_periodic_work(self):
        agent = self.agent()
        reader = agent.readers[0][1]
        ticks = itertools.count(0, 301)
        count = 0

        def next_line():
            nonlocal count
            count += 1
            if count == 3:
                agent.request_stop(0, None)
            return json.dumps(self.event)

        with patch("tsa_core.time.monotonic", side_effect=lambda: next(ticks)), \
             patch.object(reader, "readline", side_effect=next_line), \
             patch.object(reader, "acknowledge"), \
             patch.object(agent, "run_posture_scan") as baseline, \
             patch.object(agent, "generate_report") as report, \
             patch.object(agent.store, "prune") as prune:
            agent.run_daemon()
        self.assertGreaterEqual(baseline.call_count, 2)
        self.assertGreaterEqual(report.call_count, 3)
        self.assertGreaterEqual(prune.call_count, 1)

    def test_prune_keeps_unexpired_risk(self):
        agent = self.agent()
        now = time.time()
        agent.store.record_event(received_time="2000-01-01", event_time="", source="falco",
                                 rule_name="long-risk", status="scored", deducted_points=10,
                                 event_key="long-risk", payload={}, risk_expires_at=now + 3600)
        agent.store.prune(now, 1)
        self.assertEqual(agent.store.active_risk_points(now, 20), 10)

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_stale_or_stopped_fusion_rejects_score(self, _service):
        agent = self.agent()
        self.mark_ready(agent.store)
        data = DashboardData(self.config_path, self.root / "bpf.yaml")
        self.assertEqual(data.scores()["final"], 92)
        for status, heartbeat in (("running", time.time() - 60), ("stopped", time.time())):
            agent.store.set("fusion_status", status)
            agent.store.set("fusion_heartbeat", heartbeat)
            with self.assertRaises(ValueError):
                data.scores()
            self.assertIsNone(data.snapshot()["scores"]["final"])

    @patch("tsa_dashboard.service_state", return_value="inactive")
    def test_inactive_sensor_rejects_score(self, _service):
        agent = self.agent()
        self.mark_ready(agent.store)
        with self.assertRaises(ValueError):
            DashboardData(self.config_path, self.root / "bpf.yaml").scores()

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_missing_log_rejects_score_even_with_active_services(self, _service):
        agent = self.agent()
        self.mark_ready(agent.store)
        agent.store.set("source_status", {"falco": False})
        with self.assertRaisesRegex(ValueError, "event log is unavailable"):
            DashboardData(self.config_path, self.root / "bpf.yaml").scores()

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_missing_baseline_still_displays_valid_runtime(self, _service):
        agent = self.agent()
        self.mark_ready(agent.store)
        agent.scorer.set_posture_score(None)
        agent.store.set("baseline_status", "unavailable")
        data = DashboardData(self.config_path, self.root / "bpf.yaml")
        self.assertEqual(data.snapshot()["scores"], {"posture": None, "final": None, "runtime": 100})
        with self.assertRaises(ValueError):
            data.scores()

    @contextmanager
    def http_server(self):
        server = DashboardServer(("127.0.0.1", 0), DashboardHandler)
        server.data = DashboardData(self.config_path, self.root / "bpf.yaml")
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    @patch("tsa_dashboard.service_state", return_value="active")
    def test_http_api_health_and_dns_rebinding(self, _service):
        agent = self.agent()
        self.mark_ready(agent.store)
        with self.http_server() as port:
            client = HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                client.request("GET", "/systemManage/risk/score")
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["data"]["final"], 92)
                client.request("GET", "/api/status", headers={"Host": "attacker.example"})
                response = client.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                agent.store.set("fusion_status", "stopped")
                for path in ("/healthz", "/systemManage/risk/score"):
                    client.request("GET", path)
                    response = client.getresponse()
                    self.assertEqual(response.status, 503)
                    response.read()
            finally:
                client.close()

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaises(ValueError):
            DashboardServer(("0.0.0.0", 0), DashboardHandler)


if __name__ == "__main__":
    unittest.main()
