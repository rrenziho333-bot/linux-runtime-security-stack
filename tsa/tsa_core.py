"""Core implementation for the TSA Falco/Lynis fusion agent."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shlex
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import yaml


LOG = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp_score(value: float) -> float:
    return max(0.0, min(100.0, value))


def _resolve_path(config_dir: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else config_dir / path


class StateStore:
    """SQLite-backed durable state, deduplication, and event history."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dedup_windows (
                event_key TEXT PRIMARY KEY,
                window_started REAL NOT NULL,
                last_seen REAL NOT NULL,
                occurrence_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                rule_name TEXT PRIMARY KEY,
                window_started REAL NOT NULL,
                deducted_points INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_time TEXT NOT NULL,
                event_time TEXT,
                source TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                status TEXT NOT NULL,
                deducted_points INTEGER NOT NULL,
                event_key TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_received
                ON events(received_time DESC);
            """
        )
        columns = {
            row["name"] for row in self.db.execute("PRAGMA table_info(events)")
        }
        if "risk_expires_at" not in columns:
            self.db.execute("ALTER TABLE events ADD COLUMN risk_expires_at REAL")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def get(self, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def set(self, key: str, value: Any) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        self.db.execute(
            """
            INSERT INTO state(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, encoded),
        )
        self.db.commit()

    def admit_points(
        self,
        *,
        event_key: str,
        rule_name: str,
        now: float,
        requested_points: int,
        dedup_window: int,
        max_points_per_minute: int,
    ) -> Tuple[int, str, int]:
        """Atomically apply deduplication and per-rule rate limiting."""

        requested_points = max(0, requested_points)
        with self.db:
            row = self.db.execute(
                "SELECT * FROM dedup_windows WHERE event_key = ?", (event_key,)
            ).fetchone()
            if row is not None and now - row["window_started"] < dedup_window:
                count = int(row["occurrence_count"]) + 1
                self.db.execute(
                    """
                    UPDATE dedup_windows
                    SET last_seen = ?, occurrence_count = ?
                    WHERE event_key = ?
                    """,
                    (now, count, event_key),
                )
                return 0, "duplicate", count

            self.db.execute(
                """
                INSERT INTO dedup_windows(
                    event_key, window_started, last_seen, occurrence_count
                ) VALUES(?, ?, ?, 1)
                ON CONFLICT(event_key) DO UPDATE SET
                    window_started = excluded.window_started,
                    last_seen = excluded.last_seen,
                    occurrence_count = 1
                """,
                (event_key, now, now),
            )

            if requested_points == 0:
                return 0, "ignored", 1

            rate = self.db.execute(
                "SELECT * FROM rate_limits WHERE rule_name = ?", (rule_name,)
            ).fetchone()
            if rate is None or now - rate["window_started"] >= 60:
                used = 0
                window_started = now
            else:
                used = int(rate["deducted_points"])
                window_started = float(rate["window_started"])

            if max_points_per_minute <= 0:
                admitted = requested_points
            else:
                admitted = min(requested_points, max(0, max_points_per_minute - used))

            self.db.execute(
                """
                INSERT INTO rate_limits(rule_name, window_started, deducted_points)
                VALUES(?, ?, ?)
                ON CONFLICT(rule_name) DO UPDATE SET
                    window_started = excluded.window_started,
                    deducted_points = excluded.deducted_points
                """,
                (rule_name, window_started, used + admitted),
            )
            return admitted, "scored" if admitted else "rate_limited", 1

    def record_event(
        self,
        *,
        received_time: str,
        event_time: str,
        source: str,
        rule_name: str,
        status: str,
        deducted_points: int,
        event_key: str,
        payload: Mapping[str, Any],
        risk_expires_at: Optional[float] = None,
    ) -> None:
        with self.db:
            self.db.execute(
                """
                INSERT INTO events(
                    received_time, event_time, source, rule_name, status,
                    deducted_points, event_key, payload, risk_expires_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    received_time,
                    event_time,
                    source,
                    rule_name,
                    status,
                    deducted_points,
                    event_key,
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    risk_expires_at,
                ),
            )

    def active_risk_points(self, now: float, max_points_per_rule: int) -> int:
        rows = self.db.execute(
            """
            SELECT rule_name, SUM(deducted_points) AS points
            FROM events
            WHERE status = 'scored'
              AND deducted_points > 0
              AND risk_expires_at IS NOT NULL
              AND risk_expires_at > ?
            GROUP BY rule_name
            """,
            (now,),
        ).fetchall()
        total = 0
        for row in rows:
            points = max(0, int(row["points"] or 0))
            total += (
                min(points, max_points_per_rule)
                if max_points_per_rule > 0
                else points
            )
        return min(100, total)

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            """
            SELECT received_time, event_time, source, rule_name, status,
                   deducted_points, payload, risk_expires_at
            FROM events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for row in reversed(rows):
            item = json.loads(row["payload"])
            item.update(
                {
                    "received_time": row["received_time"],
                    "event_time": row["event_time"],
                    "source": row["source"],
                    "rule": row["rule_name"],
                    "status": row["status"],
                    "deducted_points": row["deducted_points"],
                    "risk_expires_time": (
                        datetime.fromtimestamp(
                            row["risk_expires_at"], timezone.utc
                        ).isoformat()
                        if row["risk_expires_at"] is not None
                        else None
                    ),
                }
            )
            result.append(item)
        return result

    def prune(self, now: float, retention_days: int) -> None:
        cutoff_iso = datetime.fromtimestamp(
            now - retention_days * 86400, timezone.utc
        ).isoformat()
        dedup_cutoff = now - 86400
        with self.db:
            self.db.execute("DELETE FROM events WHERE received_time < ?", (cutoff_iso,))
            self.db.execute(
                "DELETE FROM dedup_windows WHERE last_seen < ?", (dedup_cutoff,)
            )


@dataclass(frozen=True)
class RulePolicy:
    points: int
    dedup_window: int
    max_points_per_minute: int
    risk_ttl_seconds: int
    enabled: bool = True
    explicit: bool = False


class RiskScorer:
    def __init__(self, config: Mapping[str, Any], store: StateStore):
        self.config = config
        self.store = store
        runtime_cfg = config.get("runtime_rules", {}) or {}
        self.runtime_score = float(
            store.get("runtime_score", runtime_cfg.get("init_score", 100))
        )
        self.posture_score = float(store.get("posture_score", 100))
        self.last_attack_time = float(store.get("last_attack_time", 0.0))
        self.last_recovery_time = float(store.get("last_recovery_time", 0.0))
        self.refresh_runtime_score(time.time())

    def set_posture_score(self, score: float) -> None:
        self.posture_score = _clamp_score(score)
        self.store.set("posture_score", self.posture_score)

    def _risk_ttl(self, priority: str, defaults: Mapping[str, Any]) -> int:
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        by_priority = runtime_cfg.get("risk_ttl_by_priority", {}) or {}
        return max(
            1,
            int(
                by_priority.get(
                    priority,
                    defaults.get("risk_ttl_seconds", 3600),
                )
            ),
        )

    def _specific_policy(
        self, rule: str, priority: str
    ) -> Optional[RulePolicy]:
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        specific = runtime_cfg.get("specific_rules", {}) or {}
        if rule not in specific:
            return None

        defaults = runtime_cfg.get("event_control", {}) or {}
        raw = specific[rule]
        if isinstance(raw, Mapping):
            return RulePolicy(
                points=max(0, int(raw.get("points", 0))),
                dedup_window=max(
                    0, int(raw.get("dedup_window", defaults.get("dedup_window", 10)))
                ),
                max_points_per_minute=max(
                    0,
                    int(
                        raw.get(
                            "max_points_per_minute",
                            defaults.get("max_points_per_minute", 30),
                        )
                    ),
                ),
                risk_ttl_seconds=max(
                    1,
                    int(
                        raw.get(
                            "risk_ttl_seconds",
                            self._risk_ttl(priority, defaults),
                        )
                    ),
                ),
                enabled=bool(raw.get("enabled", True)),
                explicit=True,
            )
        return RulePolicy(
            points=max(0, int(raw)),
            dedup_window=max(0, int(defaults.get("dedup_window", 10))),
            max_points_per_minute=max(
                0, int(defaults.get("max_points_per_minute", 30))
            ),
            risk_ttl_seconds=self._risk_ttl(priority, defaults),
            explicit=True,
        )

    def resolve_policy(
        self, rule: str, priority: str, tags: Iterable[str]
    ) -> Tuple[RulePolicy, str]:
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        specific = self._specific_policy(rule, priority)
        if specific is not None:
            if not specific.enabled:
                return specific, "rule explicitly disabled"
            return specific, f"specific rule [{rule}]"

        defaults = runtime_cfg.get("event_control", {}) or {}
        tag_mapping = runtime_cfg.get("tag_mapping", {}) or {}
        tag_points = [int(tag_mapping[tag]) for tag in tags if tag in tag_mapping]
        if tag_points:
            mode = str(runtime_cfg.get("tag_weight_mode", "max")).lower()
            points = sum(max(0, point) for point in tag_points) if mode == "add" else max(tag_points)
            return (
                RulePolicy(
                    max(0, points),
                    max(0, int(defaults.get("dedup_window", 10))),
                    max(0, int(defaults.get("max_points_per_minute", 30))),
                    self._risk_ttl(priority, defaults),
                ),
                "MITRE/tag mapping",
            )

        priority_mapping = runtime_cfg.get("priority_mapping", {}) or {}
        points = int(priority_mapping.get(priority, 0))
        return (
            RulePolicy(
                max(0, points),
                max(0, int(defaults.get("dedup_window", 10))),
                max(0, int(defaults.get("max_points_per_minute", 30))),
                self._risk_ttl(priority, defaults),
            ),
            f"priority [{priority}]",
        )

    @staticmethod
    def _event_key(rule: str, output_fields: Mapping[str, Any]) -> str:
        identity = {
            "rule": rule,
            "container": output_fields.get("container.id", "host"),
            "pid": output_fields.get("proc.pid", ""),
            "process": output_fields.get("proc.name", ""),
            "user": output_fields.get("user.name", ""),
            "file": output_fields.get("fd.name", ""),
            "command": output_fields.get("proc.cmdline", ""),
        }
        canonical = json.dumps(identity, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _is_whitelisted(self, output_fields: Mapping[str, Any]) -> bool:
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        whitelist = runtime_cfg.get("whitelist", {}) or {}
        process = str(output_fields.get("proc.name", ""))
        user = str(output_fields.get("user.name", ""))
        path = str(output_fields.get("fd.name", ""))
        if process and process in set(whitelist.get("proc_names", [])):
            return True
        if user and user in set(whitelist.get("users", [])):
            return True
        return any(path.startswith(prefix) for prefix in whitelist.get("paths_prefix", []))

    def process_falco_event(
        self,
        event: Mapping[str, Any],
        received_at: Optional[float] = None,
        suppress_scoring: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(event, Mapping) or "rule" not in event:
            return None

        now = time.time() if received_at is None else received_at
        received_time = datetime.fromtimestamp(now, timezone.utc).isoformat()
        rule = str(event.get("rule", "Unknown"))
        priority = str(event.get("priority", "INFO")).upper()
        tags = event.get("tags", []) or []
        tags = tags if isinstance(tags, list) else []
        output_fields = event.get("output_fields", {}) or {}
        output_fields = output_fields if isinstance(output_fields, Mapping) else {}
        event_key = self._event_key(rule, output_fields)
        risk_ttl_seconds = 0

        if suppress_scoring:
            status, admitted, reason, count = "maintenance", 0, "maintenance window", 1
        elif self._is_whitelisted(output_fields):
            status, admitted, reason, count = "whitelisted", 0, "whitelist", 1
        else:
            policy, reason = self.resolve_policy(rule, priority, tags)
            if not policy.enabled:
                status, admitted, count = "ignored", 0, 1
            else:
                risk_ttl_seconds = policy.risk_ttl_seconds
                admitted, status, count = self.store.admit_points(
                    event_key=event_key,
                    rule_name=rule,
                    now=now,
                    requested_points=policy.points,
                    dedup_window=policy.dedup_window,
                    max_points_per_minute=policy.max_points_per_minute,
                )

        if admitted > 0:
            self.last_attack_time = now
            self.store.set("last_attack_time", self.last_attack_time)

        record = {
            "priority": priority,
            "tags": tags,
            "reason": reason,
            "occurrence_count": count,
            "user": output_fields.get("user.name", ""),
            "process": output_fields.get("proc.name", ""),
            "pid": output_fields.get("proc.pid", ""),
            "file": output_fields.get("fd.name", ""),
            "command": output_fields.get("proc.cmdline", ""),
            "container_id": output_fields.get("container.id", "host"),
            "runtime_score": self.runtime_score,
        }
        self.store.record_event(
            received_time=received_time,
            event_time=str(event.get("time", "")),
            source="falco",
            rule_name=rule,
            status=status,
            deducted_points=admitted,
            event_key=event_key,
            payload=record,
            risk_expires_at=(
                now + risk_ttl_seconds if admitted > 0 else None
            ),
        )
        self.refresh_runtime_score(now)
        record["runtime_score"] = self.runtime_score
        return {**record, "status": status, "deducted_points": admitted}

    def process_bpf_lsm_event(
        self,
        event: Mapping[str, Any],
        received_at: Optional[float] = None,
        suppress_scoring: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(event, Mapping) or event.get("source") != "bpf_lsm":
            return None

        now = time.time() if received_at is None else received_at
        received_time = datetime.fromtimestamp(now, timezone.utc).isoformat()
        action = str(event.get("action", "unknown")).lower()
        policy_id = int(event.get("policy_id", 0))
        policy_name = str(event.get("policy_name", "") or policy_id)
        bpf_cfg = self.config.get("bpf_lsm", {}) or {}
        action_points = bpf_cfg.get("action_points", {}) or {}
        per_policy = bpf_cfg.get("policy_points", {}) or {}
        policy_override = per_policy.get(policy_id, per_policy.get(str(policy_id), {}))
        if isinstance(policy_override, Mapping) and action in policy_override:
            requested_points = max(0, int(policy_override[action]))
            reason = f"BPF LSM policy override [{policy_name}]"
        else:
            requested_points = max(0, int(action_points.get(action, 0)))
            reason = f"BPF LSM action [{action}]"

        controls = bpf_cfg.get("event_control", {}) or {}
        dedup_window = max(0, int(controls.get("dedup_window", 10)))
        max_per_minute = max(
            0, int(controls.get("max_points_per_minute", 30))
        )
        action_ttl = bpf_cfg.get("risk_ttl_by_action", {}) or {}
        risk_ttl = max(
            1,
            int(
                action_ttl.get(
                    action,
                    controls.get("risk_ttl_seconds", 3600),
                )
            ),
        )
        identity = {
            "source": "bpf_lsm",
            "policy_id": policy_id,
            "action": action,
            "operation": event.get("operation", "unknown"),
            "pid": event.get("pid", 0),
            "uid": event.get("uid", 0),
            "device": event.get("device", 0),
            "inode": event.get("inode", 0),
        }
        canonical = json.dumps(identity, sort_keys=True, ensure_ascii=False)
        event_key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        rule_name = f"bpf_lsm:{policy_name}:{action}"
        if suppress_scoring:
            admitted, status, count = 0, "maintenance", 1
            reason = "maintenance window"
        else:
            admitted, status, count = self.store.admit_points(
                event_key=event_key,
                rule_name=rule_name,
                now=now,
                requested_points=requested_points,
                dedup_window=dedup_window,
                max_points_per_minute=max_per_minute,
            )
        if admitted > 0:
            self.last_attack_time = now
            self.store.set("last_attack_time", self.last_attack_time)

        record = {
            "policy_id": policy_id,
            "policy_name": policy_name,
            "action": action,
            "operation": event.get("operation", "unknown"),
            "result": event.get("result", 0),
            "reason": reason,
            "occurrence_count": count,
            "pid": event.get("pid", 0),
            "tgid": event.get("tgid", 0),
            "uid": event.get("uid", 0),
            "gid": event.get("gid", 0),
            "command": event.get("command", ""),
            "device": event.get("device", 0),
            "inode": event.get("inode", 0),
            "runtime_score": self.runtime_score,
        }
        self.store.record_event(
            received_time=received_time,
            event_time=str(event.get("received_time", "")),
            source="bpf_lsm",
            rule_name=rule_name,
            status=status,
            deducted_points=admitted,
            event_key=event_key,
            payload=record,
            risk_expires_at=now + risk_ttl if admitted > 0 else None,
        )
        self.refresh_runtime_score(now)
        record["runtime_score"] = self.runtime_score
        return {**record, "status": status, "deducted_points": admitted}

    def refresh_runtime_score(self, now: Optional[float] = None) -> float:
        current = time.time() if now is None else now
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        controls = runtime_cfg.get("event_control", {}) or {}
        max_per_rule = max(0, int(controls.get("max_active_points_per_rule", 20)))
        active_risk = self.store.active_risk_points(current, max_per_rule)
        self.runtime_score = _clamp_score(100 - active_risk)
        self.store.set("runtime_score", self.runtime_score)
        return self.runtime_score

    def maybe_recover(self, now: Optional[float] = None) -> int:
        current = time.time() if now is None else now
        previous = self.runtime_score
        self.refresh_runtime_score(current)
        return max(0, int(self.runtime_score - previous))

    def final_score(self) -> float:
        self.refresh_runtime_score(time.time())
        scoring = self.config.get("scoring", {}) or {}
        weights = scoring.get("weights", {}) or {}
        posture_weight = max(0.0, float(weights.get("posture", 0.4)))
        runtime_weight = max(0.0, float(weights.get("runtime", 0.6)))
        total = posture_weight + runtime_weight
        if total == 0:
            posture_weight, runtime_weight, total = 0.4, 0.6, 1.0
        return round(
            _clamp_score(
                (
                    self.posture_score * posture_weight
                    + self.runtime_score * runtime_weight
                )
                / total
            ),
            2,
        )


class RotatingLineReader:
    """Tail a file while preserving offsets and following rotation/truncation."""

    def __init__(
        self,
        path: Path,
        store: StateStore,
        *,
        start_at_end: bool = True,
        state_prefix: str = "falco_log",
    ):
        self.path = path
        self.store = store
        self.start_at_end = start_at_end
        self.state_prefix = state_prefix
        self.file: Optional[Any] = None
        self.identity = ""

    def close(self) -> None:
        if self.file is not None:
            self.file.close()
            self.file = None

    def _saved_identity(self) -> str:
        return str(self.store.get(f"{self.state_prefix}.identity", ""))

    def _open(self) -> bool:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return False

        identity = f"{stat.st_dev}:{stat.st_ino}"
        saved_identity = self._saved_identity()
        saved_offset = int(self.store.get(f"{self.state_prefix}.offset", 0))
        first_seen = not saved_identity

        self.close()
        self.file = self.path.open("r", encoding="utf-8", errors="replace")
        if identity == saved_identity:
            self.file.seek(min(saved_offset, stat.st_size))
        elif first_seen and self.start_at_end:
            self.file.seek(0, os.SEEK_END)
        else:
            self.file.seek(0)

        self.identity = identity
        self.store.set(f"{self.state_prefix}.identity", identity)
        self.store.set(f"{self.state_prefix}.offset", self.file.tell())
        return True

    def _needs_reopen(self) -> bool:
        if self.file is None:
            return True
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return False
        identity = f"{stat.st_dev}:{stat.st_ino}"
        return identity != self.identity or stat.st_size < self.file.tell()

    def readline(self) -> Optional[str]:
        if self.file is None and not self._open():
            return None
        assert self.file is not None

        position = self.file.tell()
        line = self.file.readline()
        if line:
            if not line.endswith("\n"):
                self.file.seek(position)
                return None
            self.store.set(f"{self.state_prefix}.offset", self.file.tell())
            return line

        if self._needs_reopen():
            self._open()
        return None


def parse_lynis_report(
    report_path: Path,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    warnings: List[Tuple[str, str]] = []
    suggestions: List[Tuple[str, str]] = []
    if not report_path.exists():
        return warnings, suggestions

    with report_path.open("r", encoding="utf-8", errors="replace") as report:
        for raw_line in report:
            line = raw_line.strip()
            if line.startswith("warning[]="):
                kind, target = "warning", warnings
            elif line.startswith("suggestion[]="):
                kind, target = "suggestion", suggestions
            else:
                continue
            body = line[len(kind) + 3 :]
            parts = body.split("|")
            control = parts[0].strip() if parts else ""
            message = parts[1].strip() if len(parts) > 1 else ""
            if control:
                target.append((control, message))
    return warnings, suggestions


class TSAFusionAgent:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path).expanduser().resolve()
        self.config_dir = self.config_path.parent
        with self.config_path.open("r", encoding="utf-8") as config_file:
            self.config = yaml.safe_load(config_file) or {}
        if not isinstance(self.config, Mapping):
            raise ValueError("TSA configuration root must be a mapping")

        storage = self.config.get("storage", {}) or {}
        state_db = _resolve_path(
            self.config_dir, str(storage.get("state_db", "state/tsa.db"))
        )
        self.report_path = _resolve_path(
            self.config_dir, str(storage.get("report_path", "reports/last_scan.json"))
        )
        self.store = StateStore(state_db)
        self.scorer = RiskScorer(self.config, self.store)
        self.stop_event = threading.Event()
        self.recent_lynis_hits: List[Dict[str, Any]] = list(
            self.store.get("recent_lynis_hits", [])
        )
        maintenance = self.config.get("maintenance", {}) or {}
        self.maintenance_file = _resolve_path(
            self.config_dir,
            str(maintenance.get("file", "/run/tsa-fusion/maintenance")),
        )

        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        self.falco_log_path = _resolve_path(
            self.config_dir,
            str(runtime_cfg.get("log_path", "/var/log/falco/falco.json")),
        )
        self.readers: List[Tuple[str, RotatingLineReader]] = [
            (
                "falco",
                RotatingLineReader(
                    self.falco_log_path,
                    self.store,
                    start_at_end=bool(runtime_cfg.get("start_at_end", True)),
                    state_prefix="falco_log",
                ),
            )
        ]
        bpf_cfg = self.config.get("bpf_lsm", {}) or {}
        self.bpf_lsm_log_path: Optional[Path] = None
        if bpf_cfg.get("enabled", False):
            self.bpf_lsm_log_path = _resolve_path(
                self.config_dir,
                str(bpf_cfg.get("log_path", "/var/log/bpf-lsm/events.jsonl")),
            )
            self.readers.append(
                (
                    "bpf_lsm",
                    RotatingLineReader(
                        self.bpf_lsm_log_path,
                        self.store,
                        start_at_end=bool(bpf_cfg.get("start_at_end", True)),
                        state_prefix="bpf_lsm_log",
                    ),
                )
            )

    def close(self) -> None:
        for _, reader in self.readers:
            reader.close()
        self.store.close()

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_event.set()

    def run_posture_scan(self) -> float:
        baseline = self.config.get("baseline_lynis", {}) or {}
        if not baseline.get("enabled", False):
            self.scorer.set_posture_score(100)
            return 100

        if baseline.get("run_lynis", False):
            command = str(baseline.get("lynis_cmd", "lynis audit system --quick --quiet"))
            completed = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                check=False,
                timeout=int(baseline.get("timeout_seconds", 1800)),
            )
            if completed.returncode:
                LOG.warning("Lynis exited with rc=%s: %s", completed.returncode, completed.stderr[:300])

        report_path = _resolve_path(
            self.config_dir,
            str(baseline.get("report_path", "/var/log/lynis-report.dat")),
        )
        warnings, suggestions = parse_lynis_report(report_path)
        controls = set(baseline.get("include_controls", []) or [])
        deductions = baseline.get("deduct_by_control", {}) or {}
        defaults = baseline.get("default_deduct", {}) or {}
        mode = str(baseline.get("scoring_mode", "warnings_only"))
        hits: List[Dict[str, Any]] = []

        def apply(kind: str, items: Iterable[Tuple[str, str]]) -> int:
            subtotal = 0
            default = int(defaults.get(kind, 0))
            for control, message in items:
                if controls and control not in controls:
                    continue
                points = max(0, int(deductions.get(control, default)))
                if points:
                    subtotal += points
                    hits.append(
                        {
                            "type": kind.upper(),
                            "control": control,
                            "deducted_points": points,
                            "message": message,
                        }
                    )
            return subtotal

        total = apply("warning", warnings)
        if mode == "warnings_and_selected_suggestions":
            total += apply("suggestion", suggestions)
        self.scorer.set_posture_score(100 - total)
        self.recent_lynis_hits = hits[-50:]
        self.store.set("recent_lynis_hits", self.recent_lynis_hits)
        LOG.info(
            "Posture score %.2f/100 from %s (%d deductions)",
            self.scorer.posture_score,
            report_path,
            total,
        )
        return self.scorer.posture_score

    def process_line(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            LOG.warning("Ignoring malformed Falco JSON line")
            return None
        result = self.scorer.process_falco_event(
            event,
            suppress_scoring=self.maintenance_file.exists(),
        )
        if result and result["deducted_points"]:
            LOG.warning(
                "Falco rule=%s status=%s points=-%s runtime=%.2f",
                event.get("rule"),
                result["status"],
                result["deducted_points"],
                self.scorer.runtime_score,
            )
        return result

    def process_bpf_lsm_line(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            LOG.warning("Ignoring malformed BPF LSM JSON line")
            return None
        result = self.scorer.process_bpf_lsm_event(
            event,
            suppress_scoring=self.maintenance_file.exists(),
        )
        if result and result["deducted_points"]:
            LOG.warning(
                "BPF LSM policy=%s action=%s status=%s points=-%s runtime=%.2f",
                result["policy_name"],
                result["action"],
                result["status"],
                result["deducted_points"],
                self.scorer.runtime_score,
            )
        return result

    def generate_report(self, status: str = "running") -> None:
        report = {
            "generated_time": _utc_now(),
            "status": status,
            "sources": {
                "falco_log_path": str(self.falco_log_path),
                "bpf_lsm_log_path": (
                    str(self.bpf_lsm_log_path) if self.bpf_lsm_log_path else None
                ),
                "lynis_report_path": str(
                    (self.config.get("baseline_lynis", {}) or {}).get("report_path", "")
                ),
            },
            "scores": {
                "final": self.scorer.final_score(),
                "posture": self.scorer.posture_score,
                "runtime": self.scorer.runtime_score,
            },
            "recent_lynis_hits": self.recent_lynis_hits[-50:],
            "recent_security_events": self.store.recent_events(50),
        }
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.report_path.with_suffix(self.report_path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2, ensure_ascii=False)
            report_file.flush()
            os.fsync(report_file.fileno())
        os.replace(temporary, self.report_path)

    def run_daemon(self) -> None:
        self.run_posture_scan()
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        poll_interval = max(0.1, float(runtime_cfg.get("poll_interval", 1)))
        reporting = self.config.get("reporting", {}) or {}
        report_interval = max(10, int(reporting.get("interval_seconds", 300)))
        retention_days = max(1, int(reporting.get("retention_days", 30)))
        next_report = time.monotonic() + report_interval

        LOG.info(
            "Watching security event sources: %s",
            ", ".join(f"{source}={reader.path}" for source, reader in self.readers),
        )
        while not self.stop_event.is_set():
            processed = False
            for source, reader in self.readers:
                line = reader.readline()
                if line is None:
                    continue
                processed = True
                if source == "falco":
                    self.process_line(line)
                else:
                    self.process_bpf_lsm_line(line)
            if processed:
                continue

            recovered = self.scorer.maybe_recover()
            if recovered:
                LOG.info(
                    "Runtime score recovered by %d to %.2f",
                    recovered,
                    self.scorer.runtime_score,
                )
            if time.monotonic() >= next_report:
                self.generate_report("running")
                self.store.prune(time.time(), retention_days)
                next_report = time.monotonic() + report_interval
            self.stop_event.wait(poll_interval)

        self.generate_report("stopped")
