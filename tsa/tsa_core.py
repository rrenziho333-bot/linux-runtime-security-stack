"""Core implementation for the TSA Falco/Lynis fusion agent."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import sqlite3
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

import yaml

from weight_policy import read_policy, final_score as weighted_score
from baseline_scoring import baseline_snapshot, read_report, score_report
from runtime_context import advisory_reason, apply_signal_budget, score_effect, validate_runtime_config


LOG = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp_score(value: float) -> float:
    return max(0.0, min(100.0, value))


def _resolve_path(config_dir: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else config_dir / path


def parse_event_time(value: str) -> float:
    # Falco uses nanoseconds; Ubuntu 22.04's Python 3.10 expects microseconds.
    normalized = re.sub(r"\.\d+(?=Z|[+-]\d{2}:\d{2}$)",
                        lambda match: match.group()[:7].ljust(7, "0"), value)
    timestamp = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Missing timezone")
    return timestamp.timestamp()


def runtime_risk_breakdown(
    db: sqlite3.Connection, runtime_cfg: Mapping[str, Any], now: float
) -> List[Dict[str, Any]]:
    """Shared by the collector and read-only API, including pre-migration databases."""
    controls = runtime_cfg.get("event_control", {}) or {}
    cap = max(0, int(controls.get("max_active_points_per_rule", 20)))
    peak = runtime_cfg.get("aggregation") == "peak_per_rule"
    columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
    weight = "COALESCE(risk_points, deducted_points)" if peak and "risk_points" in columns else "deducted_points"
    aggregate = "MAX" if peak else "SUM"
    statuses = "'scored', 'risk_refreshed'" if peak else "'scored'"
    if peak and runtime_cfg.get('context_advisories') and 'payload' in columns:
        # Re-evaluate active historical evidence without rewriting its audit record.
        merged = {}
        for row in db.execute(
            f"SELECT rule_name, {weight} points, risk_expires_at, payload FROM events WHERE source='falco' "
            f"AND status IN ({statuses}) AND {weight} > 0 AND risk_expires_at > ?", (now,)
        ):
            try:
                evidence = json.loads(row['payload'])
            except (TypeError, ValueError):
                evidence = {}
            if isinstance(evidence, dict) and advisory_reason(row['rule_name'], evidence, runtime_cfg):
                continue
            group = merged.setdefault(row['rule_name'], {'rule_name': row['rule_name'], 'points': 0,
                                                         'evidence_count': 0, 'expires_at': 0})
            group['points'] = max(group['points'], row['points'])
            group['evidence_count'] += 1
            group['expires_at'] = max(group['expires_at'], row['risk_expires_at'])
        rows = list(merged.values())
    else:
        rows = db.execute(
            f"SELECT rule_name, {aggregate}({weight}) points, COUNT(*) evidence_count, "
            f"MAX(risk_expires_at) expires_at FROM events WHERE source='falco' "
            f"AND status IN ({statuses}) AND {weight} > 0 AND risk_expires_at > ? "
            "GROUP BY rule_name ORDER BY points DESC, rule_name", (now,)
        ).fetchall()
    specific = runtime_cfg.get("specific_rules", {}) or {}
    result = []
    for row in rows:
        name = row["rule_name"]
        if runtime_cfg.get("unmapped_rule_action") == "record_only" and name not in specific:
            continue
        policy = specific.get(name)
        if isinstance(policy, Mapping) and (not policy.get("enabled", True) or policy.get('test_only', False)):
            continue
        points = max(0, int(row["points"] or 0))
        if cap:
            points = min(points, cap)
        if peak and policy is not None:
            points = min(points, max(0, int(policy.get("points", 0) if isinstance(policy, Mapping) else policy)))
        if points:
            result.append({"rule": name, "points": points,
                           "evidence_count": row["evidence_count"], "expires_at": row["expires_at"],
                           "reason": policy.get("reason", "") if isinstance(policy, Mapping) else ""})
    return apply_signal_budget(result, runtime_cfg) if peak else result


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
        if "risk_points" not in columns:
            self.db.execute("ALTER TABLE events ADD COLUMN risk_points INTEGER")
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_risk_expiry ON events(risk_expires_at, rule_name)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_active "
            "ON events(risk_expires_at, rule_name) "
            "WHERE status = 'scored' AND deducted_points > 0"
        )
        self.db.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        outermost = not self.db.in_transaction
        if outermost:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            if outermost:
                self.db.commit()
        except BaseException:
            if outermost:
                self.db.rollback()
            raise

    def close(self) -> None:
        self.db.close()

    def get(self, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def set(self, key: str, value: Any) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        with self.transaction():
            self.db.execute(
                """
                INSERT INTO state(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, encoded),
            )

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
        with self.transaction():
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
        risk_points: Optional[int] = None,
    ) -> None:
        with self.transaction():
            self.db.execute(
                """
                INSERT INTO events(
                    received_time, event_time, source, rule_name, status,
                    deducted_points, event_key, payload, risk_expires_at, risk_points
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    risk_points,
                ),
            )

    def active_risk_points(self, now: float, max_points_per_rule: int) -> int:
        rows = self.db.execute(
            """
            SELECT rule_name, SUM(deducted_points) AS points
            FROM events
            WHERE source = 'falco' AND status = 'scored'
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
            FROM events WHERE source = 'falco' ORDER BY id DESC LIMIT ?
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
        with self.transaction():
            self.db.execute(
                "DELETE FROM events WHERE received_time < ? "
                "AND (risk_expires_at IS NULL OR risk_expires_at <= ?)",
                (cutoff_iso, now),
            )
            self.db.execute(
                "DELETE FROM dedup_windows WHERE last_seen < ?", (dedup_cutoff,)
            )
            self.db.execute("DELETE FROM rate_limits WHERE window_started < ?", (dedup_cutoff,))


@dataclass(frozen=True)
class RulePolicy:
    points: int
    dedup_window: int
    max_points_per_minute: int
    risk_ttl_seconds: int
    enabled: bool = True


class RiskScorer:
    def __init__(self, config: Mapping[str, Any], store: StateStore, config_dir: Optional[Path] = None):
        self.config = config
        validate_runtime_config(config.get('runtime_rules', {}) or {})
        self.store = store
        self.config_dir = config_dir
        posture = store.get("posture_score", None)
        self.posture_score = float(posture) if posture is not None else None
        self.refresh_runtime_score(time.time())

    def set_posture_score(self, score: Optional[float]) -> None:
        self.posture_score = _clamp_score(score) if score is not None else None
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
            )
        return RulePolicy(
            points=max(0, int(raw)),
            dedup_window=max(0, int(defaults.get("dedup_window", 10))),
            max_points_per_minute=max(
                0, int(defaults.get("max_points_per_minute", 30))
            ),
            risk_ttl_seconds=self._risk_ttl(priority, defaults),
        )

    def resolve_policy(
        self, rule: str, priority: str, tags: Iterable[str]
    ) -> Tuple[RulePolicy, str]:
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        specific = self._specific_policy(rule, priority)
        if specific is not None:
            if not specific.enabled:
                return specific, "rule explicitly disabled"
            raw = (runtime_cfg.get("specific_rules", {}) or {})[rule]
            detail = raw.get("reason", "") if isinstance(raw, Mapping) else ""
            return specific, detail or f"specific rule [{rule}]"

        if runtime_cfg.get("unmapped_rule_action") == "record_only":
            return RulePolicy(0, 0, 0, 3600, False), "No reviewed scoring policy; evidence only"

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
        with self.store.transaction():
            return self._process_falco_event(event, received_at, suppress_scoring)

    def _process_falco_event(
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
        tags = [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []
        output_fields = event.get("output_fields", {}) or {}
        output_fields = output_fields if isinstance(output_fields, Mapping) else {}
        evidence = {key: output_fields.get(field) for key, field in {
            'process': 'proc.name', 'executable': 'proc.exepath', 'parent': 'proc.pname',
            'command': 'proc.cmdline', 'file': 'fd.name', 'uid': 'user.uid',
            'container_id': 'container.id', 'syscall': 'evt.type',
            'is_open_write': 'evt.is_open_write', 'syscall_result': 'evt.rawres'}.items()}
        event_key = self._event_key(rule, output_fields)
        risk_ttl_seconds = 0
        risk_points = None
        expires_at = None
        effect = None
        runtime_cfg = self.config.get("runtime_rules", {}) or {}

        if suppress_scoring:
            status, admitted, reason, count = "maintenance", 0, "maintenance window", 1
        elif self._is_whitelisted(output_fields):
            status, admitted, reason, count = "whitelisted", 0, "whitelist", 1
        else:
            policy, reason = self.resolve_policy(rule, priority, tags)
            if not policy.enabled:
                status, admitted, count = "ignored", 0, 1
            elif runtime_cfg.get("aggregation") == "peak_per_rule":
                status, admitted, count = "ignored", 0, 1
                risk_points = policy.points
                occurred = now
                valid_time = True
                if runtime_cfg.get("event_time_scoring", False):
                    try:
                        occurred = parse_event_time(str(event.get("time", "")))
                        valid_time = occurred <= now + 300
                    except (ValueError, OverflowError, OSError):
                        valid_time = False
                expires_at = min(occurred, now) + policy.risk_ttl_seconds
                if not valid_time:
                    status, risk_points, expires_at = "invalid_time", 0, None
                    reason += "; missing/invalid event time or clock ahead by over 5 minutes"
                    self.store.set("runtime_time_error_at", now)
                    LOG.warning("Falco event time is invalid for rule %s; check clock and log format", rule)
                elif expires_at <= now:
                    self.store.set("runtime_valid_time_at", now)
                    status, risk_points, expires_at = "expired", 0, None
                    reason += "; event risk already expired before ingestion"
                elif risk_points > 0:
                    self.store.set("runtime_valid_time_at", now)
                    raw_policy = (runtime_cfg.get('specific_rules', {}) or {}).get(rule, {})
                    context = advisory_reason(rule, evidence, runtime_cfg)
                    if isinstance(raw_policy, Mapping) and raw_policy.get('test_only', False):
                        status, admitted, expires_at = 'test_event', 0, None
                        reason += '; 专用验收规则，只在独立测试中计算分数，不计入实际风险'
                    elif context:
                        status, admitted, expires_at = 'context_advisory', 0, None
                        reason = context
                    else:
                        active = runtime_risk_breakdown(self.store.db, runtime_cfg, now)
                        before = sum(item["points"] for item in active)
                        previous = next((item.get('rule_points', item['points']) for item in active if item["rule"] == rule), 0)
                        cap = int((runtime_cfg.get("event_control", {}) or {}).get("max_active_points_per_rule", 20))
                        contribution = min(risk_points, cap) if cap > 0 else risk_points
                        projected = [item for item in active if item['rule'] != rule]
                        projected.append({'rule': rule, 'points': max(previous, contribution)})
                        after = sum(item['points'] for item in apply_signal_budget(projected, runtime_cfg))
                        effect = score_effect(previous, contribution, before, after)
                        admitted = effect['deducted_points']
                        status = "scored" if admitted else "risk_refreshed"
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
                expires_at = now + risk_ttl_seconds if admitted > 0 else None

        record = {
            "priority": priority,
            "tags": tags,
            "reason": reason,
            "score_effect": effect,
            "risk_points": risk_points,
            "scoring_model": runtime_cfg.get("aggregation", "sum_capped"),
            "occurrence_count": count,
            "user": output_fields.get("user.name", ""),
            "process": output_fields.get("proc.name", ""),
            "pid": output_fields.get("proc.pid", ""),
            "uid": output_fields.get("user.uid"),
            "executable": output_fields.get("proc.exepath", ""),
            "parent": output_fields.get("proc.pname", ""),
            "syscall": output_fields.get("evt.type", ""),
            "is_open_write": output_fields.get("evt.is_open_write"),
            "syscall_result": output_fields.get("evt.rawres"),
            "file": output_fields.get("fd.name", ""),
            "command": output_fields.get("proc.cmdline", ""),
            "container_id": output_fields.get("container.id"),
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
            risk_expires_at=expires_at,
            risk_points=risk_points,
        )
        self.refresh_runtime_score(now)
        record["runtime_score"] = self.runtime_score
        return {**record, "status": status, "deducted_points": admitted}



    def refresh_runtime_score(self, now: Optional[float] = None) -> float:
        current = time.time() if now is None else now
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        active_risk = sum(item["points"] for item in runtime_risk_breakdown(self.store.db, runtime_cfg, current))
        self.runtime_score = _clamp_score(100 - active_risk)
        self.store.set("runtime_score", self.runtime_score)
        return self.runtime_score

    def maybe_recover(self, now: Optional[float] = None) -> int:
        current = time.time() if now is None else now
        previous = self.runtime_score
        self.refresh_runtime_score(current)
        return max(0, int(self.runtime_score - previous))

    def final_score(self, weights=None) -> Optional[float]:
        self.refresh_runtime_score(time.time())
        weights = weights if weights is not None else read_policy(self.config, self.config_dir)
        details = self.store.get("baseline_details")
        posture = baseline_snapshot({"baseline_details": details}).get("score") if details else self.posture_score
        return weighted_score(posture, self.runtime_score, weights)


class RotatingLineReader:
    """Tail a file while preserving offsets and following rotation/truncation."""

    MAX_LINE_LENGTH = 1024 * 1024

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
        self.discarding = False

    def close(self) -> None:
        if self.file is not None:
            self.file.close()
            self.file = None

    def _saved_identity(self) -> str:
        return str(self.store.get(f"{self.state_prefix}.identity", ""))

    def _open(self, reset_offset: bool = False) -> bool:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            # Only skip history that already exists when watching begins.
            # A file created after this point contains new events, not history.
            self.start_at_end = False
            return False

        identity = f"{stat.st_dev}:{stat.st_ino}"
        saved_identity = self._saved_identity()
        saved_offset = int(self.store.get(f"{self.state_prefix}.offset", 0))
        first_seen = not saved_identity

        self.close()
        self.file = self.path.open("r", encoding="utf-8", errors="replace")
        if identity == saved_identity and not reset_offset:
            self.file.seek(saved_offset if saved_offset <= stat.st_size else 0)
        elif first_seen and self.start_at_end:
            self.file.seek(0, os.SEEK_END)
        else:
            self.file.seek(0)

        self.identity = identity
        self.discarding = False
        self.acknowledge()
        return True

    def acknowledge(self) -> None:
        """Commit the cursor in the same transaction as the consumed event."""
        assert self.file is not None
        with self.store.transaction():
            self.store.set(f"{self.state_prefix}.identity", self.identity)
            self.store.set(f"{self.state_prefix}.offset", self.file.tell())

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
        line = self.file.readline(self.MAX_LINE_LENGTH + 1)
        if line:
            if self.discarding or len(line) > self.MAX_LINE_LENGTH:
                self.discarding = not line.endswith("\n")
                if not self.discarding:
                    LOG.warning("Discarded oversized event from %s", self.path)
                    return ""
                return None
            if not line.endswith("\n"):
                self.file.seek(position)
                if self._needs_reopen():
                    self._open(reset_offset=True)
                return None
            return line

        if self._needs_reopen():
            self._open(reset_offset=True)
        return None


def parse_lynis_report(
    report_path: Path,
    *,
    require_complete: bool = False,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    warnings: List[Tuple[str, str]] = []
    suggestions: List[Tuple[str, str]] = []
    if not report_path.exists():
        if require_complete:
            raise FileNotFoundError(report_path)
        return warnings, suggestions

    header = finished = False
    with report_path.open("r", encoding="utf-8", errors="replace") as report:
        for raw_line in report:
            line = raw_line.strip()
            header = header or line.startswith("report_version_major=")
            finished = finished or line == "finish=true"
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
    if require_complete and not (header and finished):
        raise ValueError("Lynis report is incomplete or invalid")
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
        self.scorer = RiskScorer(self.config, self.store, self.config_dir)
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
        ] if runtime_cfg.get("enabled", True) else []
        self.store.set("enabled_sources", {
            "runtime_rules": runtime_cfg.get("enabled", True),
        })

    def close(self) -> None:
        for _, reader in self.readers:
            reader.close()
        self.store.close()

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_event.set()

    def run_posture_scan(self) -> Optional[float]:
        baseline = self.config.get("baseline_lynis", {}) or {}
        if not baseline.get("enabled", False):
            self.recent_lynis_hits = []
            with self.store.transaction():
                self.scorer.set_posture_score(None)
                self.store.set("baseline_status", "disabled")
                self.store.set("baseline_details", {"status": "disabled", "score": None})
                self.store.set("recent_lynis_hits", [])
            return None

        try:
            return self._run_posture_scan(baseline)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            LOG.warning("Baseline unavailable: %s", error)
            self.recent_lynis_hits = []
            with self.store.transaction():
                self.scorer.set_posture_score(None)
                self.store.set("baseline_status", "unavailable")
                self.store.set("recent_lynis_hits", [])
                self.store.set("baseline_details", {"status": "unavailable", "score": None, "errors": [str(error)]})
            return None

    def _run_posture_scan(self, baseline: Mapping[str, Any]) -> Optional[float]:
        report_path = _resolve_path(
            self.config_dir,
            str(baseline.get("report_path", "/var/log/lynis-report.dat")),
        )

        if baseline.get("run_lynis", False):
            command = str(baseline.get("lynis_cmd", "lynis audit system --quick --quiet"))
            arguments = shlex.split(command)
            if "--report-file" not in arguments:
                arguments.extend(["--report-file", str(report_path)])
            completed = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                check=False,
                timeout=int(baseline.get("timeout_seconds", 1800)),
            )
            if completed.returncode:
                raise ValueError(f"Lynis exited with rc={completed.returncode}")

        report_stat = report_path.stat()
        max_age = max(1, int(baseline.get("max_report_age_seconds", 86400)))
        age = time.time() - report_stat.st_mtime
        if report_stat.st_size == 0:
            raise ValueError("Lynis 报告为空；检查 tsa-baseline.service 日志")
        if age < -300:
            raise ValueError("Lynis 报告时间领先主机时钟；请校时并重新扫描")
        if age > max_age:
            raise ValueError(f"Lynis 报告已过期（{age / 3600:.1f} 小时，有效期 {max_age / 3600:g} 小时）；检查 tsa-baseline.timer 或手动启动 tsa-baseline.service")
        parsed = read_report(report_path)
        if report_path.stat().st_mtime_ns != report_stat.st_mtime_ns:
            raise ValueError("Lynis report changed while being read; retry after scan finishes")
        details = score_report(parsed, baseline)
        details.update({"report_path": str(report_path), "report_mtime": report_stat.st_mtime,
                        "expires_at": report_stat.st_mtime + max_age})
        self.recent_lynis_hits = [
            {"type": "CONTROL", "control": c["control"], "deducted_points": c["deducted_points"],
             "message": c["reason"]} for c in details["controls"] if c["deducted_points"]
        ]
        with self.store.transaction():
            self.scorer.set_posture_score(details["score"])
            self.store.set("baseline_status", details["status"])
            self.store.set("baseline_details", details)
            self.store.set("baseline_report_mtime", report_stat.st_mtime)
            self.store.set("recent_lynis_hits", self.recent_lynis_hits)
        LOG.info(
            "Posture score %s/100 from %s (%d deductions)",
            self.scorer.posture_score,
            report_path,
            details["deducted_points"],
        )
        return self.scorer.posture_score

    def process_line(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
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


    def generate_report(self, status: str = "running") -> None:
        weights = read_policy(self.config, self.config_dir)
        baseline = baseline_snapshot({"baseline_details": self.store.get("baseline_details"),
                                      "baseline_status": self.store.get("baseline_status", "unavailable"),
                                      "posture_score": self.scorer.posture_score})
        report = {
            "generated_time": _utc_now(),
            "status": status,
            "baseline_status": baseline["status"],
            "baseline": baseline,
            "sources": {
                "falco_log_path": str(self.falco_log_path),
                "lynis_report_path": str(
                    (self.config.get("baseline_lynis", {}) or {}).get("report_path", "")
                ),
            },
            "scores": {
                "final": self.scorer.final_score(weights),
                "posture": baseline.get("score"),
                "runtime": self.scorer.runtime_score,
            },
            "recent_lynis_hits": self.recent_lynis_hits[-50:],
            "weights": weights,
            "runtime_risks": runtime_risk_breakdown(
                self.store.db, self.config.get("runtime_rules", {}) or {}, time.time()
            ),
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
        self.store.set("fusion_status", "starting")
        self.run_posture_scan()
        runtime_cfg = self.config.get("runtime_rules", {}) or {}
        poll_interval = max(0.1, float(runtime_cfg.get("poll_interval", 1)))
        reporting = self.config.get("reporting", {}) or {}
        report_interval = max(10, int(reporting.get("interval_seconds", 300)))
        retention_days = max(1, int(reporting.get("retention_days", 30)))
        next_report = time.monotonic() + report_interval
        baseline = self.config.get("baseline_lynis", {}) or {}
        baseline_interval = max(10, int(baseline.get("interval_seconds", 300)))
        next_baseline = time.monotonic() + baseline_interval
        next_heartbeat = 0.0
        self.generate_report("running")

        LOG.info(
            "Watching security event sources: %s",
            ", ".join(f"{source}={reader.path}" for source, reader in self.readers),
        )
        while not self.stop_event.is_set():
            monotonic = time.monotonic()
            if monotonic >= next_heartbeat:
                with self.store.transaction():
                    self.store.set("fusion_heartbeat", time.time())
                    self.store.set("fusion_status", "running")
                    self.store.set("source_status", {
                        source: reader.file is not None and reader.path.is_file()
                        for source, reader in self.readers
                    })
                next_heartbeat = monotonic + 5
            if monotonic >= next_baseline:
                self.run_posture_scan()
                next_baseline = time.monotonic() + baseline_interval
            if monotonic >= next_report:
                self.generate_report("running")
                self.store.prune(time.time(), retention_days)
                next_report = time.monotonic() + report_interval
            processed = False
            for source, reader in self.readers:
                line = reader.readline()
                if line is None:
                    continue
                processed = True
                with self.store.transaction():
                    self.process_line(line)
                    reader.acknowledge()
            if processed:
                continue

            recovered = self.scorer.maybe_recover()
            if recovered:
                LOG.info(
                    "Runtime score recovered by %d to %.2f",
                    recovered,
                    self.scorer.runtime_score,
                )
            self.stop_event.wait(poll_interval)

        self.store.set("fusion_status", "stopped")
        self.generate_report("stopped")
