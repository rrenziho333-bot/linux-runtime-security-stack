"""Versioned scoring weights shared by the collector and management API."""

import math
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path


class VersionConflict(ValueError):
    pass


def validate_weights(posture, runtime):
    for value in (posture, runtime):
        if isinstance(value, bool) or not isinstance(value, (float, int)):
            raise ValueError('Weights must be JSON numbers')
        if not 0 <= value <= 1 or not math.isfinite(value):
            raise ValueError('Weights must be finite numbers between 0 and 1')
    if Decimal(str(posture)) + Decimal(str(runtime)) != Decimal('1'):
        raise ValueError('Weights must sum to 1')


def policy_path(config, config_dir):
    if config_dir is None:
        return None
    value = (config.get('scoring', {}) or {}).get('weights_db', 'settings/weights.db')
    path = Path(value)
    return path if path.is_absolute() else Path(config_dir) / path


def default_policy(config):
    # Retain compatibility with the existing local YAML weight normalization.
    weights = (config.get('scoring', {}) or {}).get('weights', {}) or {}
    posture = max(0.0, float(weights.get('posture', 0.4)))
    runtime = max(0.0, float(weights.get('runtime', 0.6)))
    total = posture + runtime
    if total == 0:
        posture, runtime, total = 0.4, 0.6, 1.0
    return {'posture': posture / total, 'runtime': runtime / total, 'version': 0,
            'updated_at': None, 'updated_by': 'local-config', 'reason': 'Initial YAML defaults'}


def _row_policy(row, config):
    if row is None:
        return default_policy(config)
    policy = dict(row)
    validate_weights(policy['posture'], policy['runtime'])
    return policy


def read_policy(config, config_dir):
    path = policy_path(config, config_dir)
    if path is None:
        return default_policy(config)
    if path.is_symlink():
        raise ValueError('Weights database must not be a symlink')
    if not path.exists():
        return default_policy(config)
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        row = db.execute('SELECT * FROM weight_revisions ORDER BY version DESC LIMIT 1').fetchone()
        return _row_policy(row, config)


def update_policy(config, config_dir, *, posture, runtime, expected_version, actor, reason=''):
    validate_weights(posture, runtime)
    if type(expected_version) is not int or expected_version < 0:
        raise ValueError('expected_version must be a nonnegative integer')
    if not isinstance(reason, str) or len(reason) > 500:
        raise ValueError('reason must be a string of at most 500 characters')
    path = policy_path(config, config_dir)
    if path is None:
        raise ValueError('Missing configuration directory')
    if path.is_symlink():
        raise ValueError('Weights database must not be a symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute('''CREATE TABLE IF NOT EXISTS weight_revisions (
            posture REAL NOT NULL, runtime REAL NOT NULL,
            version INTEGER PRIMARY KEY, updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL, reason TEXT NOT NULL)''')
        db.execute('BEGIN IMMEDIATE')
        current = _row_policy(db.execute('SELECT * FROM weight_revisions ORDER BY version DESC LIMIT 1').fetchone(), config)
        if current['version'] != expected_version:
            raise VersionConflict('Weight version changed; GET current weights before retrying')
        if current['version'] == 0:
            initial = dict(current, updated_at=datetime.now(timezone.utc).isoformat())
            db.execute('INSERT INTO weight_revisions VALUES (:posture,:runtime,:version,:updated_at,:updated_by,:reason)', initial)
        policy = {'posture': float(posture), 'runtime': float(runtime),
                  'version': current['version'] + 1,
                  'updated_at': datetime.now(timezone.utc).isoformat(),
                  'updated_by': actor, 'reason': reason}
        db.execute('INSERT INTO weight_revisions VALUES (:posture,:runtime,:version,:updated_at,:updated_by,:reason)', policy)
        db.commit()
    return policy


def final_score(posture, runtime, weights):
    if weights['posture'] > 0 and posture is None:
        return None
    return round(max(0, min(100, (posture or 0) * weights['posture'] + runtime * weights['runtime'])), 2)
