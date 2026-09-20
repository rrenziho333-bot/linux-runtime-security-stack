#!/usr/bin/env python3
"""Write only the existing demo file, then locate this attempt's durable evidence."""

import argparse
import copy
import errno
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from contextlib import closing
from pathlib import Path

from tsa_dashboard import DashboardData
from tsa_core import RiskScorer, StateStore, parse_event_time


TARGET = Path("/etc/tsa-protected-demo")
RULE = "Monitor specific file access"


def write_demo(token, device, inode):
    result = {"pid": os.getpid(), "token": token, "outcome": "error"}
    try:
        fd = os.open(TARGET, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (int(device), int(inode)):
                raise ValueError("Demo file identity changed; no data written")
            content = (token + "\n").encode("utf-8")
            if os.write(fd, content) != len(content):
                raise ValueError("Incomplete demo write")
        finally:
            os.close(fd)
        result["outcome"] = "written"
    except OSError as error:
        result.update(outcome="denied" if error.errno == errno.EPERM else "error", error=str(error))
    except ValueError as error:
        result["error"] = str(error)
    print(json.dumps(result))
    return 0


def evaluate(events, attempt):
    falco = [e for e in events if e.get("source") == "falco"
             and str(e.get("pid")) == str(attempt["pid"])
             and e.get("file") == TARGET.as_posix()
             and (e.get("syscall") in ("write", "writev", "pwrite", "pwritev")
                  or e.get("is_open_write") is True)]
    return attempt["outcome"] == "written" and bool(falco), falco


def check_probe_times(events, started, finished):
    """A known, just-executed probe must not be mistaken for historical backlog."""
    if finished < started:
        raise ValueError("测试期间系统时间回退；校时后重新执行验收")
    for event in events:
        if event.get("rule") != RULE:
            continue
        try:
            timestamp = parse_event_time(event.get("event_time", ""))
        except (ValueError, TypeError):
            raise ValueError("本次 Falco 证据缺少有效事件时间，无法验收") from None
        if not started - 5 <= timestamp <= finished + 5:
            raise ValueError(
                f"本次 Falco 事件时间与实际操作不符（相对操作开始偏差 {timestamp - started:+.1f} 秒）。"
                "先用 timedatectl 检查系统时间；校时后执行 sudo systemctl restart falco-modern-bpf，"
                "再重新验收。虚拟机挂起恢复后尤其需要检查；不要延长告警有效期来绕过此错误。")


def score_test_evidence(config, event):
    """Replay captured demo evidence in a disposable database, not the live score."""
    isolated = copy.deepcopy(config)
    isolated['runtime_rules']['specific_rules'][RULE]['test_only'] = False
    fields = {field: event.get(key) for key, field in {
        'pid': 'proc.pid', 'process': 'proc.name', 'file': 'fd.name',
        'is_open_write': 'evt.is_open_write', 'syscall': 'evt.type'}.items()}
    alert = {'rule': RULE, 'time': event['event_time'], 'priority': event.get('priority', 'WARNING'),
             'output_fields': fields}
    with tempfile.TemporaryDirectory(prefix='lrss-isolated-score-') as directory:
        store = StateStore(Path(directory) / 'test.db')
        try:
            scorer = RiskScorer(isolated, store)
            first = scorer.process_falco_event(alert)
            score = scorer.runtime_score
            second = scorer.process_falco_event(alert)
            expected = isolated['runtime_rules']['specific_rules'][RULE]['points']
            if first['deducted_points'] != expected or score != 100 - expected or second['deducted_points'] != 0:
                raise ValueError('独立测试计分或重复去重不符合策略')
            return score
        finally:
            store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-demo", nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run this verification on the deployed Ubuntu host")
    if args.write_demo:
        return write_demo(*args.write_demo)
    try:
        if os.geteuid() != 0:
            subprocess.run(['sudo', '-v'], check=True)
        data = DashboardData(Path(__file__).with_name("policy_config.yaml"))
        before = data.snapshot()
        if not before['availability']['ready']:
            raise ValueError('评分尚不可用：' + before['availability']['reason'])
        with closing(data._connect()) as db:
            after = db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        info = TARGET.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Demo target must be an existing regular file, not a symlink")
        token = "lrss-verify-" + uuid.uuid4().hex[:12]
        command = ([] if os.geteuid() == 0 else ["sudo"]) + [
            "/usr/bin/python3", str(Path(__file__).resolve()), "--write-demo", token, str(info.st_dev), str(info.st_ino)]
        started = time.time()
        completed = subprocess.run(command, text=True, capture_output=True, timeout=90, check=True)
        finished = time.time()
        attempt = json.loads(completed.stdout)
        print(f"测试编号：{token} | PID：{attempt['pid']} | 文件：{TARGET}")
        print("实际写入结果：" + {"written": "成功", "denied": "EPERM 拒绝", "error": "失败"}[attempt["outcome"]])
        if attempt.get("error"):
            print(attempt["error"])
        print(f"本次证据：http://127.0.0.1:8766/?pid={attempt['pid']}&after={after}")
        deadline = time.monotonic() + 15
        while True:
            with closing(data._connect()) as db:
                events = data._events(db, after=after, pid=attempt["pid"])
            success, falco = evaluate(events, attempt)
            if success or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        for event in falco:
            print(f"{event['source']} #{event['id']} | {event['rule']} | {event['status']} | 历史扣分 {event['deducted_points']}")
        if success:
            check_probe_times(falco, started, finished)
            after_snapshot = data.snapshot()
            risks = after_snapshot['runtime_risks']
            active = next((r['points'] for r in risks if r['rule'] == RULE), None)
            policy = data.config['runtime_rules']['specific_rules'][RULE]
            expected = policy['points']
            matching = [e for e in falco if e['rule'] == RULE]
            if policy.get('test_only'):
                if not matching or active is not None or any(e['status'] != 'test_event' or e['deducted_points'] != 0 for e in matching):
                    raise ValueError('验收事件未与实际评分隔离')
                isolated_score = score_test_evidence(data.config, matching[0])
                print(f'独立验收运行时分：100 → {isolated_score}；重复证据不再次扣分。')
            elif not matching or active != expected:
                raise ValueError(f'验收规则未正确计分：期望 {expected}，实际 {active}')
            if not after_snapshot['availability']['ready']:
                raise ValueError('测试后评分不可用：' + after_snapshot['availability']['reason'])
            scores = after_snapshot['scores']
            if scores['runtime'] != max(0, 100 - sum(r['points'] for r in risks)):
                raise ValueError('运行时总分与当前风险明细不一致')
            prior = next((r['points'] for r in before['runtime_risks'] if r['rule'] == RULE), 0)
            print('测试前分数：' + json.dumps(before['scores'], ensure_ascii=False))
            print('测试后分数：' + json.dumps(scores, ensure_ascii=False))
            print(f'本规则实际风险：{prior} → {active or 0} 分；其他并发告警可能影响总分。')
            print("PASS：真实写入、同 PID 告警、规则风险值和运行时总分对账一致（不代表完整攻击覆盖）。")
            return 0
        print("FAIL：结果或证据不完整；不要仅凭服务 active 判断成功。")
        if not falco:
            print("未找到本次 PID 的写入告警；检查 Falco 服务、规则和 PID 输出配置。")
        return 1
    except subprocess.CalledProcessError as error:
        print("FAIL：测试写入命令执行失败；请在可输入 sudo 密码的 Ubuntu 终端运行。")
        if error.stderr:
            print(error.stderr.strip())
        return 1
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"FAIL：{error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
