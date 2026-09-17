#!/usr/bin/env python3
"""Write only the existing demo file, then locate this attempt's durable evidence."""

import argparse
import errno
import json
import os
import sqlite3
import stat
import subprocess
import time
import uuid
from contextlib import closing
from pathlib import Path

from tsa_dashboard import DashboardData


TARGET = Path("/etc/tsa-protected-demo")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-demo", nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run this verification on the deployed Ubuntu host")
    if args.write_demo:
        return write_demo(*args.write_demo)
    try:
        data = DashboardData(Path(__file__).with_name("policy_config.yaml"))
        with closing(data._connect()) as db:
            after = db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        info = TARGET.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Demo target must be an existing regular file, not a symlink")
        token = "lrss-verify-" + uuid.uuid4().hex[:12]
        command = ([] if os.geteuid() == 0 else ["sudo"]) + [
            "/usr/bin/python3", str(Path(__file__).resolve()), "--write-demo", token, str(info.st_dev), str(info.st_ino)]
        completed = subprocess.run(command, text=True, capture_output=True, timeout=90, check=True)
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
            print("PASS：本次文件操作结果与入库证据一致（不代表完整攻击覆盖）。")
            return 0
        print("FAIL：结果或证据不完整；不要仅凭服务 active 判断成功。")
        if not falco:
            print("未找到本次 PID 的写入告警；检查 Falco 服务、规则和 PID 输出配置。")
        return 1
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"FAIL：{error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
