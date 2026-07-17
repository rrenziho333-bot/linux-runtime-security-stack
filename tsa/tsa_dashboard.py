#!/usr/bin/env python3
"""Read-only local dashboard for the TSA/Falco/BPF LSM security pipeline."""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse

import yaml


HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TSA 安全流水线</title>
  <style>
    :root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2d;--line:#203550;--text:#eaf2ff;
      --muted:#91a6c0;--blue:#55b6ff;--green:#4fd1a1;--yellow:#f3c969;--red:#ff7185}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#102b48 0,var(--bg) 38%);
      color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
    main{max-width:1280px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center}
    h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 14px}.muted{color:var(--muted)}
    .live{display:flex;align-items:center;gap:8px}.dot{width:9px;height:9px;border-radius:50%;background:var(--green);
      box-shadow:0 0 12px var(--green)}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:18px}
    .panel{background:rgba(13,27,45,.92);border:1px solid var(--line);border-radius:14px;padding:17px;
      box-shadow:0 12px 30px rgba(0,0,0,.18)}.scores{grid-column:span 4}.pipeline{grid-column:span 8}
    .policies{grid-column:span 4}.events{grid-column:span 8}.score-row{display:flex;gap:13px}
    .score{flex:1;border:1px solid var(--line);border-radius:12px;padding:13px}.score strong{display:block;font-size:28px}
    .stages{display:flex;align-items:stretch;gap:7px}.stage{flex:1;padding:11px;border:1px solid var(--line);
      border-radius:10px;min-width:0}.stage.ok{border-color:#28755e}.stage.bad{border-color:#7c3442}.arrow{align-self:center;color:var(--muted)}
    .badge{display:inline-block;border-radius:99px;padding:2px 8px;font-size:12px;border:1px solid var(--line)}
    .audit{color:var(--yellow);border-color:#826c30}.deny{color:var(--red);border-color:#8c3544}
    .falco{color:var(--blue);border-color:#28638d}.oktxt{color:var(--green)}.policy{padding:12px 0;border-top:1px solid var(--line)}
    .policy:first-of-type{border-top:0}.policy-line{display:flex;justify-content:space-between;gap:10px}
    .incident{border-top:1px solid var(--line);padding:15px 0}.incident:first-of-type{border-top:0;padding-top:0}
    .incident-head{display:flex;justify-content:space-between;gap:12px}.steps{margin:10px 0 0;padding:0;list-style:none}
    .steps li{position:relative;margin-left:8px;padding:4px 0 4px 20px;border-left:1px solid #31506f}
    .steps li:before{content:"";position:absolute;left:-4px;top:12px;width:7px;height:7px;border-radius:50%;background:var(--blue)}
    .raw{margin-top:8px}.raw summary{cursor:pointer;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;
      background:#081321;padding:10px;border-radius:8px;max-height:240px;overflow:auto;font-size:12px}
    .empty{color:var(--muted);padding:18px 0}.error{background:#5f2631;padding:12px;border-radius:8px;margin-top:12px}
    @media(max-width:900px){.scores,.pipeline,.policies,.events{grid-column:1/-1}.stages{flex-direction:column}.arrow{display:none}}
  </style>
</head>
<body><main>
  <div class="top"><div><h1>TSA 安全事件流水线</h1><div class="muted">Falco 观察 · BPF LSM 决策 · TSA 融合评分</div></div>
    <div class="live"><span class="dot"></span><span id="refresh">正在连接本机数据</span></div></div>
  <div id="error"></div>
  <div class="grid">
    <section class="panel scores"><h2>风险评分</h2><div id="scores" class="score-row"></div></section>
    <section class="panel pipeline"><h2>组件流水线</h2><div id="pipeline" class="stages"></div></section>
    <section class="panel policies"><h2>BPF LSM 保护策略</h2><div id="policies"></div></section>
    <section class="panel events"><h2>最近操作与证据链</h2><div id="events"></div></section>
  </div>
</main>
<script>
const esc=v=>String(v??"");
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=esc(text);return n}
function renderScore(data){const root=document.querySelector("#scores");root.replaceChildren();
  [["最终",data.final],["基线",data.posture],["运行时",data.runtime]].forEach(([name,val])=>{
    const box=el("div","score");box.append(el("span","muted",name),el("strong","",Number(val).toFixed(1)));root.append(box)})}
function renderPipeline(stages){const root=document.querySelector("#pipeline");root.replaceChildren();
  stages.forEach((s,i)=>{const box=el("div","stage "+(s.active?"ok":"bad"));box.append(el("strong","",s.name),
    el("div",s.active?"oktxt":"muted",s.status),el("small","muted",s.detail));root.append(box);
    if(i<stages.length-1)root.append(el("span","arrow","→"))})}
function renderPolicies(items){const root=document.querySelector("#policies");root.replaceChildren();
  if(!items.length){root.append(el("div","empty","没有加载 BPF LSM 策略"));return}
  items.forEach(p=>{const box=el("div","policy");const line=el("div","policy-line");
    line.append(el("strong","",p.name),el("span","badge "+p.mode,p.mode.toUpperCase()));box.append(line);
    box.append(el("div","muted","保护："+p.paths.join(", ")),el("div","muted","策略 ID："+p.id+" · 允许 UID："+(p.allowed_uids.join(", ")||"无")));
    root.append(box)})}
function renderEvents(items){const root=document.querySelector("#events");root.replaceChildren();
  if(!items.length){root.append(el("div","empty","尚无安全事件。对保护文件执行测试操作后会出现在这里。"));return}
  items.forEach(x=>{const box=el("article","incident");const head=el("div","incident-head");const left=el("div");
    left.append(el("strong","",x.title),el("div","muted",x.time+" · PID "+(x.pid||"未知")));
    head.append(left,el("span","badge "+x.badge_class,x.decision));box.append(head);
    const steps=el("ol","steps");x.steps.forEach(s=>steps.append(el("li","",s)));box.append(steps);
    const raw=document.createElement("details");raw.className="raw";raw.append(el("summary","","查看原始证据"));
    raw.append(el("pre","",JSON.stringify(x.evidence,null,2)));box.append(raw);root.append(box)})}
async function refresh(){try{const r=await fetch("/api/status",{cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);
  const d=await r.json();renderScore(d.scores);renderPipeline(d.pipeline);renderPolicies(d.policies);renderEvents(d.incidents);
  document.querySelector("#refresh").textContent="已更新 "+new Date(d.generated_time).toLocaleTimeString();
  document.querySelector("#error").replaceChildren()}catch(e){const box=el("div","error","读取看板数据失败："+e.message);
  document.querySelector("#error").replaceChildren(box);document.querySelector("#refresh").textContent="连接异常"}}
refresh();setInterval(refresh,2000);
</script></body></html>"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def service_state(name: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


class DashboardData:
    def __init__(self, tsa_config: Path, bpf_policy: Path):
        with tsa_config.open("r", encoding="utf-8") as stream:
            self.config = yaml.safe_load(stream) or {}
        storage = self.config.get("storage", {}) or {}
        state_db = Path(str(storage.get("state_db", "state/tsa.db"))).expanduser()
        self.state_db = state_db if state_db.is_absolute() else tsa_config.parent / state_db
        self.bpf_policy = bpf_policy

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"file:{self.state_db}?mode=ro", uri=True, timeout=2
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _state(self, db: sqlite3.Connection) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for row in db.execute("SELECT key, value FROM state"):
            try:
                values[row["key"]] = json.loads(row["value"])
            except json.JSONDecodeError:
                values[row["key"]] = row["value"]
        return values

    def _events(self, db: sqlite3.Connection, limit: int = 80) -> List[Dict[str, Any]]:
        rows = db.execute(
            """
            SELECT id, received_time, event_time, source, rule_name, status,
                   deducted_points, payload, risk_expires_at
            FROM events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        events = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                payload = {"malformed_payload": row["payload"]}
            events.append(
                {
                    "id": row["id"],
                    "received_time": row["received_time"],
                    "event_time": row["event_time"],
                    "source": row["source"],
                    "rule": row["rule_name"],
                    "status": row["status"],
                    "deducted_points": row["deducted_points"],
                    "risk_expires_at": row["risk_expires_at"],
                    **payload,
                }
            )
        return events

    def _scores(
        self, db: sqlite3.Connection, state: Mapping[str, Any]
    ) -> Dict[str, float]:
        now = time.time()
        controls = (
            (self.config.get("runtime_rules", {}) or {}).get("event_control", {}) or {}
        )
        cap = max(0, int(controls.get("max_active_points_per_rule", 20)))
        rows = db.execute(
            """
            SELECT rule_name, SUM(deducted_points) points FROM events
            WHERE status='scored' AND deducted_points > 0
              AND risk_expires_at IS NOT NULL AND risk_expires_at > ?
            GROUP BY rule_name
            """,
            (now,),
        ).fetchall()
        active = sum(
            min(int(row["points"] or 0), cap) if cap else int(row["points"] or 0)
            for row in rows
        )
        runtime = float(max(0, 100 - min(100, active)))
        posture = float(state.get("posture_score", 100))
        weights = (self.config.get("scoring", {}) or {}).get("weights", {}) or {}
        posture_weight = max(0.0, float(weights.get("posture", 0.4)))
        runtime_weight = max(0.0, float(weights.get("runtime", 0.6)))
        total = posture_weight + runtime_weight or 1.0
        final = (posture * posture_weight + runtime * runtime_weight) / total
        return {"final": round(final, 2), "posture": posture, "runtime": runtime}

    def _policies(self) -> List[Dict[str, Any]]:
        try:
            with self.bpf_policy.open("r", encoding="utf-8") as stream:
                document = yaml.safe_load(stream) or {}
        except OSError:
            return []
        result = []
        for policy in document.get("policies", []) or []:
            if not isinstance(policy, Mapping):
                continue
            result.append(
                {
                    "id": policy.get("id", 0),
                    "name": str(policy.get("name", "unnamed")),
                    "mode": str(policy.get("mode", "unknown")).lower(),
                    "paths": list(policy.get("paths", []) or []),
                    "allowed_uids": list(policy.get("allowed_uids", []) or []),
                }
            )
        return result

    @staticmethod
    def _tsa_step(event: Mapping[str, Any]) -> str:
        status = str(event.get("status", "unknown"))
        points = int(event.get("deducted_points", 0))
        labels = {
            "scored": f"TSA 已接收并计入风险：-{points} 分",
            "duplicate": "TSA 已接收：命中去重窗口，不重复扣分",
            "rate_limited": "TSA 已接收：命中限速，不继续扣分",
            "maintenance": "TSA 已接收：维护窗口，仅记录不扣分",
            "maintenance_reclassified": "TSA 已将该部署事件归类为维护活动",
            "whitelisted": "TSA 已接收：白名单事件，不扣分",
            "ignored": "TSA 已接收：规则配置为不扣分",
        }
        return labels.get(status, f"TSA 已接收：状态 {status}，扣分 {points}")

    def _incidents(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        falco = [item for item in events if item.get("source") == "falco"]
        paired_falco = set()
        incidents = []
        policy_paths = {
            str(policy["name"]): set(policy["paths"]) for policy in self._policies()
        }
        for event in events:
            if event.get("source") != "bpf_lsm":
                continue
            event_ts = parse_time(str(event.get("received_time", "")))
            pid = str(event.get("pid", ""))
            match: Optional[Dict[str, Any]] = None
            match_basis = ""
            for candidate in falco:
                if candidate["id"] in paired_falco:
                    continue
                delta = abs(
                    parse_time(str(candidate.get("received_time", ""))) - event_ts
                )
                if delta > 3:
                    continue
                candidate_pid = str(candidate.get("pid", ""))
                same_pid = bool(pid and candidate_pid and candidate_pid == pid)
                same_process = (
                    bool(event.get("command"))
                    and str(candidate.get("process", "")) == str(event.get("command"))
                )
                same_path = str(candidate.get("file", "")) in policy_paths.get(
                    str(event.get("policy_name", "")), set()
                )
                if same_pid or (same_process and same_path):
                    match = candidate
                    match_basis = (
                        "PID + 时间"
                        if same_pid
                        else "进程名 + 保护路径 + 时间"
                    )
                    paired_falco.add(candidate["id"])
                    break

            action = str(event.get("action", "unknown")).lower()
            operation = str(event.get("operation", "unknown"))
            command = str(event.get("command", "unknown"))
            policy = str(event.get("policy_name", event.get("rule", "unknown")))
            steps = [f"进程 {command} 请求执行 {operation}"]
            if match:
                steps.append(
                    f"Falco 匹配规则：{match.get('rule')}（关联依据：{match_basis}）"
                )
            else:
                steps.append("未关联到 3 秒窗口内同一操作的 Falco 报警")
            steps.append(f"BPF LSM 命中策略：{policy}")
            if action == "deny":
                decision = "已拦截"
                badge = "deny"
                steps.append("BPF LSM 返回 -EPERM：内核拒绝操作")
            elif action == "audit":
                decision = "审计放行"
                badge = "audit"
                steps.append("BPF LSM 记录 AUDIT：操作继续执行")
            else:
                decision = action
                badge = "audit"
                steps.append(f"BPF LSM 返回决策：{action}")
            steps.append(self._tsa_step(event))
            evidence = {"bpf_lsm": event}
            if match:
                evidence["falco"] = match
            incidents.append(
                {
                    "time": event.get("received_time", ""),
                    "title": f"{command} · {operation} · {policy}",
                    "pid": event.get("pid", ""),
                    "decision": decision,
                    "badge_class": badge,
                    "steps": steps,
                    "evidence": evidence,
                    "_timestamp": event_ts,
                }
            )

        for event in falco:
            if event["id"] in paired_falco:
                continue
            process = str(event.get("process", "") or event.get("command", "unknown"))
            incidents.append(
                {
                    "time": event.get("received_time", ""),
                    "title": f"{event.get('rule')} · {process}",
                    "pid": event.get("pid", ""),
                    "decision": "Falco 报警",
                    "badge_class": "falco",
                    "steps": [
                        f"Falco 观察到系统调用并匹配规则：{event.get('rule')}",
                        "Falco 只报警，不负责阻止该操作",
                        "未关联到 BPF LSM 策略命中；不能据此判断操作被拦截",
                        self._tsa_step(event),
                    ],
                    "evidence": {"falco": event},
                    "_timestamp": parse_time(str(event.get("received_time", ""))),
                }
            )
        incidents.sort(key=lambda item: item["_timestamp"], reverse=True)
        for incident in incidents:
            incident.pop("_timestamp", None)
        return incidents[:30]

    def scores(self) -> Dict[str, float]:
        """Return only the current risk scores (lighter than snapshot())."""
        with self._connect() as db:
            state = self._state(db)
            return self._scores(db, state)

    def snapshot(self) -> Dict[str, Any]:
        with self._connect() as db:
            state = self._state(db)
            events = self._events(db)
            scores = self._scores(db, state)
        policies = self._policies()
        states = {
            "falco": service_state("falco-modern-bpf.service"),
            "bpf": service_state("bpf-lsm-controller.service"),
            "tsa": service_state("tsa-fusion.service"),
        }
        modes = sorted({item["mode"].upper() for item in policies}) or ["无策略"]
        pipeline = [
            {
                "name": "Falco",
                "active": states["falco"] == "active",
                "status": states["falco"],
                "detail": "观察行为并按规则报警",
            },
            {
                "name": "BPF LSM",
                "active": states["bpf"] == "active",
                "status": states["bpf"],
                "detail": "内核决策：" + "/".join(modes),
            },
            {
                "name": "TSA",
                "active": states["tsa"] == "active",
                "status": states["tsa"],
                "detail": "融合、去重和风险评分",
            },
            {
                "name": "看板",
                "active": True,
                "status": "active",
                "detail": "只读显示，不修改策略",
            },
        ]
        return {
            "generated_time": utc_now(),
            "scores": scores,
            "pipeline": pipeline,
            "policies": policies,
            "incidents": self._incidents(events),
        }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "TSADashboard/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _send(
        self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send(HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            self._send(b'{"status":"ok"}', "application/json")
            return
        if path == "/api/status":
            try:
                snapshot = self.server.data.snapshot()  # type: ignore[attr-defined]
                body = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
                self._send(body, "application/json; charset=utf-8")
            except (OSError, sqlite3.Error, ValueError) as error:
                body = json.dumps(
                    {"error": str(error)}, ensure_ascii=False
                ).encode("utf-8")
                self._send(
                    body,
                    "application/json; charset=utf-8",
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        if path == "/systemManage/risk/score":
            # Zero-trust management API: GET current risk scores.
            # Unified response envelope per 《零信任管理系统接口文档》.
            try:
                data = self.server.data.scores()  # type: ignore[attr-defined]
                envelope = {
                    "code": 20000,
                    "status": True,
                    "message": "操作成功",
                    "data": {
                        "final": data["final"],
                        "posture": data["posture"],
                        "runtime": data["runtime"],
                        "generated_time": utc_now(),
                    },
                }
                body = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
                self._send(body, "application/json; charset=utf-8")
            except (OSError, sqlite3.Error, ValueError) as error:
                body = json.dumps(
                    {
                        "code": 50000,
                        "status": False,
                        "message": f"查询失败: {error}",
                        "data": None,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
                self._send(
                    body,
                    "application/json; charset=utf-8",
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
            return
        self._send(b'{"error":"not found"}', "application/json", HTTPStatus.NOT_FOUND)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local TSA security pipeline dashboard")
    parser.add_argument(
        "--tsa-config",
        default=str(Path(__file__).with_name("policy_config.yaml")),
    )
    parser.add_argument(
        "--bpf-policy",
        default="/etc/bpf-lsm/policy.yaml",
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer(
        (args.bind, args.port),
        DashboardHandler,
    )
    server.data = DashboardData(  # type: ignore[attr-defined]
        Path(args.tsa_config).expanduser().resolve(),
        Path(args.bpf_policy).expanduser().resolve(),
    )
    print(f"TSA dashboard listening on http://{args.bind}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
