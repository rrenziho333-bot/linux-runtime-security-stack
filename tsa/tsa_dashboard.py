#!/usr/bin/env python3
"""Read-only local dashboard for the TSA/Falco/Lynis security pipeline."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import sqlite3
import subprocess
import time
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import parse_qs, urlparse

import yaml


HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TSA 主机安全监测</title>
<style>
:root{color-scheme:light;--bg:#f4f6f5;--paper:#fff;--ink:#202826;--muted:#65716c;--line:#dce3df;
--green:#147257;--red:#b52c3e;--amber:#88610c;--blue:#276b91}
*{box-sizing:border-box;letter-spacing:0}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1440px;margin:auto;padding:24px 28px}h1{font-size:24px;margin:0}h2{font-size:17px;margin:0}p{margin:0}
.top,.section-head,.toolbar,.service{display:flex;align-items:center;justify-content:space-between;gap:12px}
.top{padding-bottom:20px;border-bottom:1px solid var(--line);align-items:flex-start}.muted,small{color:var(--muted)}
.refresh{text-align:right;font-size:12px;font-variant-numeric:tabular-nums}.refresh strong{display:block;color:var(--green)}
.overview{display:grid;grid-template-columns:1fr 1.4fr;border-bottom:1px solid var(--line);background:var(--paper)}
.score-row{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));padding:20px 0}
.score{padding:0 20px;border-right:1px solid var(--line)}.score strong{display:block;font-size:30px;font-variant-numeric:tabular-nums;line-height:1.3}
.score:first-child strong{color:var(--green)}.score small{font-size:11px}.score strong.unknown{font-size:20px}
.components{padding:20px 24px}.services{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 24px;margin-top:12px}
.service{min-width:0}.service small{display:block}.state{white-space:nowrap;font-size:12px;color:var(--green)}.state.bad{color:var(--red)}
.badge{font-size:12px;padding:2px 6px;white-space:nowrap;border-radius:3px;display:inline-block}
.falco{color:var(--blue);background:#e9f3f9}
section.events{padding-top:22px}.section-head{align-items:flex-start}.toolbar{justify-content:flex-start;flex-wrap:wrap;margin:16px 0 12px}
label{display:flex;align-items:center;gap:7px;font-size:13px}input,select{font:inherit;color:inherit;background:var(--paper);border:1px solid #bcc9c1;border-radius:4px;padding:7px 9px;min-height:36px;max-width:100%}
input{width:260px}select{max-width:270px}input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--green);outline-offset:3px}
.table-head,.event-summary{display:grid;grid-template-columns:minmax(175px,1.2fr) minmax(220px,2.2fr) minmax(110px,1fr) 95px 130px;gap:14px;align-items:center}
.table-head{padding:9px 14px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line)}
.incident{border-bottom:1px solid var(--line);background:var(--paper)}.event-summary{padding:14px;cursor:pointer;list-style:none}
.event-summary::-webkit-details-marker{display:none}.event-summary:hover{background:#f1f7f3}.incident[open]>.event-summary{background:#eaf3ed}
.event-summary>div{min-width:0}.event-title{display:flex;gap:8px;align-items:flex-start;overflow-wrap:anywhere;font-weight:600}
.event-title:before{content:"▸";flex:none;color:var(--muted)}.incident[open]>.event-summary .event-title:before{content:"▾"}
.time{display:block;font-size:13px;font-variant-numeric:tabular-nums;white-space:nowrap}.subline{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
.source{font-size:12px}.points{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}.points .subline{font-weight:400}
.pages{display:flex;justify-content:space-between;gap:12px;padding:16px 0}.pages button{font:inherit;padding:7px 12px;background:#fff;border:1px solid #bcc9c1;border-radius:4px;cursor:pointer;white-space:nowrap;flex-shrink:0}.pages button:disabled{opacity:.5;cursor:default}
.toolbar input[type=checkbox]{width:16px;min-height:16px}.toolbar input[type=number]{width:120px}.record-list{max-height:440px;overflow:auto}.detail>div{min-width:0}
.detail{padding:16px 24px 20px;border-top:1px solid var(--line);display:grid;grid-template-columns:1fr 1fr;gap:18px}
.detail h3{font-size:14px;margin:0 0 8px}.steps{padding-left:20px;margin:0}.steps li{margin:6px 0;overflow-wrap:anywhere}
.evidence-row{padding:8px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.raw{grid-column:1/-1}.raw summary{cursor:pointer;color:var(--muted);font-size:13px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f5;max-height:300px;overflow:auto;padding:12px;font-size:12px}
.error{background:#fce8eb;border-left:3px solid var(--red);padding:12px;margin:12px 0;overflow-wrap:anywhere}
.empty{padding:30px 14px;color:var(--muted);background:var(--paper)}.stale #pipeline,.stale #events{opacity:.55}
@media(max-width:1000px){.overview{grid-template-columns:1fr}.score:last-child{border-right:0}.components{border-top:1px solid var(--line)}
.table-head,.event-summary{grid-template-columns:minmax(160px,1fr) minmax(180px,2fr) 100px 85px 65px;gap:10px}}
@media(max-width:700px){main{padding:16px 12px}.top{flex-direction:column;gap:10px}.refresh{text-align:left}h1{font-size:21px}
.score{padding:0 12px}.score strong{font-size:26px}.components{padding:16px 12px}.services{gap:12px}.section-head{flex-direction:column}
.toolbar{align-items:stretch}.toolbar label{flex:1 1 100%;justify-content:space-between}input,select{width:75%;max-width:none}
.toolbar input[type=number]{width:75%}.toolbar .group-label{justify-content:flex-start}
.table-head{display:none}.event-summary{grid-template-columns:minmax(0,1fr) auto;padding:13px;gap:9px}
.event-summary .event-main{grid-column:1/-1;grid-row:1}.event-summary .when{grid-column:1/-1;grid-row:2}
.event-summary .outcome{grid-column:2;grid-row:3}.event-summary .source{grid-column:1;grid-row:3}
.event-summary .points{grid-column:1/-1;grid-row:4}.detail{grid-template-columns:1fr;padding:14px}.raw{grid-column:1}
}
</style>
</head>
<body><main>
<header class="top"><h1>TSA 主机安全监测</h1><div class="refresh" role="status"><strong id="connection">正在连接</strong><span id="refresh">页面刷新：—</span><div id="zone-label"></div></div></header>
<div id="error" role="alert"></div>
<div class="overview">
<div id="scores" class="score-row" aria-label="风险评分"></div>
<section class="components"><h2>组件状态</h2><div id="pipeline" class="services"></div></section>
</div>
<section class="events">
<div class="section-head"><h2>最近事件 <span id="event-count" class="muted"></span></h2><span id="window" class="muted"></span></div>
<div class="toolbar">
<label>搜索<input id="search" type="search" placeholder="规则、进程、路径或事件编号" autocomplete="off"></label>
<label>PID<input id="pid" type="number" min="1" max="2147483647" placeholder="全部"></label>
<label>计分<select id="scoring"><option value="all">全部状态</option><option value="scored">有扣分</option><option value="zero">未扣分</option></select></label>
<label class="group-label"><input id="grouped" type="checkbox" checked>同类汇总</label>
<label>时区<select id="timezone"><option value="local">浏览器本地时区</option><option value="UTC">UTC</option></select></label>
</div>
<div id="scope" class="muted"></div>
<div class="table-head" aria-hidden="true"><span>事件 / 采集时间</span><span>事件与进程</span><span>证据来源</span><span>结果</span><span style="text-align:right">历史扣分</span></div>
<div id="events"></div>
<div class="pages"><button id="latest" type="button">返回最新</button><span id="page-state" class="muted"></span><button id="older" type="button">更早记录 →</button></div>
</section>
</main>
<script>
const $=s=>document.querySelector(s);
const localZone=Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC";
const timeKinds={falco_event:"Falco 发生时间",tsa_received:"TSA 入库时间"};
const sourceNames={falco:"Falco"};
const statusNames={scored:"已计分",duplicate:"去重，不重复扣分",rate_limited:"限速，不扣分",maintenance:"维护，不扣分",maintenance_reclassified:"维护，不扣分",whitelisted:"白名单，不扣分",ignored:"不计分"};
const ruleNames={"Program run with disallowed http proxy env":"进程使用未允许的代理环境","Write below etc":"写入 /etc 下的文件","Monitor specific file access":"打开演示文件","Read sensitive file untrusted":"程序读取敏感文件（未列入规则例外）","Non sudo setuid":"非 sudo 程序切换用户身份"};
let current=null,eventSignature="",pending=false,timer=null,before=0;
const initial=new URLSearchParams(location.search);
let after=/^\d+$/.test(initial.get("after")||"")?initial.get("after"):"0";
$("#pid").value=/^\d+$/.test(initial.get("pid")||"")?initial.get("pid"):"";
$("#search").value=(initial.get("q")||"").slice(0,200);$("#search").maxLength=200;
const expanded=new Set();
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text??"");return n}
function zone(){return $("#timezone").value==="UTC"?"UTC":localZone}
function formatTime(value){
  if(!value)return "未知";
  const date=new Date(String(value).replace(/(\.\d{3})\d+(?=Z|[+-]\d\d:\d\d$)/,"$1"));
  if(!Number.isFinite(date.getTime()))return "时间无效";
  const parts=new Intl.DateTimeFormat("zh-CN",{timeZone:zone(),year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",fractionalSecondDigits:3,hourCycle:"h23"}).formatToParts(date);
  const p=Object.fromEntries(parts.map(x=>[x.type,x.value]));
  return p.year+"-"+p.month+"-"+p.day+" "+p.hour+":"+p.minute+":"+p.second+"."+p.fractionalSecond;
}
function renderScore(data){const root=$("#scores");root.replaceChildren();
  [["综合评分",data.final,"0-100 · 越低风险越高"],["基线评分",data.posture,"Lynis 报告计分"],["运行时评分",data.runtime,"未过期事件计分"]].forEach(([name,val,note])=>{
    const box=el("div","score");box.append(el("span","muted",name),el("strong",val==null?"unknown":"",val==null?"未评估":Number(val).toFixed(1)),el("small","",note));root.append(box)})}
function renderPipeline(stages){const root=$("#pipeline");root.replaceChildren();
  stages.forEach(s=>{const box=el("div","service");const left=el("div");left.append(el("strong","",s.name),el("small","",s.detail));
    const status=el("span","state"+(s.active?"":" bad"),s.active?(s.name==="Lynis"?"报告有效":"运行中"):({"inactive":"未运行","failed":"失败","activating":"启动中"}[s.status]||s.status));
    box.append(left,status);root.append(box)})}
function groupTitle(x){const f=x.evidence.falco;return ruleNames[f.rule]||f.rule||x.title}
function statusText(x,short=false){const counts=x.status_counts||Object.values(x.evidence).reduce((a,e)=>(a[e.status]=(a[e.status]||0)+1,a),{});
  const names=short?{scored:"计分",duplicate:"去重未扣分",rate_limited:"限额未扣分",maintenance:"维护",maintenance_reclassified:"维护",whitelisted:"白名单",ignored:"不计分"}:statusNames;
  return Object.entries(counts).map(([s,n])=>(names[s]||s)+" ×"+n).join("；")}
function renderEvidence(source,item){
  const row=el("div","evidence-row");row.append(el("strong","",(sourceNames[source]||source)+" #"+item.id),el("div","",item.rule),
    el("div","subline","事件发生："+formatTime(item.event_time)),
    el("div","subline","TSA 入库："+formatTime(item.received_time)),el("div","subline",(statusNames[item.status]||item.status)+" · 历史扣分 "+item.deducted_points));
  if(item.risk_expires_at&&item.deducted_points>0)row.append(el("div","subline","计分到期："+formatTime(new Date(item.risk_expires_at*1000).toISOString())));
  if(item.file)row.append(el("div","subline","文件："+item.file));
  if(item.command)row.append(el("div","subline","命令："+item.command));
  if(item.executable)row.append(el("div","subline","程序路径："+item.executable));
  row.append(el("div","subline","PID："+(item.pid||"未采集")+" · 用户："+(item.user||(item.uid??"未知"))));
  return row;
}
function renderEvents(force=false){
  if(!current)return;
  const items=$("#grouped").checked?current.summaries:current.incidents,scoring=$("#scoring").value;
  const signature=JSON.stringify([items,scoring,zone(),$("#grouped").checked]);
  if(!force&&signature===eventSignature)return;
  eventSignature=signature;
  const selected=items.filter(x=>scoring==="all"||(scoring==="scored"?x.deducted_points>0:x.deducted_points===0));
  $("#event-count").textContent="· 本页 "+selected.length+" / "+items.length+($("#grouped").checked?" 组":" 项");
  const root=$("#events");root.replaceChildren();
  if(!selected.length){root.append(el("div","empty",items.length?"没有符合条件的事件":"暂无事件"));return}
  selected.forEach(x=>{
    const box=el("details","incident");box.dataset.openKey=x.id;box.open=expanded.has(x.id);
    const head=el("summary","event-summary");const when=el("div","when");const t=el("time","time",formatTime(x.display_time));t.dateTime=x.display_time;t.title=x.display_time;
    when.append(t,el("span","subline",timeKinds[x.time_kind]));
    if(x.activity_count>1)when.append(el("span","subline","首次："+formatTime(x.first_time)),el("span","subline","末次："+formatTime(x.last_time)));
    const main=el("div","event-main");main.append(el("div","event-title",groupTitle(x)),el("span","subline",(x.process||"进程未知")+" · PID "+(x.pid||"未知")+" · "+x.id));
    const targets=x.targets||[x.target].filter(Boolean);
    if(targets.length)main.append(el("span","subline",targets.length===1?targets[0]:targets.length+" 个路径 · "+targets.slice(0,2).join("、")));
    main.append(el("span","subline",x.activity_count>1?"同类活动 "+x.activity_count+" 项 / "+x.record_count+" 条证据（非同一次操作）":Object.values(x.evidence).map(e=>e.rule).join(" + ")));
    const sources=el("div","source",x.sources.map(s=>sourceNames[s]||s).join(" + "));
    sources.append(el("span","subline","告警记录"));
    const outcome=el("div","outcome");outcome.append(el("span","badge "+x.badge_class,x.decision));
    const points=el("div","points",x.deducted_points?"−"+x.deducted_points:"0");
    points.append(el("span","subline",statusText(x,true)));
    head.append(when,main,sources,outcome,points);box.append(head);
    const detail=el("div","detail"),chain=el("div");chain.append(el("h3","","处理记录"));
    const steps=el("ol","steps");(x.activity_count>1?["60 秒内同规则、进程及身份特征的活动汇总；每条证据保留独立编号",statusText(x),"历史扣分合计："+x.deducted_points+"；风险到期与每规则上限会影响当前评分"]:x.steps).forEach(s=>steps.append(el("li","",s)));chain.append(steps);
    const ev=el("div");ev.append(el("h3","","证据与时间"));
    const list=el("div","record-list");(x.members||[x]).forEach(m=>Object.entries(m.evidence).forEach(([s,e])=>list.append(renderEvidence(s,e))));ev.append(list);
    const raw=el("details","raw");raw.dataset.openKey=x.id+":raw";raw.open=expanded.has(raw.dataset.openKey);
    raw.append(el("summary","","入库证据 JSON"),el("pre","",JSON.stringify((x.members||[x]).map(m=>m.evidence),null,2)));
    detail.append(chain,ev,raw);box.append(detail);root.append(box);
  });
}
$("#events").addEventListener("toggle",e=>{if(!$("#events").contains(e.target)||!e.target.dataset.openKey)return;
  if(e.target.open)expanded.add(e.target.dataset.openKey);else expanded.delete(e.target.dataset.openKey)},true);
function render(){
  renderScore(current.scores);renderPipeline(current.pipeline);renderEvents();
  $("#refresh").textContent="页面刷新："+formatTime(current.generated_time);
  $("#zone-label").textContent="显示时区："+zone();
  $("#window").textContent="本页 "+current.event_window.records+" 条证据 · "+current.summaries.length+" 组同类活动 · 非规则数量";
  $("#scope").textContent=(current.event_window.pid?"限定 PID "+current.event_window.pid+" · ":"")+(after!=="0"?"仅入库编号 > "+after+" · ":"")+"按入库时间倒序；汇总限当前页 60 秒窗口";
  $("#page-state").textContent=(before?"历史页 · ":"最新页 · ")+(current.event_window.has_more?"还有更早记录":"已到符合条件的最早记录");
  $("#older").disabled=!current.event_window.has_more;
}
$("#timezone").options[0].textContent="本地 · "+localZone;
$("#timezone").addEventListener("change",()=>{if(current)render();if(document.body.classList.contains("stale"))renderScore({final:null,posture:null,runtime:null})});
$("#scoring").addEventListener("change",()=>renderEvents());
$("#grouped").addEventListener("change",()=>renderEvents());
function eventUrl(){const p=new URLSearchParams({before:String(before),after,pid:$("#pid").value||"0",q:$("#search").value.trim()});return "/api/status?"+p}
function requestRefresh(){clearTimeout(timer);document.body.classList.add("stale");$("#connection").textContent="正在查询";timer=setTimeout(refresh,250)}
$("#search").addEventListener("input",()=>{before=0;requestRefresh()});
$("#pid").addEventListener("input",()=>{before=0;requestRefresh()});
$("#older").addEventListener("click",()=>{before=current.event_window.next_before||0;requestRefresh()});
$("#latest").addEventListener("click",()=>{before=0;after="0";$("#pid").value="";$("#search").value="";requestRefresh()});
async function refresh(){
  if(pending)return;pending=true;
  const url=eventUrl();
  try{
    const r=await fetch(url,{cache:"no-store",signal:AbortSignal.timeout(8000)});
    if(!r.ok)throw Error("HTTP "+r.status);
    const data=await r.json();if(url!==eventUrl())return;
    current=data;render();document.body.classList.remove("stale");$("#error").replaceChildren();
    $("#connection").textContent=current.availability.ready?"数据正常":"数据未就绪";
    if(!current.availability.ready)$("#error").append(el("div","error",current.availability.reason));
  }catch(e){
    if(url!==eventUrl())return;
    document.body.classList.add("stale");renderScore({final:null,posture:null,runtime:null});
    $("#connection").textContent="连接异常";$("#error").replaceChildren(el("div","error","数据刷新失败："+e.message));
  }finally{pending=false;clearTimeout(timer);timer=setTimeout(refresh,url===eventUrl()?3000:0)}
}
refresh();
</script></body></html>"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str) -> float:
    if not value:
        return 0.0
    try:
        # Falco emits nanoseconds; Python 3.10's ISO parser expects microseconds.
        normalized = re.sub(r"\.\d+(?=Z|[+-]\d{2}:\d{2}$)",
                            lambda match: match.group()[:7].ljust(7, "0"), value)
        return datetime.fromisoformat(normalized.replace("Z", "+00:00")).timestamp()
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
    def __init__(self, tsa_config: Path):
        with tsa_config.open("r", encoding="utf-8") as stream:
            self.config = yaml.safe_load(stream) or {}
        storage = self.config.get("storage", {}) or {}
        state_db = Path(str(storage.get("state_db", "state/tsa.db"))).expanduser()
        self.state_db = state_db if state_db.is_absolute() else tsa_config.parent / state_db

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.state_db.resolve().as_uri() + "?mode=ro", uri=True, timeout=2
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

    def _events(self, db: sqlite3.Connection, limit: int = 200, *, before: int = 0,
                after: int = 0, pid: int = 0, query: str = "") -> List[Dict[str, Any]]:
        rows = db.execute(
            """
            SELECT id, received_time, event_time, source, rule_name, status,
                   deducted_points, payload, risk_expires_at
            FROM events
            WHERE source = 'falco' AND (? = 0 OR id < ?) AND id > ?
              AND (? = 0 OR CAST(json_extract(payload, '$.pid') AS INTEGER) = ?)
              AND (? = '' OR instr(lower(source || ':' || id || ' ' || rule_name || ' ' || payload), lower(?)) > 0)
            ORDER BY id DESC LIMIT ?
            """,
            (before, before, after, pid, pid, query, query, limit),
        ).fetchall()
        events = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                payload = {"malformed_payload": row["payload"]}
            if not isinstance(payload, dict):
                payload = {"malformed_payload": payload}
            events.append(
                {
                    **payload,
                    "id": row["id"],
                    "received_time": row["received_time"],
                    "event_time": row["event_time"],
                    "source": row["source"],
                    "rule": row["rule_name"],
                    "status": row["status"],
                    "deducted_points": row["deducted_points"],
                    "risk_expires_at": row["risk_expires_at"],
                }
            )
        return events

    def _scores(
        self, db: sqlite3.Connection, state: Mapping[str, Any]
    ) -> Dict[str, Optional[float]]:
        now = time.time()
        controls = (
            (self.config.get("runtime_rules", {}) or {}).get("event_control", {}) or {}
        )
        cap = max(0, int(controls.get("max_active_points_per_rule", 20)))
        rows = db.execute(
            """
            SELECT rule_name, SUM(deducted_points) points FROM events
            WHERE source='falco' AND status='scored' AND deducted_points > 0
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
        posture_value = state.get("posture_score")
        posture = float(posture_value) if posture_value is not None else None
        weights = (self.config.get("scoring", {}) or {}).get("weights", {}) or {}
        posture_weight = max(0.0, float(weights.get("posture", 0.4)))
        runtime_weight = max(0.0, float(weights.get("runtime", 0.6)))
        total = posture_weight + runtime_weight
        if total == 0:
            posture_weight, runtime_weight, total = 0.4, 0.6, 1.0
        final = None if posture is None and posture_weight else round(
            ((posture or 0) * posture_weight + runtime * runtime_weight) / total, 2
        )
        return {"final": final, "posture": posture, "runtime": runtime}

    def _availability(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        heartbeat = float(state.get("fusion_heartbeat", 0))
        age = time.time() - heartbeat
        reasons = []
        if state.get("fusion_status") != "running" or not 0 <= age <= 30:
            reasons.append("TSA heartbeat is missing or stale")
        if service_state("tsa-fusion.service") != "active":
            reasons.append("tsa-fusion.service is not active")
        enabled = state.get("enabled_sources", {}).get(
            "runtime_rules", (self.config.get("runtime_rules", {}) or {}).get("enabled", True)
        )
        if not enabled:
            reasons.append("Falco monitoring is disabled")
        if service_state("falco-modern-bpf.service") != "active":
            reasons.append("falco-modern-bpf.service is not active")
        if not state.get("source_status", {}).get("falco", False):
            reasons.append("falco event log is unavailable")
        runtime_ready = not reasons
        baseline = state.get("baseline_status", "unavailable")
        weights = (self.config.get("scoring", {}) or {}).get("weights", {}) or {}
        needs_baseline = float(weights.get("posture", 0.4)) > 0 or not any(
            float(weights.get(key, default)) > 0 for key, default in
            (("posture", 0.4), ("runtime", 0.6))
        )
        if needs_baseline and (baseline != "ok" or state.get("posture_score") is None):
            reasons.append("Lynis baseline is unavailable")
        return {"ready": not reasons, "runtime_ready": runtime_ready, "reason": "; ".join(reasons),
                "baseline_status": baseline, "heartbeat": heartbeat or None}


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
        incidents = []
        for event in events:
            if event.get("source") != "falco":
                continue
            event_time = str(event.get("event_time", ""))
            has_event_time = bool(parse_time(event_time))
            process = event.get("process") or event.get("command", "")
            incidents.append({
                "id": f"falco:{event['id']}",
                "time": event.get("received_time", ""),
                "title": f"{event.get('rule')} · {process}",
                "pid": event.get("pid", ""),
                "decision": "Falco 报警",
                "badge_class": "falco",
                "steps": [
                    f"Falco 匹配规则：{event.get('rule')}",
                    "仅记录和评分，不阻断操作或终止进程",
                    self._tsa_step(event),
                ],
                "evidence": {"falco": event},
                "display_time": event_time if has_event_time else event.get("received_time", ""),
                "time_kind": "falco_event" if has_event_time else "tsa_received",
                "received_time": event.get("received_time", ""),
                "process": process,
                "target": event.get("file", ""),
                "sources": ["falco"],
                "deducted_points": int(event.get("deducted_points", 0)),
            })
        return sorted(incidents, key=lambda x: parse_time(x["received_time"]), reverse=True)

    @staticmethod
    def _summaries(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collapse similar activity for display only; retain every evidence row."""
        groups: List[Dict[str, Any]] = []
        latest: Dict[str, Dict[str, Any]] = {}
        for incident in reversed(incidents):
            identity = []
            for source, event in sorted(incident["evidence"].items()):
                fields = ("rule", "pid", "process", "command", "user", "uid", "container_id", "executable")
                identity.append([source, *[event.get(k, "") for k in fields]])
            key = json.dumps(identity, ensure_ascii=False, sort_keys=True)
            ts = parse_time(str(incident["received_time"]))
            group = latest.get(key)
            if group is None or not ts or not 0 <= ts - group["started"] < 60:
                group = {"id": incident["id"], "started": ts, "members": []}
                groups.append(group)
                latest[key] = group
            group["members"].insert(0, incident)
        result = []
        for group in reversed(groups):
            members = group["members"]
            records = [e for item in members for e in item["evidence"].values()]
            result.append({
                **members[0], "id": group["id"], "members": members,
                "record_count": len(records), "activity_count": len(members),
                "first_time": min((x["display_time"] for x in members), key=parse_time),
                "last_time": max((x["display_time"] for x in members), key=parse_time),
                "targets": sorted({x["target"] for x in members if x["target"]}),
                "status_counts": dict(Counter(str(e["status"]) for e in records)),
                "deducted_points": sum(int(e["deducted_points"]) for e in records),
            })
        return sorted(result, key=lambda x: parse_time(x["received_time"]), reverse=True)

    def scores(self) -> Dict[str, Optional[float]]:
        """Return only the current risk scores (lighter than snapshot())."""
        with closing(self._connect()) as db:
            state = self._state(db)
            availability = self._availability(state)
            if not availability["ready"]:
                raise ValueError(availability["reason"])
            return self._scores(db, state)

    def snapshot(self, *, before: int = 0, after: int = 0, pid: int = 0, query: str = "") -> Dict[str, Any]:
        with closing(self._connect()) as db:
            state = self._state(db)
            events = self._events(db, limit=201, before=before, after=after, pid=pid, query=query)
            has_more = len(events) > 200
            events = events[:200]
            scores = self._scores(db, state)
        availability = self._availability(state)
        if not availability["ready"]:
            scores["final"] = None
        if not availability["runtime_ready"]:
            scores["runtime"] = None
        states = {
            "falco": service_state("falco-modern-bpf.service"),
            "tsa": service_state("tsa-fusion.service"),
        }
        pipeline = [
            {
                "name": "Falco",
                "active": states["falco"] == "active",
                "status": states["falco"],
                "detail": "观察行为并按规则报警",
            },
            {
                "name": "Lynis",
                "active": availability["baseline_status"] == "ok",
                "status": "报告有效" if availability["baseline_status"] == "ok" else "报告不可用",
                "detail": "系统基线报告",
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
        incidents = self._incidents(events)
        return {
            "generated_time": utc_now(),
            "scores": scores,
            "availability": availability,
            "pipeline": pipeline,
            "incidents": incidents,
            "summaries": self._summaries(incidents),
            "event_window": {"records": len(events), "limit": 200, "has_more": has_more,
                             "next_before": events[-1]["id"] if has_more else None,
                             "after": after, "pid": pid, "query": query},
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
        # Reject DNS-rebinding requests directed at this loopback-only service.
        try:
            host = urlparse("//" + self.headers.get("Host", "")).hostname
        except ValueError:
            host = None
        if not is_loopback_host(host):
            self._send(b'{"error":"invalid host"}', "application/json", HTTPStatus.FORBIDDEN)
            return
        path = urlparse(self.path).path
        if path == "/":
            self._send(HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            try:
                self.server.data.scores()  # type: ignore[attr-defined]
                self._send(b'{"status":"ok"}', "application/json")
            except (OSError, sqlite3.Error, ValueError):
                self._send(b'{"status":"unavailable"}', "application/json",
                           HTTPStatus.SERVICE_UNAVAILABLE)
            return
        if path == "/api/status":
            try:
                params = parse_qs(urlparse(self.path).query)
                filters = {k: int(params.get(k, ["0"])[0]) for k in ("before", "after", "pid")}
                query = params.get("q", [""])[0]
                if any(v < 0 or v > 2**63 - 1 for v in filters.values()) or len(query) > 200:
                    raise ValueError("invalid event filter")
            except ValueError:
                self._send(b'{"error":"invalid event filter"}', "application/json", HTTPStatus.BAD_REQUEST)
                return
            try:
                snapshot = self.server.data.snapshot(**filters, query=query)  # type: ignore[attr-defined]
                body = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
                self._send(body, "application/json; charset=utf-8")
            except (OSError, sqlite3.Error, ValueError) as error:
                logging.warning("Dashboard snapshot unavailable: %s", error)
                body = json.dumps(
                    {"error": "Security data unavailable"}, ensure_ascii=False
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
                logging.warning("Risk score unavailable: %s", error)
                body = json.dumps(
                    {
                        "code": 50000,
                        "status": False,
                        "message": "安全数据不可用或已过期",
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


def is_loopback_host(host: Optional[str]) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


class DashboardServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        address = ipaddress.ip_address(self.server_address[0])
        if not address.is_loopback:
            raise ValueError("Dashboard must bind to loopback; use an authenticated TLS reverse proxy or SSH tunnel")
        super().server_bind()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local TSA security pipeline dashboard")
    parser.add_argument(
        "--tsa-config",
        default=str(Path(__file__).with_name("policy_config.yaml")),
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = DashboardServer(
        (args.bind, args.port),
        DashboardHandler,
    )
    server.data = DashboardData(  # type: ignore[attr-defined]
        Path(args.tsa_config).expanduser().resolve(),
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
