#!/usr/bin/env python3
"""
log_aggregator.py — 日志汇聚服务
部署: VM1 Gateway
监听: 0.0.0.0:5000
功能:
  1. POST /events — 接收各节点上报的事件
  2. GET /events — 查询事件（支持数量、严重级别过滤）
  3. GET /dashboard — 简易 HTML 仪表盘
  4. 事件存储到 /var/log/lab3/events.jsonl
"""

import json
import os
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string

EVENTS_LOG = "/var/log/lab3/events.jsonl"
os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)

app = Flask(__name__)
events_buffer = []
BUFFER_SIZE = 50


def flush_buffer():
    global events_buffer
    if events_buffer:
        with open(EVENTS_LOG, "a", encoding="utf-8") as f:
            for e in events_buffer:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        events_buffer = []


@app.route("/events", methods=["POST"])
def receive_event():
    try:
        event = request.get_json(force=True)
        if not event.get("ts"):
            event["ts"] = datetime.now(timezone.utc).isoformat()
        events_buffer.append(event)
        if len(events_buffer) >= BUFFER_SIZE:
            flush_buffer()
        return jsonify({"status": "ok", "event_id": event.get("event_id", "?")}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/events", methods=["GET"])
def get_events():
    flush_buffer()
    limit = request.args.get("limit", 100, type=int)
    severity = request.args.get("severity", None)

    events = []
    try:
        with open(EVENTS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if severity and e.get("severity") != severity:
                        continue
                    events.append(e)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass

    return jsonify(events[-limit:])


@app.route("/dashboard")
def dashboard():
    flush_buffer()

    events = []
    try:
        with open(EVENTS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass

    critical = sum(1 for e in events if e.get("severity") == "critical")
    high = sum(1 for e in events if e.get("severity") == "high")
    medium = sum(1 for e in events if e.get("severity") == "medium")
    recent = events[-20:][::-1]

    return render_template_string("""
<!DOCTYPE html>
<html><head><title>Lab3 安全监控仪表盘</title>
<meta http-equiv="refresh" content="5">
<style>
body{background:#0a0e17;color:#e0e0e0;font-family:monospace;margin:0;padding:20px}
h1{color:#ff6b35;text-align:center;font-size:24px}
.stats{display:flex;gap:20px;justify-content:center;margin:20px 0}
.stat{background:#141b2d;padding:20px;border-radius:8px;text-align:center;flex:1;max-width:150px}
.stat .num{font-size:36px;font-weight:bold}
.stat .label{color:#888;font-size:12px;margin-top:5px}
.stat.critical .num{color:#e74c3c}
.stat.high .num{color:#e67e22}
.stat.medium .num{color:#f1c40f}
.events{border-collapse:collapse;width:100%;margin-top:20px}
.events th{background:#141b2d;padding:10px;text-align:left;color:#ff6b35;font-size:13px}
.events td{padding:8px;border-bottom:1px solid #1a2332;font-size:12px}
.sev{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}
.sev-critical{background:#e74c3c;color:#fff}
.sev-high{background:#e67e22;color:#fff}
.sev-medium{background:#f1c40f;color:#000}
.sev-low{background:#3498db;color:#fff}
.sev-info{background:#2ecc71;color:#000}
</style></head><body>
<h1>LAB3 安全监控仪表盘</h1>
<div class="stats">
<div class="stat critical"><div class="num">{{ critical }}</div><div class="label">严重 CRITICAL</div></div>
<div class="stat high"><div class="num">{{ high }}</div><div class="label">高危 HIGH</div></div>
<div class="stat medium"><div class="num">{{ medium }}</div><div class="label">中危 MEDIUM</div></div>
</div>
<table class="events">
<tr><th>时间</th><th>节点</th><th>检测器</th><th>层级</th><th>级别</th><th>消息</th></tr>
{% for e in recent %}
<tr>
<td>{{ e.ts[11:19] if e.ts else '?' }}</td>
<td>{{ e.host }}</td>
<td>{{ e.detector }}</td>
<td>{{ e.layer }}</td>
<td><span class="sev sev-{{ e.severity }}">{{ e.severity }}</span></td>
<td>{{ e.message[:80] }}</td>
</tr>
{% endfor %}
</table></body></html>
""", critical=critical, high=high, medium=medium, recent=recent)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "log_aggregator"})


if __name__ == "__main__":
    print("[log_aggregator] 启动事件汇聚服务 @ :5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
