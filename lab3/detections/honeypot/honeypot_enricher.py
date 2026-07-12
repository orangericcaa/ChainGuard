#!/usr/bin/env python3
"""
honeypot_enricher.py — Cowrie SSH 蜜罐增强模块
部署: VM3 DB Server
功能:
  1. 实时解析 Cowrie 日志
  2. 记录攻击行为 → JSONL
  3. 自动封禁攻击源 IP
"""

import os
import json
import time
import uuid
import subprocess
from datetime import datetime, timezone

COWRIE_LOG = "/opt/cowrie/var/log/cowrie/cowrie.json"
EVENTS_LOG = "/var/log/lab3/events.jsonl"
HOST_IP = "192.168.20.10"
BLOCKED = set()
BLOCK_THRESHOLD = 5
ATTEMPTS = {}


def write_event(severity, message, **kwargs):
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": os.environ.get("LAB3_RUN_ID", "default"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": "VM3",
        "host_ip": HOST_IP,
        "detector": "cowrie",
        "layer": "honeypot",
        "severity": severity,
        "message": message,
        **kwargs
    }
    os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)
    with open(EVENTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def block_ip(src_ip):
    if src_ip in BLOCKED:
        return
    BLOCKED.add(src_ip)
    subprocess.run(["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"], capture_output=True)
    write_event("high", f"SSH蜜罐自动封禁攻击源: {src_ip}",
                src_ip=src_ip, action_taken="iptables block", attack_type="auto_block")


def process_event(obj):
    eventid = obj.get("eventid", "")
    src_ip = obj.get("src_ip", "0.0.0.0")

    if eventid == "cowrie.login.success":
        username = obj.get("username", "?")
        password = obj.get("password", "?")
        write_event("critical",
                    f"SSH蜜罐登录成功: {username}/{password} 来自 {src_ip}",
                    src_ip=src_ip, raw_detail=f"user={username} pass={password}",
                    attack_type="brute_force", attack_phase="exploitation",
                    mitre_id="T1110")

    elif eventid == "cowrie.login.failed":
        username = obj.get("username", "?")
        ATTEMPTS[src_ip] = ATTEMPTS.get(src_ip, 0) + 1
        if ATTEMPTS[src_ip] >= BLOCK_THRESHOLD:
            block_ip(src_ip)

    elif eventid == "cowrie.command.input":
        cmd = obj.get("input", "")
        write_event("high", f"SSH蜜罐执行命令: {cmd[:100]}",
                    src_ip=src_ip, raw_detail=cmd, attack_type="cmd_injection",
                    attack_phase="exploitation")

    elif eventid == "cowrie.command.failed":
        cmd = obj.get("input", "")
        write_event("low", f"SSH蜜罐命令失败: {cmd[:80]}",
                    src_ip=src_ip, raw_detail=cmd)

    elif eventid == "cowrie.session.file_download":
        url = obj.get("url", "")
        write_event("critical", f"SSH蜜罐文件下载: {url}",
                    src_ip=src_ip, raw_detail=url, attack_type="data_exfil",
                    attack_phase="exfiltration")

    elif eventid == "cowrie.client.version":
        version = obj.get("version", "")
        write_event("info", f"SSH蜜罐客户端连接: {src_ip} ({version})",
                    src_ip=src_ip, attack_type="unknown", attack_phase="recon")

    elif eventid == "cowrie.session.closed":
        pass


def main():
    print("[honeypot_enricher] 启动 Cowrie 增强模块...")
    write_event("info", "Cowrie增强模块启动")

    try:
        with open(COWRIE_LOG, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    try:
                        process_event(json.loads(line))
                    except (json.JSONDecodeError, KeyError):
                        pass
                else:
                    time.sleep(0.2)
    except FileNotFoundError:
        print(f"[!] Cowrie 日志文件不存在: {COWRIE_LOG}")
    except KeyboardInterrupt:
        print("[honeypot_enricher] 已停止")


if __name__ == "__main__":
    main()
