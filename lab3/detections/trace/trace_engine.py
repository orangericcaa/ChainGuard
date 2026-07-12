#!/usr/bin/env python3
"""
trace_engine.py — 攻击行为关联分析与溯源引擎
部署: VM1 Gateway
功能:
  1. 读取 events.jsonl 汇聚日志
  2. 按时间窗口 + 源IP 聚类
  3. 映射 MITRE ATT&CK 攻击阶段
  4. 重建攻击链
  5. 攻击者画像
  6. 输出溯源报告 (Markdown + JSON)
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from collections import defaultdict

EVENTS_LOG = "/var/log/lab3/events.jsonl"
REPORT_DIR = "/var/log/lab3/trace_reports"
os.makedirs(REPORT_DIR, exist_ok=True)

ATTACK_STAGES = ["recon", "exploitation", "persistence", "lateral_movement", "exfiltration"]

METHOD_MAP = {
    "port_scan": "端口扫描",
    "brute_force": "暴力破解",
    "sql_injection": "SQL注入",
    "xss": "XSS跨站脚本",
    "dir_traversal": "目录遍历/文件包含",
    "cmd_injection": "命令注入",
    "webshell": "Webshell上传/利用",
    "file_access": "敏感文件读取",
    "data_exfil": "数据外传/窃取",
    "lateral_move": "横向移动",
    "host_compromised": "主机失陷判定",
    "persistence": "持久化/后门",
}


def cluster_by_src_ip(events, window_minutes=10):
    clusters = defaultdict(list)
    for e in events:
        if not e.get("src_ip"):
            continue
        clusters[e["src_ip"]].append(e)

    result = {}
    for src_ip, evts in clusters.items():
        evts.sort(key=lambda x: x.get("ts", ""))
        chains = []
        current_chain = []
        last_ts = None
        for e in evts:
            ts = e.get("ts", "")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts)
            except ValueError:
                continue
            if last_ts and (dt - last_ts) > timedelta(minutes=window_minutes):
                if current_chain:
                    chains.append(current_chain)
                current_chain = []
            current_chain.append(e)
            last_ts = dt
        if current_chain:
            chains.append(current_chain)
        result[src_ip] = chains
    return result


def classify_severity_distribution(events):
    dist = defaultdict(int)
    for e in events:
        dist[e.get("severity", "info")] += 1
    return dict(dist)


def extract_attack_chain(chain):
    stages = {}
    path = []
    for e in chain:
        phase = e.get("attack_phase", "unknown")
        atype = e.get("attack_type", "unknown")
        host = e.get("host", "unknown_host")
        if phase not in stages:
            stages[phase] = []
        stages[phase].append(e)
        if host not in path:
            path.append(host)
    return stages, path


def profile_attacker(src_ip, chains):
    all_events = [e for chain in chains for e in chain]
    if not all_events:
        return {}

    techniques = set()
    severity_dist = classify_severity_distribution(all_events)
    hosts_touched = set(e.get("host", "unknown") for e in all_events)
    ua = "N/A"
    for e in all_events:
        if e.get("user_agent"):
            ua = e["user_agent"]
            break
    times = [e.get("ts", "") for e in all_events]
    if times:
        first = min(times)
        last = max(times)
        duration = f"{first} ~ {last}"
    else:
        duration = "N/A"

    for e in all_events:
        if e.get("mitre_id"):
            techniques.add(e["mitre_id"])
        at = e.get("attack_type", "")
        if at in METHOD_MAP:
            techniques.add(METHOD_MAP[at])

    tools = []
    if any("nmap" in e.get("raw_detail", "").lower() for e in all_events):
        tools.append("nmap")
    if any("sqlmap" in e.get("raw_detail", "").lower() for e in all_events):
        tools.append("sqlmap")
    if any("hydra" in e.get("raw_detail", "").lower() for e in all_events):
        tools.append("hydra")
    if any("dirb" in e.get("raw_detail", "").lower() for e in all_events):
        tools.append("dirb")

    honeypot_hit = any(e.get("detector", "") in ("web_honeypot", "db_honeypot", "cowrie") for e in all_events)

    level = "低"
    if len(techniques) >= 3:
        level = "中"
    if len(techniques) >= 5:
        level = "高"

    return {
        "source_ip": src_ip,
        "attack_duration": duration,
        "severity_distribution": severity_dist,
        "techniques_used": list(techniques),
        "tools_detected": tools,
        "hosts_touched": list(hosts_touched),
        "honeypot_hit": honeypot_hit,
        "user_agent": ua,
        "skill_level": level
    }


def generate_report(clusters):
    lines = []
    lines.append("# 攻击行为溯源分析报告")
    lines.append(f"生成时间: {datetime.now(timezone.utc).isoformat()}")
    lines.append("---")

    for src_ip, chains in clusters.items():
        lines.append(f"\n## 攻击源: {src_ip}")

        profile = profile_attacker(src_ip, chains)
        lines.append(f"\n### 攻击者画像")
        lines.append(f"- 技能水平: **{profile.get('skill_level', 'N/A')}**")
        lines.append(f"- 活跃时间: {profile.get('attack_duration', 'N/A')}")
        lines.append(f"- 使用的攻击技术: {', '.join(profile.get('techniques_used', []))}")
        lines.append(f"- 检测到的工具: {', '.join(profile.get('tools_detected', [])) or '未识别'}")
        lines.append(f"- 触及的主机: {', '.join(profile.get('hosts_touched', []))}")
        lines.append(f"- 触发蜜罐: {'是 ⚠' if profile.get('honeypot_hit') else '否'}")

        for i, chain in enumerate(chains, 1):
            lines.append(f"\n### 攻击链 {i} (共 {len(chain)} 个步骤)")
            lines.append("")

            stages, path = extract_attack_chain(chain)
            lines.append(f"**攻击路径**: {' → '.join(path)}")
            lines.append("")

            lines.append("| 时间 | 主机 | 阶段 | 类型 | 严重级别 | 描述 |")
            lines.append("|------|------|------|------|----------|------|")
            for e in chain:
                ts = e.get("ts", "?")[11:19] if len(e.get("ts", "")) > 10 else e.get("ts", "?")
                host = e.get("host", "?")
                phase = e.get("attack_phase", "?")
                atype = e.get("attack_type", "?")
                sev = e.get("severity", "?")
                msg = e.get("message", "")[:60]
                lines.append(f"| {ts} | {host} | {phase} | {atype} | {sev} | {msg} |")
            lines.append("")

    return "\n".join(lines)


def main():
    print("[trace_engine] 开始读取事件日志...")

    if not os.path.exists(EVENTS_LOG):
        print(f"[!] 日志文件不存在: {EVENTS_LOG}")
        return

    events = []
    with open(EVENTS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        print("[trace_engine] 无事件可分析，退出。")
        return

    print(f"[trace_engine] 已加载 {len(events)} 条事件")

    clusters = cluster_by_src_ip(events, window_minutes=10)
    print(f"[trace_engine] 识别到 {len(clusters)} 个攻击源")

    report = generate_report(clusters)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORT_DIR, f"trace_report_{ts}.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report)

    json_file = os.path.join(REPORT_DIR, f"trace_report_{ts}.json")
    profiles = {ip: profile_attacker(ip, chains) for ip, chains in clusters.items()}
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "attack_sources": len(clusters),
            "profiles": profiles
        }, f, ensure_ascii=False, indent=2)

    print(f"[trace_engine] 报告已生成:")
    print(f"    Markdown: {report_file}")
    print(f"    JSON:     {json_file}")
    print(report)


if __name__ == "__main__":
    main()
