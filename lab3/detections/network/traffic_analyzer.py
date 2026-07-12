#!/usr/bin/env python3
"""
traffic_analyzer.py — 网络流量对比分析 + 自动拦截
部署: VM1 Gateway
功能:
  1. 同时监听 Suricata DMZ(eve-dmz.json) 和内网(eve-internal.json) 告警
  2. 对比分析内外网攻击流量差异，识别防御薄弱环节
  3. 对 HIGH/CRITICAL 告警自动封禁源 IP
  4. 流量基线统计异常检测（2.5σ偏离模型 → 发现未知攻击模式）
  5. 输出统一 JSONL 事件
"""

import os
import json
import time
import subprocess
import uuid
import threading
from datetime import datetime, timezone

DMZ_LOG = "/var/log/suricata/eve-dmz.json"
INTERNAL_LOG = "/var/log/suricata/eve-internal.json"
EVENTS_LOG = "/var/log/lab3/events.jsonl"
BLOCKED_IPS = set()
WHITELIST_IPS = {"192.168.10.1", "192.168.20.1", "192.168.10.10", "192.168.20.10", "192.168.20.20"}


def write_event(detector, severity, message, **kwargs):
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": os.environ.get("LAB3_RUN_ID", "default"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": "VM1",
        "detector": detector,
        "layer": "network",
        "severity": severity,
        "message": message,
        **kwargs
    }
    os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)
    with open(EVENTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def block_ip(src_ip):
    if src_ip in BLOCKED_IPS or src_ip in WHITELIST_IPS:
        return
    BLOCKED_IPS.add(src_ip)
    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
        capture_output=True
    )
    write_event(
        "traffic_analyzer", "high",
        f"自动封禁攻击源IP: {src_ip}",
        src_ip=src_ip, action_taken="iptables -A INPUT -s {} -j DROP".format(src_ip),
        attack_type="auto_block"
    )


def severity_from_suricata(alert):
    sig = alert.get("alert", {}).get("signature", "")
    if "扫描" in sig or "爆破" in sig:
        return "medium"
    if "SQL注入" in sig or "XSS" in sig or "命令注入" in sig:
        return "high"
    if "Webshell" in sig or "反弹" in sig or "数据外传" in sig:
        return "critical"
    return "medium"


def classify_attack(signature):
    mapping = {
        "扫描": "port_scan", "爆破": "brute_force",
        "SQL注入": "sql_injection", "XSS": "xss",
        "目录遍历": "dir_traversal", "文件包含": "dir_traversal",
        "Webshell": "webshell", "上载": "webshell",
        "命令注入": "cmd_injection", "反弹": "cmd_injection",
        "数据外传": "data_exfil", "横向移动": "lateral_move",
        "DNS隧道": "data_exfil",
    }
    for key, val in mapping.items():
        if key in signature:
            return val
    return "unknown"


def phase_from_attack(attack_type):
    mapping = {
        "port_scan": "recon", "brute_force": "exploitation",
        "sql_injection": "exploitation", "xss": "exploitation",
        "dir_traversal": "exploitation", "cmd_injection": "exploitation",
        "webshell": "persistence", "data_exfil": "exfiltration",
        "lateral_move": "lateral_movement",
    }
    return mapping.get(attack_type, "unknown")


def follow_file(filepath, callback):
    with open(filepath, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                try:
                    obj = json.loads(line)
                    callback(obj)
                except (json.JSONDecodeError, KeyError):
                    pass
            else:
                time.sleep(0.1)


def process_dmz_alert(alert):
    sig = alert.get("alert", {}).get("signature", "Unknown")
    src_ip = alert.get("src_ip", "0.0.0.0")
    dst_ip = alert.get("dest_ip", "0.0.0.0")
    dst_port = alert.get("dest_port", 0)
    severity = severity_from_suricata(alert)
    attack_type = classify_attack(sig)

    event = write_event(
        "suricata_dmz", severity,
        f"[DMZ] {sig}，源: {src_ip} → 目标: {dst_ip}:{dst_port}",
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        attack_type=attack_type, attack_phase=phase_from_attack(attack_type),
        protocol=alert.get("proto", "unknown"),
        raw_detail=json.dumps(alert.get("alert", {}), ensure_ascii=False)
    )

    if severity in ("high", "critical"):
        block_ip(src_ip)


def process_internal_alert(alert):
    sig = alert.get("alert", {}).get("signature", "Unknown")
    src_ip = alert.get("src_ip", "0.0.0.0")
    dst_ip = alert.get("dest_ip", "0.0.0.0")
    severity = severity_from_suricata(alert)
    attack_type = classify_attack(sig)

    write_event(
        "suricata_internal", severity,
        f"[内网] {sig}，源: {src_ip} → 目标: {dst_ip}  ⚠ 攻击已穿透外网到内网",
        src_ip=src_ip, dst_ip=dst_ip,
        attack_type=attack_type, attack_phase=phase_from_attack(attack_type),
        raw_detail="PENETRATED: " + sig
    )


# ===== 5. 流量基线异常检测（基于统计的"未知漏洞"发现） =====
from collections import deque

BASELINE_WINDOW = deque(maxlen=1440)
BASELINE_INITIALIZED = False
BASELINE_LOCK = threading.Lock()

def collect_traffic_stats():
    """采集当前1分钟的流量统计快照"""
    stats = {"ts": time.time(), "conns": 0, "unique_ips": set(), "unique_ports": set(), "alerts": 0}
    for source_log in (DMZ_LOG, INTERNAL_LOG):
        if not os.path.exists(source_log):
            continue
        try:
            with open(source_log, "r", encoding="utf-8") as f:
                f.seek(max(0, os.path.getsize(source_log) - 65536))
                for line in f:
                    try:
                        obj = json.loads(line.strip())
                        if obj.get("event_type") == "alert":
                            stats["alerts"] += 1
                        if obj.get("src_ip"):
                            stats["unique_ips"].add(obj.get("src_ip"))
                        if obj.get("dest_port"):
                            stats["unique_ports"].add(obj.get("dest_port"))
                        stats["conns"] += 1
                    except (json.JSONDecodeError, KeyError):
                        pass
        except (FileNotFoundError, PermissionError):
            pass
    return stats


def baseline_monitor():
    """定期采集统计 → 维护滚动基线 → 偏离2σ即告警"""
    global BASELINE_INITIALIZED
    while True:
        time.sleep(60)
        try:
            stats = collect_traffic_stats()
            sample = {
                "conns": stats["conns"],
                "unique_ips": len(stats["unique_ips"]),
                "unique_ports": len(stats["unique_ports"]),
                "alerts": stats["alerts"],
            }
            with BASELINE_LOCK:
                BASELINE_WINDOW.append(sample)

                if len(BASELINE_WINDOW) < 30:
                    continue

                if not BASELINE_INITIALIZED and len(BASELINE_WINDOW) >= 30:
                    BASELINE_INITIALIZED = True
                    write_event("traffic_analyzer", "info",
                                f"流量基线已初始化 ({len(BASELINE_WINDOW)} 个采样点)")

                if not BASELINE_INITIALIZED:
                    continue

                recent = list(BASELINE_WINDOW)[-30:]
                baseline = list(BASELINE_WINDOW)[-60:-30]

                if len(baseline) < 10:
                    continue

                metrics = [("连接数", "conns"), ("独立IP数", "unique_ips"),
                           ("独立端口数", "unique_ports"), ("告警数", "alerts")]

                for label, key in metrics:
                    recent_vals = [s[key] for s in recent]
                    base_vals = [s[key] for s in baseline]

                    mean = sum(base_vals) / len(base_vals)
                    variance = sum((v - mean) ** 2 for v in base_vals) / len(base_vals)
                    std = variance ** 0.5
                    threshold = mean + 2.5 * std

                    curr_avg = sum(recent_vals) / len(recent_vals)
                    if std < 0.5:
                        continue
                    if curr_avg > threshold:
                        write_event("traffic_analyzer", "high",
                                    f"[基线异常] {label}当前 {curr_avg:.1f}，基线均值 {mean:.1f}±{std:.1f}，偏离 {((curr_avg - mean) / std):.1f}σ",
                                    attack_type="unknown", attack_phase="unknown",
                                    raw_detail=f"metric={key} curr={curr_avg:.1f} mean={mean:.1f} std={std:.1f}")
        except Exception:
            pass


def main():
    print("[traffic_analyzer] 启动...")
    write_event("traffic_analyzer", "info", "流量分析器启动")

    t1 = threading.Thread(target=follow_file, args=(DMZ_LOG, process_dmz_alert), daemon=True)
    t2 = threading.Thread(target=follow_file, args=(INTERNAL_LOG, process_internal_alert), daemon=True)
    t3 = threading.Thread(target=baseline_monitor, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    print("[traffic_analyzer] 已启动双通道监听 + 基线异常检测")
    print(f"    DMZ:  {DMZ_LOG}")
    print(f"    内网: {INTERNAL_LOG}")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("[traffic_analyzer] 已停止")


if __name__ == "__main__":
    main()
