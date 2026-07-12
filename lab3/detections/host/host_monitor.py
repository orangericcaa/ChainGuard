#!/usr/bin/env python3
"""
host_monitor.py — 主机异常行为检测守护进程
部署: VM2 / VM3 / VM4
功能:
  1. 进程监控 — 检测新进程、可疑命令行、非预期用户进程
  2. 文件监控 — 监控敏感目录的新增/修改
  3. 网络监控 — 检测异常外联、非预期监听端口
  4. 持久化监控 — 监控 crontab/systemd/rc.local 变更
  5. 系统日志协同 — tail auth.log(syslog) / syslog，协同 auditd 审计事件
  6. 综合评分 — 多维告警 → 累计分数 → 判定失陷
  7. 自动处置 — kill 进程 / block IP
"""

import os
import re
import json
import time
import uuid
import socket
import hashlib
import subprocess
from datetime import datetime, timezone
from collections import defaultdict

HOST_IP = "192.168.10.10"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    HOST_IP = s.getsockname()[0]
    s.close()
except Exception:
    pass

HOSTNAME = socket.gethostname()
EVENTS_LOG = "/var/log/lab3/events.jsonl"
STATE_DIR = "/var/lib/lab3/host_monitor"
os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)

SCORE_THRESHOLD = 80
SUSPICIOUS_CMDS = ["bash -i", "nc ", "ncat ", "/dev/tcp", "python -c",
                    "eval(", "base64 -d", "wget ", "curl ", "| sh", "| bash"]
SENSITIVE_DIRS = ["/var/www/html", "/etc", "/tmp", "/home"]
SENSITIVE_FILES = ["/etc/shadow", "/etc/passwd", "/etc/crontab"]
PERSISTENCE_FILES = ["/etc/crontab", "/etc/rc.local", "/var/spool/cron/crontabs"]
KNOWN_PROCESSES = set()
FILE_HASHES = {}
SCORE_PER_HOST = defaultdict(int)


def write_event(detector, severity, message, **kwargs):
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": os.environ.get("LAB3_RUN_ID", "default"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": HOSTNAME,
        "host_ip": HOST_IP,
        "detector": detector,
        "layer": "host",
        "severity": severity,
        "message": message,
        **kwargs
    }
    with open(EVENTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    write_event("host_monitor", "high", f"主机侧自动封禁IP: {ip}",
                src_ip=ip, action_taken=f"iptables block {ip}", attack_type="auto_block")


def kill_process(pid, reason):
    try:
        subprocess.run(["kill", "-9", str(pid)], capture_output=True, timeout=5)
        write_event("host_monitor", "high", f"已杀死可疑进程 PID={pid}: {reason}",
                    action_taken=f"kill -9 {pid}", attack_type="process_kill")
    except Exception:
        pass


# ===== 1. 进程监控 =====
def watch_processes():
    current = set()
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        try:
            with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            with open(f"/proc/{pid_dir}/status", "r") as f:
                status = f.read()
                uid_match = re.search(r"Uid:\s+\d+\s+(\d+)", status)
                uid = uid_match.group(1) if uid_match else "?"
            current.add((pid_dir, cmdline, uid))
        except (FileNotFoundError, PermissionError):
            continue

    if not KNOWN_PROCESSES:
        KNOWN_PROCESSES.update(current)
        return

    for pid, cmdline, uid in current:
        if (pid, cmdline, uid) not in KNOWN_PROCESSES:
            score = 0
            for sc in SUSPICIOUS_CMDS:
                if sc in cmdline:
                    score += 40
                    break
            if uid == "33" and "sh" in cmdline:
                score += 50
            if uid == "33" and ("bash" in cmdline or "python" in cmdline):
                score += 60

            if score > 0:
                SCORE_PER_HOST[HOST_IP] += score
                write_event("host_monitor", "high" if score >= 50 else "medium",
                            f"可疑进程创建 PID={pid} UID={uid}: {cmdline}",
                            raw_detail=cmdline, attack_type="suspicious_process",
                            attack_phase="exploitation",
                            action_taken="kill" if score >= 60 else "log",
                            mitre_id="T1059")
                if score >= 40:
                    kill_process(pid, cmdline)

    KNOWN_PROCESSES.clear()
    KNOWN_PROCESSES.update(current)


# ===== 2. 文件监控 =====
def watch_filesystem():
    global FILE_HASHES
    new_hashes = {}

    for base_dir in SENSITIVE_DIRS:
        if not os.path.isdir(base_dir):
            continue
        for root, _, files in os.walk(base_dir):
            for fn in files:
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, "rb") as f:
                        new_hashes[fpath] = hashlib.md5(f.read()).hexdigest()
                except (PermissionError, FileNotFoundError):
                    continue

    if not FILE_HASHES:
        FILE_HASHES = new_hashes
        return

    for fpath, new_hash in new_hashes.items():
        if fpath not in FILE_HASHES:
            ext = os.path.splitext(fpath)[1].lower()
            score = 0
            if ext in (".php", ".jsp", ".py", ".sh", ".pl"):
                score = 60
                write_event("host_monitor", "critical",
                            f"可疑文件创建: {fpath}",
                            raw_detail=fpath, attack_type="webshell",
                            attack_phase="persistence", mitre_id="T1505",
                            action_taken="quarantine")
            elif fpath in SENSITIVE_FILES:
                score = 70
                write_event("host_monitor", "critical",
                            f"敏感文件被修改: {fpath}",
                            raw_detail=fpath, attack_type="file_access",
                            attack_phase="persistence")
            SCORE_PER_HOST[HOST_IP] += score
        elif new_hash != FILE_HASHES[fpath]:
            if fpath in SENSITIVE_FILES:
                SCORE_PER_HOST[HOST_IP] += 70
                write_event("host_monitor", "critical",
                            f"敏感文件内容变更: {fpath}",
                            attack_type="file_access", mitre_id="T1003")

    FILE_HASHES = new_hashes


# ===== 3. 网络监控 =====
def watch_network():
    try:
        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]  # skip header
        with open("/proc/net/tcp6", "r") as f:
            lines += f.readlines()[1:]
    except Exception:
        return

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 10:
            continue
        local = parts[1].split(":")
        port = int(local[1], 16) if len(local) > 1 else 0
        state = parts[3]
        state_hex = int(state, 16)

        if state_hex in (1, 10):
            if port not in (22, 53, 80, 443, 3306, 8080, 5000) and port > 1024:
                write_event("host_monitor", "medium",
                            f"非预期监听端口: {port}",
                            dst_port=port, attack_type="lateral_move",
                            attack_phase="persistence")
                SCORE_PER_HOST[HOST_IP] += 20


# ===== 4. 持久化监控 =====
PERSISTENCE_BASELINE = {}

def watch_persistence():
    global PERSISTENCE_BASELINE
    current = {}

    for fpath in PERSISTENCE_FILES:
        if os.path.isfile(fpath):
            try:
                with open(fpath, "rb") as f:
                    current[fpath] = hashlib.md5(f.read()).hexdigest()
            except Exception:
                continue

    if not PERSISTENCE_BASELINE:
        PERSISTENCE_BASELINE = current
        return

    for fpath, new_hash in current.items():
        if fpath in PERSISTENCE_BASELINE and new_hash != PERSISTENCE_BASELINE[fpath]:
            SCORE_PER_HOST[HOST_IP] += 50
            write_event("host_monitor", "critical",
                        f"持久化机制变更: {fpath}",
                        raw_detail=fpath, attack_type="persistence",
                        attack_phase="persistence", mitre_id="T1053",
                        action_taken="alert")
    PERSISTENCE_BASELINE = current


# ===== 5. 系统日志协同监控（auditd + syslog） =====
SYSLOG_POSITIONS = {}

def watch_syslog():
    log_files = [
        ("/var/log/auth.log", "auth"),
        ("/var/log/syslog", "syslog"),
    ]
    for log_path, log_type in log_files:
        if not os.path.exists(log_path):
            continue
        try:
            fsize = os.path.getsize(log_path)
            last_pos = SYSLOG_POSITIONS.get(log_path, fsize)
            if fsize < last_pos:
                last_pos = 0
            if fsize == last_pos:
                continue

            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    score = 0
                    atype = "unknown"
                    msg = ""

                    if log_type == "auth":
                        if "Failed password" in line:
                            score = 10
                            atype = "brute_force"
                            msg = f"SSH登录失败: {line[:120]}"
                        elif "authentication failure" in line:
                            score = 15
                            atype = "brute_force"
                            msg = f"认证失败: {line[:120]}"
                        elif "new user" in line.lower():
                            score = 40
                            atype = "persistence"
                            msg = f"新用户创建: {line[:120]}"
                        elif "sudo:" in line and "COMMAND=" in line:
                            score = 20
                            atype = "suspicious_process"
                            msg = f"sudo执行: {line[:120]}"
                        elif "Accepted publickey" in line:
                            write_event("host_monitor", "low",
                                        f"SSH公钥登录: {line[:120]}",
                                        attack_type="unknown", attack_phase="recon")

                    elif log_type == "syslog":
                        if any(kw in line.lower() for kw in ["segfault", "oops", "bug"]):
                            score = 15
                            atype = "unknown"
                            msg = f"系统异常: {line[:120]}"
                        elif "CRON" in line and ("/tmp/" in line or "/dev/shm/" in line):
                            score = 50
                            atype = "persistence"
                            msg = f"可疑定时任务: {line[:120]}"

                    if score > 0:
                        SCORE_PER_HOST[HOST_IP] += score
                        write_event("host_monitor", "high" if score >= 30 else "medium",
                                    f"[{log_type}] {msg}",
                                    raw_detail=line[:200], attack_type=atype,
                                    attack_phase="persistence" if atype == "persistence" else "exploitation")
                SYSLOG_POSITIONS[log_path] = f.tell()
        except (PermissionError, OSError):
            pass


def flush_scores():
    for ip, score in SCORE_PER_HOST.items():
        if score >= SCORE_THRESHOLD:
            write_event("host_monitor", "critical",
                        f"⚠ 主机 {ip} 累计异常分数 {score}，判定为可能已失陷",
                        attack_type="host_compromised", attack_phase="unknown")
    SCORE_PER_HOST.clear()


def main():
    print(f"[host_monitor] 启动 @ {HOST_IP} ({HOSTNAME})")
    write_event("host_monitor", "info", f"主机监控启动 (IP: {HOST_IP})")

    counter = 0
    try:
        while True:
            counter += 1
            watch_processes()
            if counter % 5 == 0:
                watch_filesystem()
                watch_persistence()
            if counter % 3 == 0:
                watch_network()
                watch_syslog()
            if counter % 20 == 0:
                flush_scores()
            time.sleep(2)
    except KeyboardInterrupt:
        print("[host_monitor] 已停止")


if __name__ == "__main__":
    main()
