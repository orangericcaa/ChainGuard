#!/usr/bin/env python3
"""
db_honeypot.py — MySQL 蜜罐（中交互）
部署: VM4 Workstation
监听: 0.0.0.0:3306
功能:
  1. 模拟 MySQL 5.7 握手协议
  2. 记录所有连接尝试（IP、时间、用户名、密码）
  3. 对 SQL 查询返回假数据
  4. 输出 JSONL 事件
"""

import os
import json
import time
import uuid
import socket
import struct
import hashlib
import threading
from datetime import datetime, timezone

HOST_IP = "192.168.20.20"
EVENTS_LOG = "/var/log/lab3/events.jsonl"
HONEYPOT_LOG = "/var/log/lab3/db_honeypot.log"
os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)

FAKE_PLUGIN_DATA = b"\x00" * 13
SERVER_VERSION = b"5.7.42-0ubuntu0.22.04.1\x00"


def write_event(severity, message, **kwargs):
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": os.environ.get("LAB3_RUN_ID", "default"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": "VM4",
        "host_ip": HOST_IP,
        "detector": "db_honeypot",
        "layer": "honeypot",
        "severity": severity,
        "message": message,
        **kwargs
    }
    with open(EVENTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def log_info(msg):
    with open(HONEYPOT_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n")


def scramble(password, salt):
    if not password:
        return b"\x00"
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(salt + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def build_handshake_packet(conn_id):
    salt = os.urandom(20)
    proto_version = 10
    filler = b"\x00" * 23
    packet = (
        struct.pack("<B", proto_version) +
        SERVER_VERSION +
        struct.pack("<I", conn_id) +
        salt[:8] +
        filler +
        salt[8:] +
        FAKE_PLUGIN_DATA
    )
    return len(packet).to_bytes(3, "little") + b"\x00" + packet


def build_ok_packet():
    return b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"


def build_err_packet(code, msg):
    payload = struct.pack("<H", code) + b"#42000" + msg.encode() + b"\x00"
    return len(payload).to_bytes(3, "little") + b"\x00\xff" + payload


def build_column_definition(name, col_type=0xfd):
    catalog = b"def\x00"
    schema = b"honeypot_db\x00"
    table = b"fake_table\x00"
    org_table = table
    col_name = name.encode() + b"\x00"
    org_name = col_name
    fixed = b"\x0c" + struct.pack("<H", 33) + b"\x08\x00\x00\x03"
    payload = catalog + schema + table + org_table + col_name + org_name + fixed
    return len(payload).to_bytes(3, "little") + b"\x01" + payload


def build_resultset(columns, rows):
    packets = []
    packets.append(struct.pack("<B", len(columns)).rjust(4, b"\x00"))
    for col in columns:
        packets.append(build_column_definition(col))
    packets.append(b"\x05\x00\x00\x05\xfe\x00\x00\x02\x00")
    for row in rows:
        for val in row:
            v = str(val).encode() if val is not None else b"\xfb"
            if v != b"\xfb":
                payload = struct.pack("<B", len(v)) + v
            else:
                payload = b"\xfb"
            packets.append(len(payload).to_bytes(3, "little") + b"\x00" + payload)
    packets.append(b"\x05\x00\x00\x01\xfe\x00\x00\x02\x00")
    return b"".join(packets)


def handle_client(conn, addr):
    src_ip = addr[0]
    log_info(f"New connection: {src_ip}")
    write_event("medium", f"DB蜜罐新连接: {src_ip}",
                src_ip=src_ip, attack_type="unknown", attack_phase="recon")

    try:
        conn_id = int(time.time()) % 0xFFFFFFFF
        conn.sendall(build_handshake_packet(conn_id))
        conn.settimeout(30)

        init_data = conn.recv(1024)
        if not init_data:
            return

        try:
            client_flags = struct.unpack("<I", init_data[:4])[0]
            offset = 36
            username_end = init_data.find(b"\x00", offset)
            username = init_data[offset:username_end].decode("utf-8", errors="replace") if username_end > offset else "?"
            offset = username_end + 1
            auth_len = init_data[offset]
            offset += 1
            auth_data = init_data[offset:offset+auth_len]
            offset += auth_len
            db_end = init_data.find(b"\x00", offset)
            database = init_data[offset:db_end].decode("utf-8", errors="replace") if db_end > offset else "?"
        except Exception:
            username = "?"
            auth_data = b""
            database = "?"

        hashed_auth = auth_data.hex()[:40] if auth_data else "none"
        write_event("high", f"DB蜜罐登录尝试: {username}@{src_ip}",
                    src_ip=src_ip, raw_detail=f"user={username} db={database} auth={hashed_auth}",
                    attack_type="brute_force", attack_phase="exploitation",
                    mitre_id="T1190")

        conn.sendall(build_ok_packet())
        log_info(f"Login: {username} from {src_ip}")

        while True:
            cmd_data = conn.recv(4096)
            if not cmd_data:
                break

            if cmd_data[4:5] == b"\x03":
                query = cmd_data[5:].decode("utf-8", errors="replace")
                log_info(f"Query from {src_ip}: {query[:200]}")
                write_event("medium", f"DB蜜罐收到查询: {query[:150]}",
                            src_ip=src_ip, raw_detail=query[:500],
                            attack_type="sql_injection" if any(x in query.lower() for x in ["union", "select", "sleep", "or 1=1"]) else "unknown",
                            attack_phase="exploitation")

                q = query.lower().strip()
                if "show databases" in q:
                    data = build_resultset(["Database"], [["honeypot_db"], ["employee_db"], ["finance_db"], ["customer_db"]])
                    conn.sendall(data)
                elif "show tables" in q:
                    data = build_resultset([f"Tables_in_honeypot_db"], [["users"], ["employees"], ["payroll"], ["secrets"], ["api_keys"]])
                    conn.sendall(data)
                elif "union" in q or "select" in q:
                    data = build_resultset(["id", "username", "password"], [
                        [1, "admin", "Admin@2025!"],
                        [2, "root", "SuperSecret123"],
                        [3, "webapp", "webapp123"]
                    ])
                    conn.sendall(data)
                elif "quit" in q or "exit" in q:
                    break
                else:
                    conn.sendall(build_ok_packet())

            elif cmd_data[4:5] == b"\x01":
                break

    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log_info(f"Error with {src_ip}: {e}")
    finally:
        conn.close()


def main():
    print("[db_honeypot] 启动 MySQL 蜜罐 @ :3306 ...")
    write_event("info", "DB蜜罐启动", severity="info")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 3306))
    sock.listen(10)

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_info(f"Accept error: {e}")

    sock.close()


if __name__ == "__main__":
    main()
