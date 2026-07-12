#!/usr/bin/env python3
"""
web_honeypot.py — 高交互 Web 蜜罐
部署: VM2 Web Server
监听: 0.0.0.0:8080
功能:
  1. 模拟真实企业网站（登录页、后台、文件上传、API）
  2. 记录所有 HTTP 请求（URL / Headers / Body / Cookie / IP / UA）
  3. SQL 注入诱饵 — 返回假数据
  4. 文件包含诱饵 — 返回假配置文件
  5. 登录诱饵 — 接受任意凭证，记录尝试
  6. 记录蜜罐内向外发起的连接
  7. 定时自动恢复
"""

import os
import json
import time
import uuid
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string, session

HOST_IP = "192.168.10.10"
EVENTS_LOG = "/var/log/lab3/events.jsonl"
HONEYPOT_DB = "/opt/lab3/web_honeypot/honeypot.db"
os.makedirs("/opt/lab3/web_honeypot", exist_ok=True)
os.makedirs("/opt/lab3/web_honeypot/uploads", exist_ok=True)

app = Flask(__name__)
app.secret_key = "honeypot-secret-not-real-production-key-2025"

DB = None


def init_db():
    global DB
    DB = sqlite3.connect(HONEYPOT_DB, check_same_thread=False)
    DB.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, method TEXT, path TEXT, full_url TEXT,
            src_ip TEXT, user_agent TEXT, headers TEXT,
            body TEXT, cookies TEXT, is_attack INTEGER DEFAULT 0,
            attack_type TEXT
        )
    """)
    DB.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, username TEXT, password TEXT, src_ip TEXT
        )
    """)
    DB.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, filename TEXT, filepath TEXT, src_ip TEXT, size INTEGER
        )
    """)
    DB.commit()


def log_request(is_attack=False, attack_type=None):
    data = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "full_url": request.url,
        "src_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)[:2000],
        "cookies": dict(request.cookies),
        "is_attack": int(is_attack),
        "attack_type": attack_type or ""
    }
    DB.execute("""INSERT INTO requests (ts, method, path, full_url, src_ip, user_agent,
                  headers, body, cookies, is_attack, attack_type)
                  VALUES (:ts, :method, :path, :full_url, :src_ip, :user_agent,
                  :headers, :body, :cookies, :is_attack, :attack_type)""", data)
    DB.commit()


def write_event(severity, message, **kwargs):
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": os.environ.get("LAB3_RUN_ID", "default"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": "VM2",
        "host_ip": HOST_IP,
        "detector": "web_honeypot",
        "layer": "honeypot",
        "severity": severity,
        "message": message,
        "src_ip": request.remote_addr,
        **kwargs
    }
    with open(EVENTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def detect_attack_type(path, body, headers):
    if any(x in path.lower() for x in ["union", "select", "or 1=1", "' or ", "sleep("]):
        return "sql_injection"
    if any(x in path.lower() for x in ["<script>", "onerror=", "onload=", "javascript:"]):
        return "xss"
    if "../" in path or "..\\" in path:
        return "dir_traversal"
    if any(x in path.lower() for x in ["/etc/passwd", "wp-config", ".htaccess", "/etc/shadow"]):
        return "file_access"
    if any(x in path.lower() + body.lower() for x in ["eval(", "system(", "exec(", "passthru("]):
        return "webshell"
    if "wget " in body or "curl " in body or "|sh" in body:
        return "cmd_injection"
    return None


HTML_TEMPLATES = {
    "index": """<!DOCTYPE html>
<html><head><title>XX企业协同办公平台</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}
.login{max-width:400px;margin:100px auto;padding:30px;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h1{color:#333;text-align:center}input{display:block;width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px}
button{width:100%;padding:10px;background:#4a90d9;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
.footer{text-align:center;margin-top:20px;color:#999;font-size:12px}</style></head>
<body>
<div class="login"><h1>XX企业协同办公平台</h1>
<form method="POST" action="/admin/login">
<input type="text" name="username" placeholder="用户名">
<input type="password" name="password" placeholder="密码">
<button>登 录</button></form>
<p class="footer">v2.3.1 | 技术支持: IT运维部 ext.888</p></div></body></html>""",

    "dashboard": """<!DOCTYPE html>
<html><head><title>管理后台 - XX企业</title>
<style>body{font-family:Arial;margin:0;display:flex}
.sidebar{width:220px;background:#2c3e50;color:white;min-height:100vh;padding:20px}
.sidebar h2{font-size:18px;margin-bottom:30px}
.sidebar a{color:#ccc;display:block;padding:10px 0;text-decoration:none;border-bottom:1px solid #3d5266}
.main{padding:30px;flex:1}
.card{background:white;padding:20px;margin:10px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px}
.badge{background:#e74c3c;color:white;padding:2px 8px;border-radius:10px;font-size:12px}</style></head>
<body>
<div class="sidebar"><h2>XX企业管理后台</h2>
<a href="/admin/dashboard">📊 仪表盘</a>
<a href="/admin/users">👥 用户管理</a>
<a href="/admin/files">📁 文件管理</a>
<a href="/admin/upload">📤 文件上传</a>
<a href="/api/v1/users">🔌 API</a>
<a href="/admin/settings">⚙ 系统设置</a></div>
<div class="main">
<h1>系统仪表盘</h1>
<div class="grid">
<div class="card"><h3>在线用户</h3><h2>42</h2></div>
<div class="card"><h3>今日请求</h3><h2>12,847</h2></div>
<div class="card"><h3>待处理工单</h3><h2>3 <span class="badge">NEW</span></h2></div>
</div></div></body></html>""",

    "upload": """<!DOCTYPE html>
<html><head><title>文件上传</title></head><body>
<h2>文件上传</h2>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file"><br>
<button>上传</button></form></body></html>""",

    "backup": "<?php\n// Database configuration\n$db_host = '192.168.20.10';\n$db_user = 'webapp';\n$db_pass = 'webapp123';\n$db_name = 'company';\n// Internal API key: sk-internal-demo-2025\n?>",

    "fake_passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\nwebapp:x:1001:1001::/home/webapp:/sbin/nologin\nmysql:x:1002:1002::/home/mysql:/sbin/nologin"
}

LOGIN_SESSIONS = {}


@app.before_request
def before_request():
    log_request()


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATES["index"])


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        DB.execute("INSERT INTO login_attempts (ts, username, password, src_ip) VALUES (?,?,?,?)",
                   [datetime.now(timezone.utc).isoformat(), username, password, request.remote_addr])
        DB.commit()
        write_event("medium", f"蜜罐登录尝试: {username}/{password}",
                    raw_detail=f"user={username} pass={password}", attack_type="brute_force")
        session["logged_in"] = True
        session["user"] = username
        LOGIN_SESSIONS[request.remote_addr] = username
        return render_template_string(HTML_TEMPLATES["dashboard"])
    return render_template_string(HTML_TEMPLATES["index"])


@app.route("/admin/dashboard")
def dashboard():
    return render_template_string(HTML_TEMPLATES["dashboard"])


@app.route("/admin/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST" and request.files.get("file"):
        f = request.files["file"]
        fname = f.filename
        fpath = os.path.join("/opt/lab3/web_honeypot/uploads", fname)
        f.save(fpath)
        fsize = os.path.getsize(fpath)
        DB.execute("INSERT INTO uploaded_files (ts, filename, filepath, src_ip, size) VALUES (?,?,?,?,?)",
                   [datetime.now(timezone.utc).isoformat(), fname, fpath, request.remote_addr, fsize])
        DB.commit()
        write_event("high", f"文件上传至蜜罐: {fname} ({fsize} bytes)",
                    raw_detail=f"file={fname} size={fsize}", attack_type="webshell")
        return f"Upload OK: {fname}"
    return render_template_string(HTML_TEMPLATES["upload"])


@app.route("/api/v1/users")
def api_users():
    query = request.args.get("q", "")
    if any(x in query.lower() for x in ["union", "select", "' or ", "sleep("]):
        write_event("high", f"蜜罐API SQL注入尝试: {query}",
                    raw_detail=query, attack_type="sql_injection", attack_phase="exploitation")
        return jsonify({
            "status": "error",
            "message": f"You have an error in your SQL syntax near '{query}'",
            "hint": "MySQL server version 8.0.35",
            "data": [{"id": 1, "name": "admin", "role": "superuser"}]
        })
    return jsonify({"status": "ok", "data": []})


@app.route("/backup/")
def backup_dir():
    return "Index of /backup/\n..\nconfig.php.bak\nbackup_2025.sql\ndatabase_dump.tar.gz"


@app.route("/backup/config.php.bak")
def backup_config():
    return HTML_TEMPLATES["backup"], {"Content-Type": "text/plain"}


@app.route("/includes/config.php")
def fake_config():
    return HTML_TEMPLATES["backup"], {"Content-Type": "text/plain"}


@app.route("/etc/passwd")
@app.route("/etc/shadow")
@app.route("/wp-config.php")
def fake_sensitive():
    write_event("high", f"蜜罐捕获敏感文件读取: {request.path}",
                raw_detail=request.path, attack_type="file_access", attack_phase="exploitation")
    if "shadow" in request.path:
        return "Forbidden", 403
    return HTML_TEMPLATES["fake_passwd"], {"Content-Type": "text/plain"}


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /includes/\nDisallow: /api/"


@app.errorhandler(404)
def not_found(e):
    p = request.path
    attack_type = detect_attack_type(p, request.get_data(as_text=True), dict(request.headers))
    if attack_type:
        log_request(is_attack=True, attack_type=attack_type)
        write_event("medium", f"蜜罐捕获可疑请求: {p}",
                    raw_detail=p, attack_type=attack_type, attack_phase="exploitation")
    return f"<h1>404 Not Found</h1><p>The requested URL {p} was not found on this server.</p>", 404


def hex_to_ip(hex_str):
    """将 /proc/net/tcp 中的十六进制IP转为点分十进制"""
    try:
        parts = [hex_str[i:i+2] for i in range(0, 8, 2)]
        return ".".join(str(int(p, 16)) for p in reversed(parts))
    except Exception:
        return "0.0.0.0"


WHITELIST_NETS = ("127.", "192.168.10.", "192.168.20.", "0.0.0.0")

def is_internal(ip):
    return any(ip.startswith(net) for net in WHITELIST_NETS)


def read_outbound_connections():
    """读取 /proc/net/tcp 和 /proc/net/udp，返回外联的远程IP列表"""
    results = []
    for proto_path in ("/proc/net/tcp", "/proc/net/udp"):
        if not os.path.exists(proto_path):
            continue
        try:
            with open(proto_path, "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                    state_hex = int(parts[3], 16)
                    if state_hex != 1:
                        continue
                    local = parts[1].split(":")
                    remote = parts[2].split(":")
                    remote_ip = hex_to_ip(remote[0])
                    remote_port = int(remote[1], 16) if len(remote) > 1 else 0
                    if not is_internal(remote_ip):
                        results.append((remote_ip, remote_port, proto_path))
        except (PermissionError, FileNotFoundError):
            pass
    return results


def monitor_outbound():
    """监控蜜罐进程对外发起的连接，记录域名与IP"""
    seen = set()
    while True:
        try:
            conns = read_outbound_connections()
            for remote_ip, remote_port, proto in conns:
                key = f"{remote_ip}:{remote_port}"
                if key in seen:
                    continue
                seen.add(key)
                proto_name = "TCP" if "tcp" in proto else "UDP"
                write_event("high",
                            f"蜜罐检测到内部向外连接: {remote_ip}:{remote_port} ({proto_name})",
                            src_ip=HOST_IP, dst_ip=remote_ip, dst_port=remote_port,
                            protocol=proto_name, raw_detail=f"outbound_to={remote_ip}:{remote_port}/{proto_name}",
                            attack_type="lateral_move", attack_phase="exfiltration")
        except Exception:
            pass
        time.sleep(30)


if __name__ == "__main__":
    init_db()
    write_event("info", "Web蜜罐启动", severity="info")

    t = threading.Thread(target=monitor_outbound, daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=8080, debug=False)
