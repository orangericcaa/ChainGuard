#!/bin/bash
# deploy_vm4.sh — Workstation 部署脚本
# 用法: sudo bash deploy_vm4.sh
set -e

echo "[VM4] 开始部署 Workstation..."

apt update
apt install -y apache2 python3 python3-pip curl wget docker.io docker-compose

pip3 install flask requests

# ===== 内部管理系统 =====
cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>内部管理系统</title></head><body>
<h1>员工自助服务平台</h1>
<p>欢迎使用内部管理系统</p>
<ul>
  <li><a href="hr.html">人事管理</a></li>
  <li><a href="finance.html">财务查询</a></li>
  <li><a href="docs.html">文档中心</a></li>
</ul>
</body></html>
HTML

systemctl enable --now apache2

# ===== host_monitor =====
if [ -f /opt/lab3/host_monitor.py ]; then
    mkdir -p /var/log/lab3
    nohup python3 /opt/lab3/host_monitor.py > /var/log/lab3/host_monitor.log 2>&1 &
    echo "    host_monitor PID: $!"
fi

# ===== DB Honeypot =====
if [ -f /opt/lab3/db_honeypot.py ]; then
    nohup python3 /opt/lab3/db_honeypot.py > /var/log/lab3/db_honeypot.log 2>&1 &
    echo "    db_honeypot PID: $!"
fi

# ===== MailHog 邮件服务器（富化服务，SMTP:1025 / Web:8025） =====
docker run -d --name mailhog --restart unless-stopped \
    -p 192.168.20.20:1025:1025 \
    -p 192.168.20.20:8025:8025 \
    mailhog/mailhog 2>/dev/null || echo "    MailHog already running, skip"

echo "[+] VM4 部署完成"
echo "    Web:       http://192.168.20.20/"
echo "    DB蜜罐:    192.168.20.20:3306"
echo "    MailHog:   http://192.168.20.20:8025 (SMTP:1025)"

if [ -f /opt/lab3/honeypot_reset.sh ]; then
    (crontab -l 2>/dev/null; echo "0 */2 * * * bash /opt/lab3/honeypot_reset.sh db >> /var/log/lab3/honeypot_reset.log 2>&1") | crontab -
    echo "    DB蜜罐自动恢复cron: 每2小时"
fi
