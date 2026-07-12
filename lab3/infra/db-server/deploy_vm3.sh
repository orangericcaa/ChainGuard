#!/bin/bash
# deploy_vm3.sh — DB/File Server 部署脚本
# 用法: sudo bash deploy_vm3.sh
set -e

echo "[VM3] 开始部署 DB/File Server..."

apt update
apt install -y mysql-server samba python3 python3-pip curl wget git docker.io docker-compose

pip3 install flask requests

# ===== MySQL 配置 =====
systemctl enable --now mysql

# 创建数据库和用户（含可检测漏洞：弱密码）
mysql -u root << 'SQL'
CREATE DATABASE IF NOT EXISTS company;
CREATE USER IF NOT EXISTS 'webapp'@'192.168.10.10' IDENTIFIED BY 'webapp123';
GRANT ALL PRIVILEGES ON company.* TO 'webapp'@'192.168.10.10';
CREATE USER IF NOT EXISTS 'webapp'@'%' IDENTIFIED BY 'webapp123';
GRANT ALL PRIVILEGES ON company.* TO 'webapp'@'%';
FLUSH PRIVILEGES;

USE company;
CREATE TABLE IF NOT EXISTS employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    dept VARCHAR(100),
    salary INT
);
INSERT INTO employees (name, dept, salary) VALUES
    ('张三', '技术部', 15000),
    ('李四', '财务部', 18000),
    ('王五', '市场部', 13000)
ON DUPLICATE KEY UPDATE name=name;

-- 漏洞数据表：模拟敏感信息
CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(100),
    value TEXT
);
INSERT INTO secrets (label, value) VALUES
    ('canary', 'lab3-canary-flag-2025'),
    ('db_pass', 'Admin@2025Secret'),
    ('api_key', 'sk-lab3-demo-key-12345')
ON DUPLICATE KEY UPDATE label=label;
SQL

# ===== Samba 文件共享 =====
mkdir -p /srv/samba/share
chmod 777 /srv/samba/share

if ! grep -q "\[shared\]" /etc/samba/smb.conf 2>/dev/null; then
cat >> /etc/samba/smb.conf << 'SMB'
[shared]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
SMB
fi

systemctl enable --now smbd

# ===== Nextcloud（富化服务） =====
if [ -f /opt/lab3/docker-compose.yml ]; then
    cd /opt/lab3
    docker-compose up -d
fi

# ===== host_monitor =====
if [ -f /opt/lab3/host_monitor.py ]; then
    mkdir -p /var/log/lab3
    nohup python3 /opt/lab3/host_monitor.py > /var/log/lab3/host_monitor.log 2>&1 &
    echo "    host_monitor PID: $!"
fi

# ===== Cowrie SSH 蜜罐 =====
if [ -f /opt/lab3/cowrie_setup.sh ]; then
    bash /opt/lab3/cowrie_setup.sh
fi

echo "[+] VM3 部署完成"
echo "    MySQL:    192.168.20.10:3306"
echo "    Samba:    192.168.20.10:445"
echo "    SSH蜜罐:  192.168.20.10:22"

# 定时蜜罐自动恢复（每2小时，满足"空闲时自动恢复攻击前状态"）
if [ -f /opt/lab3/honeypot_reset.sh ]; then
    (crontab -l 2>/dev/null; echo "0 */2 * * * bash /opt/lab3/honeypot_reset.sh cowrie >> /var/log/lab3/honeypot_reset.log 2>&1") | crontab -
    echo "    蜜罐自动恢复cron: 每2小时执行一次"
fi
