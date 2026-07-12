#!/bin/bash
# cowrie_setup.sh — Cowrie SSH 蜜罐部署
# 部署位置: VM3 DB Server
# 用法: sudo bash cowrie_setup.sh
set -e

echo "[*] 部署 Cowrie SSH 蜜罐..."

apt update
apt install -y docker.io docker-compose python3 python3-pip
pip3 install requests

# 将真实 SSH 移到 2222（仅首次运行生效，避免重复执行导致端口号累加）
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
    sed -i 's/^Port 22$/Port 2222/' /etc/ssh/sshd_config
    systemctl restart sshd
fi

# 克隆 Cowrie
COWRIE_DIR="/opt/cowrie"
if [ ! -d "$COWRIE_DIR" ]; then
    git clone https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
fi

cd "$COWRIE_DIR"

# 配置 Cowrie
cat > etc/cowrie.cfg << 'COWCONF'
[honeypot]
hostname = db-prod-01
listen_addr = 0.0.0.0
listen_port = 22
ssh_version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

[shell]
interactive = true

[ssh]
host_key = etc/ssh_host_rsa_key
host_key_size = 4096

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_localfiles]
enabled = true
logdir = var/log/cowrie

[honeypot_files]
download_path = var/lib/cowrie/downloads
COWCONF

# 生成 SSH 主机密钥
ssh-keygen -t rsa -b 4096 -f etc/ssh_host_rsa_key -N "" -m PEM

# 创建管理员账户（蜜罐中可被暴力破解的弱密码）
mkdir -p etc
cat > etc/userdb.txt << 'USERDB'
root:x:Admin@2025!
admin:x:password123
ubuntu:x:ubuntu
test:x:test123
USERDB

# 伪造文件系统
mkdir -p honeyfs/etc
cat > honeyfs/etc/passwd << 'PASSWD'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
admin:x:1000:1000:Admin:/home/admin:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:1002:1002:MySQL:/home/mysql:/bin/bash
PASSWD

mkdir -p honeyfs/root
echo "ssh-rsa AAAAB3NzaC1yc2EAAA... admin@db-prod-01" > honeyfs/root/.ssh/authorized_keys

# 创建 Docker Compose（方便管理）
cat > docker-compose.yml << 'DOCKCOMP'
version: "3"
services:
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "22:22"
    volumes:
      - ./etc:/cowrie/cowrie-git/etc
      - ./var:/cowrie/cowrie-git/var
      - ./honeyfs:/cowrie/cowrie-git/honeyfs
    restart: unless-stopped
DOCKCOMP

docker-compose up -d 2>/dev/null || {
    # Docker 方式失败则用本地方式
    echo "[!] Docker 不可用，使用本地安装..."
    pip3 install -r requirements.txt 2>/dev/null || pip3 install twisted cryptography bcrypt
    nohup python3 bin/cowrie start > /var/log/lab3/cowrie.log 2>&1 &
}

# 启动 enricher
if [ -f /opt/lab3/honeypot_enricher.py ]; then
    nohup python3 /opt/lab3/honeypot_enricher.py > /var/log/lab3/honeypot_enricher.log 2>&1 &
    echo "    honeypot_enricher PID: $!"
fi

echo "[+] Cowrie SSH 蜜罐已部署"
echo "    蜜罐 SSH: 22 (真实SSH已移至2222)"
echo "    日志: /opt/cowrie/var/log/cowrie/"
