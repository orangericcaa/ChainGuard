#!/bin/bash
# deploy_vm2.sh — Web Server 部署脚本
# 用法: sudo bash deploy_vm2.sh
set -e

echo "[VM2] 开始部署 Web Server..."

apt update
apt install -y nginx php-fpm php-mysql php-xml php-mbstring php-curl php-zip \
    python3 python3-pip curl wget git docker.io docker-compose

# pip 依赖
pip3 install flask requests

# ===== Nginx 配置 =====
cat > /etc/nginx/sites-available/default << 'NGINX'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
NGINX

systemctl restart nginx php8.1-fpm
systemctl enable nginx php8.1-fpm

# ===== 预留 Web 漏洞（模拟真实企业网站，含可检测漏洞） =====
cat > /var/www/html/index.php << 'PHPEOF'
<!DOCTYPE html>
<html><head><title>内部管理系统</title></head><body>
<h1>XX企业员工管理系统</h1>
<form method="GET" action="search.php">
  <input name="q" placeholder="搜索员工...">
  <button>搜索</button>
</form>
</body></html>
PHPEOF

cat > /var/www/html/search.php << 'PHPEOF'
<?php
// 漏洞1: SQL 注入（无参数化查询 — 供 Suricata 检测用）
$host = '192.168.20.10';
$user = 'webapp';
$pass = 'webapp123';
$db   = 'company';
$conn = new mysqli($host, $user, $pass, $db);
$q = $_GET['q'] ?? '';
$sql = "SELECT * FROM employees WHERE name LIKE '%$q%'";
$result = $conn->query($sql);
echo "<h2>搜索结果: $q</h2>";
if ($result) {
    while ($row = $result->fetch_assoc()) {
        echo "<p>{$row['name']} - {$row['dept']}</p>";
    }
}
?>
PHPEOF

cat > /var/www/html/upload.php << 'PHPEOF'
<?php
// 漏洞2: 文件上传无校验（供主机监控检测 webshell 落地）
if ($_FILES && $_FILES['file']) {
    $target = '/var/www/html/uploads/' . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "OK: $target";
}
?>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file"><button>上传</button>
</form>
PHPEOF

mkdir -p /var/www/html/uploads
chown -R www-data:www-data /var/www/html
chmod 755 /var/www/html/uploads

# ===== WordPress（富化服务） =====
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

# ===== Web Honeypot =====
if [ -f /opt/lab3/web_honeypot.py ]; then
    nohup python3 /opt/lab3/web_honeypot.py > /var/log/lab3/web_honeypot.log 2>&1 &
    echo "    web_honeypot PID: $!"
fi

echo "[+] VM2 部署完成"
echo "    Web 主页:  http://192.168.10.10/"
echo "    Web 蜜罐:  http://192.168.10.10:8080/"
