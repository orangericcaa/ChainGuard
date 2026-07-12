#!/bin/bash
# iptables_setup.sh — Gateway 防火墙规则
# 用法: sudo bash iptables_setup.sh
set -e

# 网卡名（根据实际环境修改）
EXT_IF="ens33"    # NAT网卡（外网入口 / SSH管理 / 出站上网）
DMZ_IF="ens37"    # vmnet1（DMZ）
INT_IF="ens38"    # vmnet2（内网）

echo "[*] 配置 iptables 防火墙..."

# 清空现有规则
iptables -F
iptables -t nat -F
iptables -X
iptables -t mangle -F

# 默认策略：入站/转发丢弃，出站放行
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 放行本地回环
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 放行已建立的连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 允许 SSH 管理（从任意接口，方便开发）
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ===== 转发规则 =====

# 外网 → DMZ: 仅允许 Web 端口
iptables -A FORWARD -i "${EXT_IF}" -o "${DMZ_IF}" -d 192.168.10.10 \
    -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i "${EXT_IF}" -o "${DMZ_IF}" -d 192.168.10.10 \
    -p tcp --dport 443 -j ACCEPT

# 外网 → DMZ: 允许访问 Web 蜜罐端口(8080)
iptables -A FORWARD -i "${EXT_IF}" -o "${DMZ_IF}" -d 192.168.10.10 \
    -p tcp --dport 8080 -j ACCEPT

# 外网 → DMZ: 允许访问 WordPress (8081)
iptables -A FORWARD -i "${EXT_IF}" -o "${DMZ_IF}" -d 192.168.10.10 \
    -p tcp --dport 8081 -j ACCEPT

# DMZ → 内网: 仅允许 Web 访问 DB 和文件共享
iptables -A FORWARD -i "${DMZ_IF}" -o "${INT_IF}" -s 192.168.10.10 \
    -d 192.168.20.10 -p tcp --dport 3306 -j ACCEPT
iptables -A FORWARD -i "${DMZ_IF}" -o "${INT_IF}" -s 192.168.10.10 \
    -d 192.168.20.10 -p tcp --dport 445 -j ACCEPT

# 内网 → 外网: 允许出站（装软件、NTP 等）
iptables -A FORWARD -i "${INT_IF}" -o "${EXT_IF}" -j ACCEPT

# 外网 → 内网: 拒绝直接访问（核心隔离）
iptables -A FORWARD -i "${EXT_IF}" -o "${INT_IF}" -j LOG \
    --log-prefix "FW-DROP-EXT2INT: " --log-level 4
iptables -A FORWARD -i "${EXT_IF}" -o "${INT_IF}" -j DROP

# ===== NAT 地址转换 =====
iptables -t nat -A POSTROUTING -o "${EXT_IF}" -j MASQUERADE

# ===== 放行事件上报端口 =====
iptables -A INPUT -i "${DMZ_IF}" -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -i "${INT_IF}" -p tcp --dport 5000 -j ACCEPT

# 开启转发
sysctl -w net.ipv4.ip_forward=1

# 持久化
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
fi

echo "[+] 防火墙配置完成"
echo ""
echo "=== 当前规则摘要 ==="
iptables -L FORWARD -n -v --line-numbers
echo ""
echo "=== NAT 规则 ==="
iptables -t nat -L POSTROUTING -n -v
