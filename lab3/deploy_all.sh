#!/bin/bash
# deploy_all.sh — 从 VM1(Gateway) 向所有节点分发脚本并部署
# 执行方式：在 VM1 上以 root 运行：bash deploy_all.sh
set -e

LAB_DIR="/opt/lab3"
HOSTS=("192.168.10.10" "192.168.20.10" "192.168.20.20")
NAMES=("web" "db" "workstation")
USER="lab"

echo "=== 课题三 一键部署 ==="
echo "[*] 当前节点: VM1 Gateway"

# 确保 lab3 目录结构在 /opt/lab3
mkdir -p /opt/lab3
if [ "$(pwd)" != "/opt/lab3" ]; then
    echo "[*] 复制项目文件到 /opt/lab3 ..."
    cp -r "$(dirname "$0")"/* /opt/lab3/ 2>/dev/null || true
fi
cd /opt/lab3

# Step 0: 安装基础 Python 依赖
echo "[VM1] 安装 Python 依赖..."
pip3 install flask requests 2>/dev/null || true

# Step 1: 本地部署 Gateway
echo "[VM1] 部署 Gateway 防火墙与检测..."
bash "${LAB_DIR}/infra/gateway/iptables_setup.sh"
bash "${LAB_DIR}/infra/gateway/suricata_setup.sh"
mkdir -p /var/log/lab3
cp "${LAB_DIR}/detections/network/traffic_analyzer.py" /opt/lab3/
cp "${LAB_DIR}/detections/trace/trace_engine.py" /opt/lab3/
cp "${LAB_DIR}/attack-sim/attack_simulator.sh" /opt/lab3/

# 启动 traffic_analyzer
nohup python3 /opt/lab3/traffic_analyzer.py > /var/log/lab3/traffic_analyzer.log 2>&1 &
echo "    traffic_analyzer PID: $!"

# 启动 log_aggregator
cp "${LAB_DIR}/aggregator/log_aggregator.py" /opt/lab3/
nohup python3 /opt/lab3/log_aggregator.py > /var/log/lab3/log_aggregator.log 2>&1 &
echo "    log_aggregator PID: $!"

# Step 2: 部署 VM2 Web
echo "[VM2] 部署 Web Server..."
ssh "${USER}@${HOSTS[0]}" "sudo mkdir -p /opt/lab3"
scp -r "${LAB_DIR}/infra/web-server/"* "${USER}@${HOSTS[0]}:/opt/lab3/"
scp "${LAB_DIR}/detections/host/host_monitor.py" "${USER}@${HOSTS[0]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/web_honeypot.py" "${USER}@${HOSTS[0]}:/opt/lab3/"
scp -r "${LAB_DIR}/services/wordpress/"* "${USER}@${HOSTS[0]}:/opt/lab3/"
ssh "${USER}@${HOSTS[0]}" "sudo bash /opt/lab3/deploy_vm2.sh"

# Step 3: 部署 VM3 DB
echo "[VM3] 部署 DB Server..."
ssh "${USER}@${HOSTS[1]}" "sudo mkdir -p /opt/lab3"
scp -r "${LAB_DIR}/infra/db-server/"* "${USER}@${HOSTS[1]}:/opt/lab3/"
scp "${LAB_DIR}/detections/host/host_monitor.py" "${USER}@${HOSTS[1]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/cowrie_setup.sh" "${USER}@${HOSTS[1]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/honeypot_enricher.py" "${USER}@${HOSTS[1]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/honeypot_reset.sh" "${USER}@${HOSTS[1]}:/opt/lab3/"
scp -r "${LAB_DIR}/services/nextcloud/"* "${USER}@${HOSTS[1]}:/opt/lab3/"
ssh "${USER}@${HOSTS[1]}" "sudo bash /opt/lab3/deploy_vm3.sh"

# Step 4: 部署 VM4 Workstation
echo "[VM4] 部署 Workstation..."
ssh "${USER}@${HOSTS[2]}" "sudo mkdir -p /opt/lab3"
scp -r "${LAB_DIR}/infra/workstation/"* "${USER}@${HOSTS[2]}:/opt/lab3/"
scp "${LAB_DIR}/detections/host/host_monitor.py" "${USER}@${HOSTS[2]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/db_honeypot.py" "${USER}@${HOSTS[2]}:/opt/lab3/"
scp "${LAB_DIR}/detections/honeypot/honeypot_reset.sh" "${USER}@${HOSTS[2]}:/opt/lab3/"
# attack_simulator 在 VM1 上运行（攻击流量经网关被 Suricata 捕获）
ssh "${USER}@${HOSTS[2]}" "sudo bash /opt/lab3/deploy_vm4.sh"

echo ""
echo "=== 部署完成 ==="
echo "各节点检测服务已启动，事件汇聚至 VM1:5000"
echo "查看日志: tail -f /var/log/lab3/events.jsonl"
echo "攻击模拟: ssh lab@192.168.10.1 'bash /opt/lab3/attack_simulator.sh'"
