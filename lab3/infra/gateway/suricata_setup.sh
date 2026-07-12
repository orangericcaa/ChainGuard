#!/bin/bash
# suricata_setup.sh — Gateway 双 Suricata 实例部署
# 用法: sudo bash suricata_setup.sh
set -e

# Suricata DMZ 实例监听 DMZ 接口（eth1），攻击流量由此进出
# Suricata 内网实例监听内网接口（eth2），检测横向移动
DMZ_IF="ens37"
INT_IF="ens38"
RULES_DIR="/etc/suricata/rules"
CUSTOM_RULES="${RULES_DIR}/custom.rules"
LAB_DIR="/opt/lab3"

echo "[*] 安装 Suricata..."
apt update
apt install -y suricata suricata-update

mkdir -p "${RULES_DIR}"

# 复制自定义规则
cp "${LAB_DIR}/detections/network/custom.rules" "${CUSTOM_RULES}"

# ===== DMZ 实例配置（监听 DMZ 接口 eth1） =====
# HOME_NET 不含网关IP，确保 VM1→VM2 流量被视为 EXTERNAL→HOME
cat > /etc/suricata/dmz.yaml << 'SURICONF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.10.10]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "[192.168.10.10]"
    SQL_SERVERS: "[192.168.20.10]"

default-rule-path: /etc/suricata/rules
rule-files:
  - custom.rules

af-packet:
  - interface: DMZ_IFACE_PLACEHOLDER
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve-dmz.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - flow
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast-dmz.log

app-layer:
  protocols:
    http:
      enabled: yes
    dns:
      enabled: yes
    tls:
      enabled: yes
    ssh:
      enabled: yes

logging:
  default-log-level: info
SURICONF

# 替换 DMZ 实例网卡名
sed -i "s/DMZ_IFACE_PLACEHOLDER/${DMZ_IF}/" /etc/suricata/dmz.yaml

# ===== 内网实例配置（监听内网接口 eth2） =====
# HOME_NET 不含网关IP(192.168.20.1)，确保 VM1→VM3/VM4 流量被视为 EXTERNAL→HOME
cat > /etc/suricata/internal.yaml << 'SURICONF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.20.10,192.168.20.20]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "[192.168.20.10]"

default-rule-path: /etc/suricata/rules
rule-files:
  - custom.rules

af-packet:
  - interface: INTERNAL_IFACE_PLACEHOLDER
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve-internal.json
      types:
        - alert
        - http
        - dns
        - smb
        - flow
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast-internal.log

app-layer:
  protocols:
    http:
      enabled: yes
    smb:
      enabled: yes
    dns:
      enabled: yes

logging:
  default-log-level: info
SURICONF

sed -i "s/INTERNAL_IFACE_PLACEHOLDER/${INT_IF}/" /etc/suricata/internal.yaml

# 启动双实例（DMZ + 内网）—— 先杀掉旧实例避免重复
pkill suricata 2>/dev/null; sleep 1
suricata -c /etc/suricata/dmz.yaml -D
suricata -c /etc/suricata/internal.yaml -D

echo "[+] Suricata 双实例已启动"
echo "    DMZ实例 eve:  /var/log/suricata/eve-dmz.json"
echo "    内网实例 eve: /var/log/suricata/eve-internal.json"
echo "    fast 日志:     /var/log/suricata/fast-*.log"
