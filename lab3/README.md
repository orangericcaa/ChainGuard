# lab3 — 攻击行为全方位检测与捕获技术综合实验

## 目录结构

```
lab3/
├── deploy_all.sh              # 一键总部署脚本
├── contracts/                 # 事件契约 + 拓扑配置
├── infra/                     # 各节点部署脚本
├── services/                  # Docker Compose 富化服务
├── detections/                # 核心检测代码
│   ├── network/               # 网络流量检测
│   ├── host/                  # 主机行为检测
│   ├── honeypot/              # 蜜罐系统
│   └── trace/                 # 攻击溯源
├── attack-sim/                # 攻击模拟脚本
├── aggregator/               # 日志汇聚服务
└── runbooks/                  # 演示 + 重置手册
```

## 涉及的 VM 与文件对应

| VM | 需部署的文件 |
|----|-------------|
| VM1 Gateway | infra/gateway/*, detections/network/*, detections/trace/*, aggregator/*, attack-sim/* |
| VM2 Web | infra/web-server/*, detections/host/*, detections/honeypot/web_honeypot.py, services/wordpress/* |
| VM3 DB | infra/db-server/*, detections/host/*, detections/honeypot/cowrie_setup.sh, detections/honeypot/honeypot_enricher.py, detections/honeypot/honeypot_reset.sh, services/nextcloud/* |
| VM4 WS | infra/workstation/*, detections/host/*, detections/honeypot/db_honeypot.py, detections/honeypot/honeypot_reset.sh |
| 攻击机(宿主机) | 通过 SSH 到 VM1 并执行 VM1 上的 attack_simulator.sh |

## 使用方式

1. 将整个 lab3/ 目录通过 scp 或 U 盘分发到各 VM
2. 在每台 VM 上进入对应子目录，以 root 执行部署脚本
3. 或者：在 VM1 上执行 `bash deploy_all.sh` 统一分发+部署
