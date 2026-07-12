# 课题三 快速重置手册

## 场景一：VM 快照回滚（最快，推荐）

```bash
# VMware Workstation
# 右键 VM → 快照 → 恢复到 "baseline-imported"
# 4 台 VM 全部恢复 → 重新执行部署脚本
```

---

## 场景二：仅重置检测服务（不恢复 VM）

在 VM1 Gateway 上执行：

```bash
# 1. 停止所有检测进程
pkill -f traffic_analyzer.py
pkill -f log_aggregator.py
suricatasc -c shutdown 2>/dev/null || true

# 2. 清空日志
> /var/log/lab3/events.jsonl
> /var/log/suricata/fast-dmz.log
> /var/log/suricata/fast-internal.log
> /var/log/suricata/eve-dmz.json
> /var/log/suricata/eve-internal.json

# 3. 清空 iptables 自定义规则（保留基础规则）
iptables -F INPUT   # 谨慎！
iptables -F FORWARD
# 重新加载规则
bash /opt/lab3/infra/gateway/iptables_setup.sh

# 4. 重启 Suricata
suricata -c /etc/suricata/dmz.yaml -D
suricata -c /etc/suricata/internal.yaml -D

# 5. 重启检测服务
cd /opt/lab3
nohup python3 traffic_analyzer.py > /var/log/lab3/traffic_analyzer.log 2>&1 &
nohup python3 log_aggregator.py > /var/log/lab3/log_aggregator.log 2>&1 &
```

在 VM2 上：
```bash
pkill -f host_monitor.py; pkill -f web_honeypot.py
bash /opt/lab3/honeypot_reset.sh web
nohup python3 /opt/lab3/host_monitor.py > /var/log/lab3/host_monitor.log 2>&1 &
```

在 VM3 上：
```bash
pkill -f host_monitor.py; pkill -f honeypot_enricher.py
bash /opt/lab3/honeypot_reset.sh cowrie
nohup python3 /opt/lab3/host_monitor.py > /var/log/lab3/host_monitor.log 2>&1 &
```

在 VM4 上：
```bash
pkill -f host_monitor.py; pkill -f db_honeypot.py
bash /opt/lab3/honeypot_reset.sh db
nohup python3 /opt/lab3/host_monitor.py > /var/log/lab3/host_monitor.log 2>&1 &
```

---

## 场景三：完全重新部署

```bash
# VM1 上执行一键部署
cd /opt/lab3
bash deploy_all.sh
```

---

## 场景四：蜜罐定时重置（cron）

在 VM3 上添加 cron：
```bash
crontab -e
# 添加：
# 0 */2 * * * bash /opt/lab3/detections/honeypot/honeypot_reset.sh cowrie
# 每小时重置一次蜜罐
```
