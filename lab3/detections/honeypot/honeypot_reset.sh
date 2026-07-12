#!/bin/bash
# honeypot_reset.sh — 全部蜜罐自动恢复脚本
# 可部署在 VM3 或 VM4 上，也支持定时任务
# 用法: sudo bash honeypot_reset.sh [web|db|cowrie|all]
set -e

MODE="${1:-all}"
TIMESTAMP=$(date -Iseconds)
LOG_FILE="/var/log/lab3/honeypot_reset.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$TIMESTAMP] $1" | tee -a "$LOG_FILE"
}

reset_web() {
    log "重置 Web蜜罐..."
    systemctl stop web-honeypot 2>/dev/null || true
    pkill -f web_honeypot.py 2>/dev/null || true
    rm -rf /opt/lab3/web_honeypot/uploads/*
    rm -f /opt/lab3/web_honeypot/honeypot.db
    python3 -c "import sqlite3; sqlite3.connect('/opt/lab3/web_honeypot/honeypot.db').execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, ts TEXT, method TEXT, path TEXT, full_url TEXT, src_ip TEXT, user_agent TEXT, headers TEXT, body TEXT, cookies TEXT, is_attack INTEGER DEFAULT 0, attack_type TEXT)').close()" 2>/dev/null || true
    nohup python3 /opt/lab3/web_honeypot.py > /var/log/lab3/web_honeypot.log 2>&1 &
    log "Web蜜罐已重置并重启"
}

reset_db() {
    log "重置 DB蜜罐..."
    pkill -f db_honeypot.py 2>/dev/null || true
    nohup python3 /opt/lab3/db_honeypot.py > /var/log/lab3/db_honeypot.log 2>&1 &
    log "DB蜜罐已重置并重启"
}

reset_cowrie() {
    log "重置 Cowrie SSH蜜罐..."
    if [ -d /opt/cowrie ]; then
        cd /opt/cowrie
        docker-compose restart 2>/dev/null || {
            pkill -f "bin/cowrie" 2>/dev/null || true
            nohup python3 bin/cowrie start > /var/log/lab3/cowrie.log 2>&1 &
        }
    fi
    pkill -f honeypot_enricher.py 2>/dev/null || true
    nohup python3 /opt/lab3/honeypot_enricher.py > /var/log/lab3/honeypot_enricher.log 2>&1 &
    log "Cowrie蜜罐已重置并重启"
}

case "$MODE" in
    web)
        reset_web
        ;;
    db)
        reset_db
        ;;
    cowrie)
        reset_cowrie
        ;;
    all)
        log "====== 全部蜜罐重置 ======"
        reset_web
        reset_db
        reset_cowrie
        log "====== 重置完成 ======"
        ;;
    *)
        echo "用法: $0 [web|db|cowrie|all]"
        exit 1
        ;;
esac

# 如果以 cron 运行，同时写入 JSONL 事件
echo '{"event_id":"'$(uuidgen 2>/dev/null || echo "reset-"$(date +%s))'","ts":"'"${TIMESTAMP}"'","host":"local","detector":"honeypot_reset","layer":"honeypot","severity":"info","message":"蜜罐自动恢复完成 (mode='"'${MODE}'"'')","action_taken":"reset"}' >> /var/log/lab3/events.jsonl
