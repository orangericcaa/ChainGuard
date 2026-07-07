# Langflow Lab — B Node (Jump Host 1)

CVE-2025-3248 vulnerable lab for ChainGuard attack-defense experiment.

## Version

| Component | Version | Notes |
|---|---|---|
| Langflow | 1.2.0 | Vulnerable (< 1.3.0) |
| Docker image | `langflowai/langflow:1.2.0` | Pinned, no `latest` |
| Image digest | `sha256:1e9cfdb0e1565b1187bdd3c6849493ecbd81627645214ab0537d7cbcdbdb454a` | Immutable ref |

## Prerequisites

- Docker 20.10+ & Compose v2
- Python 3.8+ with `requests` module
- Suricata 6.0+ (for network detection)
- auditd (alternative: `host_monitor.py` for host detection)

## Quick Start

```bash
cp .env.example .env
docker compose up -d
bash healthcheck.sh
```

## Full Deployment (from Baseline VM Snapshot)

### 1. Service Deploy

```bash
cd ~/chainguard-lab/labs/langflow
cp .env.example .env
docker compose up -d
bash healthcheck.sh              # verify → [OK]
```

### 2. Network Detection (Suricata)

```bash
# Install rule
sudo cp detections/network/langflow-cve-2025-3248.rules /etc/suricata/rules/local.rules

# Register in suricata.yaml under rule-files:
#   rule-files:
#     - local.rules

# Find Langflow-bound interface
IFACE=$(ip -br addr | grep '192.168.44.136\|10.10.10.2' | awk '{print $1}')
# OR use Docker bridge:
IFACE=$(ip -br link | grep -oP 'br-[0-9a-f]+' | head -1)

# Start Suricata (pcap-live mode, not af-packet)
sudo suricata -c /etc/suricata/suricata.yaml -i $IFACE -D

# Verify rule loaded
suricata -T -c /etc/suricata/suricata.yaml -i $IFACE 2>&1 | grep -i "loaded\|failed"
```

### 3. Host Behavior Detection

```bash
cd ~/chainguard-lab/detections/host

# Capture clean baseline
sudo python3 host_monitor.py baseline

# Run detection (triggers PoC, compares snapshot)
sudo python3 host_monitor.py detect
```

Note: `host_monitor.py` requires root to read Docker overlay filesystem.

### 4. PoC Validation

```bash
cd ~/chainguard-lab/labs/langflow

# Probe RCE
python3 poc_check.py --target 192.168.44.136 --port 7860 check

# Deploy canary ×3
for i in 1 2 3; do python3 poc_check.py --target 192.168.44.136 canary; done

# Collect environment evidence
python3 poc_check.py --target 192.168.44.136 evidence

# Escape audit (read-only assessment)
python3 poc_check.py --target 192.168.44.136 escape-audit

# Test C-node reachability
python3 poc_check.py --target 192.168.44.136 reach-c --next-hop 10.20.20.2 --next-hop-port 22

# Cleanup
python3 poc_check.py --target 192.168.44.136 cleanup
```

### 5. Stop & Reset

```bash
docker compose down
sudo pkill suricata
rm -rf /tmp/b4-baseline
```

## Network Binding

> **IMPORTANT**: The service is currently bound to `192.168.44.136` for development.
> After the lab network `10.10.10.0/24` is provisioned by P1:
> 1. Change `compose.yml` port binding to `10.10.10.2:7860:7860`
> 2. Update `ALLOWED_TARGETS` in `poc_check.py` (remove 192.168.44.136)
> 3. Update `healthcheck.sh` TARGET variable
> 4. Restart: `docker compose down && docker compose up -d`

## Structure

```
labs/langflow/
├── compose.yml           # Docker Compose (pinned 1.2.0)
├── .env.example          # Env template (no secrets)
├── .env                  # Active config (.gitignored)
├── healthcheck.sh        # Health check → exit 0/1
├── poc_check.py          # 6 subcommand exploit validator
└── README.md             # This file

detections/
├── network/
│   ├── langflow-cve-2025-3248.rules   # Suricata alert rule (sid:2025001)
│   ├── network-alert.json             # PoC-triggered EVE event
│   └── normal-traffic-negative.txt    # Normal request = 0 alerts
└── host/
    ├── host_monitor.py                # Self-written Python monitor
    ├── host-alert.txt                 # PoC detection evidence
    └── host-normal.txt                # Baseline / normal ops evidence
```

## Test Matrix

| ID | Test | Command | Expected |
|---|---|---|---|
| T01 | Service healthy | `bash healthcheck.sh` | exit 0 |
| T02 | PoC RCE confirmed | `python3 poc_check.py ... check` | exit 0 |
| T03 | Canary ×3 stable | `python3 poc_check.py ... canary` ×3 | 3 successes |
| T04 | Network alert triggered | PoC → `grep sid:2025001 eve.json` | ≥1 match |
| T05 | Normal traffic no alert | POST normal code | 0 matches |
| T06 | Host monitor detects canary | `sudo python3 host_monitor.py detect` | exit 0, canary_match=true |
| T07 | Baseline no false positive | Normal request on baseline | 0 anomalies |
| T08 | Service restart recover | `docker compose restart` → healthcheck | exit 0 |
