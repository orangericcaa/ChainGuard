# B Node Evidence Index

> Host: B (Jump Host 1 — Langflow CVE-2025-3248)
> IP: 192.168.44.136 (dev) / 10.10.10.2 (production)
> Container: langflow (docker compose)

## Environment Baseline

| File | Description | Time | Command |
|---|---|---|---|
| [versions.txt](versions.txt) | OS, Docker, Git, auditd, Suricata versions | 2026-07-07 11:30 | `B0 environment check` |
| [service-health.txt](service-health.txt) | Container running, port binding, healthcheck OK | 2026-07-07 13:30 | `docker compose up -d; bash healthcheck.sh` |

## PoC Validation

| File | Description | Time | Command |
|---|---|---|---|
| [poc-success.txt](poc-success.txt) | 3 consecutive canary successes | 2026-07-07 14:47 | `python3 poc_check.py ... canary` ×3 |

### Container Environment (for P1 pivot integration)

See `python3 poc_check.py ... evidence` output:

```
hostname : 6a5bdd78fe9b
uid      : uid=1000(user) gid=0(root)
whoami   : user
pwd      : /app
HOME     : /app/data
IPs      : (bridge network)
```

Escape audit risk: **LOW** (score=0, no privileged, no docker.sock, seccomp/apparmor active)

## Network Detection

| File | Description | Time | Command |
|---|---|---|---|
| [network-alert.json](../../detections/network/network-alert.json) | EVE JSON alert (sid:2025001) triggered by PoC canary | 2026-07-07 15:17 | `poc_check.py canary` |
| [normal-traffic-negative.txt](../../detections/network/normal-traffic-negative.txt) | Normal POST to `/api/v1/validate/code` → 0 alerts | 2026-07-07 15:17 | `curl POST normal Python` |
| [langflow-cve-2025-3248.rules](../../detections/network/langflow-cve-2025-3248.rules) | Suricata detection rule | — | Suricata 6.0.4, pcap-live on Docker bridge |

## Host Detection

| File | Description | Time | Command |
|---|---|---|---|
| [host-alert.txt](../../detections/host/host-alert.txt) | PoC triggers canary detection (new file in overlay tmp) | 2026-07-07 15:47 | `sudo python3 host_monitor.py detect` |
| [host-normal.txt](../../detections/host/host-normal.txt) | Baseline snapshot — no anomalies during normal ops | 2026-07-07 15:47 | `sudo python3 host_monitor.py baseline` |
| [host_monitor.py](../../detections/host/host_monitor.py) | Self-written Python monitor (~230 lines) | — | `/proc` + overlay filesystem inspection |

## PCAP & Capture

- Not stored in Git (per workflow: PCAP, video, large files excluded)
- Suricata `eve.json` available at `/var/log/suricata/` on B VM
- VM snapshot: `langflow-baseline` (managed by P1)

## Verification Checklist

- [x] Langflow version pinned (1.2.0), image digest recorded
- [x] `docker compose up -d` → `bash healthcheck.sh` → exit 0
- [x] `docker compose restart` → healthcheck still passes
- [x] Port bound to `192.168.44.136:7860` only (not `0.0.0.0`)
- [x] PoC `check` → RCE confirmed
- [x] PoC `canary` ×3 → all succeed
- [x] PoC `evidence` → container info collected
- [x] PoC `escape-audit` → risk = LOW
- [x] Normal request → network detection: 0 alerts
- [x] PoC attack → network detection: ≥1 alert (sid:2025001)
- [x] Normal request → host detection: 0 anomalies
- [x] PoC attack → host detection: canary file detected
- [x] `cleanup` → canary files removed from container
- [x] `escape-audit` return non-zero for HIGH risk correctly documented
- [x] All evidence indexed with timestamps
- [x] No secrets, keys, PCAP, videos, or accounts in Git
