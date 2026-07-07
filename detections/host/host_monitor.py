#!/usr/bin/env python3
"""
ChainGuard B4 — Host Behavior Detection (Self-written monitor)
Monitors Langflow container for:
  1. Anomalous child processes (execve equivalent)
  2. Canary file creation in container /tmp

Since auditd cannot trace syscalls across PID namespaces on this system,
this tool uses /proc inspection and Docker overlay filesystem checks.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple


CONTAINER = "langflow"
OVERLAY_BASE = "/var/lib/docker/overlay2"


def emit_jsonl(kind: str, severity: str, message: str,
               details: Optional[dict] = None) -> dict:
    record = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "B",
        "tool": "host_monitor",
        "kind": kind,
        "severity": severity,
        "message": message,
        "details": details or {},
    }
    print(json.dumps(record))
    return record


def get_merged_dir() -> str:
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format",
         "{{.GraphDriver.Data.MergedDir}}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        sys.exit(f"[FATAL] Cannot inspect container: {result.stderr}")
    return result.stdout.strip()


def get_container_pids() -> List[int]:
    """Get all process PIDs inside the container."""
    result = subprocess.run(
        ["docker", "top", CONTAINER, "-eo", "pid"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return []
    pids = []
    for line in result.stdout.strip().split("\n")[1:]:
        try:
            pids.append(int(line.strip()))
        except ValueError:
            pass
    return pids


def snapshot_process_tree(pids: List[int]) -> Dict[int, Dict]:
    """Capture current process tree for given PIDs and their children."""
    tree = {}
    all_pids = set(pids)
    # Also capture children
    for pid in list(all_pids):
        try:
            task_dir = f"/proc/{pid}/task/{pid}/children"
            if os.path.exists(task_dir):
                with open(task_dir) as f:
                    children = f.read().strip().split()
                    for c in children:
                        all_pids.add(int(c))
        except (OSError, ValueError):
            pass

    for pid in all_pids:
        try:
            cmdline = "unknown"
            cmdline_path = f"/proc/{pid}/cmdline"
            if os.path.exists(cmdline_path):
                with open(cmdline_path) as f:
                    cmdline = f.read().replace("\0", " ").strip()
            tree[pid] = {"pid": pid, "cmdline": cmdline[:200]}
        except OSError:
            pass
    return tree


def snapshot_tmp_files(merged: str) -> Dict[str, int]:
    """Snapshot files in container /tmp with mtime."""
    tmp_path = os.path.join(merged, "tmp")
    snap = {}
    try:
        for name in os.listdir(tmp_path):
            fpath = os.path.join(tmp_path, name)
            try:
                snap[name] = int(os.path.getmtime(fpath))
            except OSError:
                snap[name] = 0
    except OSError:
        pass
    return snap


def run_command(action: str) -> Tuple[int, str]:
    """Run the specified validation action."""
    poc_dir = "/home/chenshuhua/chainguard-lab/labs/langflow"
    poc = os.path.join(poc_dir, "poc_check.py")
    if not os.path.exists(poc):
        return 1, f"poc_check.py not found at {poc}"

    result = subprocess.run(
        ["python3", poc, "--target", "192.168.44.136", "--port", "7860", action],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode, result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ChainGuard B4 — Host Behavior Monitor (Langflow container)"
    )
    subp = parser.add_subparsers(dest="command", required=True)

    baseline_p = subp.add_parser("baseline", help="Capture baseline (process tree + /tmp state)")
    baseline_p.add_argument("--baseline-dir", default="/tmp/b4-baseline",
                            help="Dir for baseline snapshots")

    detect = subp.add_parser("detect", help="Run canary attack and detect anomalies")
    detect.add_argument("--baseline-dir", default="/tmp/b4-baseline",
                        help="Dir where baseline snapshots are stored")

    clean = subp.add_parser("cleanup", help="Remove baseline files")

    args = parser.parse_args()

    if args.command == "baseline":
        merged = get_merged_dir()
        pids = get_container_pids()
        if not pids:
            emit_jsonl("baseline", "critical", "No container PIDs found")
            sys.exit(1)

        emit_jsonl("baseline", "info",
                   f"Capturing baseline: {len(pids)} PIDs, merged={merged}",
                   {"container_pids": pids[:20]})

        procs = snapshot_process_tree(pids)
        tmp_files = snapshot_tmp_files(merged)

        baseline = {
            "merged_dir": merged,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processes": {str(k): v for k, v in procs.items()},
            "tmp_files": {k: v for k, v in tmp_files.items()},
        }

        os.makedirs(args.baseline_dir, exist_ok=True)
        path = os.path.join(args.baseline_dir, "baseline.json")
        with open(path, "w") as f:
            json.dump(baseline, f, indent=2)

        emit_jsonl("baseline", "high",
                   f"Baseline saved: {len(procs)} processes, {len(tmp_files)} tmp files",
                   {"baseline_path": path})
        sys.exit(0)

    elif args.command == "detect":
        # Load baseline
        baseline_path = os.path.join(args.baseline_dir, "baseline.json")
        if not os.path.exists(baseline_path):
            emit_jsonl("detect", "critical",
                       "No baseline found. Run 'baseline' first.")
            sys.exit(1)

        with open(baseline_path) as f:
            baseline = json.load(f)

        baseline_procs = baseline["processes"]
        baseline_tmp = baseline.get("tmp_files", {})
        if isinstance(baseline_tmp, list):
            # migrate old format
            baseline_tmp = {f: 0 for f in baseline_tmp}

        merged = get_merged_dir()

        emit_jsonl("detect", "info", "Running canary attack to trigger anomalies")
        exit_code, output = run_command("canary")

        time.sleep(2)

        # Post-attack snapshots
        current_pids = get_container_pids()
        current_procs = snapshot_process_tree(current_pids)

        # Compare process trees
        old_pids = set(int(k) for k in baseline_procs.keys())
        new_pids = set(current_procs.keys()) - old_pids

        findings = []

        new_processes = []
        for pid in new_pids:
            cmd = current_procs.get(pid, {}).get("cmdline", "?")
            new_processes.append(f"PID {pid}: {cmd}")
        if new_processes:
            findings.append(f"New child processes detected: {new_processes}")

        # Compare /tmp files (new + modified)
        current_tmp = snapshot_tmp_files(merged)
        new_tmp_files = set(current_tmp.keys()) - set(baseline_tmp.keys())
        modified_tmp = set()
        for fname in set(current_tmp.keys()) & set(baseline_tmp.keys()):
            if current_tmp[fname] > baseline_tmp[fname] + 1:
                modified_tmp.add(fname)
        changed_tmp = new_tmp_files | modified_tmp

        if changed_tmp:
            findings.append(f"Changed/new files in container /tmp: {list(changed_tmp)}")

        canary_files = [f for f in changed_tmp if f.startswith("poc-")]
        if canary_files:
            findings.append(f"Canary indicator file(s) detected: {canary_files}")

        details = {
            "baseline_process_count": len(baseline_procs),
            "current_process_count": len(current_procs),
            "new_process_count": len(new_pids),
            "baseline_tmp_count": len(baseline_tmp),
            "current_tmp_count": len(current_tmp),
            "new_tmp_count": len(new_tmp_files),
            "modified_tmp_count": len(modified_tmp),
            "new_processes": new_processes[:10],
            "changed_tmp_files": list(changed_tmp),
            "canary_match": bool(canary_files),
        }

        if new_pids or canary_files:
            severity = "high"
            msg = f"Anomalies detected: {len(findings)} finding(s) — {findings}"
            exit_rc = 0
        elif changed_tmp:
            severity = "low"
            msg = f"Minor /tmp change: {list(changed_tmp)}"
            exit_rc = 0
        else:
            severity = "info"
            msg = "No anomalies detected between baseline and post-attack"
            exit_rc = 1

        emit_jsonl("detect", severity, msg, details)

        print(f"\n=== Host Behavior Detection ===", file=sys.stderr)
        print(f"  Baseline processes : {len(baseline_procs)}", file=sys.stderr)
        print(f"  Current  processes : {len(current_procs)}", file=sys.stderr)
        print(f"  New processes      : {len(new_pids)}", file=sys.stderr)
        for p in new_processes[:5]:
            print(f"    + {p}", file=sys.stderr)
        print(f"  Baseline /tmp files: {len(baseline_tmp)}", file=sys.stderr)
        print(f"  Current  /tmp files: {len(current_tmp)}", file=sys.stderr)
        print(f"  New files          : {len(new_tmp_files)}", file=sys.stderr)
        for f in new_tmp_files:
            print(f"    + {f}", file=sys.stderr)
        print(f"  Modified files     : {len(modified_tmp)}", file=sys.stderr)
        for f in modified_tmp:
            print(f"    ~ {f}", file=sys.stderr)
        print(f"  Canary match       : {bool(canary_files)}", file=sys.stderr)
        print(f"  Result             : {msg}", file=sys.stderr)
        print("==================================", file=sys.stderr)

        sys.exit(exit_rc)

    elif args.command == "cleanup":
        import shutil
        if os.path.exists(args.baseline_dir):
            shutil.rmtree(args.baseline_dir)
        emit_jsonl("cleanup", "info", f"Baseline directory removed: {args.baseline_dir}")
        sys.exit(0)


if __name__ == "__main__":
    main()
