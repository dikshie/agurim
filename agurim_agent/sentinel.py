"""Autonomous Sentinel Watchdog for Agurim.

Monitors incoming flow records, executes multi-agent anomaly diagnostics
when bursts are detected, and records structured incident reports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Any

from agurim_agent.tools import (
    DEFAULT_DATA_DIR,
    analyze_traffic_spikes,
    lookup_asn_and_threat,
    render_firewall_rules,
)


def run_sentinel_scan(
    dataset: str = "sample",
    threshold_rate: float = 10000000.0,
    alerts_file: str | None = None,
) -> dict[str, Any]:
    """Execute a single sentinel scan pass across recent flows."""
    timestamp = int(time.time())
    scan_result: dict[str, Any] = {
        "timestamp": timestamp,
        "datetime": datetime.fromtimestamp(timestamp).isoformat(),
        "dataset": dataset,
        "status": "normal",
        "incidents": [],
    }

    spike_check = analyze_traffic_spikes(dataset=dataset, suspect_time=0, window_seconds=3600)
    peak_rate = spike_check.get("peak_slot_rate", 0.0)
    top_flows = spike_check.get("top_flows_identified", [])

    if peak_rate >= threshold_rate and top_flows:
        scan_result["status"] = "anomaly_detected"
        primary_flow = top_flows[0]

        # Extract IP and port if possible
        threat_meta = None
        mitigation = None
        parts = primary_flow.split()
        candidate_ip = None
        candidate_port = 0

        for part in parts:
            if "." in part and "/" not in part and not part.startswith("["):
                candidate_ip = part.strip()
                break

        if candidate_ip:
            threat_meta = lookup_asn_and_threat(candidate_ip, port=candidate_port)
            mitigation = render_firewall_rules(
                candidate_ip,
                action="rate_limit",
                rate_mbps=10,
                port=candidate_port,
            )

        incident = {
            "id": f"inc-{timestamp}",
            "severity": "HIGH" if peak_rate > (threshold_rate * 2) else "MEDIUM",
            "peak_rate_bytes": peak_rate,
            "threshold_bytes": threshold_rate,
            "offending_flow": primary_flow,
            "threat_profile": threat_meta,
            "recommended_mitigation": mitigation,
        }
        scan_result["incidents"].append(incident)

    # Persist alert if file provided
    if alerts_file and scan_result["incidents"]:
        os.makedirs(os.path.dirname(os.path.abspath(alerts_file)), exist_ok=True)
        existing_alerts = []
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, encoding="utf-8") as f:
                    existing_alerts = json.load(f)
            except Exception:
                existing_alerts = []
        existing_alerts.append(scan_result)
        with open(alerts_file, "w", encoding="utf-8") as f:
            json.dump(existing_alerts, f, indent=2)

    return scan_result


def main():
    parser = argparse.ArgumentParser(description="Agurim Sentinel Autonomous Watchdog")
    parser.add_argument("--dataset", default="sample", help="Dataset name to monitor")
    parser.add_argument(
        "--threshold",
        type=float,
        default=20000000.0,
        help="Rate threshold in bytes/slot (default: 20MB)",
    )
    parser.add_argument(
        "--alerts-file",
        default=os.path.join(DEFAULT_DATA_DIR, "alerts.json"),
        help="Path to alerts JSON log",
    )
    parser.add_argument("--once", action="store_true", help="Run once and exit instead of loop")
    parser.add_argument("--interval", type=int, default=60, help="Loop interval in seconds")

    args = parser.parse_args()
    print(f"[*] Agurim Sentinel active for dataset: {args.dataset}")
    print(f"[*] Anomaly threshold: {args.threshold} bytes/slot")

    if args.once:
        res = run_sentinel_scan(
            dataset=args.dataset,
            threshold_rate=args.threshold,
            alerts_file=args.alerts_file,
        )
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["status"] == "normal" else 1)

    try:
        while True:
            res = run_sentinel_scan(
                dataset=args.dataset,
                threshold_rate=args.threshold,
                alerts_file=args.alerts_file,
            )
            now_str = datetime.now().strftime("%H:%M:%S")
            inc_cnt = len(res["incidents"])
            print(f"[{now_str}] Sentinel: {res['status']} ({inc_cnt} incidents)")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopping sentinel.")


if __name__ == "__main__":
    main()
