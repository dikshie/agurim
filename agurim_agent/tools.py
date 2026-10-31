"""Tools for Agurim AI Agent ecosystem.

Provides functions to query Agurim HHH flow records, list datasets,
inspect network metadata (ASN/threat profiles), and generate mitigation rules.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_AGURIM = os.path.join(REPO_ROOT, "src", "agurim")
DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "data_dir")
SAMPLE_AGR = os.path.join(REPO_ROOT, "tests", "fixtures", "sample.agr")


KNOWN_PORTS: dict[int, dict[str, str]] = {
    22: {"service": "SSH", "proto": "tcp", "risk": "Remote admin / scanning target"},
    53: {"service": "DNS", "proto": "udp/tcp", "risk": "Amplification reflector vector"},
    80: {"service": "HTTP", "proto": "tcp", "risk": "Web traffic / HTTP flood"},
    123: {"service": "NTP", "proto": "udp", "risk": "High-factor monlist amplification"},
    389: {"service": "CLDAP", "proto": "udp", "risk": "CLDAP volumetric reflection"},
    443: {"service": "HTTPS/QUIC", "proto": "tcp/udp", "risk": "Encrypted web / TLS tunnel"},
    853: {"service": "DNS-over-TLS", "proto": "tcp", "risk": "Encrypted resolver queries"},
    1900: {"service": "SSDP", "proto": "udp", "risk": "SSDP UPnP reflection vector"},
    5353: {"service": "mDNS", "proto": "udp", "risk": "Local multicast reflection"},
}

KNOWN_PREFIXES: list[tuple[str, dict[str, str]]] = [
    ("10.0.0.0/8", {"asn": "RFC1918", "org": "Private Network", "type": "Internal"}),
    ("172.16.0.0/12", {"asn": "RFC1918", "org": "Private Network", "type": "Internal"}),
    ("192.168.0.0/16", {"asn": "RFC1918", "org": "Private Network", "type": "Internal"}),
    ("192.0.2.0/24", {"asn": "RFC5737", "org": "TEST-NET-1 (Documentation)", "type": "Test"}),
    ("198.51.100.0/24", {"asn": "RFC5737", "org": "TEST-NET-2 (Documentation)", "type": "Test"}),
    ("203.0.113.0/24", {"asn": "RFC5737", "org": "TEST-NET-3 (Documentation)", "type": "Test"}),
    ("1.1.1.0/24", {"asn": "AS13335", "org": "Cloudflare Public DNS", "type": "CDN/Anycast"}),
    ("8.8.8.0/24", {"asn": "AS15169", "org": "Google Public DNS", "type": "Cloud/Anycast"}),
    ("9.9.9.0/24", {"asn": "AS19281", "org": "Quad9 Anycast DNS", "type": "Resolver"}),
]


def list_datasets_and_ranges() -> dict[str, Any]:
    """Scan the Agurim repository and data directory to report available datasets,

    file hierarchies, and sample ranges.
    """
    data_dir = os.environ.get("AGURIM_DATA_DIR", DEFAULT_DATA_DIR)
    datasets = []

    if os.path.exists(data_dir) and os.path.isdir(data_dir):
        for item in sorted(os.listdir(data_dir)):
            full_p = os.path.join(data_dir, item)
            if os.path.isdir(full_p) and not item.startswith("."):
                agr_files = []
                for root, _, files in os.walk(full_p):
                    for f in files:
                        if f.endswith(".agr"):
                            agr_files.append(os.path.join(root, f))
                datasets.append(
                    {
                        "dataset": item,
                        "file_count": len(agr_files),
                        "path": full_p,
                    }
                )

    # Always include sample fixture if no datasets or for demonstration
    has_sample = os.path.exists(SAMPLE_AGR)
    return {
        "status": "success",
        "data_dir": data_dir,
        "datasets": datasets,
        "sample_fixture_available": has_sample,
        "sample_path": SAMPLE_AGR if has_sample else None,
    }


def query_agurim_flow_data(
    dataset: str = "sample",
    criteria: str = "byte",
    start_time: int = 0,
    end_time: int = 0,
    duration: int = 0,
    interval: int = 300,
    threshold: int = 1,
    nflows: int = 7,
    filter_spec: str = "",
    view: str = "",
) -> dict[str, Any]:
    """Query Agurim reaggregation engine to extract Hierarchical Heavy Hitter (HHH) flows.

    Args:
        dataset: Dataset name or 'sample' to query sample fixtures.
        criteria: 'byte' (default) or 'packet'.
        start_time: Unix timestamp start.
        end_time: Unix timestamp end.
        duration: Duration in seconds.
        interval: Aggregation interval in seconds (e.g. 300 for 5-minute slots).
        threshold: Heavy hitter cutoff percentage (1-100, default 1).
        nflows: Maximum flows in output (default 7).
        filter_spec: Optional filter: 'src dst' IPs or 'proto:sport:dport'.
        view: 'proto' for protocol/port priority, or '' for address priority.
    """
    agurim_bin = os.environ.get("AGURIM_BIN", SRC_AGURIM)
    if not os.path.exists(agurim_bin):
        # Fallback to PATH
        agurim_bin = "agurim"

    # Select target input files
    target_files: list[str] = []
    data_dir = os.environ.get("AGURIM_DATA_DIR", DEFAULT_DATA_DIR)
    ds_path = os.path.join(data_dir, dataset)

    if os.path.exists(ds_path) and os.path.isdir(ds_path):
        for root, _, files in os.walk(ds_path):
            for f in sorted(files):
                if f.endswith(".agr"):
                    target_files.append(os.path.join(root, f))

    if not target_files:
        # Fallback to sample fixture for testing & demonstrations
        if os.path.exists(SAMPLE_AGR):
            target_files = [SAMPLE_AGR]

    if not target_files:
        return {
            "status": "error",
            "message": (
                f"No .agr flow files found for dataset '{dataset}' "
                "and no sample fixture available."
            ),
        }

    # Construct agurim command flags
    cmd = [agurim_bin, "-p"]
    if criteria in ("byte", "packet"):
        cmd.extend(["-m", criteria])
    if interval > 0:
        cmd.extend(["-i", str(interval)])
    if threshold > 0:
        cmd.extend(["-t", str(threshold)])
    if nflows > 0:
        cmd.extend(["-n", str(nflows)])
    if start_time > 0:
        cmd.extend(["-S", str(start_time)])
    if end_time > 0:
        cmd.extend(["-E", str(end_time)])
    if duration > 0:
        cmd.extend(["-s", str(duration)])
    if view == "proto":
        cmd.append("-P")
    if filter_spec.strip():
        cmd.extend(["-f", filter_spec.strip()])

    cmd.extend(target_files)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return {
                "status": "error",
                "command": " ".join(cmd),
                "error": proc.stderr.strip() or proc.stdout.strip(),
            }

        stdout = proc.stdout.strip()
        try:
            parsed_json = json.loads(stdout)
            labels = parsed_json.get("labels", [])
            data_points = parsed_json.get("data", [])
            flow_names = [lbl for lbl in labels if lbl != "TOTAL"]
            return {
                "status": "success",
                "criteria": parsed_json.get("criteria", criteria),
                "duration": parsed_json.get("duration"),
                "start_time": parsed_json.get("start_time"),
                "end_time": parsed_json.get("end_time"),
                "interval": parsed_json.get("interval"),
                "nflows": parsed_json.get("nflows", len(flow_names)),
                "flows_count": len(flow_names),
                "flow_labels": flow_names,
                "data_points_count": len(data_points),
                "raw_data": data_points,
            }
        except json.JSONDecodeError:
            # Plain text fallback
            return {
                "status": "success",
                "format": "text",
                "output": stdout[:4000],
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def lookup_asn_and_threat(ip_or_prefix: str, port: int = 0) -> dict[str, Any]:
    """Look up network attribution, Autonomous System (ASN), and protocol risk

    for an IP address or prefix and associated port.
    """
    clean_ip = ip_or_prefix.strip().split()[0].split("/")[0]
    result: dict[str, Any] = {
        "query": ip_or_prefix,
        "clean_ip": clean_ip,
        "port": port,
        "is_private": False,
        "asn": "Unknown",
        "organization": "Unknown",
        "category": "Public / Unclassified",
        "port_profile": None,
    }

    # Match port profile
    if port in KNOWN_PORTS:
        result["port_profile"] = KNOWN_PORTS[port]

    # Validate IP address
    try:
        addr = ipaddress.ip_address(clean_ip)
        result["is_private"] = addr.is_private
        result["is_loopback"] = addr.is_loopback
        result["is_multicast"] = addr.is_multicast

        # Check against known table
        for cidr, meta in KNOWN_PREFIXES:
            net = ipaddress.ip_network(cidr)
            if addr in net:
                result["asn"] = meta["asn"]
                result["organization"] = meta["org"]
                result["category"] = meta["type"]
                break

        # Attempt PTR reverse DNS if unresolved
        if result["organization"] == "Unknown":
            try:
                host, _, _ = socket.gethostbyaddr(clean_ip)
                result["reverse_dns"] = host
            except (socket.herror, OSError):
                result["reverse_dns"] = None
    except ValueError:
        result["error"] = f"Invalid IP format: {clean_ip}"

    return result


def render_firewall_rules(
    flow_spec: str,
    action: str = "rate_limit",
    rate_mbps: int = 10,
    protocol: str = "",
    port: int = 0,
) -> dict[str, Any]:
    """Generate multi-vendor mitigation rules (BGP Flowspec RFC 8955, Cisco/Juniper ACL,

    Linux nftables, and iptables) for a target flow.
    """
    action_type = "rate-limit" if action == "rate_limit" else "discard"
    clean_flow = flow_spec.strip()

    # Extract source / dest if in format 'src dst'
    parts = clean_flow.split()
    src_ip = parts[0] if parts else "any"
    dst_ip = parts[1] if len(parts) > 1 else "any"

    # 1. BGP Flowspec (RFC 8955)
    flowspec_lines = [
        "flow route {",
        "    match {",
    ]
    if src_ip != "any":
        flowspec_lines.append(f"        source {src_ip};")
    if dst_ip != "any":
        flowspec_lines.append(f"        destination {dst_ip};")
    if protocol:
        flowspec_lines.append(f"        protocol {protocol};")
    if port > 0:
        flowspec_lines.append(f"        port {port};")
    flowspec_lines.append("    }")
    flowspec_lines.append("    then {")
    if action_type == "rate-limit":
        flowspec_lines.append(f"        rate-limit {rate_mbps * 125000}; /* {rate_mbps} Mbps */")
    else:
        flowspec_lines.append("        discard;")
    flowspec_lines.append("    }")
    flowspec_lines.append("}")
    flowspec_rule = "\n".join(flowspec_lines)

    # 2. Linux nftables
    nft_proto = f"{protocol} " if protocol else "ip "
    nft_port = f"dport {port} " if port > 0 else ""
    nft_src = f"ip saddr {src_ip} " if src_ip != "any" else ""
    nft_dst = f"ip daddr {dst_ip} " if dst_ip != "any" else ""
    nft_action = (
        f"limit rate over {rate_mbps} mbytes/second drop" if action_type == "rate-limit" else "drop"
    )
    nft_rule = f"nft add rule inet filter input {nft_src}{nft_dst}{nft_proto}{nft_port}{nft_action}"

    # 3. Cisco IOS Extended ACL
    cisco_proto = protocol if protocol else "ip"
    cisco_src = f"host {src_ip}" if "/" not in src_ip and src_ip != "any" else src_ip
    cisco_dst = f"host {dst_ip}" if "/" not in dst_ip and dst_ip != "any" else dst_ip
    cisco_port = f" eq {port}" if port > 0 else ""
    cisco_act = "permit" if action_type == "rate-limit" else "deny"
    cisco_rule = f"access-list 150 {cisco_act} {cisco_proto} {cisco_src} {cisco_dst}{cisco_port}"

    return {
        "status": "success",
        "target": clean_flow,
        "action": action_type,
        "rate_mbps": rate_mbps if action_type == "rate-limit" else 0,
        "bgp_flowspec": flowspec_rule,
        "nftables": nft_rule,
        "cisco_acl": cisco_rule,
    }


def analyze_traffic_spikes(
    dataset: str = "sample",
    suspect_time: int = 0,
    window_seconds: int = 3600,
) -> dict[str, Any]:
    """Compare traffic in a suspect window against baseline to detect surges and anomalous flows."""
    current_data = query_agurim_flow_data(
        dataset=dataset,
        start_time=suspect_time,
        duration=window_seconds,
        interval=300,
    )
    if current_data.get("status") != "success":
        return current_data

    labels = current_data.get("flow_labels", [])
    raw_data = current_data.get("raw_data", [])

    # Compute total bytes and peak slot from raw_data
    peak_val = 0.0
    for row in raw_data:
        # row: [timestamp, f1, f2, ..., total]
        if len(row) > 1:
            total_val = row[-1]
            if total_val > peak_val:
                peak_val = float(total_val)

    return {
        "status": "success",
        "suspect_time": suspect_time,
        "window_seconds": window_seconds,
        "top_flows_identified": labels[:5],
        "peak_slot_rate": peak_val,
        "total_flows": len(labels),
        "surge_detected": peak_val > 0,
    }
