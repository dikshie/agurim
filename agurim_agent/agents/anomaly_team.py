"""Parallel Anomaly Diagnostic Team: Volume, Protocol Signature, Threat Intel."""

from __future__ import annotations

import os
import warnings

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from google.adk.agents import LlmAgent
        from google.adk.agents.parallel_agent import ParallelAgent
except ImportError:  # Fallback if google-adk is not installed in the environment
    class LlmAgent:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class ParallelAgent:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

from agurim_agent.tools import lookup_asn_and_threat

DEFAULT_MODEL = os.environ.get("AGURIM_AGENT_MODEL", "gemini-2.5-flash")

volume_analyst = LlmAgent(
    name="VolumeAnalyst",
    model=DEFAULT_MODEL,
    description="Analyzes traffic volume bursts, packet-to-byte ratios, and baseline spikes.",
    instruction="""Analyze traffic volume and burst patterns from Agurim flow data:
1. Examine BPS vs PPS ratios:
   - High PPS with low BPS indicates small-packet floods (SYN flood, UDP query floods).
   - High BPS with proportional PPS indicates large transfers or volumetric attacks.
2. Quantify burst magnitude and identify the primary spike flow.
""",
    output_key="volume_analysis",
)

proto_signature_analyst = LlmAgent(
    name="ProtoSignatureAnalyst",
    model=DEFAULT_MODEL,
    description="Inspects protocol and port signatures for DDoS amplification, scans, or abuse.",
    instruction="""Analyze protocol and port distributions from Agurim flow data:
1. Check for reflection/amplification vectors:
   - UDP 53 (DNS), 123 (NTP monlist), 389 (CLDAP), 1900 (SSDP).
2. Check for scanning or brute force behaviors:
   - TCP port 22 (SSH), 445 (SMB), 3389 (RDP) sweeps.
3. Classify traffic into: Legitimate Web/CDN, Background Noise, or Malicious Vector.
""",
    output_key="proto_analysis",
)

threat_intel_analyst = LlmAgent(
    name="ThreatIntelAnalyst",
    model=DEFAULT_MODEL,
    description="Enriches IP prefixes with Autonomous System (ASN) and CDN/cloud attribution.",
    instruction="""Analyze IP prefixes, ASNs, and organizational attribution:
1. Use 'lookup_asn_and_threat' to resolve top talker IP addresses and prefixes.
2. Classify source and destination subnets:
   - Hyper-scalers / CDNs (Cloudflare, Akamai, Google, Fastly, AWS).
   - Research networks (WIDE, SINET, GEANT).
   - High-risk hosting providers or unassigned address space.
""",
    tools=[lookup_asn_and_threat],
    output_key="threat_analysis",
)

# Parallel fan-out diagnostic team
parallel_anomaly_team = ParallelAgent(
    name="ParallelAnomalyTeam",
    description=(
        "Executes parallel multi-perspective analysis (Volume, Protocol Signature, "
        "and Threat Intel/ASN attribution) over flow data."
    ),
    sub_agents=[volume_analyst, proto_signature_analyst, threat_intel_analyst],
)
