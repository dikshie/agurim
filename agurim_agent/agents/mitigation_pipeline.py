"""Sequential Mitigation Pipeline: Rule Planner -> Safety Critic."""

from __future__ import annotations

import os
import warnings

from google.adk.agents import LlmAgent

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from google.adk.agents.sequential_agent import SequentialAgent

from agurim_agent.tools import render_firewall_rules

DEFAULT_MODEL = os.environ.get("AGURIM_AGENT_MODEL", "gemini-2.5-flash")

mitigation_planner = LlmAgent(
    name="MitigationPlanner",
    model=DEFAULT_MODEL,
    description="Drafts BGP Flowspec, Cisco ACL, and nftables rules for network threats.",
    instruction="""Based on flow analysis findings, draft surgical, effective mitigation rules:
1. Target the specific offending flow signature (IP prefix, protocol, and port).
2. Choose appropriate action:
   - 'rate_limit': Preferred for ambiguous or mixed traffic to prevent outage.
   - 'discard' / 'drop': Used for verified attack vectors with zero legitimate utility.
3. Call 'render_firewall_rules' to generate multi-vendor configurations.
4. Output the proposed configuration in a structured block.
""",
    tools=[render_firewall_rules],
    output_key="proposed_mitigation",
)

safety_critic = LlmAgent(
    name="SafetyCritic",
    model=DEFAULT_MODEL,
    description="Audits mitigation rules to ensure vital infrastructure is preserved.",
    instruction="""You are the Senior Network Reliability & Safety Auditor.
Inspect the proposed mitigation rules in {proposed_mitigation}:
1. MANDATORY SAFETY RULES:
   - Never allow blocking of default gateways or primary router interfaces.
   - Never allow dropping traffic to/from essential DNS resolvers or BGP peerings.
   - Reject overly broad CIDR blocks (/8 or /16) unless explicitly authorized.
   - If a proposed rule is too aggressive, modify it to a rate-limit instead of drop.
2. Certify the rules with a Risk Level rating (Low, Medium, High) and provide rollback commands.
""",
    output_key="certified_mitigation",
)

mitigation_safety_pipeline = SequentialAgent(
    name="MitigationSafetyPipeline",
    description=(
        "Executes a certified mitigation pipeline: drafts rules with MitigationPlanner, "
        "then audits them with SafetyCritic before final delivery."
    ),
    sub_agents=[mitigation_planner, safety_critic],
)
