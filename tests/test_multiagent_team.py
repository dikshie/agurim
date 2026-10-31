"""Comprehensive tests for Agurim Multi-Agent System using Google ADK."""

from __future__ import annotations

import unittest

from agurim_agent.agent import root_agent, run_agent_query
from agurim_agent.agents.anomaly_team import (
    parallel_anomaly_team,
    proto_signature_analyst,
    threat_intel_analyst,
    volume_analyst,
)
from agurim_agent.agents.data_engineer import data_engineer_agent
from agurim_agent.agents.mitigation_pipeline import (
    mitigation_planner,
    mitigation_safety_pipeline,
    safety_critic,
)
from agurim_agent.sentinel import run_sentinel_scan
from agurim_agent.tools import (
    analyze_traffic_spikes,
    list_datasets_and_ranges,
    lookup_asn_and_threat,
    query_agurim_flow_data,
    render_firewall_rules,
)


class TestAgurimTools(unittest.TestCase):
    def test_list_datasets_and_ranges(self):
        res = list_datasets_and_ranges()
        self.assertEqual(res["status"], "success")
        self.assertIn("datasets", res)
        self.assertTrue(res["sample_fixture_available"])

    def test_query_agurim_flow_data_sample(self):
        res = query_agurim_flow_data(dataset="sample", criteria="byte", interval=300)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["criteria"], "byte")
        self.assertGreater(res["flows_count"], 0)
        self.assertTrue(any("192.0.2.1" in lbl for lbl in res["flow_labels"]))

    def test_lookup_asn_and_threat(self):
        # Test RFC 5737 doc IP
        res = lookup_asn_and_threat("192.0.2.1", port=443)
        self.assertEqual(res["clean_ip"], "192.0.2.1")
        self.assertEqual(res["asn"], "RFC5737")
        self.assertIsNotNone(res["port_profile"])
        self.assertEqual(res["port_profile"]["service"], "HTTPS/QUIC")

        # Test DNS port
        dns_res = lookup_asn_and_threat("8.8.8.8", port=53)
        self.assertEqual(dns_res["asn"], "AS15169")
        self.assertIn("DNS", dns_res["port_profile"]["service"])

    def test_render_firewall_rules(self):
        rules = render_firewall_rules(
            "192.0.2.1 198.51.100.1",
            action="rate_limit",
            rate_mbps=15,
            protocol="tcp",
            port=443,
        )
        self.assertEqual(rules["status"], "success")
        self.assertIn("flow route {", rules["bgp_flowspec"])
        self.assertIn("rate-limit", rules["bgp_flowspec"])
        self.assertIn("source 192.0.2.1", rules["bgp_flowspec"])
        self.assertIn("destination 198.51.100.1", rules["bgp_flowspec"])
        self.assertIn("nft add rule", rules["nftables"])
        self.assertIn("access-list 150", rules["cisco_acl"])

    def test_analyze_traffic_spikes(self):
        spike = analyze_traffic_spikes(dataset="sample")
        self.assertEqual(spike["status"], "success")
        self.assertGreater(spike["peak_slot_rate"], 0)
        self.assertTrue(spike["surge_detected"])


class TestMultiAgentArchitecture(unittest.TestCase):
    def test_data_engineer_agent_config(self):
        self.assertEqual(data_engineer_agent.name, "AgurimDataEngineer")
        self.assertIn("query and extract Agurim flow data", data_engineer_agent.instruction)
        self.assertEqual(len(data_engineer_agent.tools), 2)

    def test_parallel_anomaly_team_structure(self):
        self.assertEqual(parallel_anomaly_team.name, "ParallelAnomalyTeam")
        sub_names = [a.name for a in parallel_anomaly_team.sub_agents]
        self.assertEqual(
            sub_names, ["VolumeAnalyst", "ProtoSignatureAnalyst", "ThreatIntelAnalyst"]
        )
        self.assertEqual(volume_analyst.output_key, "volume_analysis")
        self.assertEqual(proto_signature_analyst.output_key, "proto_analysis")
        self.assertEqual(threat_intel_analyst.output_key, "threat_analysis")

    def test_mitigation_safety_pipeline_structure(self):
        self.assertEqual(mitigation_safety_pipeline.name, "MitigationSafetyPipeline")
        sub_names = [a.name for a in mitigation_safety_pipeline.sub_agents]
        self.assertEqual(sub_names, ["MitigationPlanner", "SafetyCritic"])
        self.assertEqual(mitigation_planner.output_key, "proposed_mitigation")
        self.assertEqual(safety_critic.output_key, "certified_mitigation")

    def test_root_coordinator_config(self):
        self.assertEqual(root_agent.name, "AgurimNocCoordinator")
        tool_names = [getattr(t, "name", getattr(t, "__name__", str(t))) for t in root_agent.tools]
        self.assertIn("list_datasets_and_ranges", tool_names)
        self.assertIn("query_agurim_flow_data", tool_names)
        self.assertIn("AgurimDataEngineer", tool_names)
        self.assertIn("ParallelAnomalyTeam", tool_names)
        self.assertIn("MitigationSafetyPipeline", tool_names)


class TestSentinelWatchdog(unittest.TestCase):
    def test_sentinel_normal_scan(self):
        res = run_sentinel_scan(dataset="sample", threshold_rate=100000000.0)
        self.assertEqual(res["status"], "normal")
        self.assertEqual(len(res["incidents"]), 0)

    def test_sentinel_anomaly_trigger(self):
        res = run_sentinel_scan(dataset="sample", threshold_rate=10000000.0)
        self.assertEqual(res["status"], "anomaly_detected")
        self.assertGreater(len(res["incidents"]), 0)
        inc = res["incidents"][0]
        self.assertIn("offending_flow", inc)
        self.assertIn("bgp_flowspec", inc["recommended_mitigation"])


class TestEndToEndAgentQuery(unittest.TestCase):
    def test_run_agent_query_workflow(self):
        query = "Investigate the abnormal bandwidth surge and apply rate limit"
        res = run_agent_query(query, context={"dataset": "sample", "criteria": "byte"})
        self.assertEqual(res["status"], "success")
        self.assertIn("Agurim Multi-Agent NOC Report", res["response"])
        self.assertIn("192.0.2.1", res["response"])
        self.assertIsNotNone(res["ui_action"])
        self.assertEqual(res["ui_action"]["filter"], "192.0.2.1")
        self.assertGreaterEqual(len(res["traces"]), 4)


if __name__ == "__main__":
    unittest.main()
