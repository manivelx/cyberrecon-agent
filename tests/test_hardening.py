from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agents.analyzer_agent import AnalyzerAgent
from agents.pipeline import CyberReconPipeline
from main import main as cli_main
from tools.nmap_tools import parse_nmap_xml
from tools.security import sanitize_target_ip, sanitize_xml_data


class AuditEnv(unittest.TestCase):
    """Point the audit log at a temp file for each test."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit_path = Path(self.temp.name) / "audit.log"
        os.environ["CYBERRECON_AUDIT_LOG"] = str(self.audit_path)
        self.addCleanup(os.environ.pop, "CYBERRECON_AUDIT_LOG", None)

    def audit_records(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]


class TargetRulesTest(unittest.TestCase):
    def test_rejects_cidr_hostname_ipv6_and_172_range(self) -> None:
        for bad in ["192.168.1.0/24", "localhost", "::1", "172.16.0.1", "8.8.8.8", "", "10.0.0.1; rm -rf /"]:
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    sanitize_target_ip(bad)

    def test_accepts_the_three_documented_ranges(self) -> None:
        for good in ["10.1.2.3", "192.168.0.9", "127.0.0.1"]:
            self.assertEqual(sanitize_target_ip(good), good)


class XmlRulesTest(unittest.TestCase):
    def test_rejects_entity_declarations(self) -> None:
        payload = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
        with self.assertRaisesRegex(ValueError, "DOCTYPE or ENTITY"):
            sanitize_xml_data(payload)

    def test_malformed_xml_raises_value_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid Nmap XML"):
            parse_nmap_xml("<nmaprun><host>")

    def test_wrong_root_element_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "nmaprun"):
            parse_nmap_xml("<html></html>")


class AnalyzerTest(unittest.TestCase):
    def test_flags_nmap_names_for_smb_and_rdp(self) -> None:
        data = {
            "hosts": [
                {
                    "ports": [
                        {"portid": 445, "state": "open", "service": {"name": "microsoft-ds"}},
                        {"portid": 3389, "state": "open", "service": {"name": "ms-wbt-server"}},
                        {"portid": 22, "state": "open", "service": {"name": "ssh"}},
                        {"portid": 8443, "state": "closed", "service": {"name": "https-alt"}},
                    ]
                }
            ]
        }
        result = AnalyzerAgent().run(data)
        text = " ".join(result["risks"])
        self.assertIn("microsoft-ds", text)
        self.assertIn("ms-wbt-server", text)
        self.assertNotIn("ssh", text)
        self.assertEqual(result["summary"]["open_port_count"], 3)


class PipelineAuditTest(AuditEnv):
    def test_demo_run_writes_report_and_audit_trail(self) -> None:
        report = CyberReconPipeline(output_dir=Path(self.temp.name)).run("192.168.1.1", "version", demo_mode=True)
        self.assertTrue(report.exists())
        self.assertIn("22/tcp - ssh", report.read_text())
        self.assertEqual([r["status"] for r in self.audit_records()], ["requested", "completed"])

    def test_rejected_request_is_logged_without_copying_input(self) -> None:
        with self.assertRaises(ValueError):
            CyberReconPipeline(output_dir=Path(self.temp.name)).run("8.8.8.8\nFAKE LOG LINE", "version", demo_mode=True)
        records = self.audit_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "rejected")
        self.assertNotIn("FAKE", json.dumps(records))

    def test_failure_is_logged(self) -> None:
        pipeline = CyberReconPipeline(output_dir=Path(self.temp.name))

        def boom(**_: object) -> dict:
            raise RuntimeError("nmap missing")

        pipeline.recon_agent.run = boom  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            pipeline.run("10.0.0.5", "syn", demo_mode=False)
        self.assertEqual([r["status"] for r in self.audit_records()], ["requested", "failed"])


class CliTest(AuditEnv):
    def test_cli_demo_mode_exits_zero(self) -> None:
        self.assertEqual(cli_main(["--target", "127.0.0.1", "--demo-mode", "--output-dir", self.temp.name]), 0)

    def test_cli_public_target_exits_two(self) -> None:
        self.assertEqual(cli_main(["--target", "1.1.1.1", "--demo-mode", "--output-dir", self.temp.name]), 2)


class McpToolTest(AuditEnv):
    def test_scan_type_is_validated_before_logging(self) -> None:
        from mcp_server import scan_tool

        with self.assertRaises(ValueError):
            scan_tool("192.168.1.1", "--script=evil")
        records = self.audit_records()
        self.assertEqual([r["status"] for r in records], ["rejected"])
        self.assertNotIn("evil", json.dumps(records))

    def test_scan_tool_returns_demo_xml(self) -> None:
        from mcp_server import scan_tool

        os.environ["CYBERRECON_DEMO_MODE"] = "true"
        self.addCleanup(os.environ.pop, "CYBERRECON_DEMO_MODE", None)
        xml = scan_tool("10.0.0.7", "version")
        self.assertIn("10.0.0.7", xml)


if __name__ == "__main__":
    unittest.main()
