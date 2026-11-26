"""Local MCP server exposing private-target Nmap tools."""

from __future__ import annotations

import logging
import os

from mcp.server.mcpserver import MCPServer

from tools.audit_log import record_scan_audit
from tools.mcp_server_tools import execute_scan, summarize_scan_results
from tools.security import sanitize_scan_request, sanitize_xml_data

logging.basicConfig(level=logging.INFO)

mcp = MCPServer("CyberRecon MCP Server")


def scan_tool(target_ip: str, scan_type: str) -> str:
    """Validate, audit and run a scan. Kept separate so tests can call it."""

    try:
        request = sanitize_scan_request(target_ip=target_ip, scan_type=scan_type)
    except ValueError:
        # Never write attacker-controlled text into the audit log.
        record_scan_audit("invalid", "mcp.run_nmap_scan", scan_type="invalid", status="rejected")
        raise

    demo_mode = os.getenv("CYBERRECON_DEMO_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
    record_scan_audit(request.target_ip, "mcp.run_nmap_scan", scan_type=request.scan_type, status="requested")
    try:
        xml_output = execute_scan(
            target_ip=request.target_ip, scan_type=request.scan_type, demo_mode=demo_mode
        )
    except Exception:
        record_scan_audit(request.target_ip, "mcp.run_nmap_scan", scan_type=request.scan_type, status="failed")
        raise
    record_scan_audit(request.target_ip, "mcp.run_nmap_scan", scan_type=request.scan_type, status="completed")
    return xml_output


@mcp.tool()
def run_nmap_scan(target_ip: str, scan_type: str) -> str:
    """Execute Nmap against an allowed private target and return XML output."""

    return scan_tool(target_ip, scan_type)


@mcp.tool()
def parse_scan_results(xml_data: str) -> dict:
    """Parse Nmap XML and return a JSON-ready summary."""

    return summarize_scan_results(sanitize_xml_data(xml_data))


def main() -> int:
    """Run the MCP server on localhost:8080."""

    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8080,
        json_response=True,
        stateless_http=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
