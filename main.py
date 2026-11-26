"""Command-line entry point for the CyberRecon pipeline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from agents.pipeline import CyberReconPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CyberRecon pipeline.")
    parser.add_argument("--target", help="Private IPv4 address to scan.")
    parser.add_argument(
        "--scan-type",
        default="version",
        choices=["syn", "connect", "udp", "version"],
        help="Scan preset to use.",
    )
    parser.add_argument(
        "--demo-mode",
        action="store_true",
        help="Replay a bundled Nmap XML file instead of running a live scan.",
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for markdown reports.")
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()

    parser = build_parser()
    args = parser.parse_args(argv)

    target_ip = args.target or os.getenv("TARGET_IP")
    if not target_ip:
        parser.error("A target IP must be provided through --target or TARGET_IP in .env")

    demo_mode = args.demo_mode or os.getenv("CYBERRECON_DEMO_MODE", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }

    pipeline = CyberReconPipeline(output_dir=Path(args.output_dir))
    try:
        report_path = pipeline.run(
            target_ip=target_ip,
            scan_type=args.scan_type,
            demo_mode=demo_mode,
        )
    except ValueError as exc:
        print(f"Rejected: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    print(f"Report written to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
