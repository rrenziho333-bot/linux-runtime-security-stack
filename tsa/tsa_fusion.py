#!/usr/bin/env python3
"""TSA entry point.

TSA consumes Falco JSON alerts and a Lynis report, then maintains a durable
host posture/runtime risk score. It never changes kernel enforcement policy
directly; enforcement requests belong to a separate privileged controller.
"""

import argparse
import logging
import signal
from pathlib import Path

from tsa_core import TSAFusionAgent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Falco and Lynis risk fusion agent")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).with_name("policy_config.yaml")),
        help="Path to the TSA YAML configuration",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run the baseline scan, write a report, and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    agent = TSAFusionAgent(args.config)
    signal.signal(signal.SIGINT, agent.request_stop)
    signal.signal(signal.SIGTERM, agent.request_stop)

    if args.once:
        agent.run_posture_scan()
        agent.generate_report("one-shot")
        agent.close()
        return 0

    try:
        agent.run_daemon()
    finally:
        agent.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
