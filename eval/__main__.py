"""Command-line entry points for the evaluation checker."""

from __future__ import annotations

import argparse

from eval.report import BASELINE_PATH, accept_baseline
from eval.truth import REPO_ROOT, check_all_truth


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m eval")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-truth", help="verify ground-truth evidence at declared locations")
    accept = commands.add_parser("accept-baseline", help="accept a complete, successful eval run as baseline")
    accept.add_argument("results_dir")
    arguments = parser.parse_args()

    if arguments.command == "check-truth":
        result = check_all_truth(REPO_ROOT)
        for error in result.errors:
            print(error)
        return 0 if result.valid else 1

    if arguments.command == "accept-baseline":
        try:
            accept_baseline(arguments.results_dir, baseline_path=BASELINE_PATH)
        except (TypeError, ValueError) as error:
            print(error)
            return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
