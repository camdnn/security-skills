"""Command-line entry points for the evaluation checker."""

from __future__ import annotations

import argparse
from pathlib import Path

from eval.report import accept_baseline
from eval.runner import ResultsDirInUse, RunOptions, run
from eval.truth import REPO_ROOT, check_all_truth


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m eval")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-truth", help="verify ground-truth evidence at declared locations")
    accept = commands.add_parser("accept-baseline", help="accept a complete, successful eval run as baseline")
    accept.add_argument("results_dir")
    run_parser = commands.add_parser("run", help="run or replay checker trials")
    run_parser.add_argument("--tier", choices=("fast", "full"), required=True)
    run_parser.add_argument("--skill")
    run_parser.add_argument("--mode", choices=("code-only", "context"))
    run_parser.add_argument("--runs", type=int)
    run_parser.add_argument("--agent", choices=("claude", "codex"))
    run_parser.add_argument("--replay", type=Path)
    destination = run_parser.add_mutually_exclusive_group()
    destination.add_argument("--resume", type=Path, help="finish the missing trials of an earlier eval run in this folder")
    destination.add_argument(
        "--results-dir", type=Path, help="write a new eval run to this folder (default: eval/results/<date>-<commit>/)"
    )
    run_parser.add_argument("--no-baseline-check", action="store_true")
    run_parser.add_argument("--allow-api-key", action="store_true")
    arguments = parser.parse_args()

    if arguments.command == "check-truth":
        truth_check = check_all_truth(REPO_ROOT)
        for error in truth_check.errors:
            print(error)
        return 0 if truth_check.valid else 1

    if arguments.command == "accept-baseline":
        try:
            accept_baseline(arguments.results_dir)
        except (TypeError, ValueError) as error:
            print(error)
            return 1
        return 0

    if arguments.command == "run":
        try:
            results_dir, result = run(
                RunOptions(
                    tier=arguments.tier,
                    skill=arguments.skill,
                    mode=arguments.mode,
                    runs=arguments.runs,
                    agent=arguments.agent,
                    replay_dir=arguments.replay,
                    resume_dir=arguments.resume,
                    results_dir=arguments.results_dir,
                    baseline_check=not arguments.no_baseline_check,
                    allow_api_key=arguments.allow_api_key,
                )
            )
        except ResultsDirInUse as error:
            print(error)
            return 2
        except (OSError, ValueError) as error:
            print(error)
            return 1
        print(results_dir)
        for reason in result.reasons:
            print(reason)
        return result.exit_code

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
