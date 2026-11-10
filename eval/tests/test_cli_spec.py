"""Every `run` option is listed in TICKET-001 §7.3 (issue #76).

The spec's flag list is what humans and agents read; a flag missing from it
is a flag nobody knows to use.
"""

import argparse
import re
from pathlib import Path

from eval.__main__ import build_parser

TICKET = Path(__file__).resolve().parents[2] / "docs/tickets/TICKET-001.md"


def run_options() -> list[str]:
    commands = next(action for action in build_parser()._actions if isinstance(action, argparse._SubParsersAction))
    run_parser = commands.choices["run"]
    return [option for action in run_parser._actions for option in action.option_strings if option not in ("-h", "--help")]


def test_every_run_option_is_listed_in_the_ticket_flag_list():
    section = TICKET.read_text().split("### 7.3", 1)[1].split("\n### ", 1)[0]
    flags_line = next(line for line in section.splitlines() if line.startswith("Flags:"))
    listed = set(re.findall(r"`(--[a-z-]+)", flags_line))

    assert [option for option in run_options() if option not in listed] == []
