"""Command-line runner.

Examples:
    python -m injlab                    # all offline mock targets
    python -m injlab --target naive
    INJLAB_MODEL=... ANTHROPIC_API_KEY=... python -m injlab --target anthropic
"""

import argparse
import json
import os
from typing import Dict, List

from .attacks import ATTACKS, SYSTEM_PROMPT
from .report import build_report
from .scoring import score
from .targets import MOCK_TARGETS, AnthropicTarget


def run_target(target) -> List[dict]:
    rows = []
    for attack in ATTACKS:
        response = target.respond(SYSTEM_PROMPT, attack.user, attack.document)
        rows.append(
            {
                "target": target.name,
                "id": attack.id,
                "name": attack.name,
                "category": attack.category,
                "owasp": attack.owasp,
                "kind": attack.kind,
                "response": response,
                "result": score(attack, response),
            }
        )
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="injlab")
    parser.add_argument(
        "--target",
        default="all",
        choices=["all", *MOCK_TARGETS, "anthropic"],
        help="'all' runs the three offline mocks.",
    )
    parser.add_argument("--out", default="reports")
    args = parser.parse_args(argv)

    if args.target == "all":
        targets = [cls() for cls in MOCK_TARGETS.values()]
    elif args.target == "anthropic":
        targets = [AnthropicTarget()]
    else:
        targets = [MOCK_TARGETS[args.target]()]

    results: Dict[str, List[dict]] = {t.name: run_target(t) for t in targets}

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "report.md"), "w") as f:
        f.write(build_report(results) + "\n")
    with open(os.path.join(args.out, "results.jsonl"), "w") as f:
        for rows in results.values():
            for row in rows:
                f.write(json.dumps(row) + "\n")

    print(build_report(results))
    return 0
