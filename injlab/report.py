"""Markdown report builder."""

from typing import Dict, List

from .scoring import summarize

LIMITATIONS = """\
## Limitations (read before citing any number)

- The three mock targets are hand-written simulations. They show how classes
  of defense behave in principle. They are NOT measurements of a real model.
- The suite has 5 attacks and 2 controls. Rates like 40% or 100% come from
  tiny counts and have no statistical weight.
- Success is detected with string matching on a canary and a marker. A real
  evaluation needs human review and more robust judging.
- Single-turn only. Multi-turn and tool-use attacks are out of scope here.
"""


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def build_report(results: Dict[str, List[dict]]) -> str:
    targets = list(results)
    lines = ["# Prompt Injection Evaluation Report", ""]

    lines += [
        "## Summary",
        "",
        "| Target | Attacks succeeded | Attack success rate | "
        "False refusals | False refusal rate |",
        "|---|---|---|---|---|",
    ]
    for t in targets:
        s = summarize(results[t])
        lines.append(
            f"| {t} | {s['succeeded']}/{s['attacks']} | "
            f"{_pct(s['attack_success_rate'])} | "
            f"{s['false_refusals']}/{s['controls']} | "
            f"{_pct(s['false_refusal_rate'])} |"
        )

    lines += ["", "## Per-attack results", ""]
    header = "| ID | Attack | Category | OWASP (2025) | " + " | ".join(targets) + " |"
    lines += [header, "|" + "---|" * (4 + len(targets))]
    first = results[targets[0]]
    for i, row in enumerate(first):
        cells = [results[t][i]["result"] for t in targets]
        lines.append(
            f"| {row['id']} | {row['name']} | {row['category']} | "
            f"{row['owasp']} | " + " | ".join(cells) + " |"
        )

    lines += [
        "",
        "Legend: SUCCEEDED = attack worked (bad). BLOCKED = attack failed "
        "(good). OK = benign request answered (good). FALSE_REFUSAL = benign "
        "request refused (bad). LEAK = benign request leaked a secret (bad).",
        "",
        LIMITATIONS,
    ]
    return "\n".join(lines)
