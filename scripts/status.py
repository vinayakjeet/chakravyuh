"""Headline numbers for the portfolio page.

    uv run python scripts/status.py            human summary plus tables
    uv run python scripts/status.py --json     machine-readable, one object

Every number this prints regenerates from the corpus and the harness in this
repo, offline, in under a minute. The portfolio page cites this file as the
source for Chakravyuh's status metric.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from chakravyuh.bench import VICTIM, VICTIM_TABLE_DATED, run_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("--reps", type=int, default=3)
    args = parser.parse_args()

    report = run_all(reps=args.reps)
    payload = {
        **report.headline,
        "victim_susceptibility_dated": VICTIM_TABLE_DATED,
        "generated": date.today().isoformat(),
        "source": "scripts/status.py",
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"victim: {VICTIM}, susceptibility table dated {VICTIM_TABLE_DATED}")
    print(
        f"no-defense ASR {payload['asr_no_defense']:.3f} across "
        f"{payload['attacked_scenarios']} attacked scenarios, "
        f"{payload['defense_configs']} defense configs, {args.reps} reps"
    )
    print(
        f"best config: {payload['best_config']} at "
        f"ASR {payload['asr_best']:.3f} with benign utility "
        f"{payload['benign_utility_best']:.3f}"
    )
    print()
    for section in report.sections:
        print(section)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
