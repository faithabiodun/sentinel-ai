"""Measure the detectors against known ground truth.

Each sample in the corpus is labelled by its upstream source with the technique
it was captured executing. Nothing here is self-graded: the label came with the
file. This is the difference between "the demo works" and a number.

Usage:
    python scripts/evaluate.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.ingest.detectors import RULES, run_detectors  # noqa: E402
from app.ingest.evtx_reader import read_directory, read_evtx  # noqa: E402
from fetch_datasets import SAMPLES  # noqa: E402

RAW = ROOT / "data" / "raw"


def main() -> int:
    if not RAW.exists() or not any(RAW.glob("*.evtx")):
        print("No samples. Run: python scripts/fetch_datasets.py")
        return 1

    print(f"{'':<4}{'sample':<48}{'expected':<12}detected")
    print("-" * 96)

    recovered = 0
    considered = 0

    for sample in SAMPLES:
        path = RAW / Path(sample.path).name
        if not path.exists():
            continue

        considered += 1
        techniques = sorted({a.technique for a in run_detectors(read_evtx(path))})
        found = sample.technique in techniques
        recovered += found

        mark = "ok" if found else "MISS"
        print(
            f"{mark:<4}{path.name[:46]:<48}{sample.technique:<12}"
            f"{', '.join(techniques) or '-'}"
        )

    print("-" * 96)
    rate = recovered / considered if considered else 0.0
    print(f"ground-truth technique recovered: {recovered}/{considered} ({rate:.0%})")

    events = read_directory(RAW)
    alerts = run_detectors(events)
    fired = Counter(a.rule for a in alerts)

    print(f"events parsed:  {len(events)}")
    print(f"alerts raised:  {len(alerts)}")
    print(f"rules exercised: {len(fired)}/{len(RULES)}")

    # A rule with no coverage is a liability — it has never been shown to work.
    idle = [r.__name__ for r in RULES if r.__name__ not in fired]
    if idle:
        print(f"\nrules with no sample coverage: {', '.join(idle)}")

    for name, count in fired.most_common():
        print(f"  {name:<34}{count}")

    return 0 if recovered == considered else 1


if __name__ == "__main__":
    sys.exit(main())
