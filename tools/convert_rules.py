"""Write the committed Sigma conversions for Lucene and Splunk.

Run from the repository root. The test suite checks these files still match
a fresh conversion.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "sigma"
OUT = ROOT / "rules" / "converted"

TARGETS = (
    ("lucene", ROOT / "pipelines" / "ecs-macos.yml", "lucene"),
    ("splunk", ROOT / "pipelines" / "splunk-macos.yml", "splunk"),
)


def convert(target: str, pipeline: Path, folder: str) -> None:
    destination = OUT / folder
    destination.mkdir(parents=True, exist_ok=True)
    for stale in destination.glob("*.txt"):
        stale.unlink()
    subprocess.run(
        [
            "sigma",
            "convert",
            "-t",
            target,
            "-p",
            str(pipeline),
            "-od",
            str(destination),
            "-ot",
            "{stem}.txt",
            str(RULES),
        ],
        check=True,
    )


def main() -> None:
    for target, pipeline, folder in TARGETS:
        convert(target, pipeline, folder)
    print(f"wrote conversions under {OUT}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
