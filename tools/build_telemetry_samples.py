"""Build eslogger, ECS, and osquery samples from the Sigma fixtures.

The samples are synthetic. They reuse the inert command lines already in
tests/fixtures/sigma and only change the envelope.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sigma"
OUT = ROOT / "telemetry" / "samples"


def eslogger(event: dict) -> dict:
    image = event.get("Image")
    parent = event.get("ParentImage")
    command = event.get("CommandLine") or ""
    target = event.get("TargetFilename")
    user = event.get("User") or "dev"
    if target:
        return {
            "event_type": "create",
            "process": {
                "executable": {"path": image},
                "parent": {"executable": {"path": parent}} if parent else {},
                "user_name": user,
            },
            "event": {"create": {"target": {"path": target}}},
        }
    return {
        "event_type": "exec",
        "process": {"executable": {"path": parent}, "user_name": user},
        "event": {
            "exec": {
                "args": command.split(" ") if command else [],
                "target": {"executable": {"path": image}},
            }
        },
    }


def ecs(event: dict) -> dict:
    document = {
        "process": {
            "executable": event.get("Image"),
            "command_line": event.get("CommandLine") or None,
            "parent": {"executable": event.get("ParentImage")} if event.get("ParentImage") else {},
        },
        "user": {"name": event.get("User") or "dev"},
    }
    if event.get("TargetFilename"):
        document["file"] = {"path": event["TargetFilename"]}
    return document


def osquery(event: dict) -> dict:
    row = {
        "path": event.get("Image"),
        "cmdline": event.get("CommandLine") or "",
        "username": event.get("User") or "dev",
    }
    if event.get("ParentImage"):
        row["parent_path"] = event["ParentImage"]
    if event.get("TargetFilename"):
        row["target_path"] = event["TargetFilename"]
    return row


def main() -> None:
    builders = {"eslogger": eslogger, "ecs": ecs, "osquery": osquery}
    for schema, builder in builders.items():
        for kind in ("positive", "negative"):
            for folder in sorted(p for p in FIXTURES.iterdir() if p.is_dir() and p.name != "known_good"):
                source = folder / kind
                if not source.is_dir():
                    continue
                for path in sorted(source.glob("*.json")):
                    event = json.loads(path.read_text(encoding="utf-8"))
                    payload = {
                        "_larc": {
                            "classification": "synthetic-benign",
                            "schema": schema,
                            "rule": folder.name,
                            "expected": "match" if kind == "positive" else "no-match",
                            "source_fixture": str(path.relative_to(ROOT)),
                            "origin": "derived from the Sigma fixture, not captured from a collector",
                        },
                        "record": builder(event),
                    }
                    destination = OUT / schema / folder.name / kind / path.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote samples under {OUT}")


if __name__ == "__main__":
    main()
