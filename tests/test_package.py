"""The release archives contain the rules and the licenses, and nothing else."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_archive_contains_rules_and_licenses():
    destination = ROOT / "dist" / "package-test"
    shutil.rmtree(destination, ignore_errors=True)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "package_release.py"),
            "--tag",
            "v0.1.9",
            "--dist",
            "dist/package-test",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    zip_path = destination / "larc-seraph-0.1.9.zip"
    tar_path = destination / "larc-seraph-0.1.9.tar.gz"
    sums = (destination / "SHA256SUMS").read_text(encoding="utf-8")
    notes = (destination / "release-notes.md").read_text(encoding="utf-8")
    assert notes.startswith("## v0.1.9")
    assert "two flavors" in notes
    for path in (zip_path, tar_path):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert f"{digest}  {path.name}" in sums
    with zipfile.ZipFile(zip_path) as archive:
        names = set(archive.namelist())
    prefix = "larc-seraph-0.1.9/"
    required = [
        "LICENSE",
        "LICENSE.rules",
        "NOTICE",
        "validation/fp-allowlist.txt",
        "rules/yara/mcp_curl_pipe_shell.yar",
        "rules/sigma/macos_agent_piped_shell.yml",
        "rules/converted/lucene/macos_agent_piped_shell.txt",
        "rules/converted/splunk/macos_agent_piped_shell.txt",
    ]
    for relative in required:
        assert prefix + relative in names
    assert all(name.startswith(prefix) for name in names)
    assert not any(name.startswith(prefix + "tests/") for name in names)
    assert not any(name.startswith(prefix + "docs/") for name in names)
    yara = [name for name in names if name.startswith(prefix + "rules/yara/") and name.endswith(".yar")]
    scoped = [name for name in names if name.startswith(prefix + "rules/path-scoped/") and name.endswith(".yar")]
    sigma = [name for name in names if name.startswith(prefix + "rules/sigma/") and name.endswith(".yml")]
    assert len(yara) == 11
    assert len(scoped) == 9
    assert len(sigma) == 6
