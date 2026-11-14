"""Build the tag release archives. Does not create a git tag or a GitHub Release.

The archives contain the YARA rules, the Sigma rules, the converted queries,
the false-positive allowlist, and the license files. SHA256SUMS covers the
zip and the tarball. Release notes are the matching CHANGELOG section.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_MTIME = (2026, 11, 13, 0, 0, 0)
# 2026-11-13 00:00:00 UTC.
FIXED_EPOCH = 1762992000

_INCLUDE_FILES = (
    "LICENSE",
    "LICENSE.rules",
    "NOTICE",
    "validation/fp-allowlist.txt",
)
_INCLUDE_DIRS = (
    "rules/yara",
    "rules/path-scoped",
    "rules/sigma",
    "rules/converted",
)


def project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version = "([^"]+)"$', text)
    if not match:
        raise SystemExit("pyproject.toml has no version")
    return match.group(1)


def release_files() -> list[Path]:
    files: list[Path] = []
    for relative in _INCLUDE_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"missing release input: {relative}")
        files.append(path)
    for relative in _INCLUDE_DIRS:
        directory = ROOT / relative
        if not directory.is_dir():
            raise SystemExit(f"missing release input: {relative}")
        found = [path for path in directory.rglob("*") if path.is_file()]
        if not found:
            raise SystemExit(f"release input is empty: {relative}")
        files.extend(found)
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def changelog_notes(tag: str) -> str:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    pattern = re.compile(rf"(?m)^## {re.escape(tag)} — .*$")
    match = pattern.search(changelog)
    if not match:
        raise SystemExit(f"CHANGELOG.md has no section for {tag}")
    rest = changelog[match.end() :]
    nxt = re.search(r"(?m)^## ", rest)
    body = rest[: nxt.start()] if nxt else rest
    return (match.group(0) + body).strip() + "\n"


def _archive_name(version: str, suffix: str) -> str:
    return f"larc-seraph-{version}{suffix}"


_MEMBER = re.compile(r"^[A-Za-z0-9_./+-]+$")


def _member_name(prefix: str, path: Path) -> str:
    relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SystemExit(f"refusing archive member {relative}")
    if _MEMBER.fullmatch(relative) is None:
        raise SystemExit(f"refusing archive member {relative}")
    # Rebuild the name from the checked pieces so the archive entry is not the raw path.
    cleaned = "/".join(parts)
    return f"{prefix}/{cleaned}"


def _contained_directory(raw: str) -> Path:
    if not raw or "\x00" in raw:
        raise SystemExit("dist path is empty")
    candidate = Path(raw)
    if ".." in candidate.parts:
        raise SystemExit("dist path must not contain ..")
    resolved = candidate.resolve() if candidate.is_absolute() else (ROOT / candidate).resolve()
    root = ROOT.resolve()
    if os.path.commonpath([str(root), str(resolved)]) != str(root):
        raise SystemExit("dist must stay inside the repository")
    return resolved


def _write_zip(destination: Path, prefix: str, files: list[Path]) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            member = _member_name(prefix, path)
            info = zipfile.ZipInfo(member)
            info.date_time = FIXED_MTIME
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())


def _write_tar(destination: Path, prefix: str, files: list[Path]) -> None:
    with tarfile.open(destination, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for path in files:
            payload = path.read_bytes()
            info = tarfile.TarInfo(name=_member_name(prefix, path))
            info.size = len(payload)
            info.mtime = FIXED_EPOCH
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def build(tag: str, dist: Path) -> None:
    version = tag.removeprefix("v")
    if version != project_version():
        raise SystemExit(f"tag {tag} does not match pyproject version {project_version()}")
    notes = changelog_notes(tag)
    files = release_files()
    prefix = f"larc-seraph-{version}"
    dist.mkdir(parents=True, exist_ok=True)
    zip_path = dist / _archive_name(version, ".zip")
    tar_path = dist / _archive_name(version, ".tar.gz")
    _write_zip(zip_path, prefix, files)
    _write_tar(tar_path, prefix, files)
    sums = dist / "SHA256SUMS"
    lines = [f"{sha256_file(path)}  {path.name}" for path in (zip_path, tar_path)]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (dist / "release-notes.md").write_text(notes, encoding="utf-8")
    print(zip_path)
    print(tar_path)
    print(sums)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build larc-seraph release archives.")
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--dist", default=os.environ.get("LARC_RELEASE_DIST", "dist"))
    args = parser.parse_args()
    tag = args.tag or f"v{project_version()}"
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise SystemExit(f"tag must look like v0.1.9, got {tag}")
    build(tag, _contained_directory(args.dist))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
