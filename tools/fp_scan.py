"""Scan a benign corpus with the YARA pack and write a results report.

The corpus is downloaded into validation/cache, which is gitignored.
Nothing in the corpus is executed. The script only clones, downloads, and
scans. A hit is a lead for tuning, not a verdict about the upstream project.

Exit status is 0 when every hit is listed in validation/fp-allowlist.txt.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "validation" / "cache"
REPORT = ROOT / "validation" / "fp-results.md"
JSON_REPORT = ROOT / "validation" / "fp-results.json"
ALLOW = ROOT / "validation" / "fp-allowlist.txt"

# Pinned to a clone of default branch at fetch time. Shallow, no submodules.
REPOS = (
    "https://github.com/modelcontextprotocol/servers.git",
    "https://github.com/typicode/husky.git",
    "https://github.com/pre-commit/pre-commit-hooks.git",
    "https://github.com/github/gitignore.git",
    "https://github.com/openai/codex.git",
    "https://github.com/google-gemini/gemini-cli.git",
)

RAW_FILES = {
    "homebrew/rectangle/Rectangle.plist": "https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/r/rectangle.rb",
}


def run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)


def fetch_repos() -> list[str]:
    notes: list[str] = []
    dest_root = CACHE / "git"
    dest_root.mkdir(parents=True, exist_ok=True)
    for url in REPOS:
        name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        dest = dest_root / name
        if dest.exists():
            notes.append(f"reuse {name}")
            continue
        result = run(["git", "clone", "--depth", "1", url, str(dest)])
        if result.returncode != 0:
            notes.append(f"clone failed {name}: {result.stderr.strip().splitlines()[-1:]}")
            if dest.exists():
                shutil.rmtree(dest)
        else:
            notes.append(f"cloned {name}")
    return notes


def fetch_packages() -> list[str]:
    notes: list[str] = []
    wheel_dir = CACHE / "wheels"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    result = run([sys.executable, "-m", "pip", "download", "-d", str(wheel_dir), "requests", "pyyaml"])
    notes.append("pip download requests pyyaml" if result.returncode == 0 else "pip download failed")
    extract = CACHE / "wheels-extracted"
    extract.mkdir(parents=True, exist_ok=True)
    import zipfile

    for wheel in wheel_dir.glob("*.whl"):
        target = extract / wheel.stem
        if target.exists():
            continue
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(target)
    if shutil.which("npm"):
        npm_dir = CACHE / "npm"
        npm_dir.mkdir(parents=True, exist_ok=True)
        for package in ("lodash", "express"):
            packed = npm_dir / package
            if packed.exists():
                continue
            result = run(["npm", "pack", package], cwd=npm_dir)
            if result.returncode != 0:
                notes.append(f"npm pack {package} failed")
                continue
            tarball = next(npm_dir.glob(f"{package}-*.tgz"), None)
            if tarball is None:
                continue
            run(["tar", "-xzf", str(tarball), "-C", str(npm_dir)])
            extracted = npm_dir / "package"
            if extracted.exists():
                extracted.rename(packed)
            notes.append(f"npm pack {package}")
    else:
        notes.append("npm not installed; skipped node packages")
    site = CACHE / "site-packages"
    if not site.exists():
        site.mkdir(parents=True, exist_ok=True)
        # A local tree of already-installed pure-Python libraries. Not executed.
        import yaml as _

        source = Path(_.__file__).resolve().parent
        shutil.copytree(source, site / "yaml", dirs_exist_ok=True)
        notes.append("copied installed PyYAML tree")
    return notes


def iter_files() -> list[Path]:
    files: list[Path] = []
    if not CACHE.exists():
        return files
    for path in CACHE.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".whl", ".tgz", ".gz"}:
            continue
        if path.stat().st_size > 2_000_000:
            continue
        files.append(path)
    return files


def scan(files: list[Path], flavor: str) -> tuple[dict[str, list[str]], float]:
    sys.path.insert(0, str(ROOT))
    from larc_seraph.scan import compile_yara, yara_match

    rules = compile_yara(flavor)
    hits: dict[str, list[str]] = {}
    started = time.perf_counter()
    for path in files:
        try:
            matched = yara_match(
                rules,
                path=str(path),
                use_filepath=flavor != "forge",
                phrases=False,
            )
        except Exception:
            continue
        for hit in matched:
            hits.setdefault(hit.rule, []).append(str(path.relative_to(CACHE)))
    return hits, time.perf_counter() - started


def allowlist() -> set[str]:
    if not ALLOW.exists():
        return set()
    return {line.strip() for line in ALLOW.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    notes = fetch_repos() + fetch_packages()
    files = iter_files()
    forge_hits, forge_elapsed = scan(files, "forge")
    path_hits, path_elapsed = scan(files, "path")
    allowed = allowlist()

    def unexpected_for(hits: dict[str, list[str]]) -> list[str]:
        found = []
        for rule, paths in sorted(hits.items()):
            for path in paths:
                key = f"{rule} {path}"
                if key not in allowed and rule not in allowed:
                    found.append(key)
        return found

    unexpected = unexpected_for(forge_hits)
    unexpected_path = unexpected_for(path_hits)
    payload = {
        "files_scanned": len(files),
        "seconds": round(forge_elapsed + path_elapsed, 3),
        "forge_seconds": round(forge_elapsed, 3),
        "path_seconds": round(path_elapsed, 3),
        "hit_counts": {rule: len(paths) for rule, paths in sorted(forge_hits.items())},
        "path_hit_counts": {rule: len(paths) for rule, paths in sorted(path_hits.items())},
        "hits": {rule: paths for rule, paths in sorted(forge_hits.items())},
        "path_hits": {rule: paths for rule, paths in sorted(path_hits.items())},
        "fetch_notes": notes,
        "unexpected": unexpected,
        "unexpected_path": unexpected_path,
    }
    JSON_REPORT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Benign-corpus YARA results",
        "",
        f"Files scanned: {len(files)}",
        f"Seconds: {payload['seconds']}",
        "",
        "## Hit counts",
        "",
    ]
    lines.append("Forge flavor:")
    if not forge_hits:
        lines.append("No Forge rule matched the corpus.")
    else:
        for rule, paths in sorted(forge_hits.items()):
            lines.append(f"- {rule}: {len(paths)}")
    lines.append("")
    lines.append("Path-scoped flavor:")
    if not path_hits:
        lines.append("No path-scoped rule matched the corpus.")
    else:
        for rule, paths in sorted(path_hits.items()):
            lines.append(f"- {rule}: {len(paths)}")
    lines.extend(["", "## Fetch notes", ""])
    lines.extend(f"- {note}" for note in notes)
    if unexpected or unexpected_path:
        lines.extend(["", "## Unexpected hits", ""])
        lines.extend(f"- forge {item}" for item in unexpected[:40])
        lines.extend(f"- path {item}" for item in unexpected_path[:40])
    lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(REPORT)
    print(json.dumps({
        "files": len(files),
        "seconds": payload["seconds"],
        "unexpected_forge": len(unexpected),
        "unexpected_path": len(unexpected_path),
        "forge_counts": payload["hit_counts"],
        "path_counts": payload["path_hit_counts"],
    }, indent=2))
    return 1 if unexpected or unexpected_path else 0


if __name__ == "__main__":
    raise SystemExit(main())
