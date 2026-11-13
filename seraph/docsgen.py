"""Render the static docs site from rule metadata and Markdown sources.

The site is committed. ``python -m seraph.docsgen --check`` fails when the
HTML drifts from the sources.
"""

from __future__ import annotations

import argparse
import html
import re
import tempfile
from pathlib import Path

from seraph.inventory import CONTENT_DIR, ROOT, load_records, writeup_path

DOCS = ROOT / "docs"

SURFACE = """
<div class="surface" role="img" aria-label="Workstation attack surface: trusted files feed an agent process, which can reach SSH trust, shell startup, launchd, and the network.">
  <div>
    <p class="label">Trusted files</p>
    <div class="mini">MCP config</div>
    <div class="mini">Instruction file</div>
    <div class="mini">Git hook</div>
    <div class="mini">LaunchAgent plist</div>
  </div>
  <div class="flow" aria-hidden="true">→</div>
  <div>
    <p class="label">Local principal</p>
    <div class="mini lit">Agent process</div>
    <p class="note">Same user. New judgment.</p>
  </div>
  <div class="flow" aria-hidden="true">→</div>
  <div>
    <p class="label">What it can touch</p>
    <div class="mini">SSH trust</div>
    <div class="mini">Shell startup</div>
    <div class="mini">Launchd jobs</div>
    <div class="mini">Network</div>
  </div>
</div>
""".strip()


def _inline(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        lambda match: f'<a href="{match.group(2)}">{match.group(1)}</a>',
        escaped,
    )
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def markdown_to_html(source: str) -> str:
    lines = source.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            buff: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].startswith("```"):
                buff.append(lines[index])
                index += 1
            index += 1
            blocks.append(f"<pre><code>{html.escape(chr(10).join(buff))}</code></pre>")
            continue
        if line.strip() == "[[surface]]":
            blocks.append(SURFACE)
            index += 1
            continue
        if line.startswith("### "):
            blocks.append(f"<h3 id=\"{_slug(line[4:])}\">{_inline(line[4:])}</h3>")
            index += 1
            continue
        if line.startswith("## "):
            blocks.append(f"<h2 id=\"{_slug(line[3:])}\">{_inline(line[3:])}</h2>")
            index += 1
            continue
        if line.startswith("# "):
            blocks.append(f"<h1>{_inline(line[2:])}</h1>")
            index += 1
            continue
        if line.startswith("|"):
            table_html, index = _table(lines, index)
            blocks.append(table_html)
            continue
        if line.startswith("- "):
            items: list[str] = []
            while index < len(lines) and lines[index].startswith("- "):
                items.append(f"<li>{_inline(lines[index][2:])}</li>")
                index += 1
            blocks.append("<ul>" + "".join(items) + "</ul>")
            continue
        if re.match(r"\d+\. ", line):
            items = []
            while index < len(lines) and re.match(r"\d+\. ", lines[index]):
                item = re.sub(r"^\d+\. ", "", lines[index])
                items.append(f"<li>{_inline(item)}</li>")
                index += 1
            blocks.append("<ol>" + "".join(items) + "</ol>")
            continue
        if not line.strip():
            index += 1
            continue
        buff = [line]
        index += 1
        while index < len(lines) and lines[index].strip() and not _block_start(lines[index]):
            buff.append(lines[index])
            index += 1
        blocks.append(f"<p>{_inline(' '.join(part.strip() for part in buff))}</p>")
    return "\n".join(blocks)


def _table(lines: list[str], index: int) -> tuple[str, int]:
    header = [_inline(cell.strip()) for cell in lines[index].strip().strip("|").split("|")]
    index += 2
    rows: list[str] = []
    while index < len(lines) and lines[index].startswith("|"):
        cells = [_inline(cell.strip()) for cell in lines[index].strip().strip("|").split("|")]
        rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
        index += 1
    head = "<tr>" + "".join(f"<th>{cell}</th>" for cell in header) + "</tr>"
    return (
        f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>',
        index,
    )


def _block_start(line: str) -> bool:
    return line.startswith(("#", "-", "|", "```")) or line.strip() == "[[surface]]" or bool(
        re.match(r"\d+\. ", line)
    )


def _page(title: str, body: str, depth: int, current: str) -> str:
    prefix = "../" * depth
    assets = f"{prefix}assets/"

    def href(path: str) -> str:
        return f"{prefix}{path}"

    def current_attr(name: str) -> str:
        return ' aria-current="page"' if current == name else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <meta name="description" content="SERAPH is Light Architects detection content for AI-agent tooling on developer workstations.">
  <meta name="author" content="Kevin Francis Tan">
  <meta name="theme-color" content="#070F1A">
  <link rel="icon" href="{assets}favicon.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&amp;family=IBM+Plex+Sans:wght@400;500;600&amp;display=swap" rel="stylesheet">
  <link rel="stylesheet" href="{assets}site.css">
</head>
<body>
  <a class="skip" href="#content">Skip to content</a>
  <header class="site">
    <div class="wrap nav">
      <a class="brand" href="{href("index.html")}">
        <img src="{assets}favicon.svg" alt="">
        <span>
          <span class="brand-name">SERAPH</span>
          <small>Light Architects</small>
        </span>
      </a>
      <nav class="nav-links" aria-label="Documentation">
        <a href="{href("index.html")}"{current_attr("home")}>Overview</a>
        <a href="{href("threat-model.html")}"{current_attr("threat")}>Threat model</a>
        <a href="{href("rules/index.html")}"{current_attr("rules")}>Rules</a>
      </nav>
    </div>
  </header>
  <main id="content">
    <div class="wrap">
{body}
    </div>
  </main>
  <footer class="site">
    <div class="wrap">
      <p><strong>Kevin Francis Tan</strong> · Light Architects · <a href="https://lightarchitects.ai">lightarchitects.ai</a></p>
      <p>Rules under the Detection Rule License 1.1. Code, harness, and these pages under Apache-2.0. A match is a lead, not a verdict. Nothing in this pack is a payload.</p>
    </div>
  </footer>
</body>
</html>
"""


def _severity(value: str) -> str:
    return f'<span class="sev sev-{html.escape(value)}">{html.escape(value)}</span>'


def _technique_links(attack: str) -> str:
    parts = []
    for token in attack.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("t") or token.startswith("T"):
            parts.append(
                f'<a href="https://attack.mitre.org/techniques/{token.upper().replace(".", "/")}/">{html.escape(token.upper())}</a>'
            )
        else:
            parts.append(html.escape(token))
    return ", ".join(parts)


def _rule_rows(records, depth: int) -> str:
    prefix = "../" * depth
    rows = []
    for record in records:
        href = f"{prefix}rules/{record.name}.html"
        rows.append(
            "<tr>"
            f"<td><a href=\"{href}\">{html.escape(record.name)}</a></td>"
            f"<td>{html.escape(record.kind)}</td>"
            f"<td>{_severity(record.severity)}</td>"
            f"<td>{html.escape(record.title)}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Rule</th><th>Engine</th><th>Severity</th><th>What it watches</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _landing(records) -> str:
    counts = (
        f"{sum(r.kind == 'yara' for r in records)} YARA · "
        f"{sum(r.kind == 'sigma' for r in records)} Sigma"
    )
    return f"""
<section class="hero">
  <div>
    <p class="eyebrow">Light Architects · detection pack</p>
    <h1>SERAPH</h1>
    <p class="deck">Detection content for AI-agent tooling on a developer workstation. YARA for the files an agent trusts. Sigma for the macOS events those files become.</p>
    <div class="chips">
      <span class="chip">REAL</span>
      <span class="chip">experimental</span>
      <span class="chip">{html.escape(counts)}</span>
      <span class="chip">defensive only</span>
    </div>
    <div class="actions">
      <a class="cta" href="threat-model.html">Read the threat model</a>
      <a class="ghost" href="rules/index.html">Browse the rules</a>
    </div>
  </div>
  <figure class="gem-plate">
    <img src="assets/galaxy-opal-canonical.png" alt="Galaxy Opal canonical reference: a faceted teal solid on a navy field, captioned REAL, solid, carrying substance.">
  </figure>
</section>
<section>
  <p class="label">Coverage</p>
  <div class="grid-5">
    <article class="facet"><h3>MCP configs</h3><p>Temp-path launches, fetch-to-shell, encoded exec, remote package tags, token variables on a URL.</p></article>
    <article class="facet"><h3>Instruction files</h3><p>Unicode tags, bidi overrides, confirmation bypass, and credential paths next to a network sink.</p></article>
    <article class="facet"><h3>LaunchAgents</h3><p>RunAtLoad plus KeepAlive, a shell, and a user-writable path. Reverse SSH with host-key checking off.</p></article>
    <article class="facet"><h3>Git hooks</h3><p>A shebang plus a decode-to-shell, a fetch-to-shell, or a network call carrying a credential path.</p></article>
    <article class="facet"><h3>Process events</h3><p>Agent hosts writing SSH trust or shell rc files, dropping plists, or spawning a piped shell.</p></article>
  </div>
</section>
<section>
  <h2>Rules</h2>
  <p>Fifteen rules. Each one has a true-positive fixture, a known-good fixture, a false-positive note, and a write-up. Status is experimental: the tests prove the fixtures.</p>
  {_rule_rows(records, 0)}
</section>
<section class="grid-3">
  <article class="facet">
    <p class="label">Run</p>
    <h3>Tests</h3>
    <pre><code>pip install -e ".[test]"
pytest</code></pre>
  </article>
  <article class="facet">
    <p class="label">Scan</p>
    <h3>One file</h3>
    <pre><code>seraph-scan path/to/mcp.json
seraph-scan --sigma event.json</code></pre>
  </article>
  <article class="facet">
    <p class="label">License</p>
    <h3>Split on purpose</h3>
    <p>Rules: Detection Rule License 1.1. Code, harness, and this site: Apache-2.0. CC-BY-4.0 was the other serious option for the rules. DRL keeps the author attached when a detection product uses the rule.</p>
  </article>
</section>
"""


def _threat() -> str:
    source = (CONTENT_DIR / "threat-model.md").read_text(encoding="utf-8")
    body = markdown_to_html(source)
    return f'<article class="prose">{body}</article>'


def _rules_index(records) -> str:
    return f"""
<p class="eyebrow">Rule catalog</p>
<h1>Rules</h1>
<p class="deck">YARA judges bytes. Sigma judges a normalized macOS event. Read the threat model for the field contract before you wire the Sigma rules to a collector.</p>
{_rule_rows(records, 1)}
"""


def _rule_page(record) -> str:
    source = writeup_path(record).read_text(encoding="utf-8")
    body_md = re.sub(r"^# .+\n", "", source, count=1)
    writeup = markdown_to_html(body_md)
    references = "".join(
        f"<li><a href=\"{html.escape(ref)}\">{html.escape(ref)}</a></li>" for ref in record.references
    )
    positives = "".join(f"<li>{html.escape(item)}</li>" for item in record.false_positives)
    return f"""
<p class="eyebrow">{html.escape(record.seraph_id)} · {html.escape(record.kind)} · {_severity(record.severity)}</p>
<h1>{html.escape(record.title)}</h1>
<p class="deck">{html.escape(record.description)}</p>
<div class="meta-grid">
  <div><span>Author</span>{html.escape(record.author if "Light Architects" in record.author else record.author + " · Light Architects")}</div>
  <div><span>Date</span>{html.escape(record.date)}</div>
  <div><span>ATT&amp;CK</span>{_technique_links(record.attack)}</div>
  <div><span>Tactic</span>{html.escape(record.tactic)}</div>
  <div><span>License</span>{html.escape(record.license)}</div>
  <div><span>Scope</span>{html.escape(record.scope)}</div>
</div>
<h2>False positives</h2>
<ul>{positives}</ul>
<h2>References</h2>
<ul>{references}</ul>
<article class="prose">
{writeup}
</article>
<p class="note">Fixtures live under <code>tests/fixtures/{html.escape(record.kind)}/{html.escape(record.name)}/</code>. Positives match this rule and no other SERAPH rule. Negatives match none.</p>
"""


def render(target: Path) -> None:
    records = load_records()
    (target / "rules").mkdir(parents=True, exist_ok=True)
    pages = {
        target / "index.html": _page("SERAPH · Light Architects", _landing(records), 0, "home"),
        target / "threat-model.html": _page(
            "Threat model · SERAPH", _threat(), 0, "threat"
        ),
        target / "rules" / "index.html": _page("Rules · SERAPH", _rules_index(records), 1, "rules"),
    }
    for record in records:
        pages[target / "rules" / f"{record.name}.html"] = _page(
            f"{record.title} · SERAPH", _rule_page(record), 1, "rules"
        )
    for path, contents in pages.items():
        path.write_text(contents, encoding="utf-8")


def check() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        rendered = Path(tmp) / "docs"
        render(rendered)
        expected = [
            Path("index.html"),
            Path("threat-model.html"),
            Path("rules") / "index.html",
        ]
        expected.extend(Path("rules") / f"{record.name}.html" for record in load_records())
        for relative in expected:
            got = (rendered / relative).read_text(encoding="utf-8")
            live = DOCS / relative
            if not live.is_file() or live.read_text(encoding="utf-8") != got:
                raise SystemExit(f"docs out of date: docs/{relative}. Run python -m seraph.docsgen")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Render the SERAPH docs site.")
    parser.add_argument("--check", action="store_true", help="Fail if committed HTML drifts.")
    args = parser.parse_args(argv)
    if args.check:
        check()
        return
    render(DOCS)


if __name__ == "__main__":
    main()
