"""Confirmation-bypass checks, and the patterns the YARA rule is generated from.

tools/build_phrase_rules.py reads the pattern strings below and writes
rules/src/yara/instruction_unsafe_directive.yar. The CLI and a YARA-only
scanner are meant to agree on the instruction fixtures. Edit the patterns
here, then regenerate. Do not hand-edit the generated rule.
"""

from __future__ import annotations

import re

# What counts as a gap between two words, as UTF-8 bytes: a space, a tab, a
# vertical tab, a form feed, a carriage return, U+0085, U+00A0, U+1680, U+2000 to
# U+200D (the Unicode spaces and the zero-width marks), U+2028, U+2029, U+202F,
# U+205F, U+2060, U+3000, and U+FEFF, plus the asterisk so that Markdown
# emphasis (Do **not** ask) does not split a phrase. It has no newline, so a
# phrase never spans two lines. Every \s in a pattern below means this, except
# in the sentence lists, where \g is the same gap plus one newline, so that a
# hard-wrapped sentence (Do not / ask for confirmation) is still one phrase.
# \s is a space, a tab, a vertical tab, a form feed, a carriage return, a no-break
# space or another Unicode space or line separator, or a zero-width mark. It has no
# newline and no asterisk: it is the gap in every COMMAND pattern (a fetch, an
# installer line, a substitution), where a character that a shell treats as a glob
# or as an argument must never read as a blank.
# \e is \s plus the asterisk, so that Markdown emphasis (Do **not** ask) does not
# split a sentence. It is used in sentence-like patterns and in negations.
# \g is \e plus one newline, so that a hard-wrapped sentence (Do not / ask for
# confirmation) is still one phrase. It is used in the sentence lists.
GAP_BYTES = (
    r"([ \t\x0B\x0C\r]|\xC2[\x85\xA0]|\xE1\x9A\x80|\xE2\x80[\x80-\x8D\xA8\xA9\xAF]"
    r"|\xE2\x81[\x9F\xA0]|\xE3\x80\x80|\xEF\xBB\xBF)"
)
EMPH_GAP_BYTES = GAP_BYTES.replace("[ \\t", "[ \\t*", 1)
WRAP_GAP_BYTES = GAP_BYTES.replace("[ \\t", "[ \\t*\\n", 1)


def wrapped(pattern: str) -> str:
    """Let every gap in a sentence pattern cross one line break."""
    return pattern.replace(r"\s", r"\g").replace(r"\e", r"\g")


def emph(pattern: str) -> str:
    """Let every gap in a sentence-like pattern be crossed by Markdown emphasis."""
    return pattern.replace(r"\s", r"\e")


# An apostrophe in "don't": straight, curly, a backtick, or none.
APOSTROPHE = "('|\u2019|`)?"
# "never", "do not", "don't", "must not", "should not", then a gap. A bypass
# phrase or a fetch that follows one of these is a prohibition, not an instruction.
# The word boundary keeps "whenever" from reading as "never".
# The negation gap is \e, so emphasis is fine and a line break is not: a "never" at the
# end of one line does not veto a command that starts the next. Only the sentence-list
# vetoes below wrap it.
NEGATION_PATTERN = r"\b(never|do\e+not|don" + APOSTROPHE + r"t|must\e+not|should\e+not)\e+(ever\e+)?"
# How far into its line a phrase may start and still be judged with its line,
# in bytes. yara-python 4.5.4 does not match a regex span much longer than this,
# so a larger number would make the engines disagree. A phrase further into its
# line than this is a match outright: nobody pads an instruction by a kilobyte.
# OUTER_BOUND is how many occurrences of one phrase the generated rule judges
# before it treats the count as a match.
LINE_REACH = 1000
OUTER_BOUND = 256


def byte_regex(pattern: str) -> str:
    """Translate one pattern in this module into a byte regex.

    The result is the text of the YARA string, and it is also what the CLI
    compiles. Both sides therefore match the same bytes: ASCII-only case
    folding, byte offsets, and the same gap class.
    """
    text = pattern.replace("(?:", "(")
    text = re.sub(r"(?<!\\)\.", r"[^\\n]", text)
    text = text.replace(r"\s", GAP_BYTES)
    text = text.replace(r"\e", EMPH_GAP_BYTES)
    text = text.replace(r"\g", WRAP_GAP_BYTES)
    text = text.replace(r"\w", "[A-Za-z0-9_]")
    text = re.sub(r"(?<!\\)/", r"\\/", text)
    # YARA's strict-escape check rejects an escaped double quote.
    text = text.replace('\\"', '"')
    # A character outside ASCII becomes its UTF-8 bytes.
    return "".join(
        char if ord(char) < 128 else "".join(f"\\x{byte:02X}" for byte in char.encode("utf-8"))
        for char in text
    )


def line_regex(body: str) -> str:
    """A whole line that holds ``body`` and does not open with # or |."""
    return (
        r"(^|\n)[ \t]*(" + body + r"|[^# \t|\n][^\n]{0," + str(LINE_REACH) + "}" + body + r")[^\n]*"
    )


def lean_line_regex(body: str) -> str:
    """``line_regex`` with the body written once, for bodies too large to repeat."""
    return r"(^|\n)[ \t]*([^# \t|\n][^\n]{0," + str(LINE_REACH) + "})?(" + body + r")[^\n]*"


def compile_bytes(pattern: str, *, translated: bool = False) -> re.Pattern[bytes]:
    text = pattern if translated else byte_regex(pattern)
    return re.compile(text.encode("ascii"), re.IGNORECASE)


_PATH = re.compile(
    r"(/agents\.md|/claude\.md|/gemini\.md|/skill\.md|/\.cursorrules|"
    r"/copilot-instructions\.md|/\.cursor/rules/|\.mdc$|/\.windsurfrules$|/\.windsurf/rules/|"
    r"/\.clinerules($|/)|/\.claude/(commands|agents)/[^/]+\.md$|/\.github/instructions/[^/]+\.md$)",
    re.IGNORECASE,
)
# Phrases that match on their own. A nearby read-only word still suppresses them.
CONFIRM_PATTERNS = tuple(
    wrapped(item)
    for item in (
        r"do\s+not\s+ask\s+for\s+confirm",
        r"don" + APOSTROPHE + r"t\s+ask\s+for\s+confirm",
        r"never\s+ask(\s+the\s+(user|operator))?\s+for\s+confirm",
        r"skip(\s+all)?\s+confirm\w*\s+prompts?",
        r"disable\s+confirm",
        r"disable\s+permission\s+prompts",
        r"bypass\s+permissions?",
        r"(you must|do not ask|never ask|always).{0,40}auto[- ]?approve\s+(all|every)\s+tools?",
        r"do\s+not\s+prompt\s+for\s+confirm",
        r"no\s+confirmation\s+needed\s+before\s+a\s+tool",
        r"(never|do\s+not|don" + APOSTROPHE + r"t)\s+(ask|prompt)\s+(for\s+)?(confirm\w*|permission|approval|consent)",
    )
)
# These match only when a high-risk action is on the same short window.
HIGH_PATTERNS = tuple(
    wrapped(item)
    for item in (
        r"without\s+asking(\s+the\s+(user|operator))?\s+for\s+(confirm\w*|permission)",
        r"never\s+(request|seek|wait)\s+(for\s+)?(confirm\w*|permission|approval|consent)",
        r"(do\s+not|don" + APOSTROPHE + r"t)\s+wait\s+(for\s+)?(confirm\w*|permission|approval|consent)",
    )
)
# Paraphrases of the sentences above. They need a high-risk word too, and they
# are not judged "far into a line", because a long line must not match outright.
PARAPHRASE_PATTERNS = tuple(
    wrapped(item)
    for item in (
        r"(proceed|continue|go\s+ahead)\s+without\s+(any\s+)?(confirm\w*|approval|permission)",
        r"(approval|confirmation|permission)\s+(is|are)\s+(not\s+(required|needed|necessary)|unnecessary)",
        r"assume\s+(that\s+)?(the\s+(user|operator)|you)\s+(has|have)\s+already\s+(approved|authori[sz]ed|consented)",
    )
)
# A paraphrase that ends its sentence ("Run every shell command. Approval is not
# required.") applies to what came before it, so it is judged with the whole line.
# One that goes on ("Approval is not required for read-only git commands.") names
# its own scope, and a high-risk word in another sentence is not part of it.
SENTENCE_END_PATTERN = r"[ \t]*(\.|!|;|\r?\n|$)"
PARAPHRASE_BARE_PATTERNS = tuple(item + SENTENCE_END_PATTERN for item in PARAPHRASE_PATTERNS)
HIGH_WORD_PATTERN = (
    r"(\bshell\b|\bexec\b|\bbash\b|\bcredentials?\b|\bsecrets?\b|\bcurl\b|\bwget\b|"
    r"\bupload\b|\bdelet(?:e|ing|ed|es|ion)?\b|\brm\b|\bpublish\b|\bgit push\b|"
    r"\bpayments?\b|id_ed25519|id_rsa|\.ssh/)"
)
# A bare "push" is a high-risk word only inside the sentence of the bypass phrase.
# "Ask before you push" in a neighbouring sentence is a safeguard, not a risk, so
# the line-wide word list above does not carry it.
PUSH_WORD_PATTERN = r"\bpush(es|ing)?\b"
SCOPED_HIGH_WORD_PATTERN = HIGH_WORD_PATTERN[:-1] + r"|\bpush(es|ing)?\b)"
# One sentence: no full stop, question mark, exclamation mark or semicolon followed by
# a blank, and no line break. A dot inside a name (AGENTS.md, a path) does not end it.
# Every string has exactly one parse, so a backtracking engine takes linear time, and the
# alternatives are few enough for libyara: a unit with more branches (e.g. and i.e. as
# branches of the repeated group) made libyara stop with "too many fibers" on a 4 MB
# executable, and a scan that stops is a file that goes unscanned. An abbreviation
# followed by a blank (e.g. for) ends a sentence here. It is read by its own pair of
# patterns in sentence_scoped, which have no repeated alternation.
SENTENCE_UNIT = r"([^\.!?;\n]|[\.!?;][^ \t\r\n\.!?;])"
ABBREVIATION = r"(e\.g\.|i\.e\.)[ \t]"
ABBREVIATION_SEGMENT = r"[^\.!?;\n]{0,80}"
SENTENCE_REACH = 160


def sentence_scoped(phrase: str, word: str) -> tuple[str, str, str, str]:
    """The phrase then the word, and the word then the phrase, inside one sentence.

    The last two read across one abbreviation (e.g. or i.e.) inside the sentence.
    """
    unit = SENTENCE_UNIT + "{0," + str(SENTENCE_REACH) + "}"
    across = ABBREVIATION_SEGMENT + ABBREVIATION + ABBREVIATION_SEGMENT
    return (phrase + unit + word, word + unit + phrase, phrase + across + word, word + across + phrase)


LOW_PATTERN = (
    r"(rename_chat|\blisting\b|\blist\b|\bread\b|\bview\b|\bsearch\b|\bls\b|"
    r"\bgit[ \t]+(status|log|diff)\b)"
)
POISON_PATTERN = (
    r"--dangerously-skip-permissions|--yolo\b|--always-approve|--auto-approve|"
    r"--trust-all-tools|--no-confirm\b|--permission-mode"
)
# Absolute same-line vetoes. A permission flag or a backticked status label.
ABSOLUTE_VETO_PATTERNS = (
    r"--[A-Za-z0-9].{0,40}(skip confirmation|confirm)",
    r"`[^`]{0,40}bypass\s+permissions?[^`]{0,40}`",
    # "never bypass permissions" and "do not disable confirmation" forbid the bypass.
    wrapped(NEGATION_PATTERN + r"(try\s+to\s+)?(bypass\s+permissions?|disable\s+confirm|disable\s+permission\s+prompts)"),
)
# Vetoes for the paraphrases: "never proceed without confirmation" and "never assume
# the user has approved" forbid them. A second string keeps each regex small.
# The paraphrase veto also reads the other ways to forbid: may not, cannot, is not
# allowed to, is forbidden to, under no circumstances, nothing may. Its gaps are
# plain ASCII blanks, line breaks and asterisks. A phrase that hides a veto behind
# a Unicode space is read as no veto, so the rule fails towards a match.
_G = r"[ \t\r\n*]+"
PARAPHRASE_NEGATION_PATTERN = (
    r"\b(never|do" + _G + "not|don" + APOSTROPHE + r"t|must" + _G + "not|should" + _G + "not|shall" + _G + "not|may"
    + _G + "not|cannot|can" + APOSTROPHE + "t|can" + _G + "not|nothing" + _G + "may|not" + _G + "(allowed|permitted)"
    + _G + "to|(forbidden|prohibited)" + _G + "(to|from)|under" + _G + "no" + _G + "circumstances)(,?" + _G
    + "(ever|under" + _G + "any" + _G + "circumstances,?))?" + _G
)
# What follows the verb has to be what the paraphrase is about: "never proceed without
# asking for confirmation" vetoes "proceed without confirmation", but "never proceed
# without a backup" does not. "Never assume" needs an object about approval within the
# sentence, so "never assume the build is green" does not veto "assume the user has
# already approved".
_CONFIRMATION = (
    "(any" + _G + ")?(asking(" + _G + "(the" + _G + ")?(user|operator))?(" + _G + "for)?" + _G + ")?"
    "(confirm[A-Za-z0-9_]*|approval|permission|consent)"
)
PARAPHRASE_VETO_PATTERNS = (
    PARAPHRASE_NEGATION_PATTERN
    + "((try"
    + _G
    + "to"
    + _G
    + ")?([A-Za-z0-9_]+"
    + _G
    + ")?assume[^\\.!?;\\n]{0,60}(approv|authori[sz]|consent|permission)"
    + "|([A-Za-z0-9_]+"
    + _G
    + ")?(proceed|continue|go"
    + _G
    + "ahead)"
    + _G
    + "without"
    + _G
    + _CONFIRMATION
    + ")",
)
# The phrases that need a high-risk word in their own sentence. The three older ones
# keep the line-wide word list as well (HIGH_PATTERNS); the paraphrases use this alone.
SCOPED_PHRASE_PATTERNS = tuple(
    pattern
    for phrases, word in ((HIGH_PATTERNS, PUSH_WORD_PATTERN), (PARAPHRASE_PATTERNS, SCOPED_HIGH_WORD_PATTERN))
    for item in phrases
    for pattern in sentence_scoped(item, word)
)
TOKENS = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "NPM_TOKEN",
    "CURSOR_API_KEY",
)
VENDOR_HOST = {
    "GITHUB_TOKEN": "github.com",
    "GH_TOKEN": "github.com",
    "GITHUB_PERSONAL_ACCESS_TOKEN": "github.com",
    "OPENAI_API_KEY": "openai.com",
    "ANTHROPIC_API_KEY": "anthropic.com",
    "NPM_TOKEN": "npmjs.org",
    "CURSOR_API_KEY": "cursor.com",
}
# AWS_SECRET_ACCESS_KEY has no vendor host on purpose. A SigV4 secret signs a
# request and is never sent, and any attacker can own a bucket under amazonaws.com.
# A vendor host has to end where the URL's authority ends. github.com.attacker.example
# and github.com@attacker.example are not GitHub.
# A quote, a bracket, or a backslash only ends the host when the token ends there
# too. A shell drops the backslash in github.com\\@attacker.example and joins
# "https://github.com"@attacker.example, so neither is GitHub.
HOST_END_PATTERN = r"(/|\?|#|[ \t\r\n]|$|\\?[\"')>`]([ \t\r\n,;\]}]|$))"
# High-precision signals. They do not use the confirmation veto. Three of them
# need more than the bare words: a recipient has to be a literal number or
# address, the inventory file has to sit beside what is being inventoried, and
# the CopyPasta license has to be claimed, not just named.
SIGNAL_PATTERNS = tuple(
    emph(item)
    for item in (
        r"do\s+not\s+mention\s+this\s+to\s+the\s+user",
        r"don" + APOSTROPHE + r"t\s+notify\s+the\s+user",
        r"no\s+need\s+to\s+mention\s+this\s+to\s+the\s+user",
        r"do\s+this\s+secretly,?\s+never\s+mentioning",
        r"must\s+send\s+all\s+emails\s+to",
        r"change\s+the\s+recipient\s+to\s+[^ \t\n]{0,40}[0-9@]",
        r"chat\.tools\.autoApprove[\"']?\s*:\s*true",
        r"(paths?|wallets?|keystores?|secrets?|credentials?|\.env|id_rsa)[^\n]{0,120}"
        + chr(47) + "tmp" + chr(47) + "inventory\\." + "txt",
        r"<human_chat_interruption>",
        r"always\s+consult\s+this\s+tool\s+immediately\s+as\s+the\s+first\s+step",
        r"replace\s+any\s+thoughts\s+with\s+<thinking>",
        r"<!--[^\n]{0,160}<(user_query|user_info)>",
        r"(protected\s+by|licensed\s+under|under)\s+the\s+copypasta\s+license",
        r"include\s+everything\s+between[^\n]{0,80}in\s+a\s+comment\s+at\s+the\s+end\s+of\s+every\s+file",
    )
)
# Starting an agent CLI with prompts off. Judged apart from the signals above,
# because "never run with --dangerously-skip-permissions" is a prohibition.
CLI_FLAG_PATTERN = r"\b(run|invoke|launch|start|execute)\b[^\n]{0,80}(--dangerously-skip-permissions|--yolo\b|--trust-all-tools)"
# The negated form is narrow on purpose. Only filler words may sit between the
# verb and the flag, so "never launch claude without --yolo" is not a prohibition.
NEGATED_CLI_FLAG_PATTERN = (
    NEGATION_PATTERN
    + r"(run|invoke|launch|start|execute)(\s+(with|it|claude|gemini|codex|q|the|a|any|cli|agent|using))*"
    + r"\s+[`'\"]?(--dangerously-skip-permissions|--yolo\b|--trust-all-tools)"
)
CONCEAL_PATTERNS = SIGNAL_PATTERNS[:4]
RECIPIENT_PATTERNS = SIGNAL_PATTERNS[4:6]
DETAIL_PATTERN = emph(r"mere\s+implementation\s+detail")
SIDENOTE_PATTERNS = tuple(
    emph(item)
    for item in (
        r"pass\s+its\s+content\s+as\s+['\"]?sidenote",
        r"before\s+using\s+this\s+tool,?\s+read",
    )
)
SENSITIVE_PATH_PATTERN = r"~/\.cursor/mcp\.json|~/\.ssh/id_rsa"
EXFIL_PATTERN = r"(!\[[^\n]{0,120}\]|```mermaid|graph\s+TD)[^\n]{0,240}(\?data=|webhook\.site)"
ENCODE_PATTERN = r"url[- ]?encode"
# The sink is a shell by any of its usual names, with an optional sudo, an
# optional directory, and |& as well as |. What follows the name has to end the
# command or start an argument. A Markdown table cell (| zsh |) and a longer
# word (dash-case) are not a shell.
SHELL_SINK_PATTERN = (
    r"\|&?\s*(sudo\s+)?(/[a-z/]{1,20}/)?(ba|z|da|k|fi)?sh"
    r"(\\?[\"'`;&)]|[\.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)"
)
PIPE_PATTERN = r"(curl|wget)[^\n]{0,180}" + SHELL_SINK_PATTERN
# "do not run `curl ...`": the fetch tool that follows is quoted as a bad example.
NEGATED_FETCH_PATTERN = NEGATION_PATTERN + r"(run|use|execute|pipe|paste)\s+(the\s+)?[`'\"]?(curl|wget)"
NEGATED_FETCH_BOUND = 256  # the generated rule compares this many "do not run" phrases
# Exact first-party installer URLs. Each was read on the vendor's own install page.
# A pipe is exempt only when the whole command is the vendor's documented shape:
# the fetch tool in command position, options from a closed list, one of these
# URLs and nothing after it, then the pipe into sh or bash. A second URL, a header,
# a path after the URL, or any other option keeps the match. A third-party repository is never listed here.
# A benign corpus line that pipes one is recorded in validation/fp-allowlist.txt.
INSTALLER_URLS = (
    "https://antigravity.google/cli/install.sh",
    "https://sh.rustup.rs",
    "https://get.docker.com",
    "https://deno.land/install.sh",
    "https://bun.com/install",
    "https://bun.sh/install",
    "https://astral.sh/uv/install.sh",
    "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh",
    "https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh",
    "https://install.ohmyz.sh/",
)
# The command has to sit in command position: at the start of a line, after a
# shell prompt, or right after a backtick. PATH=./bin:$PATH curl and ./bin/curl
# are not the vendor's line.
INSTALLER_PREFIX_PATTERN = r"(^|\n|`)[ \t$]{0,39}"
# Options are a closed list. A generic dash option would let -K (a config file),
# -x (a proxy), or wget -i (a URL list) choose what is downloaded.
INSTALLER_OPTION_PATTERN = (
    r"(-[fsSLqO]{1,5}-?|--proto|['\"]=https['\"]|--tlsv1\.2|--silent|--show-error|--fail|--location)"
)
# Bounded on purpose. The whole line stays shorter than PIPE_PATTERN's window, so a
# listed line is always one PIPE_PATTERN match and the generated rule can compare counts.
# After the shell only "-s" and plain words may follow, so "| sh ./other.sh" and
# "| sh -s -c ..." are not exempt.
INSTALLER_FETCH_PATTERN = (
    r"(curl|wget)(\s{1,2}" + INSTALLER_OPTION_PATTERN + r"){0,4}\s{1,2}['\"]?("
    + "|".join(re.escape(url) for url in INSTALLER_URLS)
    + r")['\"]?"
)
INSTALLER_BODY_PATTERN = (
    INSTALLER_FETCH_PATTERN
    + r"\s{0,2}\|\s{0,2}(ba)?sh"
    # Only "-s", an optional "--", and plain words may follow the shell.
    + r"([ \t]+-s([ \t]+--)?([ \t]+[A-Za-z0-9_=\./:-]{1,40}){0,4})?[ \t]*(`|\r?\n|$)"
)
INSTALLER_PIPE_PATTERN = INSTALLER_PREFIX_PATTERN + INSTALLER_BODY_PATTERN
# The same fetch run through command substitution: bash -c "$(curl ...)", eval
# "$(curl ...)", or source <(curl ...). The vendor's own line is exempt when the
# whole line is the listed installer URL and nothing follows the closing bracket.
SUBST_HEAD_PATTERN = (
    r"(\b(eval|(ba|z|da|k)?sh[ \t]+-c)[ \t]+[\"'`]?\$\(|(\bsource|[ \t;&|(]\.)[ \t]+<\()[ \t]*"
)
SUBST_PATTERN = SUBST_HEAD_PATTERN + r"(curl|wget)\b"
SUBST_INSTALLER_PATTERN = (
    SUBST_HEAD_PATTERN + INSTALLER_FETCH_PATTERN + r"\s{0,2}\)[\"']?\.?[ \t]*(`|\r?\n|$)"
)
NEGATED_SUBST_PATTERN = NEGATION_PATTERN + r"(run|use|execute|paste)\s+(the\s+)?[`'\"]?" + SUBST_PATTERN
# "do not ask for confirmation" with at least one Cyrillic о (U+043E) standing for
# a Latin o, whichever of its five o's it replaces. A plain Latin spelling is the
# job of the confirmation patterns above, so this one needs a Cyrillic letter and
# is never vetoed. Kept here so the generated rule carries no private copy.
_CYR = "\u043e"
_SLOT = f"(o|{_CYR})"


def _homo_variant(forced: int) -> str:
    slots = [_CYR if index == forced else _SLOT for index in range(5)]
    return (
        f"d{slots[0]}[ \\t]+n{slots[1]}t[ \\t]+ask[ \\t]+f{slots[2]}r[ \\t]+c{slots[3]}nfirmati{slots[4]}n"
    )


HOMO_PATTERN = "(" + "|".join(_homo_variant(index) for index in range(5)) + ")"
CRED_FORWARD = r"(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)[^\n]{0,320}(curl |wget )"
CRED_REVERSE = r"(curl |wget )[^\n]{0,320}(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)"
INJECT_FORWARD = emph(r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions[^\n]{0,400}(curl |wget |https?:\/\/)")
INJECT_REVERSE = emph(r"(curl |wget |https?:\/\/)[^\n]{0,400}(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions")

# A JSON file counts as tool descriptions only when it also has one of these keys.
# A CLI manifest or an API description has a "description" key and is not a tool list.
TOOL_KEY_PATTERN = r'"(tools|inputSchema|input_schema|mcpServers|context_servers)"'
_TOOL_KEY = re.compile(TOOL_KEY_PATTERN.encode())
MAX_FILE_BYTES = 5_000_000

# A file is treated as binary when its first kilobyte holds this many control
# bytes. Two ASCII letters (MZ) or one NUL are not enough. The path-scoped rules
# do not use this at all: a file named AGENTS.md is read as instructions.
BINARY_CONTROL_BYTES = 8
BINARY_GUARD_YARA = (
    "not for 8 i in (0..1023): "
    "(i < filesize and (uint8(i) < 9 or (uint8(i) > 13 and uint8(i) < 32 and uint8(i) != 27)))"
)


def looks_binary(data: bytes) -> bool:
    """The Python twin of BINARY_GUARD_YARA."""
    head = data[:1024]
    count = sum(1 for byte in head if byte < 9 or (13 < byte < 32 and byte != 27))
    return count >= BINARY_CONTROL_BYTES


# Everything below reads bytes with the same patterns the generated rule holds,
# and follows that rule's condition step by step. Offsets are byte offsets.
URL_PATTERN = r"https?://[^ \t\r\n\"'/?#\\]{1,255}"
FETCH_PATTERN = r"(curl |wget )"
_HIGH = compile_bytes(HIGH_WORD_PATTERN)
_SOFT = compile_bytes(f"({POISON_PATTERN})|({LOW_PATTERN})")
# Two veto sets. The general one applies to every sentence list. The second one
# ("never assume", "never proceed without") applies only to the lists that those
# prohibitions are about: the "without asking" and paraphrase patterns. Applied to
# the others it would let "Never assume anything. Do not ask for confirmation"
# hide a real instruction behind an unrelated prohibition on the same line.
_BAD = compile_bytes("|".join(ABSOLUTE_VETO_PATTERNS))
_BADP = compile_bytes("|".join(PARAPHRASE_VETO_PATTERNS))
_CONFIRM_LINES = tuple(compile_bytes(line_regex(byte_regex(item)), translated=True) for item in CONFIRM_PATTERNS)
_HIGH_LINES = tuple(
    compile_bytes(line_regex(byte_regex(item)), translated=True) for item in HIGH_PATTERNS + PARAPHRASE_BARE_PATTERNS
)
_SCOPED_LINES = tuple(
    compile_bytes(lean_line_regex(byte_regex(item)), translated=True) for item in SCOPED_PHRASE_PATTERNS
)
_BARE = tuple(compile_bytes(item) for item in CONFIRM_PATTERNS + HIGH_PATTERNS)
_PLAIN = tuple(compile_bytes(item) for item in (CRED_FORWARD, CRED_REVERSE, INJECT_FORWARD, INJECT_REVERSE))
_HOMO = compile_bytes(HOMO_PATTERN)
_URL = compile_bytes(URL_PATTERN)
_FETCH = compile_bytes(FETCH_PATTERN)
_TOKENS: tuple[tuple[re.Pattern[bytes], re.Pattern[bytes] | None], ...] = tuple(
    (
        re.compile(rb"\b(" + "|".join(names).encode() + rb")\b"),
        compile_bytes(rf"https?://([A-Za-z0-9-]+\.)*{re.escape(host)}{HOST_END_PATTERN}") if host else None,
    )
    for host, names in (
        [(host, [t for t in TOKENS if VENDOR_HOST.get(t) == host]) for host in dict.fromkeys(VENDOR_HOST.values())]
        + [("", [t for t in TOKENS if t not in VENDOR_HOST])]
    )
    if names
)
_SIGNALS = tuple(compile_bytes(item) for item in SIGNAL_PATTERNS)
_CONCEAL_RECIPIENT = tuple(compile_bytes(item) for item in CONCEAL_PATTERNS + RECIPIENT_PATTERNS)
_DETAIL = compile_bytes(DETAIL_PATTERN)
_SIDENOTE = tuple(compile_bytes(item) for item in SIDENOTE_PATTERNS)
_SENSITIVE = re.compile(byte_regex(SENSITIVE_PATH_PATTERN).encode("ascii"))
_EXFIL = compile_bytes(EXFIL_PATTERN)
_ENCODE = compile_bytes(ENCODE_PATTERN)
_PIPE = compile_bytes(PIPE_PATTERN)
_INSTALLER_BODY = compile_bytes(INSTALLER_BODY_PATTERN)
_NEGATED_FETCH = compile_bytes(NEGATED_FETCH_PATTERN)
_SUBST = compile_bytes(SUBST_PATTERN)
_SUBST_INSTALLER = compile_bytes(SUBST_INSTALLER_PATTERN)
_NEGATED_SUBST = compile_bytes(NEGATED_SUBST_PATTERN)
_CLI_FLAG = compile_bytes(CLI_FLAG_PATTERN)
_NEGATED_CLI_FLAG = compile_bytes(NEGATED_CLI_FLAG_PATTERN)
_MARKERS = (
    b"agent instructions",
    b"agents.md",
    b"claude.md",
    b"gemini.md",
    b"skill.md",
    b".cursorrules",
    b"copilot-instructions",
    b".cursor/rules/",
)


def _is_tool_json(data: bytes) -> bool:
    return b'"description"' in data and _TOOL_KEY.search(data) is not None


def in_scope(data: bytes, filepath: str, *, use_filepath: bool) -> bool:
    if use_filepath:
        if _PATH.search(filepath or ""):
            return True
        return (filepath or "").lower().endswith((".json", ".jsonc")) and _is_tool_json(data)
    if data[:1] == b"{" and _is_tool_json(data):
        return True
    folded = data.lower()
    return any(marker in folded for marker in _MARKERS)


def _starts(pattern: re.Pattern[bytes], data: bytes, low: int = 0, high: int | None = None) -> list[int]:
    """Every offset in [low, high] where ``pattern`` matches, overlapping ones too."""
    found: list[int] = []
    position = max(0, low)
    limit = len(data) if high is None else min(high, len(data))
    while position <= limit:
        match = pattern.search(data, position)
        if match is None or match.start() > limit:
            break
        found.append(match.start())
        position = match.start() + 1
    return found


def _starts_in(pattern: re.Pattern[bytes], data: bytes, low: int, high: int) -> bool:
    match = pattern.search(data, max(0, low))
    return match is not None and match.start() <= high


def _occurrence_hit(
    pattern: re.Pattern[bytes], data: bytes, *, needs_high: bool, scoped: bool = False
) -> bool:
    # needs_high is true for exactly the lists the paraphrase vetoes are about.
    count = 0
    for match in pattern.finditer(data):
        count += 1
        if count > OUTER_BOUND:
            # More occurrences than the generated rule judges.
            return True
        low, high = match.start(), match.end() - 1
        if _starts_in(_BAD, data, low, high) or (needs_high and _starts_in(_BADP, data, low, high)):
            continue
        if scoped:
            # The pattern itself holds the high-risk word, inside the phrase's sentence.
            return True
        risky = _starts_in(_HIGH, data, low, high)
        if _starts_in(_SOFT, data, low, high) and not risky:
            continue
        if needs_high and not risky:
            continue
        return True
    return False


def _far_hit(data: bytes) -> bool:
    """A bypass phrase more than LINE_REACH + 1 bytes into its line."""
    span = LINE_REACH + 2
    for pattern in _BARE:
        for start in _starts(pattern, data)[:OUTER_BOUND]:
            if start >= span and b"\n" not in data[start - span : start]:
                return True
    return False


def _phrase_hit(data: bytes) -> bool:
    return (
        _far_hit(data)
        or any(_occurrence_hit(pattern, data, needs_high=False) for pattern in _CONFIRM_LINES)
        or any(_occurrence_hit(pattern, data, needs_high=True) for pattern in _HIGH_LINES)
        or any(_occurrence_hit(pattern, data, needs_high=True, scoped=True) for pattern in _SCOPED_LINES)
    )


def _token_exfil(data: bytes) -> bool:
    for token, vendor in _TOKENS:
        for anchor in _starts(token, data)[:OUTER_BOUND]:
            low, high = anchor - 200, anchor + 200
            urls = len(_starts(_URL, data, low, high))
            vendors = len(_starts(vendor, data, low, high)) if vendor is not None else 0
            if urls > vendors and _starts_in(_FETCH, data, low, high):
                return True
    return False


_FETCH_NAME = re.compile(rb"curl|wget", re.IGNORECASE)
_BLANKS = b" \t$"


def _command_position(data: bytes, start: int) -> bool:
    """The fetch tool starts a line, follows a shell prompt, or follows a backtick."""
    for back in range(1, 41):
        if start < back:
            return True  # only blanks back to the start of the file
        byte = data[start - back : start - back + 1]
        if byte in (b"\n", b"`"):
            return True
        if byte not in (b" ", b"\t", b"$"):
            return False
    return False


def installer_pipe_allowlisted(data: bytes, start: int = 0) -> bool:
    """True when the fetch tool at ``start`` begins a listed installer line."""
    return _INSTALLER_BODY.match(data, start) is not None and _command_position(data, start)


def _pipe_hit(data: bytes) -> bool:
    pipes = [name.start() for name in _FETCH_NAME.finditer(data) if _PIPE.match(data, name.start())]
    if len(pipes) > OUTER_BOUND:
        return True
    negated_ends = set()
    for start in _starts(_NEGATED_FETCH, data)[:NEGATED_FETCH_BOUND]:
        negated_ends.add(_NEGATED_FETCH.match(data, start).end())
    for start in pipes:
        if installer_pipe_allowlisted(data, start):
            continue
        if start + 4 in negated_ends:
            continue
        return True
    return False


def _subst_hit(data: bytes) -> bool:
    # Each exemption belongs to one fetch. A listed installer line exempts the
    # substitution that starts where it starts. A "do not run" sentence exempts the
    # substitution that ends where it ends. One line cannot exempt two fetches, and
    # two exemptions on one fetch cannot cancel another.
    negated_ends = {
        _NEGATED_SUBST.match(data, start).end() for start in _starts(_NEGATED_SUBST, data)[:OUTER_BOUND]
    }
    starts = _starts(_SUBST, data)
    if len(starts) > OUTER_BOUND:
        return True
    for start in starts:
        if _SUBST_INSTALLER.match(data, start) is not None:
            continue
        if _SUBST.match(data, start).end() in negated_ends:
            continue
        return True
    return False


def _cli_flag_hit(data: bytes) -> bool:
    # A prohibition negates exactly the flag sentence that follows it.
    return len(_starts(_CLI_FLAG, data)) > len(_starts(_NEGATED_CLI_FLAG, data))


def _near_hit(left: re.Pattern[bytes], rights: tuple[re.Pattern[bytes], ...], data: bytes, reach: int = 400) -> bool:
    for anchor in _starts(left, data)[:OUTER_BOUND]:
        if any(_starts_in(right, data, anchor - reach, anchor + reach) for right in rights):
            return True
    return False


def _signal_hit(data: bytes) -> bool:
    return (
        any(pattern.search(data) for pattern in _SIGNALS)
        or _cli_flag_hit(data)
        or _near_hit(_DETAIL, _CONCEAL_RECIPIENT, data)
        or any(_near_hit(side, (_SENSITIVE,), data) for side in _SIDENOTE)
        or _near_hit(_EXFIL, (_ENCODE,), data)
        or _pipe_hit(data)
        or _subst_hit(data)
    )


def instruction_bypass(data: bytes, filepath: str, *, use_filepath: bool) -> bool:
    """True when the Python twin of SUSP_SERAPH_Instruction_Unsafe_Directive matches."""
    if not data or len(data) >= MAX_FILE_BYTES:
        return False
    if not in_scope(data, filepath, use_filepath=use_filepath):
        return False
    if not use_filepath and looks_binary(data):
        return False
    return (
        _HOMO.search(data) is not None
        or any(pattern.search(data) for pattern in _PLAIN)
        or _phrase_hit(data)
        or _token_exfil(data)
        or _signal_hit(data)
    )
