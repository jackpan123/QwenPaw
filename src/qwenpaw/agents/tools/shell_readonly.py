# -*- coding: utf-8 -*-
"""Read-only shell command classification for the role-based mutation gate.

Non-privileged members are denied ``MUTATE`` tool calls, which used to
block the shell tool outright.  This module lets the shell tool resolve
its effect per invocation: a command that parses as a pipeline of
whitelisted read-only commands resolves to :class:`ActionEffect.READ`
(allowed for members); anything else resolves to ``MUTATE`` (denied,
unchanged behavior).

The classifier is deliberately conservative:

* no shell metacharacters outside single quotes — no redirection
  (``>`` ``<``), chaining (``;`` ``&&`` ``||`` ``&``), subshells
  (``( )``), command/variable substitution (``$`` backticks), escapes
  (``\\``) or newlines;
* every pipeline segment must start with a whitelisted read-only
  command;
* arguments may not reference absolute paths, ``~`` or ``..`` — members
  stay inside the agent workspace (the shell tool's default cwd);
* ``find`` is rejected when given action flags (``-exec``/``-delete``…).

Note: classification gates *execution*, it does not sandbox it — a
whitelisted command still reads any workspace file the process can read
(including other users' session transcripts of the same agent).
"""

from __future__ import annotations

import shlex
from typing import Any, Optional

from ...runtime.tool_registry import ToolEffectSpec
from ...security.mutation_guard import ActionEffect

# View-only commands: no write flags, no process control, no network.
# ``env``/``printenv`` are deliberately absent (they would dump provider
# API keys from the process environment).
READONLY_COMMANDS: frozenset = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "grep",
        "egrep",
        "fgrep",
        "find",
        "pwd",
        "wc",
        "sort",
        "uniq",
        "cut",
        "tr",
        "df",
        "du",
        "free",
        "ps",
        "date",
        "uptime",
        "whoami",
        "id",
        "uname",
        "hostname",
        "echo",
        "file",
        "stat",
        "which",
        "tree",
        "lscpu",
        "lsblk",
    },
)

# ``find`` flags that execute commands or write/delete files.  The
# ``-fprint``/``-fprintf`` family is matched by prefix below.
_FIND_ACTION_FLAGS = frozenset(
    {
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fls",
    },
)

# Metacharacters rejected everywhere outside single quotes.  Inside
# double quotes ``$`` and backticks still expand in bash, so they are
# rejected there too (see _split_pipeline).
_FORBIDDEN_CHARS = frozenset("$`&;<>()\\\n\r")


def _split_pipeline(command: str) -> Optional[list]:
    # pylint: disable=too-many-return-statements,too-many-branches
    """Split a command into per-segment argv lists.

    Returns ``None`` when the command uses any shell feature beyond a
    simple pipeline (redirection, chaining, substitution, escapes) or
    fails to parse.  Single-quoted spans are literal; inside double
    quotes ``$`` and backticks are rejected because bash would still
    expand them.
    """
    segments: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == quote:
                quote = ""
            elif quote == '"' and ch in "$`":
                return None
            buf.append(ch)
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch in _FORBIDDEN_CHARS:
            return None
        elif ch == "|":
            if command[i + 1 : i + 2] == "|":
                return None
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if quote:
        return None
    segments.append("".join(buf))

    pipeline = []
    for segment in segments:
        try:
            argv = shlex.split(segment)
        except ValueError:
            return None
        if not argv:
            return None
        pipeline.append(argv)
    return pipeline


def _is_forbidden_path(arg: str) -> bool:
    """Absolute paths, ``~`` expansion and ``..`` escape the workspace."""
    if arg.startswith(("/", "~")):
        return True
    return ".." in arg.split("/")


def is_readonly_shell_command(command: Any) -> bool:
    """Return True only when every pipeline segment is read-only safe."""
    if not isinstance(command, str):
        return False
    pipeline = _split_pipeline(command.strip())
    if pipeline is None:
        return False
    for argv in pipeline:
        if argv[0] not in READONLY_COMMANDS:
            return False
        args = argv[1:]
        if argv[0] == "find" and any(
            a in _FIND_ACTION_FLAGS or a.startswith("-fprint") for a in args
        ):
            return False
        if any(_is_forbidden_path(a) for a in args):
            return False
    return True


class ShellCommandEffectSpec(ToolEffectSpec):
    """Resolve the shell tool's effect from the concrete ``command``.

    Read-only pipelines resolve to :class:`ActionEffect.READ`; anything
    else (including a missing/unparseable command, or a caller-chosen
    ``cwd`` that could escape the workspace) resolves to ``MUTATE`` —
    fail closed, identical to the pre-classification behavior.
    """

    def resolve(self, params: dict | None) -> ActionEffect:
        params = params or {}
        if params.get("cwd") is not None:
            return ActionEffect.MUTATE
        if is_readonly_shell_command(params.get("command")):
            return ActionEffect.READ
        return ActionEffect.MUTATE


__all__ = [
    "READONLY_COMMANDS",
    "ShellCommandEffectSpec",
    "is_readonly_shell_command",
]
