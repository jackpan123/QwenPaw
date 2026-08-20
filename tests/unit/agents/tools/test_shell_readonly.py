# -*- coding: utf-8 -*-
"""UT for the read-only shell command classifier and its effect spec.

Non-privileged members (guarded, can_mutate=False) may run read-only
shell commands (``ls``, ``df``, ``grep`` …) while anything else stays
denied.  The classifier is the security core of the feature: every
bypass shape (redirection, chaining, substitution, escapes, path
escape, dangerous flags) must resolve to MUTATE.
"""

from __future__ import annotations

# pylint: disable=protected-access

from types import SimpleNamespace

import pytest

from qwenpaw.agents.tools.shell_readonly import (
    ShellCommandEffectSpec,
    is_readonly_shell_command,
)
from qwenpaw.security.mutation_guard import ActionEffect, tool_gate

# ---------------------------------------------------------------------------
# is_readonly_shell_command — allowed shapes
# ---------------------------------------------------------------------------

ALLOWED = [
    "ls",
    "ls -la",
    "pwd",
    "df -h",
    "free -m",
    "ps aux",
    "date",
    "uptime",
    "whoami",
    "uname -a",
    "cat notes.txt",
    "head -n 20 app.log",
    'grep "error" app.log',
    "grep -rn 'TODO' .",
    "find . -name '*.py'",
    "wc -l *.md",
    "sort ids.txt | uniq -c | sort -nr",
    "ps aux | grep python | grep -v grep",
    "ls | grep '^\\d'  ",  # whitespace tolerated
    'echo "hello world"',
    "stat pyproject.toml",
    "du -sh .",
    "tree -L 2",
]

# ---------------------------------------------------------------------------
# is_readonly_shell_command — denied shapes (must NEVER read as read-only)
# ---------------------------------------------------------------------------

DENIED = [
    "",  # empty
    "   ",
    "rm -rf x",  # non-whitelisted command
    "sh",  # shells are not read-only
    "bash -c ls",
    "sudo ls",
    "env",  # would dump provider API keys
    "printenv",
    "sed -n 1p x",  # sed e-flag can execute
    "awk '{print $1}' x",  # awk system()
    "ls > files.txt",  # redirection
    "ls >> files.txt",
    "grep x app.log 2> err.txt",
    "cat < input.txt",
    "ls; pwd",  # chaining
    "ls && pwd",
    "ls || pwd",
    "ls &",
    "cat $(ls)",  # command substitution
    "cat `ls`",
    'echo "$HOME"',  # expands inside double quotes
    "echo $HOME",
    "cat ~/",  # tilde escape
    "cat ~/.bashrc",
    "cat /etc/passwd",  # absolute path
    "ls -la /tmp",
    "cat ../secrets.txt",  # parent traversal
    "cat a/../../b",
    "find . -delete",  # find action flags
    "find . -exec rm {} ;",  # (also has metachars; flag alone suffices)
    "find . -fprintf out.txt '%p'",
    "cat 'unterminated",
    'echo "unterminated',
    "cat a\\ b",  # backslash escape games
    "cat file\nid",  # literal newline join
    "FOO=bar ls",  # env-prefix is not a whitelisted command
    "/bin/ls",  # absolute command path
    "ls | sh",  # pipeline segment must also be whitelisted
    "ls | cat | rm x",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_readonly_commands_allowed(command):
    assert is_readonly_shell_command(command) is True


@pytest.mark.parametrize("command", DENIED)
def test_non_readonly_commands_denied(command):
    assert is_readonly_shell_command(command) is False


def test_non_string_command_denied():
    assert is_readonly_shell_command(None) is False
    assert is_readonly_shell_command(["ls"]) is False


# ---------------------------------------------------------------------------
# ShellCommandEffectSpec.resolve
# ---------------------------------------------------------------------------


def _spec():
    return ShellCommandEffectSpec(default=ActionEffect.MUTATE)


def test_spec_readonly_resolves_read():
    assert _spec().resolve({"command": "ls -la"}) is ActionEffect.READ


def test_spec_mutation_resolves_mutate():
    assert _spec().resolve({"command": "rm -rf x"}) is ActionEffect.MUTATE


def test_spec_missing_command_fails_closed():
    assert _spec().resolve(None) is ActionEffect.MUTATE
    assert _spec().resolve({}) is ActionEffect.MUTATE


def test_spec_custom_cwd_fails_closed():
    # A caller-chosen cwd could escape the agent workspace.
    assert (
        _spec().resolve({"command": "ls", "cwd": "/etc"})
        is ActionEffect.MUTATE
    )


# ---------------------------------------------------------------------------
# Through the authoritative tool gate with a member principal
# ---------------------------------------------------------------------------

_DENY_MESSAGE = "Permission denied."


def _patch_mutation_guard(monkeypatch, *, enabled: bool = True):
    fake_config = SimpleNamespace(
        security=SimpleNamespace(
            mutation_guard=SimpleNamespace(
                enabled=enabled,
                privileged_roles=["admin", "root"],
                intent_precheck_enabled=True,
                classifier_timeout_seconds=8,
                deny_message=_DENY_MESSAGE,
            ),
        ),
    )
    monkeypatch.setattr(
        tool_gate,
        "load_config",
        lambda *a, **k: fake_config,
    )


def _principal_context(*, can_mutate: bool) -> dict:
    return {
        "request_principal": {
            "user_id": "member",
            "roles": ["member"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": can_mutate,
        },
    }


def test_member_allowed_readonly_through_gate(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    decision = tool_gate.authorize_tool_call(
        request_context=_principal_context(can_mutate=False),
        effect_spec=_spec(),
        input_data={"command": "df -h"},
    )
    assert decision.allowed is True


def test_member_denied_mutation_through_gate(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    decision = tool_gate.authorize_tool_call(
        request_context=_principal_context(can_mutate=False),
        effect_spec=_spec(),
        input_data={"command": "ls > /tmp/x"},
    )
    assert decision.allowed is False


def test_privileged_unaffected_through_gate(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    decision = tool_gate.authorize_tool_call(
        request_context=_principal_context(can_mutate=True),
        effect_spec=_spec(),
        input_data={"command": "rm -rf x"},
    )
    assert decision.allowed is True


def test_shell_tool_descriptor_carries_classifier_spec():
    # The wired-in shell tool must expose the classifier spec so the
    # production gate path (get_tool_effect_spec) resolves per command.
    from qwenpaw.agents.tools.shell import execute_shell_command
    from qwenpaw.runtime.tool_registry import get_tool_effect_spec

    spec = get_tool_effect_spec(execute_shell_command)
    assert isinstance(spec, ShellCommandEffectSpec)
    assert spec.resolve({"command": "ls"}) is ActionEffect.READ
    assert spec.resolve({"command": "touch x"}) is ActionEffect.MUTATE
