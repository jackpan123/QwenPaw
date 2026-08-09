# -*- coding: utf-8 -*-
"""Catalog test for builtin tool side-effect classification (Task 6).

Every builtin tool must declare a NON-UNKNOWN default effect so no tool is
left accidentally fail-closed and no tool is silently privileged. Each tool
is also asserted to map to its expected category per the fixed catalog.
"""

# pylint: disable=protected-access

from __future__ import annotations

# Importing the tools package triggers every @tool_descriptor at import
# time, auto-collecting them into the global registry.
import qwenpaw.agents.tools  # noqa: F401  pylint: disable=unused-import
from qwenpaw.runtime.tool_registry import get_builtin_tool_funcs
from qwenpaw.security.mutation_guard import ActionEffect

# Fixed catalog (descriptor name -> expected default ActionEffect).
_EXPECTED: dict[str, ActionEffect] = {
    "read_file": ActionEffect.READ,
    "grep_search": ActionEffect.READ,
    "glob_search": ActionEffect.READ,
    "ast_search": ActionEffect.READ,
    "get_current_time": ActionEffect.READ,
    "get_token_usage": ActionEffect.READ,
    "view_image": ActionEffect.READ,
    "view_video": ActionEffect.READ,
    "web_search": ActionEffect.READ,
    "web_fetch": ActionEffect.READ,
    "desktop_screenshot": ActionEffect.READ,
    "write_file": ActionEffect.MUTATE,
    "edit_file": ActionEffect.MUTATE,
    "append_file": ActionEffect.MUTATE,
    "set_user_timezone": ActionEffect.MUTATE,
    "materialize_skill": ActionEffect.MUTATE,
    "execute_shell_command": ActionEffect.MUTATE,
    "send_file_to_user": ActionEffect.EXTERNAL_SIDE_EFFECT,
    "chat_with_agent": ActionEffect.EXTERNAL_SIDE_EFFECT,
    "submit_to_agent": ActionEffect.EXTERNAL_SIDE_EFFECT,
    "spawn_subagent": ActionEffect.EXTERNAL_SIDE_EFFECT,
    "delegate_external_agent": ActionEffect.EXTERNAL_SIDE_EFFECT,
    "list_agents": ActionEffect.READ,
    "check_agent_task": ActionEffect.READ,
    "run_tool_batch": ActionEffect.READ,
    # browser_use default is EXTERNAL_SIDE_EFFECT (per-action selector below).
    "browser_use": ActionEffect.EXTERNAL_SIDE_EFFECT,
}


def _by_name() -> dict[str, object]:
    return {fn._tool_descriptor.name: fn for fn in get_builtin_tool_funcs()}


def test_every_builtin_tool_has_non_unknown_effect() -> None:
    """No builtin may default to UNKNOWN (no accidental fail-closed)."""
    funcs = get_builtin_tool_funcs()
    assert funcs  # sanity
    for fn in funcs:
        d = fn._tool_descriptor
        assert d.effect.default is not ActionEffect.UNKNOWN, d.name


def test_catalog_matches_every_builtin() -> None:
    """Each builtin resolves to its expected category."""
    by_name = _by_name()
    # Every catalog entry must be a real registered builtin.
    assert set(_EXPECTED).issubset(set(by_name)), set(_EXPECTED) - set(by_name)
    for name, expected in _EXPECTED.items():
        d = by_name[name]._tool_descriptor
        assert d.effect.default is expected, (
            f"{name}: expected {expected.value}, "
            f"got {d.effect.default.value}"
        )


def test_no_extra_builtins_left_unclassified() -> None:
    """Any builtin not in the catalog is a classification gap."""
    by_name = _by_name()
    extra = set(by_name) - set(_EXPECTED)
    assert not extra, f"uncatalogued builtins: {sorted(extra)}"


def test_browser_use_snapshot_resolves_read() -> None:
    """browser_use action=snapshot is READ via the selector."""
    d = _by_name()["browser_use"]._tool_descriptor
    assert d.effect.resolve({"action": "snapshot"}) is ActionEffect.READ


def test_browser_use_click_resolves_external_side_effect() -> None:
    """browser_use action=click stays EXTERNAL_SIDE_EFFECT (not in
    read_only_values)."""
    d = _by_name()["browser_use"]._tool_descriptor
    assert (
        d.effect.resolve({"action": "click"})
        is ActionEffect.EXTERNAL_SIDE_EFFECT
    )


def test_browser_use_read_only_actions_whitelist() -> None:
    """The documented read-only browser actions all resolve to READ."""
    d = _by_name()["browser_use"]._tool_descriptor
    read_only = (
        "start",
        "stop",
        "open",
        "navigate",
        "snapshot",
        "screenshot",
        "console_messages",
        "network_requests",
        "tabs",
        "wait_for",
        "list_cdp_targets",
    )
    for action in read_only:
        assert (
            d.effect.resolve({"action": action}) is ActionEffect.READ
        ), action


def test_browser_use_mutating_actions_stay_external() -> None:
    """click/type/evaluate/upload/download/select/run_code/cache actions
    stay EXTERNAL_SIDE_EFFECT (must NOT be added to read_only_values)."""
    d = _by_name()["browser_use"]._tool_descriptor
    mutating = (
        "click",
        "type",
        "evaluate",
        "upload",
        "download",
        "form",
        "drag",
        "select",
        "run_code",
        "cache",
    )
    for action in mutating:
        assert (
            d.effect.resolve({"action": action})
            is ActionEffect.EXTERNAL_SIDE_EFFECT
        ), action


# ---------------------------------------------------------------------------
# Scroll + goal tools (direct ToolDescriptor, NOT auto-collected builtins)
# ---------------------------------------------------------------------------


def test_recall_history_is_read() -> None:
    """recall_history (scroll) runs read-only SQL queries -> READ."""
    from qwenpaw.agents.context.scroll.recall_tool import make_recall_history

    fn = make_recall_history(
        history_db_path="/tmp/nonexistent.db",
        session_id="s1",
        agent_id="a1",
    )
    d = fn._tool_descriptor
    assert d.name == "recall_history"
    assert d.effect.default is ActionEffect.READ


def test_recall_history_python_is_mutate() -> None:
    """recall_history_python runs model-authored code -> MUTATE."""
    from qwenpaw.agents.context.scroll.repl import (
        make_recall_history_python,
    )

    fn = make_recall_history_python(
        history_db_path="/tmp/nonexistent.db",
        session_id="s1",
        agent_id="a1",
        scratch_root="/tmp/scratch",
    )
    d = fn._tool_descriptor
    assert d.name == "recall_history_python"
    assert d.effect.default is ActionEffect.MUTATE


def test_goal_tools_effects() -> None:
    """get_goal=READ; create_goal/update_goal=MUTATE."""
    from qwenpaw.modes.goal.goal_mode import GoalMode

    # GoalMode.tools() builds descriptors whose ``func`` closures reference
    # ``owner`` only when invoked — building the descriptors needs no owner
    # state, so a bare __new__ instance suffices.
    mode = GoalMode.__new__(GoalMode)
    descs = mode.tools()
    by_name = {d.name: d for d in descs}
    assert set(by_name) == {"get_goal", "create_goal", "update_goal"}
    assert by_name["get_goal"].effect.default is ActionEffect.READ
    assert by_name["create_goal"].effect.default is ActionEffect.MUTATE
    assert by_name["update_goal"].effect.default is ActionEffect.MUTATE
