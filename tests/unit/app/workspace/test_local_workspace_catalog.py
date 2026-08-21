# -*- coding: utf-8 -*-
"""Tests for potentially loadable local-workspace tool descriptors."""

# pylint: disable=protected-access

from __future__ import annotations

from types import SimpleNamespace

from qwenpaw.app.workspace.local_workspace import QwenPawLocalWorkspace
from qwenpaw.runtime.tool_registry import ToolDescriptor, ToolRegistry


def _workspace(*descriptors: ToolDescriptor) -> QwenPawLocalWorkspace:
    registry = ToolRegistry()
    registry.register_many(descriptors)
    workspace = object.__new__(QwenPawLocalWorkspace)
    workspace._tool_registry = registry
    return workspace


def _descriptor(name: str, **kwargs: object) -> ToolDescriptor:
    return ToolDescriptor(name=name, func=lambda: None, **kwargs)


def _config(**tools: object) -> SimpleNamespace:
    return SimpleNamespace(
        tools=SimpleNamespace(builtin_tools=tools),
    )


def test_potential_descriptors_include_registered_conditional_tools() -> None:
    """Include descriptors gated by any registered mode, skill, or feature."""
    workspace = _workspace(
        _descriptor("plain"),
        _descriptor("goal", requires_modes=("goal",)),
        _descriptor("research", requires_skills=("research",)),
        _descriptor(
            "browser_media",
            requires_features=("browser", "media"),
        ),
    )

    descriptors = workspace.list_potential_tool_descriptors(_config())

    assert {descriptor.name for descriptor in descriptors} == {
        "plain",
        "goal",
        "research",
        "browser_media",
    }


def test_potential_descriptors_apply_disable_and_plugin_opt_in() -> None:
    """Honor disabled core tools and explicit plugin opt-in configuration."""
    workspace = _workspace(
        _descriptor("core_enabled"),
        _descriptor("core_disabled"),
        _descriptor("plugin_opt_in", enabled_by_default=False),
    )

    disabled = _config(
        core_disabled=SimpleNamespace(enabled=False),
    )
    assert {
        descriptor.name
        for descriptor in workspace.list_potential_tool_descriptors(disabled)
    } == {"core_enabled"}

    opted_in = _config(
        core_disabled=SimpleNamespace(enabled=False),
        plugin_opt_in=SimpleNamespace(enabled=True),
    )
    assert {
        descriptor.name
        for descriptor in workspace.list_potential_tool_descriptors(opted_in)
    } == {"core_enabled", "plugin_opt_in"}
