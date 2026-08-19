# -*- coding: utf-8 -*-
"""Effect metadata must survive every dynamic wrapper construction path."""

# pylint: disable=protected-access

from __future__ import annotations

from types import SimpleNamespace

from qwenpaw.agents.tools.lsp_tool import make_lsp_tool
from qwenpaw.modes.coding import mixin as coding_mixin
from qwenpaw.runtime.builder import AgentBuilder
from qwenpaw.runtime.tool_registry import tool_descriptor
from qwenpaw.security.mutation_guard import ActionEffect


@tool_descriptor(side_effect="read")
async def _dynamic_read() -> str:
    return "read"


def test_builder_wrap_tool_preserves_descriptor_effect() -> None:
    wrapped = AgentBuilder._wrap_tool(
        _dynamic_read,
        "agent-1",
        {},
        governor=None,
    )
    assert wrapped._qp_effect_spec.default is ActionEffect.READ


def test_lsp_factory_attaches_read_descriptor() -> None:
    lsp = make_lsp_tool({"python": ["pylsp"]})
    assert lsp._tool_descriptor.effect.default is ActionEffect.READ


def test_collect_coding_tools_preserves_lsp_and_ast_effects(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        coding_mixin,
        "detect_available_lsp_languages",
        lambda _path: {"python": ["pylsp"]},
    )
    monkeypatch.setattr(
        coding_mixin.ast_tool,
        "is_ast_grep_available",
        lambda: True,
    )
    cfg = SimpleNamespace(
        coding_mode=SimpleNamespace(enabled=True, project_dir="/tmp"),
    )

    tools = coding_mixin.collect_coding_tools(
        cfg,
        "/tmp",
        request_context={},
        governor=None,
    )

    assert {tool.name for tool in tools} == {"lsp", "ast_search"}
    assert all(
        tool._qp_effect_spec.default is ActionEffect.READ for tool in tools
    )
