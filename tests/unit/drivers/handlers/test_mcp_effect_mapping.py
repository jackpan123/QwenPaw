# -*- coding: utf-8 -*-
"""MCP metadata must fail closed unless readOnlyHint is literal true."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from qwenpaw.drivers.handlers.mcp import _mcp_tool_to_capability
from qwenpaw.security.mutation_guard import ActionEffect


@pytest.mark.parametrize(
    ("read_only_hint", "expected"),
    [
        (True, ActionEffect.READ),
        (False, ActionEffect.UNKNOWN),
        ("false", ActionEffect.UNKNOWN),
        (1, ActionEffect.UNKNOWN),
        (None, ActionEffect.UNKNOWN),
    ],
)
def test_mcp_read_only_hint_requires_literal_true(
    read_only_hint,
    expected,
) -> None:
    tool = SimpleNamespace(
        name="demo",
        description="demo tool",
        inputSchema={},
        annotations=SimpleNamespace(readOnlyHint=read_only_hint),
    )

    capability = _mcp_tool_to_capability("server", tool)

    assert capability.effect is expected


def test_mcp_missing_read_only_hint_is_unknown() -> None:
    tool = SimpleNamespace(
        name="demo",
        description="demo tool",
        inputSchema={},
    )

    capability = _mcp_tool_to_capability("server", tool)

    assert capability.effect is ActionEffect.UNKNOWN
