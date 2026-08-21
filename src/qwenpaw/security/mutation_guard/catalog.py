# -*- coding: utf-8 -*-
"""Policy-derived tool permission catalog primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import BaseModel, Field

from ...runtime.tool_registry import get_tool_effect_spec
from .policy import ActionEffect, RequestPrincipal, authorize_effect

if TYPE_CHECKING:
    from ...config.config import MutationGuardConfig


@dataclass(frozen=True)
class ToolEffectCandidate:
    """A discovered tool name and its default action effect."""

    name: str
    effect: ActionEffect


class ToolPermissionEntry(BaseModel):
    """One tool's effective permission for a non-privileged member."""

    name: str = Field(description="Discovered tool name.")
    effect: ActionEffect = Field(description="Tool's default action effect.")
    allowed_for_member: bool = Field(
        description="Whether a guarded non-privileged member may use it.",
    )


_CATALOG_MEMBER_PRINCIPAL = RequestPrincipal(
    user_id="tool-permission-catalog-member",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


def build_tool_permission_entries(
    candidates: Iterable[ToolEffectCandidate],
    config: "MutationGuardConfig",
) -> list[ToolPermissionEntry]:
    """Build sorted permission entries from discovered tool candidates."""
    effects_by_name: dict[str, ActionEffect] = {}
    for candidate in candidates:
        effect = effects_by_name.get(candidate.name)
        if effect is None:
            effects_by_name[candidate.name] = candidate.effect
            continue
        if effect is not candidate.effect:
            raise ValueError(
                f"conflicting effects for tool {candidate.name!r}: "
                f"{effect.value} and {candidate.effect.value}",
            )

    return [
        ToolPermissionEntry(
            name=name,
            effect=effect,
            allowed_for_member=authorize_effect(
                _CATALOG_MEMBER_PRINCIPAL,
                effect,
                config,
            ).allowed,
        )
        for name, effect in sorted(effects_by_name.items())
    ]


def _candidate_from_dynamic_tool(tool: Any) -> ToolEffectCandidate:
    """Convert a dynamic tool object to a default-effect candidate."""
    name = getattr(tool, "name", None)
    if name is None:
        name = getattr(tool, "__name__", None)
    name = str(name) if name is not None else ""
    if not name:
        raise ValueError("discovered dynamic tool has no name")
    effect_spec = getattr(tool, "_qp_effect_spec", None)
    if effect_spec is None:
        effect_spec = get_tool_effect_spec(tool)
    return ToolEffectCandidate(name, effect_spec.default)
