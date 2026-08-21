# -*- coding: utf-8 -*-
"""Policy-derived tool permission catalog primitives."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import BaseModel, Field

from ...runtime.tool_registry import get_tool_effect_spec
from .policy import ActionEffect, RequestPrincipal, authorize_effect

if TYPE_CHECKING:
    from ...config.config import MutationGuardConfig


logger = logging.getLogger(__name__)


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
    raw_name = getattr(tool, "name", None) or getattr(
        tool,
        "__name__",
        None,
    )
    name = str(raw_name) if raw_name is not None else ""
    if not name:
        raise ValueError("discovered dynamic tool has no name")
    effect_spec = getattr(tool, "_qp_effect_spec", None)
    if effect_spec is None:
        effect_spec = get_tool_effect_spec(tool)
    return ToolEffectCandidate(name, effect_spec.default)


def _registry_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    """Discover descriptors selected by the local workspace registry."""
    descriptors = workspace.local_workspace.list_potential_tool_descriptors(
        workspace.config,
    )
    return [
        ToolEffectCandidate(descriptor.name, descriptor.effect.default)
        for descriptor in descriptors
    ]


def _memory_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    """Discover tools supplied by the configured memory manager."""
    memory_manager = getattr(workspace, "memory_manager", None)
    if memory_manager is None:
        return []
    return [
        _candidate_from_dynamic_tool(tool)
        for tool in memory_manager.list_memory_tools()
    ]


def _coding_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    """Discover coding-mode tools when coding mode is enabled."""
    coding_mode = getattr(workspace.config, "coding_mode", None)
    if not getattr(coding_mode, "enabled", False):
        return []

    from ...modes.coding import collect_coding_tools

    tools = collect_coding_tools(
        agent_config=workspace.config,
        workspace_dir=workspace.workspace_dir,
        agent_id=workspace.agent_id,
        request_context={},
        governor=None,
    )
    return [_candidate_from_dynamic_tool(tool) for tool in tools]


def _scroll_repl_available(scroll_config: Any) -> bool:
    """Whether the scroll recall REPL can run in this environment."""
    from ...agents.context import scroll_unsandboxed_allowed
    from ...config import load_config
    from ...sandbox import probe_sandbox_support

    config = load_config()
    sandbox_enabled = bool(
        getattr(getattr(config, "security", None), "sandbox_enabled", False),
    )
    return bool(
        (sandbox_enabled and probe_sandbox_support().supported)
        or scroll_unsandboxed_allowed(scroll_config),
    )


def _context_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    """Discover configured light-context tools without invoking them."""
    light_context_config = workspace.config.running.light_context_config
    candidates: list[ToolEffectCandidate] = []
    if getattr(light_context_config, "strategy", "native") == "scroll":
        from ...agents.context.scroll.recall_tool import (
            RecallLoopGuard,
            make_recall_history,
        )

        scroll_config = light_context_config.scroll_config
        pruning_config = light_context_config.tool_result_pruning_config
        workspace_path = Path(workspace.workspace_dir)
        history_path = workspace_path / scroll_config.db_filename
        recall_history = make_recall_history(
            history_db_path=str(history_path),
            session_id=None,
            agent_id=workspace.agent_id,
            loop_guard=RecallLoopGuard(),
            page_max_bytes=pruning_config.pruning_recent_msg_max_bytes,
        )
        candidates.append(_candidate_from_dynamic_tool(recall_history))
        if _scroll_repl_available(scroll_config):
            from ...agents.context import scroll_unsandboxed_allowed
            from ...agents.context.scroll.repl import (
                make_recall_history_python,
            )

            recall_history_python = make_recall_history_python(
                history_db_path=str(history_path),
                session_id=None,
                agent_id=workspace.agent_id,
                scratch_root=str(workspace_path / ".scroll"),
                timeout_s=scroll_config.repl_timeout_s,
                allow_unsandboxed=scroll_unsandboxed_allowed(scroll_config),
            )
            candidates.append(
                _candidate_from_dynamic_tool(recall_history_python),
            )

    visual_compact_config = getattr(
        light_context_config,
        "visual_compact_config",
        None,
    )
    if getattr(visual_compact_config, "enabled", False):
        from ...agents.context.visual_compression.runtime.recovery import (
            TurnRecoveryStore,
            make_recover_visual_context_tool,
        )

        recover_visual_context = make_recover_visual_context_tool(
            TurnRecoveryStore(),
        )
        candidates.append(_candidate_from_dynamic_tool(recover_visual_context))
    return candidates


async def _driver_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    """Discover Driver capabilities exposed as agent tools."""
    driver_manager = getattr(workspace, "driver_manager", None)
    if driver_manager is None:
        return []
    capabilities = await driver_manager.list_capabilities(
        kind="tool",
        request_context={},
    )
    return [
        ToolEffectCandidate(
            capability.exposure.tool_name or capability.name,
            capability.effect,
        )
        for capability in capabilities
        if capability.exposure.as_tool
    ]


def _optional_candidates(
    source_name: str,
    collector: Any,
    workspace: Any,
) -> list[ToolEffectCandidate]:
    """Discover an optional source, omitting unavailable dependencies."""
    try:
        return collector(workspace)
    except (ImportError, OSError, RuntimeError):
        logger.info(
            "Tool permission catalog omitted unavailable %s tools",
            source_name,
            exc_info=True,
        )
        return []


async def collect_tool_permissions(
    workspace: Any,
    config: "MutationGuardConfig",
) -> list[ToolPermissionEntry]:
    """Discover the workspace's tools and derive member permissions."""
    candidates = [
        *_registry_candidates(workspace),
        *_memory_candidates(workspace),
        *_optional_candidates("coding", _coding_candidates, workspace),
        *_optional_candidates("context", _context_candidates, workspace),
        *(await _driver_candidates(workspace)),
    ]
    return build_tool_permission_entries(candidates, config)
