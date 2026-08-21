# -*- coding: utf-8 -*-
"""QwenPawLocalWorkspace — routes tool management to ToolRegistry.

Subclasses AgentScope's :class:`LocalWorkspace` so that
:meth:`list_tools` returns QwenPaw's own tools (managed by
:class:`ToolRegistry`) instead of AgentScope's built-in six.

All runtime tool consumers call ``list_tools()``:

- **No arguments**: returns default-enabled tools (``WorkspaceBase``
  protocol).
- **With filter kwargs**: returns tools filtered by per-request
  context (modes, skills, features, agent config gates).

The read-only metadata seam ``list_potential_tool_descriptors(agent_config)``
exposes potentially loadable descriptors for catalog consumers.

``ToolRegistry`` is an internal implementation detail.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentscope.workspace import LocalWorkspace as AgentScopeLocalWorkspace

if TYPE_CHECKING:
    from ...runtime.tool_registry import ToolDescriptor, ToolRegistry


class QwenPawLocalWorkspace(AgentScopeLocalWorkspace):
    """LocalWorkspace whose ``list_tools`` delegates to ToolRegistry."""

    def __init__(self, tool_registry: ToolRegistry, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._tool_registry = tool_registry
        self._governor: Any = None

    def set_governor(self, governor: Any) -> None:
        """Inject the ResourceGovernor for policy-governed tool wrapping.

        Called by :class:`AgentBuilder` after the governor is created.
        Must be called before the first :meth:`list_tools` invocation
        for the governor to take effect on workspace tools.
        """
        self._governor = governor

    def list_potential_tool_descriptors(
        self,
        agent_config: Any,
    ) -> list[ToolDescriptor]:
        """Return registered descriptors that could load for this agent.

        Conditional descriptor requirements are unioned so every registered
        mode, skill, and feature gate is considered potentially loadable.
        Config gates continue to determine which core and plugin tools are
        eligible for the agent.
        """
        descriptors = [
            descriptor
            for name in self._tool_registry.names()
            if (descriptor := self._tool_registry.get(name)) is not None
        ]
        required_modes = {
            mode
            for descriptor in descriptors
            for mode in descriptor.requires_modes
        }
        required_skills = {
            skill
            for descriptor in descriptors
            for skill in descriptor.requires_skills
        }
        required_features = {
            feature
            for descriptor in descriptors
            for feature in descriptor.requires_features
        }
        allowed, denied = self._resolve_config_gates(agent_config)
        return self._tool_registry.filter(
            active_modes=required_modes,
            active_skills=required_skills,
            enabled_features=required_features,
            allowed=allowed,
            denied=denied,
        )

    async def list_tools(  # type: ignore[override]
        self,
        *,
        agent_config: Any = None,
        agent_id: str | None = None,  # pylint: disable=unused-argument
        request_context: dict[str, Any] | None = None,
        active_modes: tuple[str, ...] | set[str] = (),
        active_skills: tuple[str, ...] | set[str] = (),
        enabled_features: tuple[str, ...] | set[str] = (),
    ) -> list[Any]:
        """Return QwenPaw tools, replacing AgentScope built-ins.

        Without arguments the call satisfies the ``WorkspaceBase``
        protocol and returns every default-enabled tool.  When
        *agent_config* (and optional filter sets) are supplied the
        result is narrowed by config gates and four-dimensional
        filtering.
        """
        from ...governance import PolicyGuardedTool

        if agent_config is not None:
            allowed, denied = self._resolve_config_gates(agent_config)
        else:
            allowed, denied = None, set()

        subagent_whitelist = (request_context or {}).get(
            "subagent_allowed_tools",
        )
        if isinstance(subagent_whitelist, list):
            # Empty list means deny-all workspace tools (unlike
            # ToolRegistry.filter, where empty allowed == unrestricted).
            if not subagent_whitelist:
                return []
            sa_set = set(subagent_whitelist)
            allowed = (allowed & sa_set) if allowed is not None else sa_set

        descs = self._tool_registry.filter(
            active_modes=set(active_modes),
            active_skills=set(active_skills),
            enabled_features=set(enabled_features),
            allowed=allowed,
            denied=denied,
        )

        return [
            PolicyGuardedTool(
                d.func,
                governor=self._governor,
                request_context=request_context,
                effect_spec=d.effect,
            )
            for d in descs
        ]

    # -------------------------------------------------------------- internal

    def _resolve_config_gates(
        self,
        agent_config: Any,
    ) -> tuple[set[str] | None, set[str]]:
        """Translate ``agent_config.tools.builtin_tools`` to (allowed, denied).

        Migrated verbatim from ``AgentBuilder._resolve_config_gates``.
        """
        cfg = (
            getattr(
                getattr(agent_config, "tools", None),
                "builtin_tools",
                None,
            )
            or {}
        )
        denied = {
            n for n, c in cfg.items() if getattr(c, "enabled", True) is False
        }
        explicit_enabled = {
            n for n, c in cfg.items() if getattr(c, "enabled", True)
        }

        defaults = self._tool_registry.default_enabled_names()
        plugin_opt_ins = explicit_enabled - defaults
        if plugin_opt_ins:
            return defaults | explicit_enabled, denied
        return None, denied


__all__ = ["QwenPawLocalWorkspace"]
