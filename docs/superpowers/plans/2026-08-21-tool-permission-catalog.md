# Tool Permission Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an agent-scoped, read-only Mutation Guard catalog that lists every tool the selected agent can potentially load, its existing five-way effect classification, and the effective allow/deny decision for a normal account.

**Architecture:** A new backend catalog service gathers metadata from the selected workspace without executing tools, deduplicates it, and delegates normal-account permission decisions to the existing `authorize_effect()` policy. The FastAPI route only resolves the workspace and serializes that service result. A focused React component owns catalog loading/error/pagination state independently from the Mutation Guard form and refetches on agent changes or successful settings saves.

**Tech Stack:** Python 3.10+, FastAPI, Pydantic, pytest, React 18, TypeScript, Zustand, `@agentscope-ai/design`, Vitest, Testing Library, i18next.

---

## Source specification

Implement the approved design in
`docs/superpowers/specs/2026-08-21-tool-permission-catalog-design.md`.
Do not change tool classifications as part of this feature. In particular,
`memory_search` must remain `UNKNOWN` until a separate change annotates it.

## File map

### Backend

- Create `src/qwenpaw/security/mutation_guard/catalog.py`: catalog candidate
  types, source discovery, deduplication, sorting, and policy-derived member
  decisions.
- Modify `src/qwenpaw/app/workspace/local_workspace.py`: expose the existing
  configuration gates through a potential-descriptor query that deliberately
  satisfies mode/skill/feature requirements.
- Modify `src/qwenpaw/app/routers/config.py`: add the agent-scoped read-only
  endpoint.
- Create `tests/unit/app/workspace/test_local_workspace_catalog.py`: prove
  potential-mode inclusion, explicit disable, and plugin opt-in semantics.
- Create `tests/unit/security/mutation_guard/test_catalog.py`: prove all
  discovery sources, deduplication, deterministic sorting, `UNKNOWN`, and
  enabled/disabled policy results.
- Modify `tests/unit/app/routers/test_config_router.py`: prove header-scoped
  workspace selection, response serialization, and absence of writes.

### Frontend

- Modify `console/src/api/modules/security.ts`: add catalog response types and
  `getToolPermissions()`.
- Modify `console/src/api/modules/security.test.ts`: assert the exact GET path.
- Create
  `console/src/pages/Settings/Security/components/ToolPermissionCatalog.tsx`:
  independent loading/error/retry state, effect/permission tags, sorting, and
  20-row pagination.
- Create
  `console/src/pages/Settings/Security/ToolPermissionCatalog.test.tsx`: render,
  pagination, error, retry, selected-agent refresh, and stale-result tests.
- Modify
  `console/src/pages/Settings/Security/components/MutationGuardTab.tsx`: mount
  the catalog independently and increment a refresh token after a successful
  persisted save.
- Modify
  `console/src/pages/Settings/Security/MutationGuardTab.test.tsx`: prove
  independent loading and post-save refresh.
- Modify
  `console/src/pages/Settings/Security/components/index.ts`: export the new
  component.
- Modify `console/src/pages/Settings/Security/index.module.less`: catalog
  layout, monospaced names, and dark-mode-safe states.
- Modify all seven existing locale files:
  `console/src/locales/en.json`, `id.json`, `ja.json`, `pt-BR.json`, `ru.json`,
  `vi.json`, and `zh.json`.

### Documentation

- Modify `website/public/docs/security.en.md`.
- Modify `website/public/docs/security.zh.md`.

## Task 1: Expose potentially loadable registry descriptors

**Files:**

- Create: `tests/unit/app/workspace/test_local_workspace_catalog.py`
- Modify: `src/qwenpaw/app/workspace/local_workspace.py`

- [ ] **Step 1: Write failing tests for conditional descriptors and agent gates**

Create the test file with small descriptor functions and configuration stubs:

```python
# -*- coding: utf-8 -*-
from __future__ import annotations

from types import SimpleNamespace

from qwenpaw.app.workspace.local_workspace import QwenPawLocalWorkspace
from qwenpaw.runtime.tool_registry import ToolDescriptor, ToolRegistry


def _tool(name: str) -> ToolDescriptor:
    def implementation() -> None:
        return None

    return ToolDescriptor(name=name, func=implementation)


def _workspace(registry: ToolRegistry) -> QwenPawLocalWorkspace:
    workspace = object.__new__(QwenPawLocalWorkspace)
    workspace._tool_registry = registry  # pylint: disable=protected-access
    return workspace


def _config(**enabled: bool) -> SimpleNamespace:
    builtin_tools = {
        name: SimpleNamespace(enabled=value)
        for name, value in enabled.items()
    }
    return SimpleNamespace(
        tools=SimpleNamespace(builtin_tools=builtin_tools),
    )


def test_potential_descriptors_include_registered_conditional_tools():
    registry = ToolRegistry()
    registry.register(_tool("plain"))
    registry.register(
        ToolDescriptor(
            name="mode_tool",
            func=lambda: None,
            requires_modes=("goal",),
        ),
    )
    registry.register(
        ToolDescriptor(
            name="skill_tool",
            func=lambda: None,
            requires_skills=("research",),
        ),
    )
    registry.register(
        ToolDescriptor(
            name="feature_tool",
            func=lambda: None,
            requires_features=("browser", "media"),
        ),
    )

    result = _workspace(registry).list_potential_tool_descriptors(_config())

    assert [descriptor.name for descriptor in result] == [
        "plain",
        "mode_tool",
        "skill_tool",
        "feature_tool",
    ]


def test_potential_descriptors_apply_disable_and_plugin_opt_in():
    registry = ToolRegistry()
    registry.register(_tool("core_enabled"))
    registry.register(_tool("core_disabled"))
    registry.register(
        ToolDescriptor(
            name="plugin_opt_in",
            func=lambda: None,
            enabled_by_default=False,
        ),
    )
    workspace = _workspace(registry)

    without_opt_in = workspace.list_potential_tool_descriptors(
        _config(core_disabled=False),
    )
    with_opt_in = workspace.list_potential_tool_descriptors(
        _config(core_disabled=False, plugin_opt_in=True),
    )

    assert [item.name for item in without_opt_in] == ["core_enabled"]
    assert [item.name for item in with_opt_in] == [
        "core_enabled",
        "plugin_opt_in",
    ]
```

- [ ] **Step 2: Run the tests and verify the intended API is missing**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/app/workspace/test_local_workspace_catalog.py
```

Expected: FAIL with `AttributeError` for
`list_potential_tool_descriptors`.

- [ ] **Step 3: Implement the potential-descriptor query by reusing runtime gates**

Add this public method immediately before `_resolve_config_gates()` in
`QwenPawLocalWorkspace`:

```python
    def list_potential_tool_descriptors(
        self,
        agent_config: Any,
    ) -> list[Any]:
        """List descriptors this agent may load in some request context.

        Agent enable/disable and plugin opt-in gates remain authoritative.
        Mode, skill, and feature predicates are deliberately satisfied with
        the union of registered requirements because this is a potential
        catalog rather than one turn's active toolkit.
        """
        allowed, denied = self._resolve_config_gates(agent_config)
        descriptors = [
            descriptor
            for name in self._tool_registry.names()
            if (descriptor := self._tool_registry.get(name)) is not None
        ]
        active_modes = {
            mode
            for descriptor in descriptors
            for mode in descriptor.requires_modes
        }
        active_skills = {
            skill
            for descriptor in descriptors
            for skill in descriptor.requires_skills
        }
        enabled_features = {
            feature
            for descriptor in descriptors
            for feature in descriptor.requires_features
        }
        return self._tool_registry.filter(
            active_modes=active_modes,
            active_skills=active_skills,
            enabled_features=enabled_features,
            allowed=allowed,
            denied=denied,
        )
```

Keep `_resolve_config_gates()` as the single source of agent enable/disable
and plugin opt-in behavior. Do not copy its logic into the catalog service.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/app/workspace/test_local_workspace_catalog.py
```

Expected: `2 passed`.

- [ ] **Step 5: Commit the registry seam**

```bash
git add src/qwenpaw/app/workspace/local_workspace.py \
  tests/unit/app/workspace/test_local_workspace_catalog.py
git commit -m "feat(security): expose potential tool descriptors"
```

## Task 2: Build the policy-derived catalog core

**Files:**

- Create: `src/qwenpaw/security/mutation_guard/catalog.py`
- Create: `tests/unit/security/mutation_guard/test_catalog.py`

- [ ] **Step 1: Write failing pure tests for policy, sorting, and conflicts**

Start `tests/unit/security/mutation_guard/test_catalog.py` with:

```python
# -*- coding: utf-8 -*-
from __future__ import annotations

import pytest

from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import ActionEffect
from qwenpaw.security.mutation_guard.catalog import (
    ToolEffectCandidate,
    build_tool_permission_entries,
)


def _config(enabled: bool) -> MutationGuardConfig:
    return MutationGuardConfig(
        enabled=enabled,
        privileged_roles=["admin"],
        intent_precheck_enabled=False,
        classifier_timeout_seconds=8,
        deny_message="denied",
    )


def test_build_entries_sorts_and_uses_authoritative_enabled_policy():
    candidates = [
        ToolEffectCandidate("write", ActionEffect.MUTATE),
        ToolEffectCandidate("chat", ActionEffect.CHAT_INFRASTRUCTURE),
        ToolEffectCandidate("read", ActionEffect.READ),
        ToolEffectCandidate("external", ActionEffect.EXTERNAL_SIDE_EFFECT),
        ToolEffectCandidate("missing", ActionEffect.UNKNOWN),
    ]

    result = build_tool_permission_entries(candidates, _config(True))

    assert [item.name for item in result] == [
        "chat",
        "external",
        "missing",
        "read",
        "write",
    ]
    assert {item.name: item.allowed_for_member for item in result} == {
        "chat": True,
        "external": False,
        "missing": False,
        "read": True,
        "write": False,
    }


def test_build_entries_allows_every_effect_when_guard_is_disabled():
    candidates = [
        ToolEffectCandidate(effect.value, effect)
        for effect in ActionEffect
    ]

    result = build_tool_permission_entries(candidates, _config(False))

    assert all(item.allowed_for_member for item in result)


def test_build_entries_coalesces_matching_duplicates():
    candidate = ToolEffectCandidate("same", ActionEffect.READ)

    result = build_tool_permission_entries([candidate, candidate], _config(True))

    assert len(result) == 1
    assert result[0].name == "same"


def test_build_entries_rejects_conflicting_duplicates():
    with pytest.raises(
        ValueError,
        match="conflicting effects for tool 'same'",
    ):
        build_tool_permission_entries(
            [
                ToolEffectCandidate("same", ActionEffect.READ),
                ToolEffectCandidate("same", ActionEffect.MUTATE),
            ],
            _config(True),
        )
```

- [ ] **Step 2: Run the tests and verify the catalog module is absent**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/security/mutation_guard/test_catalog.py
```

Expected: collection FAIL with `ModuleNotFoundError` for
`qwenpaw.security.mutation_guard.catalog`.

- [ ] **Step 3: Implement candidates, response model, deduplication, and policy evaluation**

Create `catalog.py` with these public foundations:

```python
# -*- coding: utf-8 -*-
"""Read-only tool effect catalog for Mutation Guard diagnostics."""

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
    """One discovered tool name and its default effect."""

    name: str
    effect: ActionEffect


class ToolPermissionEntry(BaseModel):
    """Serialized effective permission for one potentially loadable tool."""

    name: str = Field(..., description="Tool function name")
    effect: ActionEffect = Field(..., description="Default tool effect")
    allowed_for_member: bool = Field(
        ...,
        description="Whether a guarded normal account may call the effect",
    )


_CATALOG_MEMBER = RequestPrincipal(
    user_id="tool-permission-catalog-member",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


def build_tool_permission_entries(
    candidates: Iterable[ToolEffectCandidate],
    config: MutationGuardConfig,
) -> list[ToolPermissionEntry]:
    """Deduplicate, sort, and authorize catalog candidates."""
    effects_by_name: dict[str, ActionEffect] = {}
    for candidate in candidates:
        existing = effects_by_name.get(candidate.name)
        if existing is not None and existing != candidate.effect:
            raise ValueError(
                f"conflicting effects for tool {candidate.name!r}: "
                f"{existing.value} != {candidate.effect.value}",
            )
        effects_by_name[candidate.name] = candidate.effect

    return [
        ToolPermissionEntry(
            name=name,
            effect=effect,
            allowed_for_member=authorize_effect(
                _CATALOG_MEMBER,
                effect,
                config,
            ).allowed,
        )
        for name, effect in sorted(effects_by_name.items())
    ]


def _candidate_from_dynamic_tool(tool: Any) -> ToolEffectCandidate:
    """Read wrapper/callable metadata without invoking the tool body."""
    name = str(
        getattr(tool, "name", "")
        or getattr(tool, "__name__", "")
    )
    if not name:
        raise ValueError("discovered dynamic tool has no name")
    effect_spec = getattr(tool, "_qp_effect_spec", None)
    if effect_spec is None:
        effect_spec = get_tool_effect_spec(tool)
    return ToolEffectCandidate(name=name, effect=effect_spec.default)
```

Keep these types in `catalog.py`; Task 4 imports them from that module directly
so the existing `mutation_guard` package entry point remains acyclic.

- [ ] **Step 4: Run the pure tests**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/security/mutation_guard/test_catalog.py
```

Expected: `4 passed`.

- [ ] **Step 5: Commit the catalog policy core**

```bash
git add src/qwenpaw/security/mutation_guard/catalog.py \
  tests/unit/security/mutation_guard/test_catalog.py
git commit -m "feat(security): add tool permission catalog policy"
```

## Task 3: Discover registry, memory, coding, context, and Driver tools

**Files:**

- Modify: `src/qwenpaw/security/mutation_guard/catalog.py`
- Modify: `tests/unit/security/mutation_guard/test_catalog.py`

- [ ] **Step 1: Add failing tests for every discovery source**

Append tests using `SimpleNamespace`, real descriptors, and a fake Driver
manager. Keep coding availability deterministic by patching its collector:

```python
from pathlib import Path
from types import SimpleNamespace

from qwenpaw.drivers.capabilities import (
    CapabilityExposure,
    DriverCapability,
)
from qwenpaw.runtime.tool_registry import ToolDescriptor, ToolEffectSpec
from qwenpaw.security.mutation_guard.catalog import collect_tool_permissions


class _MemoryManager:
    @staticmethod
    def list_memory_tools():
        def memory_search() -> None:
            return None

        return [memory_search]


class _DriverManager:
    def __init__(self) -> None:
        self.request_context = None

    async def list_capabilities(self, **kwargs):
        self.request_context = kwargs["request_context"]
        return [
            DriverCapability(
                capability_id="driver://mcp/test/tools/read#call",
                driver_name="test",
                protocol="mcp",
                kind="tool",
                action="call",
                name="driver_internal_name",
                exposure=CapabilityExposure(
                    as_tool=True,
                    tool_name="driver_read",
                ),
                effect=ActionEffect.READ,
            ),
            DriverCapability(
                capability_id="driver://mcp/test/tools/hidden#call",
                driver_name="test",
                protocol="mcp",
                kind="tool",
                action="call",
                name="driver_hidden",
                exposure=CapabilityExposure(as_tool=False),
                effect=ActionEffect.MUTATE,
            ),
        ]


def _agent_config() -> SimpleNamespace:
    return SimpleNamespace(
        id="agent-a",
        project_dir=None,
        coding_mode=SimpleNamespace(enabled=True),
        running=SimpleNamespace(
            light_context_config=SimpleNamespace(
                strategy="scroll",
                scroll_config=SimpleNamespace(
                    db_filename="history.db",
                    repl_timeout_s=30,
                    allow_unsandboxed=False,
                ),
                tool_result_pruning_config=SimpleNamespace(
                    pruning_recent_msg_max_bytes=4096,
                ),
                visual_compact_config=SimpleNamespace(enabled=True),
            ),
        ),
    )


@pytest.mark.asyncio
async def test_collects_all_sources_without_invoking_tool_bodies(
    monkeypatch,
    tmp_path: Path,
):
    registry_descriptor = ToolDescriptor(
        name="mode_registered",
        func=lambda: None,
        requires_modes=("goal",),
        effect=ToolEffectSpec(default=ActionEffect.MUTATE),
    )
    coding_tool = SimpleNamespace(
        name="coding_read",
        _qp_effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )
    monkeypatch.setattr(
        "qwenpaw.modes.coding.collect_coding_tools",
        lambda *_args, **_kwargs: [coding_tool],
    )
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._scroll_repl_available",
        lambda _scroll: True,
    )
    driver_manager = _DriverManager()
    workspace = SimpleNamespace(
        agent_id="agent-a",
        workspace_dir=tmp_path,
        config=_agent_config(),
        local_workspace=SimpleNamespace(
            list_potential_tool_descriptors=lambda _config: [
                registry_descriptor,
            ],
        ),
        memory_manager=_MemoryManager(),
        driver_manager=driver_manager,
    )

    result = await collect_tool_permissions(workspace, _config(True))
    by_name = {item.name: item for item in result}

    assert {
        "mode_registered",
        "coding_read",
        "memory_search",
        "recall_history",
        "recall_history_python",
        "recover_visual_context",
        "driver_read",
    } <= set(by_name)
    assert by_name["mode_registered"].effect is ActionEffect.MUTATE
    assert by_name["memory_search"].effect is ActionEffect.UNKNOWN
    assert by_name["recover_visual_context"].effect is ActionEffect.UNKNOWN
    assert by_name["driver_read"].effect is ActionEffect.READ
    assert "driver_hidden" not in by_name
    assert driver_manager.request_context == {}


@pytest.mark.asyncio
async def test_optional_contributors_follow_agent_configuration(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "qwenpaw.modes.coding.collect_coding_tools",
        lambda *_args, **_kwargs: pytest.fail("coding should be gated"),
    )
    config = _agent_config()
    config.coding_mode.enabled = False
    config.running.light_context_config.strategy = "native"
    config.running.light_context_config.visual_compact_config.enabled = False
    workspace = SimpleNamespace(
        agent_id="agent-a",
        workspace_dir=tmp_path,
        config=config,
        local_workspace=SimpleNamespace(
            list_potential_tool_descriptors=lambda _config: [],
        ),
        memory_manager=None,
        driver_manager=None,
    )

    result = await collect_tool_permissions(workspace, _config(True))

    assert result == []


@pytest.mark.asyncio
async def test_unavailable_optional_contributor_is_omitted(
    monkeypatch,
    tmp_path: Path,
):
    config = _agent_config()
    config.running.light_context_config.strategy = "native"
    config.running.light_context_config.visual_compact_config.enabled = False
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._coding_candidates",
        lambda _workspace: (_ for _ in ()).throw(ImportError("missing LSP")),
    )
    workspace = SimpleNamespace(
        agent_id="agent-a",
        workspace_dir=tmp_path,
        config=config,
        local_workspace=SimpleNamespace(
            list_potential_tool_descriptors=lambda _config: [],
        ),
        memory_manager=None,
        driver_manager=None,
    )

    result = await collect_tool_permissions(workspace, _config(True))

    assert result == []


@pytest.mark.asyncio
async def test_omits_scroll_repl_when_no_execution_path_is_available(
    monkeypatch,
    tmp_path: Path,
):
    config = _agent_config()
    config.coding_mode.enabled = False
    config.running.light_context_config.visual_compact_config.enabled = False
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._scroll_repl_available",
        lambda _scroll: False,
    )
    workspace = SimpleNamespace(
        agent_id="agent-a",
        workspace_dir=tmp_path,
        config=config,
        local_workspace=SimpleNamespace(
            list_potential_tool_descriptors=lambda _config: [],
        ),
        memory_manager=None,
        driver_manager=None,
    )

    result = await collect_tool_permissions(workspace, _config(True))

    assert [item.name for item in result] == ["recall_history"]
```

The first test intentionally checks `memory_search = UNKNOWN`; never annotate
that fake or production memory tool in this feature.

- [ ] **Step 2: Run the discovery tests and verify collection is missing**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/security/mutation_guard/test_catalog.py -k collect
```

Expected: FAIL because `collect_tool_permissions` is not defined.

- [ ] **Step 3: Add focused source collectors and the async public collector**

Add these functions to `catalog.py`. Optional factories are only constructed;
their returned tool bodies are never called. A missing optional dependency is
logged and omitted, while conflicting names still fail in
`build_tool_permission_entries()`.

```python
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _registry_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    descriptors = workspace.local_workspace.list_potential_tool_descriptors(
        workspace.config,
    )
    return [
        ToolEffectCandidate(descriptor.name, descriptor.effect.default)
        for descriptor in descriptors
    ]


def _memory_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    manager = getattr(workspace, "memory_manager", None)
    if manager is None:
        return []
    return [
        _candidate_from_dynamic_tool(tool)
        for tool in manager.list_memory_tools()
    ]


def _coding_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    config = workspace.config
    if not getattr(getattr(config, "coding_mode", None), "enabled", False):
        return []
    from ...modes.coding import collect_coding_tools

    tools = collect_coding_tools(
        config,
        workspace.workspace_dir,
        agent_id=workspace.agent_id,
        request_context={},
        governor=None,
    )
    return [_candidate_from_dynamic_tool(tool) for tool in tools]


def _scroll_repl_available(scroll_config: Any) -> bool:
    """Whether the configured agent has a runnable scroll REPL path."""
    from ...agents.context import scroll_unsandboxed_allowed
    from ...config import load_config
    from ...sandbox import probe_sandbox_support

    sandbox_enabled = load_config().security.sandbox_enabled
    sandbox_supported = probe_sandbox_support().supported
    return bool(
        (sandbox_enabled and sandbox_supported)
        or scroll_unsandboxed_allowed(scroll_config)
    )


def _context_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    config = workspace.config
    light_context = config.running.light_context_config
    candidates: list[ToolEffectCandidate] = []

    if light_context.strategy == "scroll":
        from ...agents.context.scroll.recall_tool import (
            RecallLoopGuard,
            make_recall_history,
        )
        from ...agents.context.scroll.repl import make_recall_history_python

        scroll = light_context.scroll_config
        history_path = Path(workspace.workspace_dir) / scroll.db_filename
        loop_guard = RecallLoopGuard()
        candidates.append(
            _candidate_from_dynamic_tool(
                make_recall_history(
                    history_db_path=str(history_path),
                    session_id=None,
                    agent_id=workspace.agent_id,
                    loop_guard=loop_guard,
                    page_max_bytes=(
                        light_context.tool_result_pruning_config
                        .pruning_recent_msg_max_bytes
                    ),
                ),
            ),
        )
        if _scroll_repl_available(scroll):
            candidates.append(
                _candidate_from_dynamic_tool(
                    make_recall_history_python(
                        history_db_path=str(history_path),
                        session_id=None,
                        agent_id=workspace.agent_id,
                        scratch_root=str(
                            Path(workspace.workspace_dir) / ".scroll"
                        ),
                        timeout_s=scroll.repl_timeout_s,
                        allow_unsandboxed=False,
                    ),
                ),
            )

    if light_context.visual_compact_config.enabled:
        from ...agents.context.visual_compression.runtime.recovery import (
            TurnRecoveryStore,
            make_recover_visual_context_tool,
        )

        candidates.append(
            _candidate_from_dynamic_tool(
                make_recover_visual_context_tool(TurnRecoveryStore()),
            ),
        )
    return candidates


async def _driver_candidates(workspace: Any) -> list[ToolEffectCandidate]:
    manager = getattr(workspace, "driver_manager", None)
    if manager is None:
        return []
    capabilities = await manager.list_capabilities(
        kind="tool",
        request_context={},
    )
    return [
        ToolEffectCandidate(
            capability.exposure.tool_name or capability.name,
            capability.effect,
        )
        for capability in capabilities
        if getattr(capability.exposure, "as_tool", False)
    ]


def _optional_candidates(
    source_name: str,
    collector: Any,
    workspace: Any,
) -> list[ToolEffectCandidate]:
    try:
        return collector(workspace)
    except (ImportError, OSError, RuntimeError):
        logger.info(
            "Tool catalog omitted unavailable %s contributor",
            source_name,
            exc_info=True,
        )
        return []


async def collect_tool_permissions(
    workspace: Any,
    config: MutationGuardConfig,
) -> list[ToolPermissionEntry]:
    """Discover selected-agent tool metadata and compute member access."""
    candidates = _registry_candidates(workspace)
    candidates.extend(_memory_candidates(workspace))
    candidates.extend(
        _optional_candidates("coding", _coding_candidates, workspace),
    )
    candidates.extend(
        _optional_candidates("context", _context_candidates, workspace),
    )
    candidates.extend(await _driver_candidates(workspace))
    return build_tool_permission_entries(candidates, config)
```

These keyword arguments match the current factory signatures. Preserve the
invariant that factories may be constructed and tool bodies may not be called.
Do not catch `ValueError` from duplicate-effect conflicts.

Do not re-export these symbols from
`src/qwenpaw/security/mutation_guard/__init__.py`.
`runtime.tool_registry` imports `ActionEffect` through that package entry
point; importing `catalog` back from the entry point would create a circular
import while `get_tool_effect_spec` is still being defined. Consumers must
import this diagnostic service directly from `.catalog`.

- [ ] **Step 4: Run discovery and existing catalog tests**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/security/mutation_guard/test_catalog.py \
  tests/unit/runtime/test_tool_effect_catalog.py
```

Expected: all tests PASS, including the assertion that `memory_search` is
`UNKNOWN` and denied with the guard enabled.

- [ ] **Step 5: Commit multi-source discovery**

```bash
git add src/qwenpaw/security/mutation_guard/catalog.py \
  tests/unit/security/mutation_guard/test_catalog.py
git commit -m "feat(security): discover agent tool permissions"
```

## Task 4: Add the agent-scoped read-only API

**Files:**

- Modify: `src/qwenpaw/app/routers/config.py`
- Modify: `tests/unit/app/routers/test_config_router.py`

- [ ] **Step 1: Write failing route tests for the exact response and header**

Add `MutationGuardConfig`, `ActionEffect`, and `ToolPermissionEntry` imports to
the router test, then append:

```python
def test_get_tool_permissions_uses_header_selected_workspace(
    client,
    monkeypatch,
):
    selected_workspace = MagicMock(name="SelectedWorkspace")
    selected_workspace.agent_id = "agent-b"

    async def get_selected_workspace(request):
        assert request.headers["X-Agent-Id"] == "agent-b"
        return selected_workspace

    collector = AsyncMock(
        return_value=[
            ToolPermissionEntry(
                name="memory_search",
                effect=ActionEffect.UNKNOWN,
                allowed_for_member=False,
            ),
        ],
    )
    config = Config()
    monkeypatch.setattr(
        "qwenpaw.app.agent_context.get_agent_for_request",
        get_selected_workspace,
    )
    monkeypatch.setattr(
        "qwenpaw.app.routers.config.collect_tool_permissions",
        collector,
    )
    monkeypatch.setattr(
        "qwenpaw.app.routers.config.load_config",
        lambda: config,
    )

    response = client.get(
        "/api/config/security/mutation-guard/tool-permissions",
        headers={"X-Agent-Id": "agent-b"},
    )

    assert response.status_code == 200
    assert response.json() == [
        {
            "name": "memory_search",
            "effect": "unknown",
            "allowed_for_member": False,
        },
    ]
    collector.assert_awaited_once_with(
        selected_workspace,
        config.security.mutation_guard,
    )


def test_get_tool_permissions_does_not_write_configuration(
    client,
    patch_get_agent,
    monkeypatch,
):
    collector = AsyncMock(return_value=[])
    mutate = MagicMock(name="mutate_config")
    monkeypatch.setattr(
        "qwenpaw.app.routers.config.collect_tool_permissions",
        collector,
    )
    monkeypatch.setattr(
        "qwenpaw.app.routers.config.mutate_config",
        mutate,
    )

    response = client.get(
        "/api/config/security/mutation-guard/tool-permissions",
    )

    assert response.status_code == 200
    assert response.json() == []
    mutate.assert_not_called()
```

- [ ] **Step 2: Run only the new route tests and verify 404/attribute failure**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/app/routers/test_config_router.py -k tool_permissions
```

Expected: FAIL because the route is not registered (or the collector is not
imported into the router module).

- [ ] **Step 3: Implement the thin GET route**

Add imports near the other Mutation Guard imports in `config.py`, using the
catalog module directly to avoid the package-entry circular import:

```python
from ...security.mutation_guard.catalog import (
    ToolPermissionEntry,
    collect_tool_permissions,
)
```

Add this route after `get_mutation_guard()` and before the PUT route. Placing
the literal suffix before mutation routes keeps the API obvious and avoids
future parameter-route ambiguity:

```python
@router.get(
    "/security/mutation-guard/tool-permissions",
    response_model=List[ToolPermissionEntry],
    summary="List effective tool permissions for a normal account",
)
async def get_mutation_guard_tool_permissions(
    request: Request,
) -> List[ToolPermissionEntry]:
    from ..agent_context import get_agent_for_request

    workspace = await get_agent_for_request(request)
    config = load_config().security.mutation_guard
    return await collect_tool_permissions(workspace, config)
```

Do not call `mutate_config`, `schedule_agent_reload`, a tool body, or the
Mutation Guard audit writer.

- [ ] **Step 4: Run the focused route and API catalog tests**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/app/routers/test_config_router.py -k tool_permissions
PYTHONPATH=src pytest -q tests/unit/app/test_api_capability_catalog.py
```

Expected: both commands PASS. The production route catalog should continue to
have no duplicate method/path registrations.

- [ ] **Step 5: Commit the endpoint**

```bash
git add src/qwenpaw/app/routers/config.py \
  tests/unit/app/routers/test_config_router.py
git commit -m "feat(security): expose tool permission catalog API"
```

## Task 5: Add the typed frontend API

**Files:**

- Modify: `console/src/api/modules/security.ts`
- Modify: `console/src/api/modules/security.test.ts`

- [ ] **Step 1: Write the failing API request test**

Add `ToolPermissionInfo` to the type imports and append:

```typescript
it("getToolPermissions calls the read-only catalog endpoint", async () => {
  const catalog: ToolPermissionInfo[] = [
    {
      name: "memory_search",
      effect: "unknown",
      allowed_for_member: false,
    },
  ];
  vi.mocked(request).mockResolvedValue(catalog);

  const result = await securityApi.getToolPermissions();

  expect(request).toHaveBeenCalledWith(
    "/config/security/mutation-guard/tool-permissions",
  );
  expect(result).toEqual(catalog);
});
```

- [ ] **Step 2: Run the API test and verify the method is missing**

Run:

```bash
cd console
npm run test:run -- src/api/modules/security.test.ts
```

Expected: FAIL because `getToolPermissions` and its response types do not
exist.

- [ ] **Step 3: Add exact effect and response types plus the GET method**

Place these types immediately after `MutationGuardConfig`:

```typescript
export type ToolPermissionEffect =
  | "read"
  | "mutate"
  | "external_side_effect"
  | "unknown"
  | "chat_infrastructure";

export interface ToolPermissionInfo {
  name: string;
  effect: ToolPermissionEffect;
  allowed_for_member: boolean;
}
```

Place this method beside `getMutationGuard()`:

```typescript
  getToolPermissions: () =>
    request<ToolPermissionInfo[]>(
      "/config/security/mutation-guard/tool-permissions",
    ),
```

- [ ] **Step 4: Run the focused API test**

Run:

```bash
cd console
npm run test:run -- src/api/modules/security.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit the frontend client**

```bash
git add console/src/api/modules/security.ts \
  console/src/api/modules/security.test.ts
git commit -m "feat(console): add tool permission catalog client"
```

## Task 6: Build the independent read-only table

**Files:**

- Create:
  `console/src/pages/Settings/Security/components/ToolPermissionCatalog.tsx`
- Create:
  `console/src/pages/Settings/Security/ToolPermissionCatalog.test.tsx`
- Modify: `console/src/pages/Settings/Security/components/index.ts`
- Modify: `console/src/pages/Settings/Security/index.module.less`

- [ ] **Step 1: Write failing component tests for rendering and pagination**

Use the real Zustand store so changing the selected agent triggers a real
rerender. Mock only the API and translations. The first tests should provide
all five effects, assert the three column headers, assert backend rows are
rendered in name order, and use 21 rows to prove a second page exists:

```typescript
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolPermissionInfo } from "../../../api/modules/security";
import { useAgentStore } from "../../../stores/agentStore";

const apiMocks = vi.hoisted(() => ({ getToolPermissions: vi.fn() }));

vi.mock("../../../api", () => ({ default: apiMocks }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

import { ToolPermissionCatalog } from "./components/ToolPermissionCatalog";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("ToolPermissionCatalog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAgentStore.setState({ selectedAgent: "default" });
  });

  it("renders sorted tools, all effects, and effective permissions", async () => {
    const catalog: ToolPermissionInfo[] = [
      { name: "z_read", effect: "read", allowed_for_member: true },
      { name: "a_mutate", effect: "mutate", allowed_for_member: false },
      {
        name: "external",
        effect: "external_side_effect",
        allowed_for_member: false,
      },
      {
        name: "chat",
        effect: "chat_infrastructure",
        allowed_for_member: true,
      },
      { name: "unknown", effect: "unknown", allowed_for_member: false },
    ];
    apiMocks.getToolPermissions.mockResolvedValue(catalog);

    render(<ToolPermissionCatalog refreshToken={0} />);

    await screen.findByText("a_mutate");
    expect(screen.getByText("security.mutationGuard.catalog.toolName"))
      .toBeInTheDocument();
    expect(screen.getByText("security.mutationGuard.catalog.classification"))
      .toBeInTheDocument();
    expect(screen.getByText("security.mutationGuard.catalog.normalAccount"))
      .toBeInTheDocument();
    for (const effect of [
      "read",
      "mutate",
      "externalSideEffect",
      "chatInfrastructure",
      "unknown",
    ]) {
      expect(
        screen.getByText(`security.mutationGuard.catalog.effects.${effect}`),
      ).toBeInTheDocument();
    }
    expect(
      screen.getAllByText("security.mutationGuard.catalog.allowed"),
    ).toHaveLength(2);
    expect(
      screen.getAllByText("security.mutationGuard.catalog.denied"),
    ).toHaveLength(3);
    const names = screen.getAllByTestId("tool-permission-name");
    expect(names.map((node) => node.textContent)).toEqual([
      "a_mutate",
      "chat",
      "external",
      "unknown",
      "z_read",
    ]);
  });

  it("paginates at twenty rows", async () => {
    apiMocks.getToolPermissions.mockResolvedValue(
      Array.from({ length: 21 }, (_, index) => ({
        name: `tool_${String(index + 1).padStart(2, "0")}`,
        effect: "read" as const,
        allowed_for_member: true,
      })),
    );
    const user = userEvent.setup();

    render(<ToolPermissionCatalog refreshToken={0} />);

    await screen.findByText("tool_01");
    expect(screen.queryByText("tool_21")).not.toBeInTheDocument();
    await user.click(screen.getByTitle("2"));
    expect(screen.getByText("tool_21")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Add failing tests for empty, retry, agent change, and stale responses**

Append these tests to the same `describe` block:

```typescript
it("shows an empty state for a successful empty catalog", async () => {
  apiMocks.getToolPermissions.mockResolvedValue([]);

  render(<ToolPermissionCatalog refreshToken={0} />);

  await screen.findByText("security.mutationGuard.catalog.empty");
});

it("keeps failures local to the catalog and retries", async () => {
  apiMocks.getToolPermissions
    .mockRejectedValueOnce(new Error("offline"))
    .mockResolvedValueOnce([
      { name: "shell", effect: "mutate", allowed_for_member: false },
    ]);
  const user = userEvent.setup();

  render(<ToolPermissionCatalog refreshToken={0} />);
  await screen.findByRole("alert");
  expect(screen.getByText("security.mutationGuard.catalog.loadFailed"))
    .toBeInTheDocument();

  await user.click(
    screen.getByRole("button", {
      name: "security.mutationGuard.catalog.retry",
    }),
  );
  await screen.findByText("shell");
  expect(apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
});

it("refetches when the selected agent changes", async () => {
  apiMocks.getToolPermissions
    .mockResolvedValueOnce([
      { name: "agent_a_tool", effect: "read", allowed_for_member: true },
    ])
    .mockResolvedValueOnce([
      { name: "agent_b_tool", effect: "read", allowed_for_member: true },
    ]);

  render(<ToolPermissionCatalog refreshToken={0} />);
  await screen.findByText("agent_a_tool");

  act(() => useAgentStore.setState({ selectedAgent: "agent-b" }));

  await screen.findByText("agent_b_tool");
  expect(apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
});

it("ignores an older response after an agent change", async () => {
  const oldRequest = deferred<ToolPermissionInfo[]>();
  apiMocks.getToolPermissions
    .mockReturnValueOnce(oldRequest.promise)
    .mockResolvedValueOnce([
      { name: "new_agent_tool", effect: "read", allowed_for_member: true },
    ]);

  render(<ToolPermissionCatalog refreshToken={0} />);
  act(() => useAgentStore.setState({ selectedAgent: "agent-b" }));
  await screen.findByText("new_agent_tool");

  oldRequest.resolve([
    { name: "stale_tool", effect: "read", allowed_for_member: true },
  ]);
  await oldRequest.promise;
  await waitFor(() =>
    expect(screen.queryByText("stale_tool")).not.toBeInTheDocument(),
  );
});

it("ignores a response after unmount", async () => {
  const request = deferred<ToolPermissionInfo[]>();
  apiMocks.getToolPermissions.mockReturnValueOnce(request.promise);
  const view = render(<ToolPermissionCatalog refreshToken={0} />);

  view.unmount();
  request.resolve([
    { name: "late_tool", effect: "read", allowed_for_member: true },
  ]);
  await request.promise;
  await Promise.resolve();

  expect(screen.queryByText("late_tool")).not.toBeInTheDocument();
});
```

- [ ] **Step 3: Run the component tests and verify the component is absent**

Run:

```bash
cd console
npm run test:run -- \
  src/pages/Settings/Security/ToolPermissionCatalog.test.tsx
```

Expected: FAIL because `ToolPermissionCatalog.tsx` does not exist.

- [ ] **Step 4: Implement the focused component**

Create `ToolPermissionCatalog.tsx` with:

```typescript
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Table, Tag } from "@agentscope-ai/design";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import api from "../../../../api";
import type {
  ToolPermissionEffect,
  ToolPermissionInfo,
} from "../../../../api/modules/security";
import { useAgentStore } from "../../../../stores/agentStore";
import styles from "../index.module.less";

interface ToolPermissionCatalogProps {
  refreshToken: number;
}

const effectColor: Record<ToolPermissionEffect, string> = {
  read: "green",
  mutate: "orange",
  external_side_effect: "volcano",
  unknown: "gold",
  chat_infrastructure: "blue",
};

const effectKey: Record<ToolPermissionEffect, string> = {
  read: "read",
  mutate: "mutate",
  external_side_effect: "externalSideEffect",
  unknown: "unknown",
  chat_infrastructure: "chatInfrastructure",
};

export function ToolPermissionCatalog({
  refreshToken,
}: ToolPermissionCatalogProps) {
  const { t } = useTranslation();
  const selectedAgent = useAgentStore((state) => state.selectedAgent);
  const [items, setItems] = useState<ToolPermissionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const mountedRef = useRef(false);
  const generationRef = useRef(0);

  const load = useCallback(async () => {
    const generation = ++generationRef.current;
    setLoading(true);
    setError(false);
    try {
      const loaded = await api.getToolPermissions();
      if (!mountedRef.current || generation !== generationRef.current) return;
      setItems(loaded);
    } catch {
      if (mountedRef.current && generation === generationRef.current) {
        setError(true);
      }
    } finally {
      if (mountedRef.current && generation === generationRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
    };
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshToken, selectedAgent]);

  const dataSource = useMemo(
    () => [...items].sort((left, right) => left.name.localeCompare(right.name)),
    [items],
  );
  const columns: ColumnsType<ToolPermissionInfo> = [
    {
      title: t("security.mutationGuard.catalog.toolName"),
      dataIndex: "name",
      key: "name",
      render: (name: string) => (
        <code
          className={styles.toolPermissionName}
          data-testid="tool-permission-name"
        >
          {name}
        </code>
      ),
    },
    {
      title: t("security.mutationGuard.catalog.classification"),
      dataIndex: "effect",
      key: "effect",
      render: (effect: ToolPermissionEffect) => (
        <Tag color={effectColor[effect]}>
          {t(`security.mutationGuard.catalog.effects.${effectKey[effect]}`)}
        </Tag>
      ),
    },
    {
      title: t("security.mutationGuard.catalog.normalAccount"),
      dataIndex: "allowed_for_member",
      key: "allowed_for_member",
      render: (allowed: boolean) => (
        <Tag color={allowed ? "green" : "red"}>
          {t(
            allowed
              ? "security.mutationGuard.catalog.allowed"
              : "security.mutationGuard.catalog.denied",
          )}
        </Tag>
      ),
    },
  ];

  return (
    <section className={styles.toolPermissionCatalog}>
      <h3>{t("security.mutationGuard.catalog.title")}</h3>
      <p>{t("security.mutationGuard.catalog.description")}</p>
      {error ? (
        <div className={styles.toolPermissionState}>
          <span role="alert">
            {t("security.mutationGuard.catalog.loadFailed")}
          </span>
          <Button onClick={() => void load()}>
            {t("security.mutationGuard.catalog.retry")}
          </Button>
        </div>
      ) : (
        <Table<ToolPermissionInfo>
          rowKey="name"
          loading={loading}
          dataSource={dataSource}
          columns={columns}
          pagination={{
            pageSize: 20,
            showSizeChanger: false,
            hideOnSinglePage: true,
          }}
          locale={{
            emptyText: t("security.mutationGuard.catalog.empty"),
          }}
          size="small"
        />
      )}
    </section>
  );
}
```

Export it from `components/index.ts`:

```typescript
export * from "./ToolPermissionCatalog";
```

Add styles after the Mutation Guard styles:

```less
.toolPermissionCatalog {
  max-width: 960px;
  margin-top: 28px;

  > h3 {
    margin: 0 0 8px;
    font-size: 16px;
  }

  > p {
    margin: 0 0 16px;
    color: #888;
    line-height: 1.6;
  }
}

.toolPermissionName {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
    "Liberation Mono", "Courier New", monospace;
  color: inherit;
}

.toolPermissionState {
  min-height: 120px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  border: 1px solid var(--color-border-secondary, #e8e8e8);
  border-radius: 12px;
}

:global(.dark-mode) {
  .toolPermissionCatalog > p {
    color: rgba(255, 255, 255, 0.45);
  }

  .toolPermissionState {
    border-color: rgba(255, 255, 255, 0.1);
  }
}
```

- [ ] **Step 5: Run the component tests**

Run:

```bash
cd console
npm run test:run -- \
  src/pages/Settings/Security/ToolPermissionCatalog.test.tsx
```

Expected: all catalog component tests PASS.

- [ ] **Step 6: Commit the independent catalog UI**

```bash
git add \
  console/src/pages/Settings/Security/components/ToolPermissionCatalog.tsx \
  console/src/pages/Settings/Security/ToolPermissionCatalog.test.tsx \
  console/src/pages/Settings/Security/components/index.ts \
  console/src/pages/Settings/Security/index.module.less
git commit -m "feat(console): render tool permission catalog"
```

## Task 7: Integrate independent loading and post-save refresh

**Files:**

- Modify:
  `console/src/pages/Settings/Security/components/MutationGuardTab.tsx`
- Modify:
  `console/src/pages/Settings/Security/MutationGuardTab.test.tsx`

- [ ] **Step 1: Extend the API mock and write failing integration tests**

Add `getToolPermissions: vi.fn()` to `apiMocks`, default it to an empty array in
`beforeEach`, and add:

```typescript
it("loads the settings and catalog independently", async () => {
  const settings = deferred<MutationGuardConfig>();
  hoisted.apiMocks.getMutationGuard.mockReturnValueOnce(settings.promise);
  hoisted.apiMocks.getToolPermissions.mockResolvedValueOnce([
    { name: "memory_search", effect: "unknown", allowed_for_member: false },
  ]);

  render(<MutationGuardTab />);

  expect(screen.getByText("common.loading")).toBeInTheDocument();
  await screen.findByText("memory_search");
  settings.resolve(config);
  await screen.findByText("security.mutationGuard.description");
});

it("refreshes the catalog only after a successful persisted save", async () => {
  hoisted.apiMocks.getToolPermissions
    .mockResolvedValueOnce([
      { name: "shell", effect: "mutate", allowed_for_member: false },
    ])
    .mockResolvedValueOnce([
      { name: "shell", effect: "mutate", allowed_for_member: true },
    ]);
  const user = userEvent.setup();
  render(<MutationGuardTab />);
  await screen.findByText("security.mutationGuard.description");
  await waitFor(() =>
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1),
  );

  await user.click(screen.getByRole("button", { name: "common.save" }));

  await waitFor(() =>
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2),
  );
});

it("does not refresh the catalog after a failed save", async () => {
  hoisted.apiMocks.updateMutationGuard.mockRejectedValueOnce(
    new Error("write failed"),
  );
  hoisted.apiMocks.getToolPermissions.mockResolvedValue([]);
  const user = userEvent.setup();
  render(<MutationGuardTab />);
  await screen.findByText("security.mutationGuard.description");
  await waitFor(() =>
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1),
  );

  await user.click(screen.getByRole("button", { name: "common.save" }));
  await screen.findByText("security.mutationGuard.saveFailed");

  expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
});

it("keeps the settings form usable when catalog loading fails", async () => {
  hoisted.apiMocks.getToolPermissions.mockRejectedValueOnce(
    new Error("catalog unavailable"),
  );

  render(<MutationGuardTab />);

  await screen.findByText("security.mutationGuard.description");
  await screen.findByText("security.mutationGuard.catalog.loadFailed");
  expect(screen.getByRole("button", { name: "common.save" })).toBeEnabled();
  expect(
    screen.getByRole("switch", {
      name: "security.mutationGuard.enabled",
    }),
  ).toBeEnabled();
});

it("keeps a successful save successful when catalog refresh fails", async () => {
  hoisted.apiMocks.getToolPermissions
    .mockResolvedValueOnce([])
    .mockRejectedValueOnce(new Error("refresh failed"));
  const user = userEvent.setup();
  render(<MutationGuardTab />);
  await screen.findByText("security.mutationGuard.description");

  await user.click(screen.getByRole("button", { name: "common.save" }));

  await waitFor(() =>
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2),
  );
  expect(hoisted.messageMocks.success).toHaveBeenCalledWith(
    "security.mutationGuard.saveSuccess",
  );
  expect(hoisted.messageMocks.error).not.toHaveBeenCalled();
  await screen.findByText("security.mutationGuard.catalog.loadFailed");
});
```

- [ ] **Step 2: Run the Mutation Guard tests and verify the child is absent**

Run:

```bash
cd console
npm run test:run -- \
  src/pages/Settings/Security/MutationGuardTab.test.tsx
```

Expected: FAIL because the catalog is not mounted and save does not change a
refresh token.

- [ ] **Step 3: Mount the child outside settings-only branches**

In `MutationGuardTab.tsx`, import the child and add state:

```typescript
import { ToolPermissionCatalog } from "./ToolPermissionCatalog";

const [catalogRefreshToken, setCatalogRefreshToken] = useState(0);
```

Immediately after a successful `updateMutationGuard(snapshot)` has passed the
mounted/generation guard, increment the token before showing success:

```typescript
setCatalogRefreshToken((current) => current + 1);
message.success(t("security.mutationGuard.saveSuccess"));
```

Wrap each of the two component-level early-return states with the shared tab
container. Keep a plain settings `<div>` as the first child and the catalog as
the second child in every render state so React preserves the catalog instance
while the settings request finishes. Replace the loading return with:

```typescript
if (loading) {
  return (
    <div className={styles.tabContent}>
      <div>
        <div className={styles.mutationGuardState}>{t("common.loading")}</div>
      </div>
      <ToolPermissionCatalog refreshToken={catalogRefreshToken} />
    </div>
  );
}
```

Replace the missing-draft return with:

```typescript
if (!draft) {
  return (
    <div className={styles.tabContent}>
      <div>
        <div className={styles.mutationGuardState}>
          <span role="alert">{error ? t(error) : null}</span>
          <Button onClick={() => void load()}>
            {t("environments.retry")}
          </Button>
        </div>
      </div>
      <ToolPermissionCatalog refreshToken={catalogRefreshToken} />
    </div>
  );
}
```

Finally, wrap the existing loaded settings content in the same first-child
`<div>`, then append the catalog as the stable second child. Change the loaded
return's opening from:

```typescript
return (
  <div className={styles.tabContent}>
    <p className={styles.tabDescription}>
```

to:

```typescript
return (
  <div className={styles.tabContent}>
    <div>
      <p className={styles.tabDescription}>
```

and replace its final save-actions closing block with:

```typescript
      <div className={styles.mutationGuardActions}>
        <Button
          type="primary"
          onClick={() => void save()}
          aria-disabled={
            saving || timeoutInvalid || draft.privileged_roles.length === 0
          }
          disabled={
            saving || timeoutInvalid || draft.privileged_roles.length === 0
          }
        >
          {t("common.save")}
        </Button>
      </div>
    </div>

    <ToolPermissionCatalog refreshToken={catalogRefreshToken} />
    </div>
  );
}
```

The settings wrapper keeps the catalog at child index 1 throughout loading,
error, and loaded states, preventing an accidental second initial request.
The rest of the loaded form remains byte-for-byte equivalent; the only new
behavior is the stable child mount and the refresh-token increment after a
successful save.

- [ ] **Step 4: Run both security component suites**

Run:

```bash
cd console
npm run test:run -- \
  src/pages/Settings/Security/MutationGuardTab.test.tsx \
  src/pages/Settings/Security/ToolPermissionCatalog.test.tsx
```

Expected: both suites PASS, including all pre-existing Mutation Guard tests.

- [ ] **Step 5: Commit integration**

```bash
git add \
  console/src/pages/Settings/Security/components/MutationGuardTab.tsx \
  console/src/pages/Settings/Security/MutationGuardTab.test.tsx
git commit -m "feat(console): refresh catalog after guard saves"
```

## Task 8: Localize the complete catalog surface

**Files:**

- Modify: `console/src/locales/en.json`
- Modify: `console/src/locales/id.json`
- Modify: `console/src/locales/ja.json`
- Modify: `console/src/locales/pt-BR.json`
- Modify: `console/src/locales/ru.json`
- Modify: `console/src/locales/vi.json`
- Modify: `console/src/locales/zh.json`

- [ ] **Step 1: Add the complete English and Chinese catalog objects**

Insert `catalog` under `security.mutationGuard` in `en.json`:

```json
"catalog": {
  "title": "Tool permission catalog",
  "description": "Read-only view of tools the selected agent may load and the effective permission for a normal account under the saved Mutation Guard settings.",
  "toolName": "Tool name",
  "classification": "Classification",
  "normalAccount": "Normal account",
  "allowed": "Allowed",
  "denied": "Denied",
  "empty": "No loadable tools found",
  "loadFailed": "Failed to load the tool permission catalog",
  "retry": "Retry",
  "effects": {
    "read": "READ",
    "mutate": "MUTATE",
    "externalSideEffect": "EXTERNAL_SIDE_EFFECT",
    "chatInfrastructure": "CHAT_INFRASTRUCTURE",
    "unknown": "UNKNOWN"
  }
}
```

Insert this object under the same key in `zh.json`:

```json
"catalog": {
  "title": "工具权限分类",
  "description": "只读展示当前智能体可能加载的工具，以及在已保存的变更防护配置下普通账号的实际权限。",
  "toolName": "工具名",
  "classification": "分类",
  "normalAccount": "普通账号",
  "allowed": "允许",
  "denied": "拒绝",
  "empty": "未发现可加载的工具",
  "loadFailed": "加载工具权限分类失败",
  "retry": "重试",
  "effects": {
    "read": "READ",
    "mutate": "MUTATE",
    "externalSideEffect": "EXTERNAL_SIDE_EFFECT",
    "chatInfrastructure": "CHAT_INFRASTRUCTURE",
    "unknown": "UNKNOWN"
  }
}
```

- [ ] **Step 2: Add equivalent objects to the other five locales**

Use the same keys and technical effect labels. Use these localized values:

```text
id:
  title=Katalog izin alat
  description=Tampilan hanya-baca untuk alat yang mungkin dimuat agen terpilih dan izin efektif akun biasa berdasarkan pengaturan Mutation Guard yang tersimpan.
  toolName=Nama alat
  classification=Klasifikasi
  normalAccount=Akun biasa
  allowed=Diizinkan
  denied=Ditolak
  empty=Tidak ada alat yang dapat dimuat
  loadFailed=Gagal memuat katalog izin alat
  retry=Coba lagi

ja:
  title=ツール権限分類
  description=選択中のエージェントが読み込む可能性のあるツールと、保存済みの変更ガード設定に基づく一般アカウントの実効権限を読み取り専用で表示します。
  toolName=ツール名
  classification=分類
  normalAccount=一般アカウント
  allowed=許可
  denied=拒否
  empty=読み込み可能なツールがありません
  loadFailed=ツール権限分類を読み込めませんでした
  retry=再試行

pt-BR:
  title=Catálogo de permissões de ferramentas
  description=Visualização somente leitura das ferramentas que o agente selecionado pode carregar e da permissão efetiva de uma conta comum conforme as configurações salvas do Mutation Guard.
  toolName=Nome da ferramenta
  classification=Classificação
  normalAccount=Conta comum
  allowed=Permitido
  denied=Negado
  empty=Nenhuma ferramenta carregável encontrada
  loadFailed=Falha ao carregar o catálogo de permissões
  retry=Tentar novamente

ru:
  title=Каталог разрешений инструментов
  description=Доступный только для чтения список инструментов, которые может загрузить выбранный агент, и фактических разрешений обычной учетной записи согласно сохраненным настройкам Mutation Guard.
  toolName=Имя инструмента
  classification=Классификация
  normalAccount=Обычная учетная запись
  allowed=Разрешено
  denied=Запрещено
  empty=Доступные для загрузки инструменты не найдены
  loadFailed=Не удалось загрузить каталог разрешений
  retry=Повторить

vi:
  title=Danh mục quyền công cụ
  description=Chế độ chỉ đọc hiển thị các công cụ mà tác nhân đã chọn có thể tải và quyền thực tế của tài khoản thông thường theo cấu hình Mutation Guard đã lưu.
  toolName=Tên công cụ
  classification=Phân loại
  normalAccount=Tài khoản thông thường
  allowed=Được phép
  denied=Bị từ chối
  empty=Không tìm thấy công cụ có thể tải
  loadFailed=Không thể tải danh mục quyền công cụ
  retry=Thử lại
```

For every locale, add this identical nested technical-label object:

```json
"effects": {
  "read": "READ",
  "mutate": "MUTATE",
  "externalSideEffect": "EXTERNAL_SIDE_EFFECT",
  "chatInfrastructure": "CHAT_INFRASTRUCTURE",
  "unknown": "UNKNOWN"
}
```

- [ ] **Step 3: Validate JSON and run the frontend security tests**

Run:

```bash
cd console
node -e 'for (const f of ["en","id","ja","pt-BR","ru","vi","zh"]) JSON.parse(require("fs").readFileSync(`src/locales/${f}.json`, "utf8"))'
npm run test:run -- \
  src/pages/Settings/Security/MutationGuardTab.test.tsx \
  src/pages/Settings/Security/ToolPermissionCatalog.test.tsx
```

Expected: JSON command exits `0`; both Vitest suites PASS.

- [ ] **Step 4: Commit localization**

```bash
git add console/src/locales/en.json console/src/locales/id.json \
  console/src/locales/ja.json console/src/locales/pt-BR.json \
  console/src/locales/ru.json console/src/locales/vi.json \
  console/src/locales/zh.json
git commit -m "feat(console): localize tool permission catalog"
```

## Task 9: Document the diagnostic behavior

**Files:**

- Modify: `website/public/docs/security.en.md`
- Modify: `website/public/docs/security.zh.md`

- [ ] **Step 1: Add the English documentation section**

Under the existing Mutation Guard section in `security.en.md`, add:

```markdown
### Tool permission catalog

The Mutation Guard settings page includes a read-only tool permission catalog
for the currently selected agent. It lists tools that the agent can
potentially load, including enabled plugin, memory, mode, context, coding, and
Driver tools. Each row shows the tool's default effect classification and
whether a guarded normal account is currently allowed to call that effect.

The result follows the saved Mutation Guard configuration, not unsaved form
edits. When Mutation Guard is disabled, every listed effect is allowed. When
it is enabled, `READ` and `CHAT_INFRASTRUCTURE` are allowed for normal accounts;
`MUTATE`, `EXTERNAL_SIDE_EFFECT`, and `UNKNOWN` are denied. `UNKNOWN` indicates
missing effect metadata and is intentionally fail-closed.

This table is diagnostic only. It cannot enable tools, edit classifications,
or change permissions. Switching the selected agent reloads that agent's
catalog, and successfully saving Mutation Guard settings refreshes the
effective allow/deny column.
```

- [ ] **Step 2: Add the Chinese documentation section**

Under the existing Mutation Guard section in `security.zh.md`, add:

```markdown
### 工具权限分类

变更防护设置页提供当前所选智能体的只读“工具权限分类”列表。列表会展示该智能体可能加载的工具，包括已启用的插件工具、记忆工具、模式工具、上下文工具、编码工具和 Driver 工具。每一行都会显示工具的默认行为分类，以及受防护的普通账号当前是否允许调用该类工具。

权限结果以已保存的变更防护配置为准，不跟随尚未保存的表单修改。关闭变更防护时，列表中的所有分类都显示为允许；开启后，普通账号允许调用 `READ` 和 `CHAT_INFRASTRUCTURE`，而 `MUTATE`、`EXTERNAL_SIDE_EFFECT` 和 `UNKNOWN` 会被拒绝。`UNKNOWN` 表示工具缺少行为元数据，并按安全优先原则默认拒绝。

该列表仅用于诊断，不能启用工具、编辑分类或修改权限。切换所选智能体会重新加载对应智能体的列表；成功保存变更防护设置后，会刷新普通账号的实际允许/拒绝结果。
```

- [ ] **Step 3: Check documentation formatting and commit**

Run:

```bash
git diff --check -- website/public/docs/security.en.md \
  website/public/docs/security.zh.md
```

Expected: exit `0` with no whitespace errors.

Commit:

```bash
git add website/public/docs/security.en.md \
  website/public/docs/security.zh.md
git commit -m "docs(security): explain tool permission catalog"
```

## Task 10: Run full relevant verification and review

**Files:**

- Verify all files changed in Tasks 1-9.
- Modify only files required to fix failures found by these commands.

- [ ] **Step 1: Format Python and frontend changes**

Run:

```bash
python -m black --line-length 79 \
  src/qwenpaw/security/mutation_guard/catalog.py \
  src/qwenpaw/app/workspace/local_workspace.py \
  src/qwenpaw/app/routers/config.py \
  tests/unit/app/workspace/test_local_workspace_catalog.py \
  tests/unit/security/mutation_guard/test_catalog.py \
  tests/unit/app/routers/test_config_router.py
cd console
npm run format
```

Expected: both commands exit `0`. If formatting changes files, rerun the
focused tests before continuing.

- [ ] **Step 2: Run the complete relevant backend test set**

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/app/workspace/test_local_workspace_catalog.py \
  tests/unit/security/mutation_guard \
  tests/unit/runtime/test_tool_effect_catalog.py \
  tests/unit/app/routers/test_config_router.py \
  tests/unit/app/test_api_capability_catalog.py
```

Expected: all tests PASS. No endpoint test may write configuration or emit a
Mutation Guard denial audit record.

- [ ] **Step 3: Run the complete relevant frontend test set**

Run:

```bash
cd console
npm run test:run -- \
  src/api/modules/security.test.ts \
  src/pages/Settings/Security/MutationGuardTab.test.tsx \
  src/pages/Settings/Security/ToolPermissionCatalog.test.tsx
npm run lint
npm run build
```

Expected: Vitest, ESLint, TypeScript, and Vite build all PASS.

- [ ] **Step 4: Run repository gates**

From the repository root, run:

```bash
git diff --check
pre-commit run --all-files
```

Expected: both commands exit `0`. If hooks modify files, inspect the changes,
rerun focused tests, then rerun `pre-commit run --all-files` until clean.

- [ ] **Step 5: Perform the required code review**

Use the `superpowers:requesting-code-review` skill. Review against the approved
spec and explicitly check:

```text
- The endpoint resolves X-Agent-Id and performs no writes.
- The collector never invokes a tool body.
- Mode/skill/feature descriptors are included, explicit disables are excluded,
  and disabled-by-default plugin tools require opt-in.
- Duplicate names with conflicting effects fail discovery.
- memory_search remains UNKNOWN and denied while the guard is enabled.
- All permission booleans come from authorize_effect().
- Catalog errors do not hide or disable the Mutation Guard form.
- Agent change and successful save refetch; failed save does not.
- Stale or post-unmount responses cannot update the component.
- All seven locales and both security documents are updated.
```

Fix every substantive review finding, rerun the affected focused tests, and
rerun `git diff --check`.

- [ ] **Step 6: Commit verification fixes and record final evidence**

If verification or review changed files:

```bash
git add src tests console website
git commit -m "fix(security): address tool catalog review"
```

Then capture final handoff evidence:

```bash
git status --short
git log --oneline -10
```

Expected: `git status --short` is empty, and the recent commits show the
registry seam, backend catalog, endpoint, frontend client/table/integration,
localization, documentation, and any review fix.

## Acceptance checklist

- [ ] The selected agent's complete potentially loadable catalog is returned,
  including core, opted-in plugin, registered mode, memory, configured context,
  available coding, and exposed Driver tools.
- [ ] Explicitly disabled tools are absent; disabled-by-default plugin tools
  appear only when enabled for that agent.
- [ ] Rows are deterministically sorted and duplicate conflicts fail closed.
- [ ] Every row uses one existing effect value: `READ`, `MUTATE`,
  `EXTERNAL_SIDE_EFFECT`, `CHAT_INFRASTRUCTURE`, or `UNKNOWN`.
- [ ] The normal-account result is computed with `authorize_effect()` against
  the persisted Mutation Guard configuration.
- [ ] `memory_search` is visible as `UNKNOWN`; it is denied when the guard is
  enabled and allowed when the guard is disabled.
- [ ] The React table is read-only, localized, paginated at 20 rows, and has
  independent loading/error/retry/empty states.
- [ ] Switching the agent or successfully saving Mutation Guard refetches the
  catalog; unsaved edits and failed saves do not alter it.
- [ ] Backend/frontend focused tests, formatting, lint, build, pre-commit, and
  review all pass.
