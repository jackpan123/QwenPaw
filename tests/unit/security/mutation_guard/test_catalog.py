# -*- coding: utf-8 -*-
"""Tests for the policy-derived tool permission catalog core."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.drivers.capabilities import (
    CapabilityExposure,
    DriverCapability,
)
from qwenpaw.runtime.tool_registry import ToolDescriptor, ToolEffectSpec
from qwenpaw.security.mutation_guard import ActionEffect, catalog
from qwenpaw.security.mutation_guard.catalog import (
    ToolEffectCandidate,
    ToolPermissionEntry,
    _candidate_from_dynamic_tool,
    build_tool_permission_entries,
    collect_tool_permissions,
)


def _config(enabled: bool) -> MutationGuardConfig:
    """Build a valid mutation guard config for catalog tests."""
    return MutationGuardConfig(enabled=enabled, privileged_roles=["admin"])


@pytest.mark.parametrize("name", ["", "   "])
def test_build_entries_rejects_blank_tool_names(name):
    candidates = [ToolEffectCandidate(name, ActionEffect.READ)]

    with pytest.raises(ValueError, match=r"tool name must be non-empty"):
        build_tool_permission_entries(candidates, _config(True))


def test_build_entries_sorts_and_uses_authoritative_enabled_policy():
    candidates = [
        ToolEffectCandidate("write", ActionEffect.MUTATE),
        ToolEffectCandidate(
            "chat",
            ActionEffect.CHAT_INFRASTRUCTURE,
        ),
        ToolEffectCandidate("read", ActionEffect.READ),
        ToolEffectCandidate(
            "external",
            ActionEffect.EXTERNAL_SIDE_EFFECT,
        ),
        ToolEffectCandidate("missing", ActionEffect.UNKNOWN),
    ]

    entries = build_tool_permission_entries(candidates, _config(True))

    assert [entry.name for entry in entries] == [
        "chat",
        "external",
        "missing",
        "read",
        "write",
    ]
    assert {entry.name: entry.allowed_for_member for entry in entries} == {
        "chat": True,
        "external": False,
        "missing": False,
        "read": True,
        "write": False,
    }


def test_build_entries_allows_every_effect_when_guard_is_disabled():
    candidates = [ToolEffectCandidate(e.value, e) for e in ActionEffect]

    entries = build_tool_permission_entries(candidates, _config(False))

    assert len(entries) == len(ActionEffect)
    assert all(entry.allowed_for_member for entry in entries)


def test_build_entries_coalesces_matching_duplicates():
    candidates = [
        ToolEffectCandidate("same", ActionEffect.READ),
        ToolEffectCandidate("same", ActionEffect.READ),
    ]

    entries = build_tool_permission_entries(candidates, _config(True))

    assert len(entries) == 1
    assert entries[0].name == "same"
    assert entries[0].effect is ActionEffect.READ


def test_build_entries_rejects_conflicting_duplicates():
    candidates = [
        ToolEffectCandidate("same", ActionEffect.READ),
        ToolEffectCandidate("same", ActionEffect.MUTATE),
    ]

    with pytest.raises(
        ValueError,
        match=r"conflicting effects for tool 'same'.*read.*mutate",
    ):
        build_tool_permission_entries(candidates, _config(True))


def test_candidate_from_dynamic_tool_reads_wrapper_metadata():
    tool = SimpleNamespace(
        name="wrapped",
        _qp_effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )

    candidate = _candidate_from_dynamic_tool(tool)

    assert candidate == ToolEffectCandidate("wrapped", ActionEffect.READ)


def test_candidate_from_dynamic_tool_defaults_unannotated_callable():
    def named_tool():
        return None

    candidate = _candidate_from_dynamic_tool(named_tool)

    assert candidate == ToolEffectCandidate("named_tool", ActionEffect.UNKNOWN)


def test_tool_permission_entry_serializes_effect_and_fields():
    entry = ToolPermissionEntry(
        name="read_file",
        effect=ActionEffect.READ,
        allowed_for_member=True,
    )

    assert json.loads(entry.model_dump_json()) == {
        "name": "read_file",
        "effect": "read",
        "allowed_for_member": True,
    }


def test_candidate_from_dynamic_tool_rejects_nameless_object():
    with pytest.raises(
        ValueError,
        match=r"^discovered dynamic tool has no name$",
    ):
        _candidate_from_dynamic_tool(object())


def test_candidate_from_dynamic_tool_rejects_empty_name():
    tool = SimpleNamespace(name="", __name__="")

    with pytest.raises(
        ValueError,
        match=r"^discovered dynamic tool has no name$",
    ):
        _candidate_from_dynamic_tool(tool)


def test_candidate_from_dynamic_tool_falls_back_from_empty_name():
    tool = SimpleNamespace(name="", __name__="fallback_name")

    candidate = _candidate_from_dynamic_tool(tool)

    assert candidate.name == "fallback_name"


class _FakeLocalWorkspace:
    def __init__(self, descriptors):
        self.descriptors = descriptors
        self.configs: list[object] = []

    def list_potential_tool_descriptors(self, config):
        self.configs.append(config)
        return self.descriptors


class _FakeMemoryManager:
    def list_memory_tools(self):
        def memory_search():
            raise AssertionError("tool bodies must not run during discovery")

        return [memory_search]


class _FakeDriverManager:
    def __init__(self, capabilities):
        self.capabilities = capabilities
        self.request_context = None

    async def list_capabilities(self, *, kind, request_context):
        assert kind == "tool"
        self.request_context = request_context
        return self.capabilities


def _workspace(
    config,
    *,
    descriptors=(),
    memory_manager=None,
    driver_manager=None,
    workspace_dir="/tmp/catalog-workspace",
):
    return SimpleNamespace(
        config=config,
        local_workspace=_FakeLocalWorkspace(descriptors),
        memory_manager=memory_manager,
        driver_manager=driver_manager,
        workspace_dir=workspace_dir,
        agent_id="catalog-agent",
    )


def _catalog_agent_config(
    *,
    coding_enabled=True,
    strategy="scroll",
    visual_enabled=True,
):
    return SimpleNamespace(
        coding_mode=SimpleNamespace(enabled=coding_enabled),
        running=SimpleNamespace(
            light_context_config=SimpleNamespace(
                strategy=strategy,
                scroll_config=SimpleNamespace(
                    db_filename="history.db",
                    repl_timeout_s=12,
                    allow_unsandboxed=False,
                ),
                tool_result_pruning_config=SimpleNamespace(
                    pruning_recent_msg_max_bytes=4096,
                ),
                visual_compact_config=SimpleNamespace(enabled=visual_enabled),
            ),
        ),
    )


@pytest.mark.asyncio
async def test_collect_tool_permissions_discovers_available_sources(
    monkeypatch,
    tmp_path,
):
    config = _catalog_agent_config()
    coding_calls: list[dict[str, object]] = []

    def collect_coding_tools(**kwargs):
        coding_calls.append(kwargs)
        return [
            SimpleNamespace(
                name="coding_read",
                _qp_effect_spec=ToolEffectSpec(ActionEffect.READ),
            ),
        ]

    monkeypatch.setattr(
        "qwenpaw.modes.coding.collect_coding_tools",
        collect_coding_tools,
    )
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._scroll_repl_available",
        lambda scroll_config: True,
    )
    driver_original_id = "driver://fake/driver/tools/driver-original#read"
    driver_manager = _FakeDriverManager(
        [
            DriverCapability(
                capability_id=driver_original_id,
                driver_name="fake",
                protocol="fake",
                kind="tool",
                action="read",
                name="driver-original",
                effect=ActionEffect.READ,
                exposure=CapabilityExposure(
                    as_tool=True,
                    tool_name="driver_read",
                ),
            ),
            DriverCapability(
                capability_id="driver://fake/driver/tools/driver_hidden#write",
                driver_name="fake",
                protocol="fake",
                kind="tool",
                action="write",
                name="driver_hidden",
                effect=ActionEffect.MUTATE,
                exposure=CapabilityExposure(as_tool=False),
            ),
        ],
    )
    workspace = _workspace(
        config,
        descriptors=[
            ToolDescriptor(
                name="mode_registered",
                func=lambda: None,
                effect=ToolEffectSpec(ActionEffect.MUTATE),
            ),
        ],
        memory_manager=_FakeMemoryManager(),
        driver_manager=driver_manager,
        workspace_dir=tmp_path,
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    by_name = {entry.name: entry for entry in entries}
    assert {
        "mode_registered",
        "coding_read",
        "memory_search",
        "recall_history",
        "recall_history_python",
        "recover_visual_context",
        "driver_read",
    }.issubset(by_name)
    assert by_name["mode_registered"].effect is ActionEffect.MUTATE
    assert by_name["memory_search"].effect is ActionEffect.UNKNOWN
    assert by_name["recover_visual_context"].effect is ActionEffect.UNKNOWN
    assert by_name["driver_read"].effect is ActionEffect.READ
    assert "driver_hidden" not in by_name
    assert driver_manager.request_context == {}
    assert workspace.local_workspace.configs == [config]
    assert coding_calls == [
        {
            "agent_config": config,
            "workspace_dir": tmp_path,
            "agent_id": "catalog-agent",
            "request_context": {},
            "governor": None,
        },
    ]


@pytest.mark.asyncio
async def test_collect_tool_permissions_skips_disabled_coding_and_context(
    monkeypatch,
):
    def coding_must_not_run(*_args, **_kwargs):
        pytest.fail(
            "coding collector was called while coding mode is disabled",
        )

    monkeypatch.setattr(
        "qwenpaw.modes.coding.collect_coding_tools",
        coding_must_not_run,
    )
    workspace = _workspace(
        _catalog_agent_config(
            coding_enabled=False,
            strategy="native",
            visual_enabled=False,
        ),
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    assert entries == []


@pytest.mark.asyncio
async def test_collect_tool_permissions_omits_unavailable_optional_source(
    monkeypatch,
):
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._coding_candidates",
        lambda workspace: (_ for _ in ()).throw(ImportError("missing coding")),
    )
    workspace = _workspace(
        _catalog_agent_config(
            strategy="native",
            visual_enabled=False,
        ),
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    assert entries == []


@pytest.mark.asyncio
async def test_collect_tool_permissions_omits_scroll_repl_when_unavailable(
    monkeypatch,
):
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._scroll_repl_available",
        lambda scroll_config: False,
    )
    workspace = _workspace(
        _catalog_agent_config(
            coding_enabled=False,
            visual_enabled=False,
        ),
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    assert [entry.name for entry in entries] == ["recall_history"]


@pytest.mark.asyncio
async def test_collect_tool_permissions_keeps_other_context_contributors(
    monkeypatch,
):
    def unavailable_repl(workspace):
        raise RuntimeError("repl unavailable")

    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.catalog._scroll_repl_candidates",
        unavailable_repl,
    )
    workspace = _workspace(
        _catalog_agent_config(coding_enabled=False),
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    names = {entry.name for entry in entries}
    assert "recall_history" in names
    assert "recover_visual_context" in names
    assert "recall_history_python" not in names


@pytest.mark.asyncio
async def test_collect_tool_permissions_offloads_synchronous_discovery(
    monkeypatch,
):
    main_thread_id = threading.get_ident()
    registry_thread_ids: list[int] = []
    memory_thread_ids: list[int] = []
    worker_thread_ids: list[int] = []
    agent_config = _catalog_agent_config(
        coding_enabled=False,
        strategy="native",
        visual_enabled=False,
    )

    def collect_registry(_workspace, captured_config=None):
        registry_thread_ids.append(threading.get_ident())
        assert captured_config is agent_config
        return []

    def collect_memory(_workspace):
        memory_thread_ids.append(threading.get_ident())
        return []

    def collect_in_worker(snapshot):
        worker_thread_ids.append(threading.get_ident())
        assert snapshot.config is not agent_config
        light_context_config = snapshot.config.running.light_context_config
        snapshot_strategy = light_context_config.strategy
        assert snapshot_strategy == "native"
        assert snapshot.agent_id == "catalog-agent"
        assert snapshot.workspace_dir == "/tmp/catalog-workspace"
        return []

    monkeypatch.setattr(
        catalog,
        "_registry_candidates",
        collect_registry,
    )
    monkeypatch.setattr(
        catalog,
        "_memory_candidates",
        collect_memory,
    )
    monkeypatch.setattr(
        catalog,
        "_collect_blocking_candidates",
        collect_in_worker,
    )
    workspace = _workspace(
        agent_config,
    )

    entries = await collect_tool_permissions(workspace, _config(True))

    assert entries == []
    assert registry_thread_ids == [main_thread_id]
    assert memory_thread_ids == [main_thread_id]
    assert len(worker_thread_ids) == 1
    assert worker_thread_ids[0] != main_thread_id


@pytest.mark.asyncio
async def test_collect_tool_permissions_propagates_cross_source_conflicts():
    def mode_registered():
        raise AssertionError("tool bodies must not run during discovery")

    mode_registered.__name__ = "shared"
    workspace = _workspace(
        _catalog_agent_config(
            coding_enabled=False,
            strategy="native",
            visual_enabled=False,
        ),
        descriptors=[
            SimpleNamespace(
                name="shared",
                effect=ToolEffectSpec(ActionEffect.READ),
            ),
        ],
        memory_manager=SimpleNamespace(
            list_memory_tools=lambda: [mode_registered],
        ),
    )

    with pytest.raises(ValueError, match=r"conflicting effects.*shared"):
        await collect_tool_permissions(workspace, _config(True))
