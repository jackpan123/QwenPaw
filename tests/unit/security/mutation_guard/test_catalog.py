# -*- coding: utf-8 -*-
"""Tests for the policy-derived tool permission catalog core."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.runtime.tool_registry import ToolEffectSpec
from qwenpaw.security.mutation_guard import ActionEffect
from qwenpaw.security.mutation_guard.catalog import (
    ToolEffectCandidate,
    ToolPermissionEntry,
    _candidate_from_dynamic_tool,
    build_tool_permission_entries,
)


def _config(enabled: bool) -> MutationGuardConfig:
    """Build a valid mutation guard config for catalog tests."""
    return MutationGuardConfig(enabled=enabled, privileged_roles=["admin"])


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
    candidates = [
        ToolEffectCandidate(effect.value, effect) for effect in ActionEffect
    ]

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
