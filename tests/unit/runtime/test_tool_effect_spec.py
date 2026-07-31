# -*- coding: utf-8 -*-
"""UT for ``ToolEffectSpec`` — per-action side-effect resolution.

A tool's effect can depend on which action the model picked (e.g. a browser
tool is READ for ``snapshot`` but EXTERNAL_SIDE_EFFECT for ``click``).
``ToolEffectSpec.resolve`` maps the chosen param value to an
:class:`ActionEffect`, falling back to ``default`` when no selector is
configured or the value is unrecognised.
"""
from __future__ import annotations

from qwenpaw.runtime.tool_registry import ToolEffectSpec
from qwenpaw.security.mutation_guard import ActionEffect


class TestBrowserEffectResolvesPerAction:
    def test_snapshot_is_read(self):
        spec = ToolEffectSpec(
            default=ActionEffect.EXTERNAL_SIDE_EFFECT,
            selector_param="action",
            read_values=("snapshot", "navigate", "open", "console_messages"),
        )
        assert spec.resolve({"action": "snapshot"}) is ActionEffect.READ

    def test_click_is_external_side_effect(self):
        spec = ToolEffectSpec(
            default=ActionEffect.EXTERNAL_SIDE_EFFECT,
            selector_param="action",
            read_values=("snapshot", "navigate", "open", "console_messages"),
        )
        assert (
            spec.resolve({"action": "click"})
            is ActionEffect.EXTERNAL_SIDE_EFFECT
        )

    def test_unknown_action_falls_back_to_default(self):
        spec = ToolEffectSpec(
            default=ActionEffect.EXTERNAL_SIDE_EFFECT,
            selector_param="action",
            read_values=("snapshot",),
        )
        assert (
            spec.resolve({"action": "totally_new_action"})
            is ActionEffect.EXTERNAL_SIDE_EFFECT
        )

    def test_case_insensitive_read_value(self):
        spec = ToolEffectSpec(
            default=ActionEffect.MUTATE,
            selector_param="action",
            read_values=("Snapshot",),
        )
        assert spec.resolve({"action": "SNAPSHOT"}) is ActionEffect.READ


class TestMutateAndExternalBranches:
    def test_mutate_values_branch(self):
        spec = ToolEffectSpec(
            default=ActionEffect.READ,
            selector_param="action",
            mutate_values=("write_file", "delete"),
        )
        assert spec.resolve({"action": "write_file"}) is ActionEffect.MUTATE
        assert spec.resolve({"action": "delete"}) is ActionEffect.MUTATE

    def test_external_values_branch(self):
        spec = ToolEffectSpec(
            default=ActionEffect.READ,
            selector_param="action",
            external_values=("send_email", "http_post"),
        )
        assert (
            spec.resolve({"action": "send_email"})
            is ActionEffect.EXTERNAL_SIDE_EFFECT
        )

    def test_read_takes_precedence_over_default_when_listed(self):
        # read_values should win even if default is MUTATE.
        spec = ToolEffectSpec(
            default=ActionEffect.MUTATE,
            selector_param="action",
            read_values=("snapshot",),
        )
        assert spec.resolve({"action": "snapshot"}) is ActionEffect.READ


class TestDefaultWithoutSelector:
    def test_no_selector_returns_default(self):
        spec = ToolEffectSpec(default=ActionEffect.READ)
        assert spec.resolve({"action": "anything"}) is ActionEffect.READ

    def test_no_selector_none_params(self):
        spec = ToolEffectSpec(default=ActionEffect.READ)
        assert spec.resolve(None) is ActionEffect.READ

    def test_selector_but_missing_param_returns_default(self):
        spec = ToolEffectSpec(
            default=ActionEffect.UNKNOWN,
            selector_param="action",
            read_values=("snapshot",),
        )
        assert spec.resolve({}) is ActionEffect.UNKNOWN

    def test_selector_empty_string_param_returns_default(self):
        spec = ToolEffectSpec(
            default=ActionEffect.UNKNOWN,
            selector_param="action",
            read_values=("snapshot",),
        )
        assert spec.resolve({"action": ""}) is ActionEffect.UNKNOWN

    def test_fail_closed_default_is_unknown(self):
        # Unannotated tools must default to UNKNOWN (fail-closed).
        spec = ToolEffectSpec()
        assert spec.default is ActionEffect.UNKNOWN
        assert spec.resolve(None) is ActionEffect.UNKNOWN
