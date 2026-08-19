# -*- coding: utf-8 -*-
"""Tests for mutation guard configuration."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from qwenpaw.config.config import (
    Config,
    MutationGuardConfig,
    SecurityConfig,
)


def test_mutation_guard_defaults():
    config = MutationGuardConfig()

    assert config.enabled is True
    assert config.privileged_roles == ["admin", "root"]
    assert config.intent_precheck_enabled is True
    assert config.classifier_timeout_seconds == 8
    assert "没有执行变更操作的权限" in config.deny_message


def test_security_config_includes_mutation_guard_defaults():
    config = SecurityConfig()

    assert config.mutation_guard == MutationGuardConfig()


def test_root_config_round_trips_mutation_guard_configuration():
    config = Config.model_validate(
        {
            "security": {
                "mutation_guard": {
                    "enabled": False,
                    "privileged_roles": ["owner"],
                    "classifier_timeout_seconds": 12,
                },
            },
        },
    )

    serialized = config.model_dump()
    restored = Config.model_validate(serialized)

    assert restored.security.mutation_guard.enabled is False
    assert restored.security.mutation_guard.privileged_roles == ["owner"]
    assert restored.security.mutation_guard.classifier_timeout_seconds == 12


@pytest.mark.parametrize("timeout", [1, 60])
def test_classifier_timeout_accepts_inclusive_boundaries(timeout):
    config = MutationGuardConfig(classifier_timeout_seconds=timeout)

    assert config.classifier_timeout_seconds == timeout


@pytest.mark.parametrize("timeout", [0, 61])
def test_classifier_timeout_rejects_values_outside_boundaries(timeout):
    with pytest.raises(ValidationError):
        MutationGuardConfig(classifier_timeout_seconds=timeout)


def test_privileged_roles_are_trimmed_casefolded_and_deduplicated():
    config = MutationGuardConfig(
        privileged_roles=[" Admin ", "ROOT", "admin"],
    )

    assert config.privileged_roles == ["admin", "root"]


@pytest.mark.parametrize("roles", [[], [""], ["   "]])
def test_privileged_roles_reject_empty_values(roles):
    with pytest.raises(ValidationError):
        MutationGuardConfig(privileged_roles=roles)
