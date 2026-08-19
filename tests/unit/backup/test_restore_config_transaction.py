# -*- coding: utf-8 -*-
"""Transactional root-config coverage for online backup restore."""

# pylint: disable=protected-access
from __future__ import annotations

import copy
import json
import os
import threading
import zipfile
from pathlib import Path

import pytest

from qwenpaw.backup._ops import restore
from qwenpaw.backup._utils.constants import PREFIX_CONFIG, PREFIX_WORKSPACES
from qwenpaw.backup.models import BackupMeta, RestoreBackupRequest
from qwenpaw.config import Config
from qwenpaw.config import utils as config_utils
from qwenpaw.config.config import AgentProfileRef


@pytest.fixture(autouse=True)
def _reset_root_config_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_utils, "_config_cache", None)
    monkeypatch.setattr(config_utils, "_config_mtime", None)
    monkeypatch.setattr(
        config_utils,
        "_config_cache_path",
        None,
        raising=False,
    )


def _write_config(path: Path, config: Config) -> None:
    path.write_text(
        json.dumps(config.model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )


def _patch_restore_paths(
    monkeypatch: pytest.MonkeyPatch,
    working_dir: Path,
) -> Path:
    config_path = working_dir / "config.json"
    monkeypatch.setattr(config_utils, "get_config_path", lambda: config_path)
    return config_path


def _patch_restore_archive(
    monkeypatch: pytest.MonkeyPatch,
    archive: Path,
) -> None:
    meta = BackupMeta(name="transaction-test")
    monkeypatch.setattr(restore, "find_zip_path", lambda _backup_id: archive)
    monkeypatch.setattr(
        restore,
        "_read_meta_or_missing",
        lambda _zf, _backup_id: meta,
    )
    monkeypatch.setattr(
        restore,
        "resolve_signature_action",
        lambda *_args, **_kwargs: None,
    )


def test_full_config_restore_serializes_real_transaction_without_lost_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config(user_timezone="UTC"))

    backup_config = Config(user_timezone="Europe/London")
    archive = tmp_path / "backup.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            PREFIX_CONFIG,
            json.dumps(
                backup_config.model_dump(mode="json", by_alias=True),
            ),
        )
    _patch_restore_archive(monkeypatch, archive)

    stage_started = threading.Event()
    release_restore = threading.Event()
    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    failures: list[BaseException] = []
    original_stage = restore._stage_global_config

    def controlled_stage(*args, **kwargs):
        staged = original_stage(*args, **kwargs)
        stage_started.set()
        assert release_restore.wait(timeout=3)
        return staged

    monkeypatch.setattr(restore, "_stage_global_config", controlled_stage)

    request = RestoreBackupRequest(
        include_agents=False,
        include_global_config=True,
        include_secrets=False,
        include_skill_pool=False,
        mode="full",
        preserve_local_protected_config=False,
    )

    def run_restore() -> None:
        try:
            restore._restore_sync_locked("backup-id", request)
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)

    def run_mutation() -> None:
        try:
            mutation_started.set()

            def mutate(config: Config) -> None:
                config.security.mutation_guard.deny_message = "online mutation"
                config.security.tool_guard.enabled = False

            config_utils.update_config_transaction(mutate, config_path)
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)
        finally:
            mutation_finished.set()

    restore_thread = threading.Thread(target=run_restore)
    mutation_thread = threading.Thread(target=run_mutation)
    restore_thread.start()
    assert stage_started.wait(timeout=3)
    mutation_thread.start()
    assert mutation_started.wait(timeout=3)
    mutation_completed_during_restore = mutation_finished.wait(timeout=0.1)
    release_restore.set()
    restore_thread.join(timeout=3)
    mutation_thread.join(timeout=3)

    assert not restore_thread.is_alive()
    assert not mutation_thread.is_alive()
    assert not failures
    assert mutation_completed_during_restore is False
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert persisted["user_timezone"] == "Europe/London"
    assert (
        persisted["security"]["mutation_guard"]["deny_message"]
        == "online mutation"
    )
    assert persisted["security"]["tool_guard"]["enabled"] is False


def test_workspace_only_restore_uses_root_config_transaction_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config())

    archive = tmp_path / "backup.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(f"{PREFIX_WORKSPACES}new-agent/note.txt", "restored")
    _patch_restore_archive(monkeypatch, archive)

    stage_started = threading.Event()
    release_restore = threading.Event()
    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    failures: list[BaseException] = []
    original_stage_all = restore._stage_all

    def controlled_stage_all(*args, **kwargs):
        staged = original_stage_all(*args, **kwargs)
        stage_started.set()
        assert release_restore.wait(timeout=3)
        return staged

    monkeypatch.setattr(restore, "_stage_all", controlled_stage_all)
    request = RestoreBackupRequest(
        include_agents=True,
        agent_ids=["new-agent"],
        include_global_config=False,
        include_secrets=False,
        include_skill_pool=False,
        default_workspace_dir=str(tmp_path / "restored"),
    )

    def run_restore() -> None:
        try:
            restore._restore_sync_locked("backup-id", request)
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)

    def run_mutation() -> None:
        try:
            mutation_started.set()
            config_utils.update_config_transaction(
                lambda config: setattr(
                    config.security.mutation_guard,
                    "deny_message",
                    "workspace concurrent mutation",
                ),
                config_path,
            )
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)
        finally:
            mutation_finished.set()

    restore_thread = threading.Thread(target=run_restore)
    mutation_thread = threading.Thread(target=run_mutation)
    restore_thread.start()
    assert stage_started.wait(timeout=3)
    mutation_thread.start()
    assert mutation_started.wait(timeout=3)
    mutation_completed_during_restore = mutation_finished.wait(timeout=0.1)
    release_restore.set()
    restore_thread.join(timeout=3)
    mutation_thread.join(timeout=3)

    assert not failures
    assert mutation_completed_during_restore is False
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert (
        persisted["security"]["mutation_guard"]["deny_message"]
        == "workspace concurrent mutation"
    )
    assert persisted["agents"]["profiles"]["new-agent"][
        "workspace_dir"
    ] == str((tmp_path / "restored" / "new-agent").resolve())


def test_independent_directory_staging_does_not_hold_root_config_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config(user_timezone="UTC"))

    archive = tmp_path / "backup.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            PREFIX_CONFIG,
            json.dumps(
                Config(user_timezone="Europe/London").model_dump(
                    mode="json",
                    by_alias=True,
                ),
            ),
        )
    _patch_restore_archive(monkeypatch, archive)

    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    mutation_thread: threading.Thread | None = None
    completed_during_secret_stage: list[bool] = []
    failures: list[BaseException] = []

    def run_mutation() -> None:
        try:
            mutation_started.set()
            config_utils.update_config_transaction(
                lambda config: setattr(
                    config.security.mutation_guard,
                    "deny_message",
                    "before root restore transaction",
                ),
                config_path,
            )
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)
        finally:
            mutation_finished.set()

    def controlled_stage_secrets(_zf, _staged_dirs) -> None:
        nonlocal mutation_thread
        mutation_thread = threading.Thread(target=run_mutation)
        mutation_thread.start()
        assert mutation_started.wait(timeout=3)
        completed_during_secret_stage.append(
            mutation_finished.wait(timeout=0.1),
        )

    monkeypatch.setattr(restore, "_stage_secrets", controlled_stage_secrets)
    request = RestoreBackupRequest(
        include_agents=False,
        include_global_config=True,
        include_secrets=True,
        include_skill_pool=False,
        mode="full",
        preserve_local_protected_config=False,
    )

    restore._restore_sync_locked("backup-id", request)
    assert mutation_thread is not None
    mutation_thread.join(timeout=3)

    assert not failures
    assert completed_during_secret_stage == [True]


def test_direct_commit_preserves_raw_fields_and_invalidates_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config(user_timezone="UTC"))
    cached = config_utils.load_config(config_path)
    original_mtime_ns = config_path.stat().st_mtime_ns

    staged = tmp_path / "config.json.tmp"
    staged_payload = Config(user_timezone="Asia/Shanghai").model_dump(
        mode="json",
        by_alias=True,
    )
    staged_payload["future_root_key"] = {"enabled": True}
    staged_payload["security"]["future_nested_key"] = "keep-me"
    staged.write_text(json.dumps(staged_payload), encoding="utf-8")
    os.utime(staged, ns=(original_mtime_ns, original_mtime_ns))

    restore._commit_staged_global_config(staged)

    assert (
        json.loads(config_path.read_text(encoding="utf-8")) == staged_payload
    )
    reloaded = config_utils.load_config(config_path)
    assert reloaded is not cached
    assert reloaded.user_timezone == "Asia/Shanghai"


def test_full_config_and_workspace_restore_preserves_unknown_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config())
    destination = (tmp_path / "restored" / "agent-a").resolve()

    backup_payload = Config(user_timezone="Europe/London").model_dump(
        mode="json",
        by_alias=True,
    )
    backup_payload["future_root_key"] = {"version": 2}
    backup_payload["security"]["future_security_key"] = {
        "policy": "keep",
    }
    backup_payload["agents"]["profiles"] = {
        "agent-a": {
            "id": "agent-a",
            "workspace_dir": "/backup/workspaces/agent-a",
            "future_agent_key": {"feature": "keep"},
        },
    }
    archive = tmp_path / "backup.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(PREFIX_CONFIG, json.dumps(backup_payload))
        zf.writestr(f"{PREFIX_WORKSPACES}agent-a/note.txt", "restored")
    _patch_restore_archive(monkeypatch, archive)

    request = RestoreBackupRequest(
        include_agents=True,
        agent_ids=["agent-a"],
        include_global_config=True,
        include_secrets=False,
        include_skill_pool=False,
        default_workspace_dir=str(tmp_path / "restored"),
        mode="full",
        preserve_local_protected_config=False,
    )

    restore._restore_sync_locked("backup-id", request)

    expected = copy.deepcopy(backup_payload)
    expected["agents"]["profiles"]["agent-a"]["workspace_dir"] = str(
        destination,
    )
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert persisted == expected


@pytest.mark.parametrize(
    ("failure_kind", "expected_error"),
    [
        ("malformed", json.JSONDecodeError),
        ("validation", ValueError),
        ("write", OSError),
    ],
)
def test_config_commit_failure_discards_all_orchestration_staging(
    failure_kind: str,
    expected_error: type[BaseException],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config(user_timezone="UTC"))
    staged_config = tmp_path / "config.json.tmp"
    if failure_kind == "malformed":
        staged_config.write_text("{", encoding="utf-8")
    elif failure_kind == "validation":
        invalid = Config().model_dump(mode="json", by_alias=True)
        invalid["security"]["mutation_guard"]["classifier_timeout_seconds"] = 0
        staged_config.write_text(json.dumps(invalid), encoding="utf-8")
    else:
        _write_config(staged_config, Config(user_timezone="Asia/Shanghai"))

        def fail_write(*_args, **_kwargs) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(config_utils, "write_json_atomic", fail_write)

    staged_dirs = [
        tmp_path / "workspace",
        tmp_path / "secrets",
        tmp_path / "skill-pool",
    ]
    staged_tmp_dirs = []
    for destination in staged_dirs:
        staged_tmp = destination.with_name(
            destination.name + ".restore_tmp",
        )
        staged_tmp.mkdir()
        (staged_tmp / "data.txt").write_text("staged", encoding="utf-8")
        staged_tmp_dirs.append(staged_tmp)

    with pytest.raises(expected_error):
        restore._commit_and_finalize(
            staged_dirs,
            staged_config,
            {},
            [],
            "backup-id",
        )

    assert not staged_config.exists()
    assert all(not staged_tmp.exists() for staged_tmp in staged_tmp_dirs)


def test_direct_global_config_write_failure_keeps_original_cache_and_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    _write_config(config_path, Config(user_timezone="UTC"))
    original_bytes = config_path.read_bytes()
    cached = config_utils.load_config(config_path)
    staged = tmp_path / "config.json.tmp"
    _write_config(staged, Config(user_timezone="Asia/Shanghai"))

    def fail_write(*_args, **_kwargs) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(config_utils, "write_json_atomic", fail_write)

    with pytest.raises(OSError, match="disk full"):
        restore._commit_staged_global_config(staged)

    assert config_path.read_bytes() == original_bytes
    assert staged.is_file()
    # Upstream hardened load_config to hand out a deep copy every
    # time, so identity no longer holds — assert the cached content
    # is unchanged instead.
    assert config_utils.load_config(config_path).model_dump(
        mode="json", by_alias=True
    ) == cached.model_dump(mode="json", by_alias=True)


def test_raw_config_mutation_revalidates_without_polluting_disk_or_cache(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))
    original_bytes = config_path.read_bytes()
    cached = config_utils.load_config(config_path)

    def make_invalid(raw_config: dict) -> None:
        raw_config["security"]["mutation_guard"][
            "classifier_timeout_seconds"
        ] = 0

    with pytest.raises(ValueError):
        config_utils.update_raw_config_transaction(make_invalid, config_path)

    assert config_path.read_bytes() == original_bytes
    # Upstream hardened load_config to hand out a deep copy every
    # time, so identity no longer holds — assert the cached content
    # is unchanged instead.
    assert config_utils.load_config(config_path).model_dump(
        mode="json", by_alias=True
    ) == cached.model_dump(mode="json", by_alias=True)


def test_workspace_config_write_failure_does_not_pollute_shared_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _patch_restore_paths(monkeypatch, tmp_path)
    old_workspace = tmp_path / "old-workspace"
    config = Config()
    config.agents.profiles["agent-a"] = AgentProfileRef(
        id="agent-a",
        workspace_dir=str(old_workspace),
    )
    _write_config(config_path, config)
    cached = config_utils.load_config(config_path)

    def fail_write(*_args, **_kwargs) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(config_utils, "write_json_atomic", fail_write)
    new_workspace = tmp_path / "new-workspace"

    with pytest.raises(OSError, match="disk full"):
        restore._commit_and_finalize(
            [],
            None,
            {"agent-a": new_workspace},
            [],
            "backup-id",
        )

    assert cached.agents.profiles["agent-a"].workspace_dir == str(
        old_workspace,
    )
    # Upstream hardened load_config to hand out a deep copy every
    # time, so identity no longer holds — assert the cached content
    # is unchanged instead.
    assert config_utils.load_config(config_path).model_dump(
        mode="json", by_alias=True
    ) == cached.model_dump(mode="json", by_alias=True)
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert persisted["agents"]["profiles"]["agent-a"]["workspace_dir"] == str(
        old_workspace,
    )
