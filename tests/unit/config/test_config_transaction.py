# -*- coding: utf-8 -*-
"""Tests for transactional root configuration updates."""

from __future__ import annotations

import json
import os
import threading
import time

import pytest

from qwenpaw.config import Config
from qwenpaw.config import utils as config_utils


@pytest.fixture(autouse=True)
def _reset_root_config_cache(monkeypatch):
    monkeypatch.setattr(config_utils, "_config_cache", None)
    monkeypatch.setattr(config_utils, "_config_mtime", None)
    monkeypatch.setattr(
        config_utils, "_config_cache_path", None, raising=False
    )


def _write_config(path, config: Config) -> None:
    path.write_text(
        json.dumps(config.model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )


def test_transaction_write_failure_does_not_mutate_cached_config(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))
    cached = config_utils.load_config(config_path)

    def fail_write(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(config_utils, "write_json_atomic", fail_write)

    def mutate(config: Config) -> None:
        config.user_timezone = "Asia/Shanghai"
        config.security.mutation_guard.deny_message = "changed"

    with pytest.raises(OSError, match="disk full"):
        config_utils.update_config_transaction(mutate, config_path)

    assert cached.user_timezone == "UTC"
    assert cached.security.mutation_guard.deny_message != "changed"
    assert config_utils.load_config(config_path) is cached
    assert (
        json.loads(config_path.read_text(encoding="utf-8"))["user_timezone"]
        == "UTC"
    )


def test_transaction_serializes_concurrent_updates_without_lost_fields(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))

    first_write_started = threading.Event()
    release_first_write = threading.Event()
    write_count_lock = threading.Lock()
    write_count = 0
    original_write = config_utils.write_json_atomic

    def controlled_write(*args, **kwargs):
        nonlocal write_count
        with write_count_lock:
            write_count += 1
            current_write = write_count
        if current_write == 1:
            first_write_started.set()
            assert release_first_write.wait(timeout=3)
        return original_write(*args, **kwargs)

    monkeypatch.setattr(
        config_utils,
        "write_json_atomic",
        controlled_write,
    )

    failures: list[BaseException] = []

    def run_update(mutate) -> None:
        try:
            config_utils.update_config_transaction(mutate, config_path)
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)

    def update_timezone(config: Config) -> None:
        config.user_timezone = "Asia/Shanghai"

    def update_mutation_guard(config: Config) -> None:
        config.security.mutation_guard.deny_message = "Task9 value"

    first = threading.Thread(target=run_update, args=(update_timezone,))
    second = threading.Thread(
        target=run_update,
        args=(update_mutation_guard,),
    )
    first.start()
    assert first_write_started.wait(timeout=3)
    second.start()
    time.sleep(0.05)
    release_first_write.set()
    first.join(timeout=3)
    second.join(timeout=3)

    assert not first.is_alive()
    assert not second.is_alive()
    assert failures == []
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert persisted["user_timezone"] == "Asia/Shanghai"
    assert (
        persisted["security"]["mutation_guard"]["deny_message"]
        == "Task9 value"
    )


def test_transaction_returns_committed_copy_and_invalidates_cache(tmp_path):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))
    cached = config_utils.load_config(config_path)
    seen: list[Config] = []

    def mutate(config: Config) -> None:
        seen.append(config)
        config.security.mutation_guard.deny_message = "committed"

    committed = config_utils.update_config_transaction(mutate, config_path)

    assert seen[0] is not cached
    assert committed.security.mutation_guard.deny_message == "committed"
    reloaded = config_utils.load_config(config_path)
    assert reloaded is not cached
    assert reloaded.security.mutation_guard.deny_message == "committed"


def test_transaction_noop_skips_write_and_preserves_cache(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))
    cached = config_utils.load_config(config_path)
    write_calls = 0

    def count_write(*_args, **_kwargs) -> None:
        nonlocal write_calls
        write_calls += 1

    monkeypatch.setattr(config_utils, "write_json_atomic", count_write)

    validated = config_utils.update_config_transaction(
        lambda _config: None,
        config_path,
    )

    assert write_calls == 0
    assert validated.model_dump(mode="json", by_alias=True) == (
        cached.model_dump(mode="json", by_alias=True)
    )
    assert config_utils.load_config(config_path) is cached


def test_root_config_cache_is_isolated_by_normalized_path(tmp_path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first = Config(user_timezone="Etc/GMT+1")
    second = Config(user_timezone="Etc/GMT+2")
    _write_config(first_path, first)
    _write_config(second_path, second)
    shared_timestamp_ns = 1_800_000_000_000_000_000
    os.utime(first_path, ns=(shared_timestamp_ns, shared_timestamp_ns))
    os.utime(second_path, ns=(shared_timestamp_ns, shared_timestamp_ns))
    assert first_path.stat().st_mtime == second_path.stat().st_mtime

    loaded_first = config_utils.load_config(first_path)
    loaded_second = config_utils.load_config(second_path)

    assert loaded_first.user_timezone == "Etc/GMT+1"
    assert loaded_second.user_timezone == "Etc/GMT+2"


def test_transaction_callback_exception_does_not_write(tmp_path):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config(user_timezone="UTC"))
    before = config_path.read_bytes()

    def fail(config: Config) -> None:
        config.user_timezone = "Asia/Shanghai"
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        config_utils.update_config_transaction(fail, config_path)

    assert config_path.read_bytes() == before
    assert config_utils.load_config(config_path).user_timezone == "UTC"


def test_transaction_revalidates_callback_changes_before_write(tmp_path):
    config_path = tmp_path / "config.json"
    _write_config(config_path, Config())
    before = config_path.read_bytes()

    def assign_invalid_value(config: Config) -> None:
        config.security.mutation_guard.classifier_timeout_seconds = 0

    with pytest.raises(ValueError):
        config_utils.update_config_transaction(
            assign_invalid_value,
            config_path,
        )

    assert config_path.read_bytes() == before


def test_write_last_api_failure_keeps_runtime_cache(monkeypatch):
    monkeypatch.setattr(
        config_utils,
        "_runtime_last_api",
        ("127.0.0.1", 8088),
    )
    monkeypatch.setattr(
        config_utils,
        "update_config_transaction",
        lambda _update: (_ for _ in ()).throw(OSError("disk full")),
    )

    with pytest.raises(OSError, match="disk full"):
        config_utils.write_last_api("127.0.0.1", 9000)

    assert config_utils._runtime_last_api == ("127.0.0.1", 8088)


def test_mutation_transaction_and_real_tool_guard_update_keep_both_fields(
    tmp_path,
    monkeypatch,
):
    from qwenpaw.app.routers.config import put_tool_guard
    from qwenpaw.config import ToolGuardConfig

    config_path = tmp_path / "config.json"
    _write_config(config_path, Config())
    monkeypatch.setattr(config_utils, "get_config_path", lambda: config_path)

    first_write_started = threading.Event()
    release_first_write = threading.Event()
    original_write = config_utils.write_json_atomic
    write_count = 0
    write_count_lock = threading.Lock()

    def controlled_write(*args, **kwargs):
        nonlocal write_count
        with write_count_lock:
            write_count += 1
            current_write = write_count
        if current_write == 1:
            first_write_started.set()
            assert release_first_write.wait(timeout=3)
        return original_write(*args, **kwargs)

    monkeypatch.setattr(
        config_utils,
        "write_json_atomic",
        controlled_write,
    )
    engine = type(
        "Engine",
        (),
        {"enabled": True, "reload_rules": lambda self: None},
    )()
    monkeypatch.setattr(
        "qwenpaw.security.tool_guard.engine.get_guard_engine",
        lambda: engine,
    )
    failures: list[BaseException] = []

    def update_mutation_guard() -> None:
        try:
            config_utils.update_config_transaction(
                lambda config: setattr(
                    config.security.mutation_guard,
                    "deny_message",
                    "transaction value",
                ),
            )
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)

    def update_tool_guard() -> None:
        import asyncio

        try:
            asyncio.run(put_tool_guard(ToolGuardConfig(enabled=False)))
        except BaseException as exc:  # pragma: no cover - diagnostic path
            failures.append(exc)

    transaction_thread = threading.Thread(target=update_mutation_guard)
    tool_guard_thread = threading.Thread(target=update_tool_guard)
    transaction_thread.start()
    assert first_write_started.wait(timeout=3)
    tool_guard_thread.start()
    time.sleep(0.05)
    release_first_write.set()
    transaction_thread.join(timeout=3)
    tool_guard_thread.join(timeout=3)

    assert failures == []
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert (
        persisted["security"]["mutation_guard"]["deny_message"]
        == "transaction value"
    )
    assert persisted["security"]["tool_guard"]["enabled"] is False
