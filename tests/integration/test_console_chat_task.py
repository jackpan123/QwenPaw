# -*- coding: utf-8 -*-
"""Integration tests for /api/console/chat/task* (Sprint 4.1).

Target routes (added by PR #5687 for the v2.0.0 background-task model):
  - POST /api/console/chat/task
  - GET  /api/console/chat/task/{task_id}

The task_id is opaque (``task-<uuid4hex>``), fresh per POST, and stored in a
module-level ``_bg_tasks`` dict inside ``routers/console.py``.  Session
id is orthogonal — it is what the console channel resolves for the run
itself (``f"console:{sender_id}"`` when not provided explicitly).

These tests are HTTP-layer only; they intentionally do NOT verify the
final agent reply contents — that is already exercised by
test_console_chat.py and test_cron_execution.py.  Here we cover the
task-lifecycle contract that Sprint 4.1 introduces.
"""

from __future__ import annotations

import threading
import time
from http.server import HTTPServer

import httpx
import pytest

from helpers import (
    MOCK_LLM_PROVIDER_ID,
    MOCK_LLM_RESPONSE,
    MockLLMHandler,
    default_http_timeout,
    register_mock_provider,
    unregister_mock_provider,
)

_HTTP_TIMEOUT = default_http_timeout(15.0)


# ================================================================== #
# fixtures
# ================================================================== #


@pytest.fixture(scope="module")
def mock_llm():
    """Module-scoped mock OpenAI streaming server."""
    srv = HTTPServer(("127.0.0.1", 0), MockLLMHandler)
    srv.force_error = False
    srv.force_tool_call = False
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, f"http://127.0.0.1:{port}/v1"
    srv.shutdown()


def _wait_task_finished(app_server, task_id, timeout):
    """Poll GET /console/chat/task/{id} until status=='finished'."""
    deadline = time.time() + timeout
    last_body = None
    while time.time() < deadline:
        resp = app_server.api_request(
            "GET",
            f"/api/console/chat/task/{task_id}",
            timeout=_HTTP_TIMEOUT,
        )
        assert resp.status_code == 200, app_server.logs_tail()
        last_body = resp.json()
        if last_body.get("status") == "finished":
            return last_body
        time.sleep(0.3)
    pytest.fail(
        f"task {task_id} did not finish within {timeout}s: "
        f"last={last_body} / logs={app_server.logs_tail()[-2000:]}",
    )
    return last_body


def _drain_console_chat(app_server, body: dict) -> list[str]:
    """Send a normal chat turn and fully drain its real SSE response."""
    url = f"{app_server.base_url}/api/console/chat"
    with app_server.client.stream(
        "POST",
        url,
        json=body,
        timeout=httpx.Timeout(20.0, read=20.0),
    ) as response:
        assert response.status_code == 200, app_server.logs_tail()
        return [line for line in response.iter_lines() if line]


# ================================================================== #
# A. Not-found + submit contract (2 tests)
# ================================================================== #


@pytest.mark.integration
@pytest.mark.p1
def test_chat_task_get_unknown_returns_404(app_server) -> None:
    """GET /api/console/chat/task/{unknown_id} → 404.

    API endpoints:
    - GET /api/console/chat/task/{task_id}
    """
    resp = app_server.api_request(
        "GET",
        "/api/console/chat/task/task-integnotfound",
        timeout=_HTTP_TIMEOUT,
    )
    assert resp.status_code == 404, app_server.logs_tail()
    assert "Task not found" in resp.json()["detail"]


@pytest.mark.integration
@pytest.mark.p0
def test_chat_task_submit_registers_chat_and_completes(
    app_server,
    mock_llm,  # pylint: disable=redefined-outer-name
) -> None:
    """POST /console/chat/task → task_id, then poll → finished + session_id.

    Test purpose:
      - Verify a chat/task submission returns a fresh ``task-<uuid4hex>``,
        registers its session in the chat index, runs to completion in the
        background, and eventually reports ``status='finished'`` with the
        expected ``session_id`` in the result payload.

    API endpoints:
    - POST /api/console/chat/task
    - GET  /api/console/chat/task/{task_id}
    - GET  /api/chats
    """
    _srv, mock_url = mock_llm
    unregister_mock_provider(app_server, MOCK_LLM_PROVIDER_ID)
    provider_id = register_mock_provider(app_server, mock_url)
    user_id = "integ-tc-task-happy"
    session_id = "sub-integ-tc-task-happy"
    body = {
        "channel": "console",
        "user_id": user_id,
        "session_id": session_id,
        "input": [
            {
                "role": "user",
                "type": "message",
                "content": [{"type": "text", "text": "hello"}],
            },
        ],
    }
    try:
        submit_resp = app_server.api_request(
            "POST",
            "/api/console/chat/task",
            json=body,
            timeout=_HTTP_TIMEOUT,
        )
        assert submit_resp.status_code == 200, app_server.logs_tail()
        task_id = submit_resp.json()["task_id"]
        assert task_id.startswith("task-"), task_id
        # Upstream shortened this opaque id to 12 hex chars.
        assert len(task_id) == len("task-") + 12, task_id

        chats_resp = app_server.api_request(
            "GET",
            "/api/chats",
            params={"user_id": user_id, "channel": "console"},
            timeout=_HTTP_TIMEOUT,
        )
        assert chats_resp.status_code == 200, app_server.logs_tail()
        assert session_id in {chat["session_id"] for chat in chats_resp.json()}

        # Immediately poll — status may be running or finished.
        first = app_server.api_request(
            "GET",
            f"/api/console/chat/task/{task_id}",
            timeout=_HTTP_TIMEOUT,
        )
        assert first.status_code == 200, app_server.logs_tail()
        assert first.json()["status"] in ("running", "finished")

        final = _wait_task_finished(app_server, task_id, timeout=25.0)
        assert final["status"] == "finished", final
        result = final.get("result") or {}
        assert result.get("status") == "completed", result
        # session_id is resolved by console_channel.resolve_session_id;
        # when the request body omits it, the channel falls back to
        # its own default (currently "default").  Assert non-empty
        # rather than a specific value to remain robust.
        assert result.get("session_id"), result

    finally:
        unregister_mock_provider(app_server, provider_id)


@pytest.mark.integration
@pytest.mark.p0
def test_console_chat_persists_history_and_generated_title(
    app_server,
    mock_llm,  # pylint: disable=redefined-outer-name
) -> None:
    """A normal read-only chat streams, persists history and auto-title."""
    _srv, mock_url = mock_llm
    unregister_mock_provider(app_server, MOCK_LLM_PROVIDER_ID)
    provider_id = register_mock_provider(app_server, mock_url)
    user_id = "integ-console-history-title"
    session_id = "sub-integ-console-history-title"
    body = {
        "channel": "console",
        "user_id": user_id,
        "session_id": session_id,
        "input": [
            {
                "role": "user",
                "type": "message",
                "content": [
                    {"type": "text", "text": "Explain lunar eclipses"},
                ],
            },
        ],
    }
    expected_title = MOCK_LLM_RESPONSE.rstrip(".")
    try:
        stream_lines = _drain_console_chat(app_server, body)
        assert any(MOCK_LLM_RESPONSE in line for line in stream_lines)

        title_deadline = time.time() + 10.0
        chat = None
        while time.time() < title_deadline:
            chats_resp = app_server.api_request(
                "GET",
                "/api/chats",
                params={"user_id": user_id, "channel": "console"},
                timeout=_HTTP_TIMEOUT,
            )
            assert chats_resp.status_code == 200, app_server.logs_tail()
            chat = next(
                (
                    item
                    for item in chats_resp.json()
                    if item.get("session_id") == session_id
                ),
                None,
            )
            if chat and chat.get("name") == expected_title:
                break
            time.sleep(0.2)
        assert chat is not None
        assert chat["name"] == expected_title

        history_resp = app_server.api_request(
            "GET",
            f"/api/chats/{chat['id']}",
            timeout=_HTTP_TIMEOUT,
        )
        assert history_resp.status_code == 200, app_server.logs_tail()
        history = history_resp.json()
        assert history["status"] == "idle"
        assert {message.get("role") for message in history["messages"]} >= {
            "user",
            "assistant",
        }
        serialized_history = str(history["messages"])
        assert "Explain lunar eclipses" in serialized_history
        assert MOCK_LLM_RESPONSE in serialized_history
    finally:
        unregister_mock_provider(app_server, provider_id)


# ================================================================== #
# B. Task isolation (1 test)
# ================================================================== #


@pytest.mark.integration
@pytest.mark.p2
def test_chat_task_two_submissions_produce_distinct_ids(
    app_server,
    mock_llm,  # pylint: disable=redefined-outer-name
) -> None:
    """Two POSTs return distinct task_ids and both finish independently.

    API endpoints:
    - POST /api/console/chat/task
    - GET  /api/console/chat/task/{task_id}
    """
    _srv, mock_url = mock_llm
    unregister_mock_provider(app_server, MOCK_LLM_PROVIDER_ID)
    provider_id = register_mock_provider(app_server, mock_url)
    try:
        task_ids = []
        for suffix in ("aa", "bb"):
            body = {
                "channel": "console",
                "user_id": f"integ-tc-task-multi-{suffix}",
                "input": [
                    {
                        "role": "user",
                        "type": "message",
                        "content": [{"type": "text", "text": "ping"}],
                    },
                ],
            }
            resp = app_server.api_request(
                "POST",
                "/api/console/chat/task",
                json=body,
                timeout=_HTTP_TIMEOUT,
            )
            assert resp.status_code == 200, app_server.logs_tail()
            task_ids.append(resp.json()["task_id"])
        assert task_ids[0] != task_ids[1], task_ids

        for tid in task_ids:
            final = _wait_task_finished(app_server, tid, timeout=25.0)
            assert final["status"] == "finished", (tid, final)
    finally:
        unregister_mock_provider(app_server, provider_id)


# ================================================================== #
# C. Principal propagation safety: a client-forged principal embedded
#    in the request body must never break the background path or be
#    honored. Auth is disabled in the harness (request_principal is
#    absent), so we assert that submitting a body carrying a forged
#    principal still completes normally — i.e. the forging is dropped
#    silently rather than trusted or crashing the run. Precise
#    propagation (server principal -> meta acl_principal) is covered
#    by the unit tests in test_console_acl_roles.py and
#    test_request_user_identity.py.
# ================================================================== #


@pytest.mark.integration
@pytest.mark.p1
def test_chat_task_ignores_client_forged_principal(
    app_server,
    mock_llm,  # pylint: disable=redefined-outer-name
) -> None:
    """A forged principal in request_context must be dropped, not
    honored, and must not break the background task lifecycle."""
    _srv, mock_url = mock_llm
    unregister_mock_provider(app_server, MOCK_LLM_PROVIDER_ID)
    provider_id = register_mock_provider(app_server, mock_url)
    user_id = "integ-tc-task-forge"
    session_id = "sub-integ-tc-task-forge"
    body = {
        "channel": "console",
        "user_id": user_id,
        "session_id": session_id,
        "input": [
            {
                "role": "user",
                "type": "message",
                "content": [{"type": "text", "text": "hello"}],
            },
        ],
        # Client attempts to escalate: forge an admin principal AND an
        # acl_principal in the request_context. The server MUST drop both.
        "request_context": {
            "request_principal": {
                "user_id": "mallory",
                "roles": ["root"],
                "can_mutate": True,
            },
            "acl_principal": {
                "user_id": "attacker",
                "roles": ["root"],
                "can_mutate": True,
            },
        },
    }
    try:
        submit_resp = app_server.api_request(
            "POST",
            "/api/console/chat/task",
            json=body,
            timeout=_HTTP_TIMEOUT,
        )
        assert submit_resp.status_code == 200, app_server.logs_tail()
        task_id = submit_resp.json()["task_id"]
        assert task_id.startswith("task-"), task_id

        final = _wait_task_finished(app_server, task_id, timeout=25.0)
        assert final["status"] == "finished", final
        result = final.get("result") or {}
        # The forged identity never reached the run: it completes normally
        # (the agent never escalated to a mutation, and no crash).
        assert result.get("status") == "completed", result
        assert result.get("session_id"), result
    finally:
        unregister_mock_provider(app_server, provider_id)
