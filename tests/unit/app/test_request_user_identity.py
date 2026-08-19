# -*- coding: utf-8 -*-
"""Unit tests for resolving the trusted caller of an AgentRequest."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from qwenpaw.app.agent_context import (
    get_current_request_principal,
    get_current_user_id,
    resolve_request_user_id,
    set_current_request_principal,
    set_current_user_id,
)
from qwenpaw.schemas import AgentRequest
from qwenpaw.security.mutation_guard import RequestPrincipal


class TestResolveRequestUserId:
    """The server-derived identity wins over anything client-supplied."""

    def test_acl_sender_id_attribute_wins(self):
        """A channel that sets ``acl_sender_id`` on the request wins."""
        request = AgentRequest(user_id="claimed-by-client")
        request.acl_sender_id = "alice@example.com"

        assert resolve_request_user_id(request) == "alice@example.com"

    def test_acl_sender_id_from_channel_meta(self):
        """The console carries the trusted id inside ``channel_meta``."""
        request = AgentRequest(user_id="claimed-by-client")
        request.channel_meta = {"acl_sender_id": "bob@example.com"}

        assert resolve_request_user_id(request) == "bob@example.com"

    def test_falls_back_to_user_id(self):
        """Without a trusted id the native sender is used."""
        request = AgentRequest(user_id="dingtalk-user-42")

        assert resolve_request_user_id(request) == "dingtalk-user-42"

    def test_empty_when_nothing_known(self):
        """No identity at all resolves to the empty string."""
        assert resolve_request_user_id(AgentRequest()) == ""


class TestContextVarsSetupHookUser:
    """The hook publishes the trusted identity, not the claimed one."""

    @pytest.fixture(autouse=True)
    def _reset_user(self):
        set_current_user_id(None)
        yield
        set_current_user_id(None)

    def _ctx(self, request):
        from qwenpaw.runtime.hooks import HookContext

        return HookContext(
            request=request,
            session_id="sess-1",
            agent_id="default",
            root_session_id="sess-1",
            root_agent_id="default",
            workspace_dir=None,
            workspace=MagicMock(),
            app_services=MagicMock(),
        )

    @pytest.mark.asyncio
    async def test_hook_publishes_trusted_user(self):
        """``acl_sender_id`` reaches the ``current_user_id`` ContextVar."""
        from qwenpaw.hooks.request_setup import ContextVarsSetupHook

        request = AgentRequest(user_id="claimed-by-client")
        request.channel_meta = {"acl_sender_id": "carol@example.com"}

        await ContextVarsSetupHook().run(self._ctx(request))

        assert get_current_user_id() == "carol@example.com"


class TestRequestPrincipalContextVar:
    """The server-trusted RequestPrincipal is carried via ContextVar."""

    @pytest.fixture(autouse=True)
    def _reset_principal(self):
        set_current_request_principal(None)
        yield
        set_current_request_principal(None)

    def test_set_and_get_round_trip(self):
        principal = RequestPrincipal(
            user_id="alice",
            roles=("member",),
            source="nocobase",
            guarded=True,
            can_mutate=False,
        )
        set_current_request_principal(principal)
        assert get_current_request_principal() == principal

    def test_default_is_none(self):
        assert get_current_request_principal() is None


class TestContextVarsSetupHookPrincipal:
    """The hook publishes the principal from channel_meta acl_principal."""

    @pytest.fixture(autouse=True)
    def _reset_principal(self):
        set_current_request_principal(None)
        yield
        set_current_request_principal(None)

    def _ctx(self, request):
        from qwenpaw.runtime.hooks import HookContext

        return HookContext(
            request=request,
            session_id="sess-1",
            agent_id="default",
            root_session_id="sess-1",
            root_agent_id="default",
            workspace_dir=None,
            workspace=MagicMock(),
            app_services=MagicMock(),
        )

    @pytest.mark.asyncio
    async def test_hook_publishes_principal_from_acl_meta(self):
        """``acl_principal`` in channel_meta reaches the ContextVar."""
        from qwenpaw.hooks.request_setup import ContextVarsSetupHook

        principal = RequestPrincipal(
            user_id="alice",
            roles=("member",),
            source="nocobase",
            guarded=True,
            can_mutate=False,
        )
        request = AgentRequest(user_id="claimed-by-client")
        request.channel_meta = {
            "acl_principal": principal.to_context(),
        }

        await ContextVarsSetupHook().run(self._ctx(request))

        published = get_current_request_principal()
        assert published == principal
        assert published.can_mutate is False

    @pytest.mark.asyncio
    async def test_hook_does_not_publish_client_request_context_principal(
        self,
    ):
        """A forged principal in request_context must never reach the CV."""
        from qwenpaw.hooks.request_setup import ContextVarsSetupHook

        request = AgentRequest(user_id="claimed-by-client")
        request.request_context = {
            "request_principal": {
                "user_id": "mallory",
                "roles": ["root"],
                "can_mutate": True,
            },
        }

        await ContextVarsSetupHook().run(self._ctx(request))

        # No server-supplied acl_principal -> stays None (fail-safe).
        assert get_current_request_principal() is None
