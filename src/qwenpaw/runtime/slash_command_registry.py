# -*- coding: utf-8 -*-
"""Per-workspace slash-command registry.

Named ``SlashCommandRegistry`` (not ``CommandRegistry``) to avoid clashing
with ``app/channels/command_registry.py:CommandRegistry`` — that one is the
IM-channel priority router and is unrelated to runtime slash dispatch.

Unifies the four previously-parallel command mechanisms
(conversation, control, daemon, skill) into a single dispatch point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from ..security.mutation_guard import ActionEffect

if TYPE_CHECKING:
    from agentscope.message import Msg

    from .hooks import HookContext


CommandHandler = Callable[["HookContext", str], Awaitable["Msg | None"]]
FallbackHandler = Callable[[str, "HookContext"], Awaitable["Msg | None"]]


@dataclass(frozen=True)
class CommandSpec:
    """Declarative description of one slash command.

    ``aliases`` are extra names that resolve to the same handler.
    ``category`` records the origin (``"daemon"`` / ``"control"`` /
    ``"conversation"`` / ``"skill"`` / ``"auto"`` / ``"user"``) so future
    introspection can group commands without re-parsing source.

    ``effect`` is the command's :class:`ActionEffect` for the role-based
    mutation gate. Defaults to UNKNOWN so unannotated commands are
    fail-closed for non-privileged members (denied). READ /
    CHAT_INFRASTRUCTURE commands run for members; MUTATE / UNKNOWN are
    denied. The gate is a no-op when no authenticated principal is present
    (local mode).
    """

    name: str
    handler: CommandHandler
    aliases: tuple[str, ...] = ()
    category: str = "user"
    help_text: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    effect: ActionEffect = ActionEffect.UNKNOWN


class SlashCommandRegistry:
    """Resolve raw text starting with ``/`` to a registered ``CommandSpec``.

    Lookup is case-insensitive on the command name; arguments are returned
    verbatim (with leading whitespace stripped). When no name matches and a
    single fallback handler is registered, ``dispatch`` delegates to it —
    typically used by ``/<skill_name>`` resolution.
    """

    def __init__(self) -> None:
        self._by_name: dict[str, CommandSpec] = {}
        self._fallback: FallbackHandler | None = None

    # ---------------------------------------------------------------- register
    def register(self, spec: CommandSpec) -> None:
        names = (spec.name, *spec.aliases)
        for nm in names:
            key = nm.lower()
            if not key:
                raise ValueError(
                    f"command spec has empty name in {names!r}",
                )
            if key in self._by_name:
                existing = self._by_name[key]
                raise ValueError(
                    f"command /{key} already registered "
                    f"by {existing.category} ({existing.name})",
                )
        for nm in names:
            self._by_name[nm.lower()] = spec

    def register_fallback(self, handler: FallbackHandler) -> None:
        if self._fallback is not None:
            raise ValueError(
                "fallback handler already registered; only one allowed",
            )
        self._fallback = handler

    # ------------------------------------------------------------------ query
    def resolve(self, raw_text: str) -> tuple[CommandSpec, str] | None:
        """Parse ``raw_text`` and return ``(spec, args)`` or ``None``.

        Leading whitespace on ``args`` is stripped; everything else is kept
        intact (including embedded quotes and unicode).
        """
        if not raw_text:
            return None
        text = raw_text.lstrip()
        if not text.startswith("/"):
            return None
        body = text[1:]
        if not body:
            return None
        name, _, rest = body.partition(" ")
        spec = self._by_name.get(name.lower())
        if spec is None:
            return None
        return spec, rest.lstrip()

    def names(self) -> list[str]:
        return sorted(self._by_name.keys())

    def advertisable_commands(
        self,
        *,
        exclude_categories: frozenset[str] | None = None,
        exclude_names: frozenset[str] | None = None,
    ) -> list[tuple[str, str]]:
        """Return ``(name, help_text)`` pairs suitable for ACP broadcast.

        Only commands with non-empty ``help_text`` are included.
        Commands in *exclude_categories* or *exclude_names* are skipped.
        Duplicates (aliases) are de-duplicated by spec identity.
        """
        if exclude_categories is None:
            exclude_categories = frozenset()
        if exclude_names is None:
            exclude_names = frozenset()

        seen_specs: set[int] = set()
        result: list[tuple[str, str]] = []
        for name, spec in self._by_name.items():
            if id(spec) in seen_specs:
                continue
            if spec.category in exclude_categories:
                continue
            if name in exclude_names:
                continue
            if not spec.help_text:
                continue
            seen_specs.add(id(spec))
            result.append((name, spec.help_text))
        return result

    # ---------------------------------------------------------------- dispatch
    async def dispatch(
        self,
        raw_text: str,
        ctx: "HookContext",
    ) -> "Msg | None":
        """Resolve and execute. Returns ``None`` if nothing matched.

        Before invoking a matched handler, the command's :attr:`CommandSpec.
        effect` is authorized against the request principal (role-based
        mutation gate). A guarded non-privileged member is denied
        MUTATE / UNKNOWN commands (handler not invoked, deny Msg returned);
        READ / CHAT_INFRASTRUCTURE commands run. The gate is a no-op when
        there is no authenticated principal (local mode). The ``/<skill>``
        fallback path is never gated — it is a chat entry whose tools are
        still gated individually at execution time.
        """
        match = self.resolve(raw_text)
        if match is not None:
            spec, args = match
            deny = _authorize_command(ctx, spec)
            if deny is not None:
                return deny
            return await spec.handler(ctx, args)
        if (
            self._fallback is not None
            and raw_text
            and raw_text.lstrip().startswith("/")
        ):
            return await self._fallback(raw_text, ctx)
        return None


def _authorize_command(
    ctx: "HookContext",
    spec: "CommandSpec",
) -> "Msg | None":
    """Authorize ``spec.effect`` for the request principal.

    Returns a deny :class:`Msg` (handler must NOT run) or ``None`` (allowed).
    The principal is sourced ONLY from the server-derived
    ``ctx.request.channel_meta["acl_principal"]`` — mirroring
    :mod:`qwenpaw.runtime.builder` and the ContextVars setup hook — so a
    client-forged identity can never reach this path. Absent principal
    (local / unauthenticated) → ``authorize_effect`` already allows.
    """
    from ..config.utils import load_config
    from ..security.mutation_guard import (
        RequestPrincipal,
        authorize_effect,
    )

    config = load_config().security.mutation_guard
    request = getattr(ctx, "request", None)
    channel_meta = getattr(request, "channel_meta", None)
    acl_principal = (
        channel_meta.get("acl_principal")
        if isinstance(channel_meta, dict)
        else None
    )
    principal = RequestPrincipal.from_context(acl_principal)
    decision = authorize_effect(principal, spec.effect, config)
    if decision.allowed:
        return None
    return _deny_msg(config.deny_message, decision.reason, spec.name)


def _deny_msg(
    deny_message: str,
    reason: str,
    command_name: str,
) -> "Msg":
    """Build the slash-command mutation-deny reply."""
    from agentscope.message import Msg, TextBlock

    return Msg(
        name="assistant",
        role="assistant",
        content=[
            TextBlock(
                type="text",
                text=(
                    f"{deny_message} mutation_permission_denied "
                    f"(command /{command_name}: {reason})"
                ),
            ),
        ],
    )


__all__ = [
    "CommandHandler",
    "CommandSpec",
    "FallbackHandler",
    "SlashCommandRegistry",
]
