# -*- coding: utf-8 -*-
"""Safe structured audit logging for mutation authorization."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

_ALLOWED_FIELDS = frozenset(
    {
        "user_id",
        "roles",
        "source",
        "agent",
        "agent_id",
        "session",
        "session_id",
        "route",
        "tool",
        "decision",
        "reason",
        "summary",
    },
)
_SENSITIVE_KEY_PARTS = ("token", "secret", "authorization")
_SUMMARY_MAX_LENGTH = 256


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]" if _is_sensitive_key(str(key)) else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _summary(value: Any) -> str:
    redacted = _redact(value)
    if isinstance(redacted, str):
        text = redacted
    else:
        text = json.dumps(
            redacted,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    if len(text) <= _SUMMARY_MAX_LENGTH:
        return text
    return text[: _SUMMARY_MAX_LENGTH - 3] + "..."


def emit_mutation_audit(event: str, **fields: Any) -> None:
    """Emit one allowlisted, redacted mutation audit event."""
    payload: dict[str, Any] = {"event": str(event)}
    for key, value in fields.items():
        if key not in _ALLOWED_FIELDS:
            continue
        if key == "summary":
            payload[key] = _summary(value)
        elif _is_sensitive_key(key):
            payload[key] = "[REDACTED]"
        else:
            payload[key] = _redact(value)

    logger.info(
        "[MUTATION AUDIT] %s",
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )
