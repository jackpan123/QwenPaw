# NocoBase 角色变更权限闸门 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 NocoBase 普通用户保持只读聊天和查询能力，同时只有 `admin`、`root` 能通过对话、工具或直接 Console/API 执行持久化修改及外部副作用。

**Architecture:** 认证中间件把 NocoBase 返回的可信用户与角色转换为 `RequestPrincipal`；API 中间件按路由能力阻止直接写请求；Runtime 在普通用户对话入口做无工具意图分类，并在工具、Driver、插件、命令和委托真正执行前按副作用等级再次授权。前端读取 `/auth/verify` 的 `can_mutate`，进入只读 Console 模式，但后端始终是最终安全边界。

**Tech Stack:** Python 3.10–3.13、FastAPI/Starlette、Pydantic、AgentScope Runtime、pytest；React 18、TypeScript、Ant Design、Zustand、Vitest。

**参考 spec：** `docs/superpowers/specs/2026-07-30-nocobase-role-mutation-guard-design.md`

---

## 执行约束

- 在独立 worktree 中执行本计划。
- 每个任务遵循红灯测试 → 最小实现 → 绿灯测试 → commit。
- 角色、权限和副作用信息只能从服务端可信上下文传播，不能从客户端请求体提权。
- Mutation Guard 必须先于现有 Governance 的 `approval_level=off` 分支执行；普通用户不能借关闭审批绕过角色限制。
- 每次 commit 前运行该任务列出的测试。最终运行完整 Python/前端门禁。

## 文件结构

### 新建

- `src/qwenpaw/security/mutation_guard/__init__.py` — 对外导出稳定类型和授权函数。
- `src/qwenpaw/security/mutation_guard/policy.py` — `RequestPrincipal`、角色匹配、路由/动作授权纯函数。
- `src/qwenpaw/security/mutation_guard/audit.py` — 结构化拒绝与降级审计。
- `src/qwenpaw/security/mutation_guard/intent.py` — 无工具意图分类器与严格 JSON 解析。
- `src/qwenpaw/security/mutation_guard/tool_gate.py` — 把 ToolDescriptor 副作用与请求主体转换为工具权限决策。
- `src/qwenpaw/app/internal_auth.py` — 本机智能体调用使用的短时、目标绑定 HMAC 身份凭证。
- `src/qwenpaw/app/mutation_authorization.py` — API 路由能力声明、解析与中间件。
- `src/qwenpaw/hooks/security/mutation_intent_hook.py` — Runtime `PRE_AGENT_BUILD` 意图预检。
- `console/src/stores/authorizationStore.ts` — 当前用户角色与 `canMutate`。
- `console/src/pages/Settings/Security/components/MutationGuardTab.tsx` — Mutation Guard 设置页。

### 修改

- `src/qwenpaw/config/config.py` — `MutationGuardConfig`。
- `src/qwenpaw/app/auth.py`、`src/qwenpaw/app/routers/auth.py` — 身份来源、Principal 和 verify 能力响应。
- `plugins/bundle/nocobase_auth/identity_resolver.py` — 标记 `source="nocobase"`。
- `src/qwenpaw/app/_app.py` — 注册 API Mutation 中间件。
- `src/qwenpaw/app/routers/console.py`、`src/qwenpaw/app/channels/console/channel.py` — 同步/后台对话可信主体注入。
- `src/qwenpaw/app/agent_context.py`、`src/qwenpaw/hooks/request_setup/contextvars_hook.py`、`src/qwenpaw/runtime/builder.py` — Principal 传播。
- `src/qwenpaw/agents/tools/agent_management.py` — 子智能体/后台任务继承 Principal。
- `src/qwenpaw/runtime/tool_registry.py` — `ToolEffectSpec` 元数据。
- `src/qwenpaw/governance/tool_adapter.py`、`src/qwenpaw/runtime/tool_guard.py` — 工具执行前角色闸门。
- `src/qwenpaw/app/workspace/local_workspace.py`、`src/qwenpaw/agents/react_agent.py` — 将 descriptor/memory effect 传入 wrapper。
- `src/qwenpaw/runtime/slash_command_registry.py`、`src/qwenpaw/runtime/builtin_commands.py` — 命令副作用授权。
- `src/qwenpaw/agents/tools/*.py`、`src/qwenpaw/modes/goal/goal_mode.py`、`src/qwenpaw/agents/context/scroll/*.py` — 内置与动态工具副作用标注。
- `src/qwenpaw/drivers/capabilities.py`、`src/qwenpaw/drivers/adapters/agentscope_tool.py`、MCP capability 构造处 — Driver/MCP 副作用。
- `src/qwenpaw/plugins/api.py` — 插件工具与命令声明副作用。
- `src/qwenpaw/app/workspace/bootstrap_factory.py` — 注册意图预检 Hook。
- `src/qwenpaw/app/routers/config.py` — Mutation Guard GET/PUT。
- `console/src/api/modules/auth.ts`、`console/src/api/modules/security.ts`、`console/src/App.tsx` — 能力加载与配置 API。
- `console/src/layouts/registry/builtinRoutes.tsx`、`console/src/plugins/registry/types.ts`、`console/src/layouts/MainLayout/index.tsx`、`console/src/layouts/Sidebar.tsx` — 普通用户只读路由。
- `console/src/layouts/SidebarSessionList.tsx`、`console/src/pages/Chat/components/ChatSessionDrawer/*`、`console/src/pages/Chat/index.tsx` — 隐藏会话修改和上传。
- `console/src/locales/*.json` — Mutation Guard 与只读提示文案。
- `plugins/bundle/nocobase_auth/README.md`、`website/public/docs/security.zh.md`、`website/public/docs/security.en.md` — 用户文档。

---

## Task 1：核心配置、可信主体与授权纯函数

**Files:**
- Create: `src/qwenpaw/security/mutation_guard/__init__.py`
- Create: `src/qwenpaw/security/mutation_guard/policy.py`
- Create: `src/qwenpaw/security/mutation_guard/audit.py`
- Modify: `src/qwenpaw/config/config.py`（`SecurityConfig` 附近）
- Test: `tests/unit/security/mutation_guard/test_policy.py`
- Test: `tests/unit/config/test_mutation_guard_config.py`

- [ ] **Step 1: 写配置和角色匹配失败测试**

```python
# tests/unit/security/mutation_guard/test_policy.py
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    RequestPrincipal,
    authorize_effect,
    build_request_principal,
)


def test_admin_and_root_are_privileged_case_insensitively():
    cfg = MutationGuardConfig()
    for role in ("admin", "ADMIN", "Root", " root "):
        principal = build_request_principal(
            user_id="alice",
            roles=[role],
            source="nocobase",
            auth_enabled=True,
            config=cfg,
        )
        assert principal.guarded is True
        assert principal.can_mutate is True


def test_authenticated_user_without_privileged_role_is_read_only():
    cfg = MutationGuardConfig()
    principal = build_request_principal(
        user_id="bob",
        roles=["member"],
        source="nocobase",
        auth_enabled=True,
        config=cfg,
    )
    assert authorize_effect(principal, ActionEffect.READ, cfg).allowed
    assert not authorize_effect(principal, ActionEffect.MUTATE, cfg).allowed
    assert not authorize_effect(
        principal,
        ActionEffect.EXTERNAL_SIDE_EFFECT,
        cfg,
    ).allowed
    assert not authorize_effect(principal, ActionEffect.UNKNOWN, cfg).allowed


def test_auth_disabled_preserves_local_operator_behavior():
    cfg = MutationGuardConfig()
    principal = build_request_principal(
        user_id="",
        roles=[],
        source="",
        auth_enabled=False,
        config=cfg,
    )
    assert principal.guarded is False
    assert authorize_effect(principal, ActionEffect.MUTATE, cfg).allowed
```

```python
# tests/unit/config/test_mutation_guard_config.py
from qwenpaw.config.config import SecurityConfig


def test_mutation_guard_defaults():
    guard = SecurityConfig().mutation_guard
    assert guard.enabled is True
    assert guard.privileged_roles == ["admin", "root"]
    assert guard.intent_precheck_enabled is True
    assert guard.classifier_timeout_seconds == 8
    assert "没有执行变更操作的权限" in guard.deny_message
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/security/mutation_guard/test_policy.py tests/unit/config/test_mutation_guard_config.py -v
```

Expected: FAIL，`MutationGuardConfig` 与 `qwenpaw.security.mutation_guard` 尚不存在。

- [ ] **Step 3: 增加配置和核心类型**

在 `src/qwenpaw/config/config.py` 的 `SecurityConfig` 前增加：

```python
class MutationGuardConfig(BaseModel):
    """Role-based guard for persistent mutations and external side effects."""

    enabled: bool = True
    privileged_roles: List[str] = Field(
        default_factory=lambda: ["admin", "root"],
    )
    intent_precheck_enabled: bool = True
    classifier_timeout_seconds: int = Field(default=8, ge=1, le=60)
    deny_message: str = (
        "当前账号没有执行变更操作的权限。"
        "你仍然可以询问相关操作方法或获取示例。"
    )
```

并在 `SecurityConfig` 中增加：

```python
    mutation_guard: MutationGuardConfig = Field(
        default_factory=MutationGuardConfig,
    )
```

`policy.py` 使用以下稳定类型：

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from ...config.config import MutationGuardConfig


class ActionEffect(str, Enum):
    READ = "read"
    MUTATE = "mutate"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    UNKNOWN = "unknown"
    CHAT_INFRASTRUCTURE = "chat_infrastructure"


class RouteCapability(str, Enum):
    PUBLIC = "public"
    READ = "read"
    CHAT = "chat"
    MUTATE = "mutate"


@dataclass(frozen=True)
class RequestPrincipal:
    user_id: str = ""
    roles: tuple[str, ...] = ()
    source: str = ""
    guarded: bool = False
    can_mutate: bool = True

    def to_context(self) -> dict[str, object]:
        return {
            "user_id": self.user_id,
            "roles": list(self.roles),
            "source": self.source,
            "guarded": self.guarded,
            "can_mutate": self.can_mutate,
        }

    @classmethod
    def from_context(cls, value: object) -> "RequestPrincipal":
        if not isinstance(value, dict):
            return cls()
        raw_roles = value.get("roles")
        roles = (
            raw_roles
            if isinstance(raw_roles, (list, tuple))
            else ()
        )
        return cls(
            user_id=str(value.get("user_id") or ""),
            roles=tuple(str(role) for role in roles),
            source=str(value.get("source") or ""),
            guarded=value.get("guarded") is True,
            can_mutate=value.get("can_mutate") is True,
        )


@dataclass(frozen=True)
class MutationDecision:
    allowed: bool
    reason: str


def _normalized(values: Iterable[str]) -> set[str]:
    return {str(value).strip().casefold() for value in values if str(value).strip()}


def build_request_principal(
    *,
    user_id: str,
    roles: Iterable[str],
    source: str,
    auth_enabled: bool,
    config: MutationGuardConfig,
) -> RequestPrincipal:
    materialized_roles = tuple(
        str(role).strip()
        for role in roles
        if str(role).strip()
    )
    normalized_roles = _normalized(materialized_roles)
    privileged = _normalized(config.privileged_roles)
    guarded = bool(config.enabled and auth_enabled and user_id)
    return RequestPrincipal(
        user_id=str(user_id or ""),
        roles=materialized_roles,
        source=str(source or ""),
        guarded=guarded,
        can_mutate=(not guarded or bool(normalized_roles & privileged)),
    )


def authorize_effect(
    principal: RequestPrincipal,
    effect: ActionEffect,
    config: MutationGuardConfig,
) -> MutationDecision:
    if not config.enabled or not principal.guarded or principal.can_mutate:
        return MutationDecision(True, "mutation_guard_not_restricting")
    if effect in {ActionEffect.READ, ActionEffect.CHAT_INFRASTRUCTURE}:
        return MutationDecision(True, "read_only_effect")
    return MutationDecision(False, f"effect_{effect.value}_requires_privileged_role")
```

`audit.py` 定义 `emit_mutation_audit(event, **fields)`，只允许用户 ID、角色、source、agent、session、route/tool、decision、reason 和截断摘要字段；对键名包含 `token`、`secret`、`authorization` 的字段替换为 `"[REDACTED]"`。

- [ ] **Step 4: 运行测试和格式检查**

Run:

```bash
pytest tests/unit/security/mutation_guard/test_policy.py tests/unit/config/test_mutation_guard_config.py -v
python -m black --check --line-length 79 src/qwenpaw/security/mutation_guard tests/unit/security/mutation_guard tests/unit/config/test_mutation_guard_config.py
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/security/mutation_guard src/qwenpaw/config/config.py tests/unit/security/mutation_guard tests/unit/config/test_mutation_guard_config.py
git commit -m "feat(security): add mutation authorization model"
```

---

## Task 2：认证中间件生成 Principal，并扩展 verify 契约

**Files:**
- Modify: `src/qwenpaw/app/auth.py`
- Modify: `src/qwenpaw/app/routers/auth.py`
- Modify: `plugins/bundle/nocobase_auth/identity_resolver.py`
- Test: `tests/unit/app/test_auth_identity_resolver.py`
- Test: `tests/unit/app/test_auth_login_route.py`
- Test: `tests/unit/plugins/test_nocobase_identity_resolver.py`

- [ ] **Step 1: 写失败测试**

向现有测试追加：

```python
def test_resolved_identity_carries_source():
    ident = ResolvedIdentity(
        sender_id="alice",
        roles=["member"],
        source="nocobase",
    )
    assert ident.source == "nocobase"
```

```python
@pytest.mark.asyncio
async def test_verify_returns_roles_and_mutation_capability(client, monkeypatch):
    async def resolver(_request):
        return ResolvedIdentity(
            sender_id="root-user",
            roles=["Root"],
            source="nocobase",
        )

    monkeypatch.setattr(auth_router, "resolve_external_identity", resolver)
    response = client.get("/api/auth/verify")
    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "username": "root-user",
        "roles": ["Root"],
        "can_mutate": True,
    }
```

并在 AuthMiddleware 测试 handler 中断言：

```python
principal = request.state.request_principal
assert principal.user_id == "carol@example.com"
assert principal.roles == ("admin",)
assert principal.can_mutate is True
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/app/test_auth_identity_resolver.py tests/unit/app/test_auth_login_route.py tests/unit/plugins/test_nocobase_identity_resolver.py -v
```

Expected: FAIL，`ResolvedIdentity.source`、`request_principal` 和 verify 字段不存在。

- [ ] **Step 3: 修改认证链**

`ResolvedIdentity` 增加：

```python
    source: str = "external"
```

NocoBase resolver 构造身份时明确传入：

```python
return ResolvedIdentity(
    sender_id=sender_id,
    roles=NocoBaseClient._extract_roles(user),
    source="nocobase",
)
```

AuthMiddleware 在设置 `request.state.user_roles` 后构建可信主体：

```python
from ..config.utils import load_config
from ..security.mutation_guard import build_request_principal

request.state.auth_source = identity.source
request.state.request_principal = build_request_principal(
    user_id=identity.sender_id,
    roles=identity.roles,
    source=identity.source,
    auth_enabled=is_auth_enabled(),
    config=load_config().security.mutation_guard,
)
```

`GET /api/auth/verify` 使用 resolver 的实时结果和同一个角色判断函数返回 `roles`、`can_mutate`。认证关闭时返回：

```json
{"valid": true, "username": "", "roles": [], "can_mutate": true}
```

- [ ] **Step 4: 运行测试**

Run:

```bash
pytest tests/unit/app/test_auth_identity_resolver.py tests/unit/app/test_auth_login_route.py tests/unit/plugins/test_nocobase_identity_resolver.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/app/auth.py src/qwenpaw/app/routers/auth.py plugins/bundle/nocobase_auth/identity_resolver.py tests/unit/app tests/unit/plugins/test_nocobase_identity_resolver.py
git commit -m "feat(auth): expose trusted mutation capability"
```

---

## Task 3：API 路由能力门禁与默认拒绝

**Files:**
- Create: `src/qwenpaw/app/mutation_authorization.py`
- Modify: `src/qwenpaw/app/_app.py`
- Modify: `src/qwenpaw/app/routers/auth.py`
- Modify: `src/qwenpaw/app/routers/console.py`
- Modify: `src/qwenpaw/app/routers/market.py`
- Modify: `src/qwenpaw/app/routers/skills_stream.py`
- Test: `tests/unit/app/test_mutation_authorization.py`
- Test: `tests/unit/app/test_api_capability_catalog.py`

- [ ] **Step 1: 写路由解析和 HTTP 403 失败测试**

```python
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwenpaw.app.mutation_authorization import (
    MutationAuthorizationMiddleware,
    api_capability,
)
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import (
    RequestPrincipal,
    RouteCapability,
)


def _app(principal):
    app = FastAPI()

    @app.get("/read")
    async def read():
        return {"ok": True}

    @app.put("/write")
    async def write():
        return {"ok": True}

    @app.post("/chat")
    @api_capability(RouteCapability.CHAT)
    async def chat():
        return {"ok": True}

    app.state.test_principal = principal
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=lambda: MutationGuardConfig(),
        principal_loader=lambda request: request.app.state.test_principal,
    )
    return app


def test_member_can_read_and_chat_but_cannot_write():
    principal = RequestPrincipal(
        user_id="member",
        roles=("member",),
        source="nocobase",
        guarded=True,
        can_mutate=False,
    )
    client = TestClient(_app(principal))
    assert client.get("/read").status_code == 200
    assert client.post("/chat").status_code == 200
    denied = client.put("/write")
    assert denied.status_code == 403
    assert denied.json()["code"] == "mutation_permission_denied"
```

目录审计测试使用真实 app，并验证未声明的写方法一律落到
`MUTATE`，不存在“未知并放行”状态：

```python
def test_every_write_route_is_declared_or_fail_closed(real_app):
    read_methods = {"GET", "HEAD", "OPTIONS"}
    known = set(RouteCapability)
    for route in real_app.routes:
        methods = set(getattr(route, "methods", set()) or set())
        for method in methods - read_methods:
            declared = getattr(
                getattr(route, "endpoint", None),
                "__qwenpaw_api_capability__",
                None,
            )
            assert declared is None or declared in known
            if declared is None:
                assert default_capability_for_method(method) is (
                    RouteCapability.MUTATE
                )
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/app/test_mutation_authorization.py tests/unit/app/test_api_capability_catalog.py -v
```

Expected: FAIL，路由能力模块不存在。

- [ ] **Step 3: 实现声明、解析和中间件**

核心接口：

```python
from collections.abc import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Match

from ..security.mutation_guard import (
    RequestPrincipal,
    RouteCapability,
)


def api_capability(capability: RouteCapability):
    def decorate(endpoint):
        endpoint.__qwenpaw_api_capability__ = capability
        return endpoint
    return decorate


def resolve_route_capability(request: Request) -> RouteCapability:
    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match is Match.FULL:
            declared = getattr(
                getattr(route, "endpoint", None),
                "__qwenpaw_api_capability__",
                None,
            )
            if isinstance(declared, RouteCapability):
                return declared
            break
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return RouteCapability.READ
    return RouteCapability.MUTATE
```

中间件只在 `principal.guarded` 时限制；`READ`、`CHAT` 放行；`MUTATE` 且 `can_mutate=False` 返回：

```python
JSONResponse(
    status_code=403,
    content={
        "detail": config.deny_message.split("。", 1)[0],
        "code": "mutation_permission_denied",
    },
)
```

在 `_app.py` 中必须按以下顺序注册，使 AuthMiddleware 成为外层并先写入 Principal：

```python
app.add_middleware(AgentContextMiddleware)
app.add_middleware(MutationAuthorizationMiddleware)
app.add_middleware(AuthMiddleware)
```

显式标注：

- `/auth/login` 为 `PUBLIC`，`/auth/status`、`/auth/verify` 为 `READ`。
- `/console/chat`、`/console/chat/task`、`/console/chat/stop`、`/console/inbox/read` 为 `CHAT`。
- `/market/search` 与 `/skills/ai/optimize/stream` 为 `READ`。
- 其余 POST/PUT/PATCH/DELETE 保持默认 `MUTATE`。

- [ ] **Step 4: 运行 API 门禁测试**

Run:

```bash
pytest tests/unit/app/test_mutation_authorization.py tests/unit/app/test_api_capability_catalog.py tests/unit/app/test_auth_identity_resolver.py -v
```

Expected: 全部 PASS；普通用户写请求返回稳定 `403`。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/app/mutation_authorization.py src/qwenpaw/app/_app.py src/qwenpaw/app/routers/auth.py src/qwenpaw/app/routers/console.py src/qwenpaw/app/routers/market.py src/qwenpaw/app/routers/skills_stream.py tests/unit/app/test_mutation_authorization.py tests/unit/app/test_api_capability_catalog.py
git commit -m "feat(api): guard mutation routes by role"
```

---

## Task 4：同步、后台、重连和签名子智能体身份传播

**Files:**
- Create: `src/qwenpaw/app/internal_auth.py`
- Modify: `src/qwenpaw/app/auth.py`
- Modify: `src/qwenpaw/app/routers/console.py`
- Modify: `src/qwenpaw/app/channels/console/channel.py`
- Modify: `src/qwenpaw/app/agent_context.py`
- Modify: `src/qwenpaw/hooks/request_setup/contextvars_hook.py`
- Modify: `src/qwenpaw/runtime/builder.py`
- Modify: `src/qwenpaw/agents/tools/agent_management.py`
- Test: `tests/unit/app/test_internal_auth.py`
- Test: `tests/unit/routers/test_console_acl_roles.py`
- Test: `tests/unit/app/test_request_user_identity.py`
- Test: `tests/integration/test_console_chat_task.py`

- [ ] **Step 1: 写传播失败测试**

```python
def test_console_payload_contains_server_principal():
    principal = RequestPrincipal(
        user_id="alice",
        roles=("member",),
        source="nocobase",
        guarded=True,
        can_mutate=False,
    )
    payload = _extract_session_and_payload(
        {"user_id": "forged", "input": []},
        acl_sender_id="alice",
        acl_roles=["member"],
        request_principal=principal,
    )
    assert payload["meta"]["acl_principal"] == principal.to_context()
    assert payload["meta"]["acl_principal"]["user_id"] == "alice"


def test_console_payload_drops_client_forged_principal():
    payload = _extract_session_and_payload(
        {
            "input": [],
            "request_context": {
                "request_principal": {
                    "user_id": "mallory",
                    "roles": ["root"],
                    "can_mutate": True,
                },
            },
        },
    )
    request_context = payload["meta"].get("request_context", {})
    assert "request_principal" not in request_context
    assert "acl_principal" not in payload["meta"]
```

```python
def test_internal_principal_is_signed_and_target_bound():
    principal = RequestPrincipal(
        user_id="alice",
        roles=("member",),
        source="nocobase",
        guarded=True,
        can_mutate=False,
    )
    credential = mint_internal_principal(
        principal,
        target_agent_id="child",
        now=100,
    )
    verified = verify_internal_principal(
        credential,
        target_agent_id="child",
        now=101,
    )
    assert verified.user_id == "alice"
    assert verified.roles == ("member",)
    assert verified.can_mutate is False
    assert (
        verify_internal_principal(
            credential,
            target_agent_id="other-child",
            now=101,
        )
        is None
    )


def test_internal_principal_rejects_forged_and_expired_credentials():
    credential = mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    assert verify_internal_principal(
        credential + "tampered",
        target_agent_id="child",
        now=101,
    ) is None
    assert verify_internal_principal(
        credential,
        target_agent_id="child",
        now=200,
    ) is None
```

再增加三组测试：

- AuthMiddleware 收到合法内部凭证时，不调用外部 resolver，按当前
  `MutationGuardConfig` 重建 `request.state.request_principal`；非法或过期凭证
  直接返回 `401`，不得降级到匿名/allowlist。
- `_request_headers(to_agent, base_url)` 只对默认地址、loopback、
  unspecified 本机监听地址附加 `X-QwenPaw-Internal-Principal`；显式远端
  URL 不发送内部凭证，避免模型诱导把签名泄露给外部主机。
- 后台接口 monkeypatch `_extract_session_and_payload`，断言
  `post_console_chat_task` 传入与普通 `/chat` 相同的服务端 Principal。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/app/test_internal_auth.py tests/unit/routers/test_console_acl_roles.py tests/unit/app/test_request_user_identity.py tests/integration/test_console_chat_task.py -v
```

Expected: 新断言 FAIL；当前请求体 Principal 可原样进入 runtime，后台
`/chat/task` 没有注入 Principal，且内部调用无可信身份凭证。

- [ ] **Step 3: 实现不可覆盖的传播链**

`_extract_session_and_payload` 增加 `request_principal` 参数。复制客户端
`request_context` 时始终删除保留键 `request_principal`、`acl_principal`；
只有服务端参数可以写入 channel meta：

```python
client_context = dict(rc)
client_context.pop("request_principal", None)
client_context.pop("acl_principal", None)
if client_context:
    meta["request_context"] = client_context
if request_principal is not None:
    meta["acl_principal"] = request_principal.to_context()
```

`post_console_chat` 和 `post_console_chat_task` 都从 `request.state.request_principal` 传入。重连沿用当前请求重新验证出的 Principal。

`AgentBuilder._build_request_context` 在 `rc.update(_payload_ctx)` 之后执行：

```python
trusted = _channel_meta.get("acl_principal")
if isinstance(trusted, dict):
    rc["request_principal"] = dict(trusted)
```

若 channel meta 不含 `acl_principal`，builder 还必须显式
`rc.pop("request_principal", None)`；不能让“服务端 Principal 缺失”变成客户端
注入机会。

`agent_context.py` 增加 `ContextVar[RequestPrincipal]`、setter/getter；
`ContextVarsSetupHook` 只从 `ctx.request.channel_meta["acl_principal"]` 设置它。
approval route 和 `_build_spawn_request_context` 不复制 Principal 到 JSON 请求体。

`internal_auth.py` 使用进程内随机 256-bit key 和 HMAC-SHA256，凭证负载仅包含
版本、purpose、用户 ID、角色、source、目标 agent、签发/过期时间和 nonce：

- 默认有效期 30 秒；
- 校验使用 `hmac.compare_digest`；
- 校验目标必须等于 `X-Agent-Id`；
- 校验后使用当前配置重新计算 `guarded/can_mutate`，不信任负载里的能力位；
- 模块绝不记录凭证或 NocoBase Token。

`_request_headers(to_agent, base_url)` 从当前 Principal mint 内部凭证，但仅在
目标 URL 经 `urlparse` 判定为本机 API 时发送。所有
`stream_agent_chat`、`collect_final_agent_chat_response`、
`submit_agent_chat_task` 和 task status 调用都传入 base URL。

AuthMiddleware 在普通 skip/allowlist 判断之前处理该 header：存在但签名无效
返回 `401`；有效则设置 `request.state.user/user_roles/auth_source/
request_principal` 并继续。这样开启认证时的子智能体调用既能通过认证，又只
继承原用户权限，不传递 NocoBase Token。

- [ ] **Step 4: 运行传播测试**

Run:

```bash
pytest tests/unit/app/test_internal_auth.py tests/unit/routers/test_console_acl_roles.py tests/unit/app/test_request_user_identity.py tests/integration/test_console_chat_task.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/app/internal_auth.py src/qwenpaw/app/auth.py src/qwenpaw/app/routers/console.py src/qwenpaw/app/channels/console/channel.py src/qwenpaw/app/agent_context.py src/qwenpaw/hooks/request_setup/contextvars_hook.py src/qwenpaw/runtime/builder.py src/qwenpaw/agents/tools/agent_management.py tests/unit/app/test_internal_auth.py tests/unit/routers/test_console_acl_roles.py tests/unit/app/test_request_user_identity.py tests/integration/test_console_chat_task.py
git commit -m "feat(runtime): sign delegated request principal"
```

---

## Task 5：工具副作用模型与权威执行闸门

**Files:**
- Modify: `src/qwenpaw/runtime/tool_registry.py`
- Create: `src/qwenpaw/security/mutation_guard/tool_gate.py`
- Modify: `src/qwenpaw/governance/tool_adapter.py`
- Modify: `src/qwenpaw/runtime/tool_guard.py`
- Modify: `src/qwenpaw/app/workspace/local_workspace.py`
- Modify: `src/qwenpaw/agents/react_agent.py`
- Test: `tests/unit/runtime/test_tool_effect_spec.py`
- Test: `tests/unit/governance/test_mutation_tool_gate.py`

- [ ] **Step 1: 写副作用解析与治理关闭不可绕过测试**

```python
def test_browser_effect_resolves_per_action():
    spec = ToolEffectSpec(
        default=ActionEffect.EXTERNAL_SIDE_EFFECT,
        selector_param="action",
        read_values=("snapshot", "navigate", "open", "console_messages"),
    )
    assert spec.resolve({"action": "snapshot"}) is ActionEffect.READ
    assert spec.resolve({"action": "click"}) is ActionEffect.EXTERNAL_SIDE_EFFECT
```

```python
@pytest.mark.asyncio
async def test_member_is_denied_before_governance_off(monkeypatch):
    tool = PolicyGuardedTool(
        mutating_tool,
        governor=None,
        request_context={
            "request_principal": {
                "user_id": "member",
                "roles": ["member"],
                "source": "nocobase",
                "guarded": True,
                "can_mutate": False,
            },
        },
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )
    monkeypatch.setattr(tool_adapter, "_is_execution_level_off", lambda: True)
    decision = await tool.check_permissions({})
    assert decision.behavior is PermissionBehavior.DENY
    assert "mutation_permission_denied" in decision.message
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/runtime/test_tool_effect_spec.py tests/unit/governance/test_mutation_tool_gate.py -v
```

Expected: FAIL，descriptor 和 wrapper 尚无 effect。

- [ ] **Step 3: 增加 `ToolEffectSpec`**

在 `runtime/tool_registry.py` 增加：

```python
@dataclass(frozen=True)
class ToolEffectSpec:
    default: ActionEffect = ActionEffect.UNKNOWN
    selector_param: str = ""
    read_values: tuple[str, ...] = ()
    mutate_values: tuple[str, ...] = ()
    external_values: tuple[str, ...] = ()

    def resolve(self, params: dict[str, Any] | None) -> ActionEffect:
        if not self.selector_param:
            return self.default
        value = str((params or {}).get(self.selector_param) or "").casefold()
        if value in {item.casefold() for item in self.read_values}:
            return ActionEffect.READ
        if value in {item.casefold() for item in self.mutate_values}:
            return ActionEffect.MUTATE
        if value in {item.casefold() for item in self.external_values}:
            return ActionEffect.EXTERNAL_SIDE_EFFECT
        return self.default
```

`ToolDescriptor` 增加 `effect: ToolEffectSpec`；`tool_descriptor` 增加 `side_effect`、`side_effect_param`、`read_only_values`、`mutate_values`、`external_values` 参数并转换为 `ToolEffectSpec`。

`tool_gate.py` 实现：

```python
def authorize_tool_call(
    *,
    request_context: dict[str, Any] | None,
    effect_spec: ToolEffectSpec,
    input_data: dict[str, Any] | None,
) -> MutationDecision:
    config = load_config().security.mutation_guard
    principal = RequestPrincipal.from_context(
        (request_context or {}).get("request_principal"),
    )
    return authorize_effect(principal, effect_spec.resolve(input_data), config)
```

`PolicyGuardedTool` 和 `GuardedFunctionTool` 初始化时保存 effect；`check_permissions` 的第一段调用 `authorize_tool_call`。拒绝时直接返回 `PermissionBehavior.DENY`，不得进入 approval level、Governance、Tool Guard 或沙箱分支。

`local_workspace.list_tools()` 把 `d.effect` 传给 wrapper。ReMe/ADBPG 暴露的 `memory_search` 在 `react_agent.py` 包装时显式传 `ToolEffectSpec(default=READ)`。

- [ ] **Step 4: 运行 wrapper 与现有 governance 回归**

Run:

```bash
pytest tests/unit/runtime/test_tool_effect_spec.py tests/unit/governance/test_mutation_tool_gate.py tests/unit/governance/test_off_mode_sandbox.py tests/unit/governance/test_tool_adapter_scope.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/runtime/tool_registry.py src/qwenpaw/security/mutation_guard/tool_gate.py src/qwenpaw/governance/tool_adapter.py src/qwenpaw/runtime/tool_guard.py src/qwenpaw/app/workspace/local_workspace.py src/qwenpaw/agents/react_agent.py tests/unit/runtime/test_tool_effect_spec.py tests/unit/governance/test_mutation_tool_gate.py
git commit -m "feat(tools): enforce role-based side effects"
```

---

## Task 6：标注全部内置、动态工具和 Slash Command

**Files:**
- Modify: `src/qwenpaw/agents/tools/agent_management.py`
- Modify: `src/qwenpaw/agents/tools/ast_tool.py`
- Modify: `src/qwenpaw/agents/tools/browser_control.py`
- Modify: `src/qwenpaw/agents/tools/desktop_screenshot.py`
- Modify: `src/qwenpaw/agents/tools/file_io.py`
- Modify: `src/qwenpaw/agents/tools/file_search.py`
- Modify: `src/qwenpaw/agents/tools/get_current_time.py`
- Modify: `src/qwenpaw/agents/tools/get_token_usage.py`
- Modify: `src/qwenpaw/agents/tools/make_skill_tools.py`
- Modify: `src/qwenpaw/agents/tools/run_tool_batch.py`
- Modify: `src/qwenpaw/agents/tools/send_file.py`
- Modify: `src/qwenpaw/agents/tools/shell.py`
- Modify: `src/qwenpaw/agents/tools/view_media.py`
- Modify: `src/qwenpaw/agents/tools/web_search.py`
- Modify: `src/qwenpaw/agents/tools/lsp_tool.py`
- Modify: `src/qwenpaw/agents/context/scroll/recall_tool.py`
- Modify: `src/qwenpaw/agents/context/scroll/repl.py`
- Modify: `src/qwenpaw/modes/goal/goal_mode.py`
- Modify: `src/qwenpaw/runtime/slash_command_registry.py`
- Modify: `src/qwenpaw/runtime/builtin_commands.py`
- Modify: `src/qwenpaw/plugins/api.py`
- Test: `tests/unit/runtime/test_tool_effect_catalog.py`
- Test: `tests/unit/runtime/test_slash_command_mutation_guard.py`

- [ ] **Step 1: 写目录完整性失败测试**

```python
def test_every_builtin_tool_has_non_unknown_effect():
    for fn in discover_builtin_tool_funcs():
        descriptor = fn._tool_descriptor
        assert descriptor.effect.default is not ActionEffect.UNKNOWN, (
            descriptor.name
        )
```

Slash Command 测试构造普通 Principal，验证 `read` 命令 handler 会执行，`mutate` 和 `unknown` handler 不执行并返回配置的拒绝消息。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/runtime/test_tool_effect_catalog.py tests/unit/runtime/test_slash_command_mutation_guard.py -v
```

Expected: FAIL，现有工具默认均为 `unknown`。

- [ ] **Step 3: 按固定目录标注**

使用以下目录，不按名称猜测：

| 工具 | Effect |
|---|---|
| `read_file`, `grep_search`, `glob_search`, `ast_search`, LSP、`get_current_time`, `get_token_usage`, `view_image`, `view_video`, `web_search`, `web_fetch`, `desktop_screenshot` | `read` |
| `write_file`, `edit_file`, `append_file`, `set_user_timezone`, `materialize_skill`, `execute_shell_command`, `recall_history_python` | `mutate` |
| `send_file_to_user`, `chat_with_agent`, `submit_to_agent`, `spawn_subagent`, `delegate_external_agent` | `external_side_effect` |
| `list_agents`, `check_agent_task`, `recall_history`, `get_goal` | `read` |
| `create_goal`, `update_goal` | `mutate` |
| `run_tool_batch` | `read`，内部每个真实工具仍逐项经过 wrapper |

`browser_use` 使用动作级解析：

```python
side_effect="external_side_effect",
side_effect_param="action",
read_only_values=(
    "start",
    "stop",
    "open",
    "navigate",
    "snapshot",
    "screenshot",
    "console_messages",
    "network_requests",
    "tabs",
    "wait_for",
    "list_cdp_targets",
),
```

未列入 `read_only_values` 的 click/type/evaluate/upload/download/form/drag/select/run_code/cache 操作保持 `external_side_effect`。

`CommandSpec` 增加 `effect: ActionEffect = ActionEffect.UNKNOWN`。`SlashCommandRegistry.dispatch` 在调用 handler 前使用 `authorize_effect`；fallback skill handler视为聊天入口继续允许，但其工具仍受执行层约束。

命令目录：

- `status`、`version`、`logs`、`approval`、`skills`、`stop` 为 `read` 或 `chat_infrastructure`。
- `restart`、`reload-config`、`approve`、`deny`、`model`、`clear`、`new`、`compact`、`create_goal` 等会改状态的命令为 `mutate`。
- 插件命令默认 `unknown`；`PluginApi.register_slash_command(..., side_effect="read")` 可显式声明。

- [ ] **Step 4: 运行目录和关键工具测试**

Run:

```bash
pytest tests/unit/runtime/test_tool_effect_catalog.py tests/unit/runtime/test_slash_command_mutation_guard.py tests/unit/agents/test_command_handler.py tests/unit/runtime/test_builtin_commands_help_text.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/agents/tools src/qwenpaw/agents/context/scroll src/qwenpaw/modes/goal src/qwenpaw/runtime/slash_command_registry.py src/qwenpaw/runtime/builtin_commands.py src/qwenpaw/plugins/api.py tests/unit/runtime
git commit -m "feat(security): classify builtin action effects"
```

---

## Task 7：Driver、MCP 与插件工具默认 fail-closed

**Files:**
- Modify: `src/qwenpaw/drivers/capabilities.py`
- Modify: `src/qwenpaw/drivers/adapters/agentscope_tool.py`
- Modify: `src/qwenpaw/drivers/handlers/mcp.py`
- Modify: `src/qwenpaw/plugins/api.py`
- Test: `tests/unit/drivers/adapters/test_agentscope_tool.py`
- Test: `tests/unit/plugins/test_plugin_tool_governance.py`
- Test: `tests/integration/test_driver_mcp_approval_level_policy.py`

- [ ] **Step 1: 写 Driver 普通用户拒绝测试**

```python
@pytest.mark.asyncio
async def test_unknown_driver_capability_denied_for_member():
    invoked = False

    async def invoke(_invocation):
        nonlocal invoked
        invoked = True
        return DriverInvocationResult(ok=True, value="unexpected")

    capability = DriverCapability(
        capability_id="driver://mcp/demo/tools/write#invoke",
        driver_name="demo",
        protocol="mcp",
        kind="tool",
        action="invoke",
        name="write",
        effect=ActionEffect.UNKNOWN,
        exposure=CapabilityExposure(as_tool=True, tool_name="write"),
    )
    tool = DriverCapabilityTool(
        capability,
        invoke,
        request_context={"request_principal": MEMBER_CONTEXT},
    )
    decision = await tool.check_permissions()
    assert decision.behavior is PermissionBehavior.DENY
    assert invoked is False
```

再增加 `readOnlyHint=True` 的 MCP schema 映射为 `READ` 并允许普通用户的测试。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/drivers/adapters/test_agentscope_tool.py tests/unit/plugins/test_plugin_tool_governance.py -v
```

Expected: FAIL，DriverCapability 没有 effect，Driver tool 无角色检查。

- [ ] **Step 3: 实现 Driver/插件声明**

`DriverCapability` 增加：

```python
effect: ActionEffect = ActionEffect.UNKNOWN
```

MCP 工具构造 capability 时：

```python
annotations = getattr(tool, "annotations", None)
read_only = bool(getattr(annotations, "readOnlyHint", False))
effect = ActionEffect.READ if read_only else ActionEffect.UNKNOWN
```

`DriverCapabilityTool.check_permissions` 先调用 `authorize_effect`；允许后才返回“Driver policy handled by Driver”的原有结果。

`PluginApi.register_tool` 增加 `side_effect: str = "unknown"`，同时写入 runtime descriptor。插件未声明时普通用户拒绝，管理员仍进入原有 Governance。

- [ ] **Step 4: 运行 Driver/MCP 回归**

Run:

```bash
pytest tests/unit/drivers/adapters/test_agentscope_tool.py tests/unit/plugins/test_plugin_tool_governance.py tests/integration/test_driver_mcp_approval_level_policy.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/drivers src/qwenpaw/plugins/api.py tests/unit/drivers tests/unit/plugins/test_plugin_tool_governance.py tests/integration/test_driver_mcp_approval_level_policy.py
git commit -m "feat(drivers): enforce capability side effects"
```

---

## Task 8：普通用户对话意图预检与只读降级

**Files:**
- Create: `src/qwenpaw/security/mutation_guard/intent.py`
- Create: `src/qwenpaw/hooks/security/__init__.py`
- Create: `src/qwenpaw/hooks/security/mutation_intent_hook.py`
- Modify: `src/qwenpaw/app/workspace/bootstrap_factory.py`
- Test: `tests/unit/security/mutation_guard/test_intent.py`
- Test: `tests/unit/hooks/test_mutation_intent_hook.py`

- [ ] **Step 1: 写分类、上下文和异常降级失败测试**

```python
def test_parse_intent_result_is_strict():
    result = parse_intent_result(
        '{"intent":"mutation_request","reason":"rename assistant"}',
    )
    assert result.intent is IntentKind.MUTATION_REQUEST
    with pytest.raises(ValueError):
        parse_intent_result("Sure, " + result.model_dump_json())
```

```python
@pytest.mark.asyncio
async def test_member_mutation_short_circuits_without_agent(monkeypatch):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="requested persistent rename",
        ),
    )
    hook = MutationIntentHook(classifier=classifier)
    ctx = member_context("你叫小明")
    result = await hook.run(ctx)
    assert result.action is HookAction.SHORT_CIRCUIT
    assert "没有执行变更操作的权限" in result.payload.get_text_content()


@pytest.mark.asyncio
async def test_classifier_timeout_injects_read_only_constraint(monkeypatch):
    async def timeout(*_args, **_kwargs):
        raise asyncio.TimeoutError

    ctx = member_context("按刚才方案处理")
    result = await MutationIntentHook(classifier=timeout).run(ctx)
    assert result.action is HookAction.CONTINUE
    assert any(
        "不得执行变更" in item["content"]
        for item in ctx.context_injections
    )
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/unit/security/mutation_guard/test_intent.py tests/unit/hooks/test_mutation_intent_hook.py -v
```

Expected: FAIL，新模块不存在。

- [ ] **Step 3: 实现无工具分类器**

`intent.py` 定义：

```python
class IntentKind(str, Enum):
    READ_ONLY = "read_only"
    MUTATION_REQUEST = "mutation_request"
    AMBIGUOUS = "ambiguous"


class IntentResult(BaseModel):
    intent: IntentKind
    reason: str = Field(max_length=240)
```

分类 prompt 必须明确：

- 教程、解释、示例、代码片段属于 `read_only`；
- 实际改名、写记忆、改配置/文件/任务、发消息、提交表单属于 `mutation_request`；
- 结合有限近期上下文判断“按刚才方案执行”；
- 只输出一个 JSON 对象。

调用方式复用 `create_model_and_formatter`、AgentScope `Msg/TextBlock` 和 `consume_model_response`，外层 `asyncio.wait_for(..., timeout=config.classifier_timeout_seconds)`。传入当前消息最多 4,000 字符，近期上下文最多 8 条且总计不超过 8,000 字符。

Hook：

- phase 为 `PRE_AGENT_BUILD`；
- `after = ("session_load",)`；
- 管理员、本地模式、禁用配置直接继续；
- 普通用户 `MUTATION_REQUEST` 返回 `HookAction.SHORT_CIRCUIT` + assistant `Msg`；
- `AMBIGUOUS`、超时、模型异常、JSON 无效时 `ctx.inject_context()` 加只读约束并继续；
- 每次拒绝或降级调用结构化审计。

在 `WorkspaceBootstrapFactory` 的 builtin hooks 中注册 `MutationIntentHook`。

- [ ] **Step 4: 运行 Hook 和 Runtime 回归**

Run:

```bash
pytest tests/unit/security/mutation_guard/test_intent.py tests/unit/hooks/test_mutation_intent_hook.py tests/unit/runtime/test_runtime_hooks.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/security/mutation_guard/intent.py src/qwenpaw/hooks/security src/qwenpaw/app/workspace/bootstrap_factory.py tests/unit/security/mutation_guard/test_intent.py tests/unit/hooks/test_mutation_intent_hook.py
git commit -m "feat(chat): preflight mutation intent for members"
```

---

## Task 9：Mutation Guard 配置 API 与安全设置页

**Files:**
- Modify: `src/qwenpaw/app/routers/config.py`
- Modify: `console/src/api/modules/security.ts`
- Modify: `console/src/api/modules/security.test.ts`
- Create: `console/src/pages/Settings/Security/components/MutationGuardTab.tsx`
- Modify: `console/src/pages/Settings/Security/components/index.ts`
- Modify: `console/src/pages/Settings/Security/index.tsx`
- Modify: `console/src/locales/en.json`
- Modify: `console/src/locales/zh.json`
- Modify: `console/src/locales/ja.json`
- Modify: `console/src/locales/ru.json`
- Modify: `console/src/locales/id.json`
- Modify: `console/src/locales/pt-BR.json`
- Modify: `console/src/locales/vi.json`
- Test: `tests/integration/test_security_config.py`
- Test: `console/src/pages/Settings/Security/MutationGuardTab.test.tsx`

- [ ] **Step 1: 写配置往返和前端 API 失败测试**

后端测试：

```python
def test_mutation_guard_roundtrip(app_server):
    body = {
        "enabled": True,
        "privileged_roles": ["admin", "root"],
        "intent_precheck_enabled": True,
        "classifier_timeout_seconds": 6,
        "deny_message": "没有变更权限",
    }
    put = app_server.api_request(
        "PUT",
        "/api/config/security/mutation-guard",
        json=body,
    )
    assert put.status_code == 200
    get = app_server.api_request(
        "GET",
        "/api/config/security/mutation-guard",
    )
    assert get.json() == body
```

前端测试断言 `getMutationGuard()` 使用 GET，`updateMutationGuard(body)` 使用 PUT 和 JSON body。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
pytest tests/integration/test_security_config.py -k mutation_guard -v
cd console && npm run test:run -- src/api/modules/security.test.ts src/pages/Settings/Security/MutationGuardTab.test.tsx
```

Expected: FAIL，端点和组件不存在。

- [ ] **Step 3: 实现配置端点和 Tab**

后端：

```python
@router.get(
    "/security/mutation-guard",
    response_model=MutationGuardConfig,
)
async def get_mutation_guard() -> MutationGuardConfig:
    return load_config().security.mutation_guard


@router.put(
    "/security/mutation-guard",
    response_model=MutationGuardConfig,
)
async def put_mutation_guard(
    body: MutationGuardConfig = Body(...),
) -> MutationGuardConfig:
    config = load_config()
    config.security.mutation_guard = body
    save_config(config)
    return body
```

PUT 自动被 Task 3 的 API 默认规则标记为 `mutate`。

前端类型字段与后端同名；Tab 提供启用开关、角色 Tag 输入、意图预检开关、1–60 秒超时和拒绝文案。保存按钮调用单独的 `updateMutationGuard`，避免与 Tool Guard 部分保存。

- [ ] **Step 4: 运行后端与前端测试**

Run:

```bash
pytest tests/integration/test_security_config.py -k mutation_guard -v
cd console && npm run test:run -- src/api/modules/security.test.ts src/pages/Settings/Security/MutationGuardTab.test.tsx
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/qwenpaw/app/routers/config.py tests/integration/test_security_config.py console/src/api/modules/security.ts console/src/api/modules/security.test.ts console/src/pages/Settings/Security console/src/locales
git commit -m "feat(console): configure mutation guard"
```

---

## Task 10：前端普通用户只读模式

**Files:**
- Create: `console/src/stores/authorizationStore.ts`
- Create: `console/src/stores/authorizationStore.test.ts`
- Modify: `console/src/api/modules/auth.ts`
- Modify: `console/src/api/modules/auth.test.ts`
- Modify: `console/src/App.tsx`
- Modify: `console/src/plugins/registry/types.ts`
- Modify: `console/src/plugins/registry/store.ts`
- Modify: `console/src/plugins/registry/__tests__/routes.test.tsx`
- Modify: `console/src/layouts/registry/builtinRoutes.tsx`
- Modify: `console/src/layouts/MainLayout/index.tsx`
- Modify: `console/src/layouts/Sidebar.tsx`
- Modify: `console/src/layouts/SidebarSessionList.tsx`
- Modify: `console/src/pages/Chat/components/ChatSessionDrawer/index.tsx`
- Modify: `console/src/pages/Chat/components/ChatSessionDrawer/useSessionListData.ts`
- Modify: `console/src/pages/Chat/index.tsx`
- Test: `console/src/layouts/MainLayout/MainLayout.authorization.test.tsx`
- Test: `console/src/pages/Chat/components/ChatSessionDrawer/ChatSessionDrawer.test.tsx`
- Test: `console/src/pages/Chat/ChatPage.test.tsx`

- [ ] **Step 1: 写 capability store 和只读 UI 失败测试**

```typescript
it("stores roles and canMutate from verify", () => {
  useAuthorizationStore.getState().setAuthorization({
    authEnabled: true,
    username: "member",
    roles: ["member"],
    canMutate: false,
  });
  expect(useAuthorizationStore.getState().canMutate).toBe(false);
});
```

registry 测试断言 `capability` 从 `Route` 保留到 `ResolvedRoute`，且插件未声明
时为 `undefined`。MainLayout 测试断言普通用户可以进入 `/chat`、`/inbox`、
`/token-usage`、`/agent-stats`、`/debug`，访问 `/security` 或插件未知路由时
重定向 `/chat`。Chat 测试断言 rename/pin/delete 和上传入口对
`canMutate=false` 不渲染。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
cd console && npm run test:run -- src/stores/authorizationStore.test.ts src/plugins/registry/__tests__/routes.test.tsx src/layouts/MainLayout/MainLayout.authorization.test.tsx src/pages/Chat/components/ChatSessionDrawer/ChatSessionDrawer.test.tsx src/pages/Chat/ChatPage.test.tsx
```

Expected: FAIL，store 和路由能力字段不存在。

- [ ] **Step 3: 实现 verify store 与 fail-closed 路由**

`authApi` 增加：

```typescript
export interface VerifyResponse {
  valid: boolean;
  username: string;
  roles: string[];
  can_mutate: boolean;
}

verify: async (): Promise<VerifyResponse> => {
  const res = await fetch(getApiUrl("/auth/verify"), {
    headers: buildAuthHeaders(),
  });
  if (!res.ok) throw new Error("Invalid or expired token");
  return res.json();
},
```

`AuthGuard`：

- auth 关闭时 store 设为 `canMutate=true`；
- verify 成功时用服务端 `roles/can_mutate`；
- 不从 localStorage 或 URL 读取角色。

`Route` 和 `MenuItem` 增加 `capability?: "read" | "mutate"`；
`RouteRegistryImpl.resolveAll()` 把 base route 的 capability 复制到
`ResolvedRoute`。组件 replace/wrap 只能替换渲染组件，不能把原 route 的
capability 提升；插件新增 route 不声明时仍为 `undefined`，由授权过滤器按
`mutate` 处理。内置只读路由明确标记：

```typescript
{ id: "core.root", path: "/", component: DefaultRedirect, capability: "read" }
{ id: "core.chat", path: "/chat/*", component: Chat, capability: "read" }
{ id: "core.inbox", path: "/inbox", component: InboxPage, capability: "read" }
{ id: "core.token-usage", path: "/token-usage", component: TokenUsagePage, capability: "read" }
{ id: "core.agent-stats", path: "/agent-stats", component: AgentStatsPage, capability: "read" }
{ id: "core.debug", path: "/debug", component: DebugPage, capability: "read" }
```

其他内置和插件未知路由默认 `mutate`。MainLayout 和 Sidebar 使用同一个 `filterRoutesForAuthorization` 纯函数；普通用户直接输入受限 URL 时渲染 `<Navigate to="/chat" replace />`。

Chat 页面普通用户：

- 可以发送文本并停止当前生成；
- 不显示文件上传；
- 不显示会话 rename、pin、delete 和批量删除；
- 后端 API 仍会阻止手工构造请求。

- [ ] **Step 4: 运行前端授权测试**

Run:

```bash
cd console && npm run test:run -- src/api/modules/auth.test.ts src/stores/authorizationStore.test.ts src/plugins/registry/__tests__/routes.test.tsx src/layouts/MainLayout/MainLayout.authorization.test.tsx src/pages/Chat/components/ChatSessionDrawer/ChatSessionDrawer.test.tsx src/pages/Chat/ChatPage.test.tsx
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add console/src
git commit -m "feat(console): add read-only member experience"
```

---

## Task 11：端到端权限矩阵与绕过回归

**Files:**
- Create: `tests/integration/test_nocobase_mutation_guard.py`
- Modify: `tests/integration/test_console.py`
- Modify: `tests/integration/test_console_chat_task.py`
- Modify: `tests/integration/test_driver_mcp_approval_level_policy.py`
- Test: `tests/integration/test_nocobase_mutation_guard.py`

- [ ] **Step 1: 建立可重复的身份 fixture**

测试内使用可控 external resolver：

```python
@asynccontextmanager
async def identity_for(role: str):
    async def resolver(request):
        token = request.headers.get("X-Test-Role")
        if not token:
            return None
        return ResolvedIdentity(
            sender_id=f"{token}@test",
            roles=[role],
            source="nocobase",
        )

    register_external_identity_resolver(resolver)
    try:
        yield
    finally:
        unregister_external_identity_resolver(resolver)
```

若现有注册表没有单个 unregister，则在测试 fixture 中保存并恢复 resolver 列表，不能让测试身份泄漏到其他用例。

- [ ] **Step 2: 写完整权限矩阵**

至少覆盖：

```python
@pytest.mark.parametrize("role", ["member", "viewer", ""])
def test_member_direct_put_is_403(role, auth_app_client):
    response = auth_app_client.put(
        "/api/config/security/tool-guard",
        headers={"X-Test-Role": role},
        json=VALID_TOOL_GUARD,
    )
    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"


@pytest.mark.parametrize("role", ["admin", "root", "ADMIN", "Root"])
def test_privileged_role_reaches_write_handler(role, auth_app_client):
    response = auth_app_client.put(
        "/api/config/security/mutation-guard",
        headers={"X-Test-Role": role},
        json=VALID_MUTATION_GUARD,
    )
    assert response.status_code == 200
```

对话矩阵：

- member：“如何修改名称”与“给我配置示例”进入 agent；
- member：“你叫小明”返回拒绝，memory/config 文件 hash 不变；
- member：“按刚才方案执行”结合近期上下文返回拒绝；
- admin/root 相同变更消息进入原有 agent/tool 流程；
- classifier 超时后模拟模型调用写工具，wrapper 拒绝且目标文件不存在。

绕过矩阵：

- body 中伪造 `roles=["root"]`、`can_mutate=true`、其他 `user_id` 无效；
- `/console/chat/task` 和重连保留 member Principal；
- batch 中 read 成功、write 子步骤拒绝；
- spawn/ACP/Driver 未标注能力拒绝；
- auth disabled 时现有本地写 API 测试仍通过；
- 普通聊天会话、历史和自动标题正常保存。

- [ ] **Step 3: 运行矩阵并修复只属于本功能的缺口**

Run:

```bash
pytest tests/integration/test_nocobase_mutation_guard.py tests/integration/test_console.py tests/integration/test_console_chat_task.py tests/integration/test_driver_mcp_approval_level_policy.py -v
```

Expected: 全部 PASS。若出现权限绕过，修复对应 Task 的组件并在本文件增加回归断言后再继续。

- [ ] **Step 4: 运行安全相关回归**

Run:

```bash
pytest tests/unit/app tests/unit/security tests/unit/governance tests/unit/runtime tests/unit/drivers tests/unit/plugins -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add tests src/qwenpaw plugins/bundle/nocobase_auth
git commit -m "test(security): cover nocobase mutation boundaries"
```

---

## Task 12：文档、全量验证与交付

**Files:**
- Modify: `plugins/bundle/nocobase_auth/README.md`
- Modify: `website/public/docs/security.zh.md`
- Modify: `website/public/docs/security.en.md`

- [ ] **Step 1: 更新用户文档**

中文文档必须明确：

- Token 由 NocoBase 验证，角色实时来自 `auth:check?appends=roles`；
- 默认特权角色为 `admin`、`root`，大小写不敏感精确匹配；
- 普通用户可以聊天、查询、询问教程和示例；
- 普通用户不能让智能体实际改名、改记忆、写文件、改配置、发消息或调用写 API；
- 意图分类器只是体验层，动作/API 闸门才是安全边界；
- auth disabled 的本地模式不启用角色闸门；
- Mutation Guard 配置入口和 403/SSE 拒绝示例。

英文文档表达相同契约，不添加 NocoBase 管理员 token 依赖。

- [ ] **Step 2: 运行 Python 全量测试**

Run:

```bash
pytest
```

Expected: 全部 PASS；如存在仓库原有且与本变更无关的失败，保存完整命令和失败用例，不把它描述为通过。

- [ ] **Step 3: 运行前端全量测试与构建**

Run:

```bash
cd console
npm run test:run
npm run format
npm run lint
npm run build
```

Expected: Vitest、TypeScript/Prettier、ESLint 和 Vite build 全部成功。

- [ ] **Step 4: 运行仓库提交门禁**

Run:

```bash
pre-commit run --all-files
```

Expected: 全部 hook PASS。若 hook 修改文件，重新 `git add` 并再次运行，直到工作树只包含预期变更。

- [ ] **Step 5: 手工 HTTP 验收**

使用真实 NocoBase 的 member/admin/root Token：

```bash
curl -i \
  -H "Authorization: Bearer ${MEMBER_TOKEN}" \
  -H "Content-Type: application/json" \
  -X PUT \
  http://127.0.0.1:8088/api/config/security/mutation-guard \
  --data '{"enabled":true,"privileged_roles":["admin","root"],"intent_precheck_enabled":true,"classifier_timeout_seconds":8,"deny_message":"当前账号没有执行变更操作的权限。你仍然可以询问相关操作方法或获取示例。"}'
```

Expected: member 返回 `403 mutation_permission_denied`；admin/root 返回业务 handler 的正常结果。

再分别通过 `/api/console/chat` 发送：

```text
如何修改你的名称？
你叫小明
```

Expected: member 第一条正常回答教程，第二条返回统一拒绝；admin/root 第二条可进入现有安全执行流程。

- [ ] **Step 6: 提交文档和最终机械修复**

```bash
git add plugins/bundle/nocobase_auth/README.md website/public/docs/security.zh.md website/public/docs/security.en.md
git commit -m "docs(security): document nocobase mutation guard"
```

- [ ] **Step 7: 最终状态检查**

Run:

```bash
git status --short
git log --oneline -12
```

Expected: 工作树干净；提交历史包含本计划的独立功能提交。
