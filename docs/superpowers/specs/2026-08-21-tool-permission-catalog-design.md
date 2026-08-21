# Tool Permission Catalog Design

**Status:** Approved

**Date:** 2026-08-21

## Problem

The Mutation Guard settings page exposes the global switch and privileged
roles, but it does not show how tools are classified. Operators currently
have to inspect source code or audit logs to learn why a normal NocoBase
member can or cannot call a tool. This also hides classification gaps such as
`memory_search` resolving to `UNKNOWN`.

## Goals

- Add a read-only "Tool permission catalog" to the Mutation Guard settings
  page.
- Show every tool the currently selected agent can potentially load,
  including core, plugin, mode, memory, context, coding, and Driver tools.
- Show each tool's default `ActionEffect` classification and the effective
  allow/deny result for a guarded, non-privileged member.
- Make the permission result reflect the currently persisted Mutation Guard
  configuration. When the guard is disabled, every listed tool is allowed.
- Keep the settings form usable if catalog discovery fails.

## Non-goals

- The catalog will not edit tool classifications or enabled state.
- The feature will not change Mutation Guard policy or fix existing
  classifications such as `memory_search = UNKNOWN`.
- The feature will not expose tool parameters, credentials, schemas, or
  governance rules.
- The first version will display a tool's default effect. It will not add a
  sixth "conditional" category for selector-dependent effects.
- Slash commands are not tools and are outside this catalog.

## User experience

The existing Mutation Guard form remains unchanged. A new section appears
below the form actions with the localized title "Tool permission catalog" and
a short explanation that the rows describe tools the current agent may load
and permissions under the currently saved guard settings.

The table is read-only and contains three columns:

1. **Tool name** — rendered in a monospaced style.
2. **Classification** — a colored tag containing one of `READ`, `MUTATE`,
   `EXTERNAL_SIDE_EFFECT`, `CHAT_INFRASTRUCTURE`, or `UNKNOWN`.
3. **Normal account** — a green "Allowed" tag or red "Denied" tag.

Rows are sorted by tool name. The table uses 20 rows per page. `UNKNOWN` uses
a warning color so missing metadata is immediately visible. An empty catalog
shows the standard empty state.

The catalog represents persisted effective state, not unsaved form edits.
After a successful Mutation Guard save, the page refetches the catalog. When
the selected agent changes, the request is repeated with that agent's normal
`X-Agent-Id` request header.

## API

Add an agent-scoped, read-only endpoint:

```text
GET /api/config/security/mutation-guard/tool-permissions
```

Each response item has this shape:

```json
{
  "name": "memory_search",
  "effect": "unknown",
  "allowed_for_member": false
}
```

The endpoint returns a JSON array sorted by `name`. It resolves the selected
workspace through the existing agent-context machinery, so the same endpoint
returns different catalogs when `X-Agent-Id` changes.

The endpoint is read-only: it does not mutate configuration, toggle tools,
reload an agent, execute a tool, or emit a mutation-denial audit event.

## Catalog collection

A focused backend catalog service owns discovery and permission calculation.
The HTTP router only resolves the workspace and serializes the service result.
The service gathers metadata without building a model or executing a tool.

Sources are merged in this order:

1. The selected workspace's `ToolRegistry`, which already contains core,
   installed plugin, and registered mode descriptors. Mode-gated descriptors
   are included because the catalog represents tools the agent may load, not
   only tools active in a particular chat turn.
2. Optional tool contributors enabled by the selected agent configuration,
   including coding, scroll-context, visual-recovery, and Driver capabilities.
   Discovery reuses their existing descriptor/effect metadata and must not
   invoke the tool body. Unavailable optional capabilities are not reported as
   loadable tools.
3. The selected workspace's memory manager via `list_memory_tools()`. The
   existing `get_tool_effect_spec()` function is intentionally used so an
   unannotated callable appears as `UNKNOWN` rather than being silently
   reclassified.

Agent tool configuration is applied before returning rows. A tool explicitly
disabled for the selected agent is excluded. Plugin tools that are disabled by
default are included only when the selected agent has opted in. Conditional
mode tools are included when their owning mode is registered for the agent,
even if no current chat has activated that mode.

Tool names are required to be unique in the runtime toolkit. The collector
coalesces duplicate rows only when their effect metadata agrees. A duplicate
name with conflicting effects is treated as catalog discovery failure instead
of displaying a misleading permission. Results are sorted after
deduplication.

## Effective permission calculation

The backend must not reproduce policy rules in the frontend. For each default
effect, the catalog service constructs a synthetic guarded,
non-privileged `RequestPrincipal` and calls the existing
`authorize_effect()` function with the current persisted
`MutationGuardConfig`.

Consequences:

- Guard disabled: every classification is allowed.
- Guard enabled: `READ` and `CHAT_INFRASTRUCTURE` are allowed.
- Guard enabled: `MUTATE`, `EXTERNAL_SIDE_EFFECT`, and `UNKNOWN` are denied.
- Future policy changes automatically flow into the catalog.

The synthetic principal is used only for policy evaluation. It is not a real
user identity and is not written to logs or audit storage.

## Frontend data flow

The frontend security API adds a typed `getToolPermissions()` method. The
Mutation Guard component maintains catalog loading, data, and error state
separately from the editable configuration state.

On mount, configuration and catalog requests run independently. A catalog
failure renders an inline error and retry action inside the catalog section;
it does not replace or disable the Mutation Guard form. A successful settings
save triggers a catalog refetch only after the server confirms persistence.

The table receives only server-computed `effect` and
`allowed_for_member` values. It does not derive permission from the switch or
hard-code the allowlist.

## Localization and documentation

Add localized strings for the section title, description, column headers,
effect labels, permission labels, empty state, load error, and retry action to
all existing console locale files. Update the user-facing security
documentation to explain that the table is diagnostic and read-only, follows
the selected agent, and uses the persisted Mutation Guard configuration.

## Error handling

- A failure to resolve the selected agent returns the existing agent-context
  HTTP error.
- Catalog discovery errors are surfaced by the endpoint and handled only in
  the catalog section.
- Component unmount and stale-request protections match the existing
  Mutation Guard load/save generation pattern.
- Empty results are successful and display an empty state.
- A failed catalog refresh after a successful settings save does not turn the
  successful save into a failure.

## Testing

Backend tests cover:

- Collection of core, plugin, mode, memory, context, coding, and Driver tool
  metadata.
- Agent enabled/disabled gates, plugin opt-in behavior, defensive
  deduplication, and deterministic sorting.
- `memory_search` remaining visible as `UNKNOWN` until separately fixed.
- Effective member permission with the guard enabled and disabled.
- The endpoint selecting the workspace named by `X-Agent-Id` and performing
  no writes.

Frontend tests cover:

- Security API request path and response typing.
- Rendering the three required columns and all effect/permission tags.
- Sorting and 20-row pagination.
- Empty state and catalog-only error/retry behavior.
- Catalog refresh after a successful settings save.
- Catalog refresh when the selected agent changes.
- Ignoring stale responses after unmount or agent changes.

Verification runs the focused backend pytest suite, focused Vitest suite,
TypeScript/Prettier checks, and the broader relevant security and tools tests.

## Acceptance criteria

- An administrator can open Mutation Guard settings and see the complete
  potential tool catalog for the selected agent.
- Every row shows a tool name, one of the five existing effect categories,
  and the effective normal-account allow/deny result.
- `memory_search` is visibly classified as `UNKNOWN` and denied while the
  guard is enabled.
- Disabling and saving Mutation Guard refreshes the table so all rows show
  "Allowed"; re-enabling and saving restores policy-derived results.
- The catalog cannot modify tools, classifications, or configuration.
- A catalog error never prevents viewing or saving Mutation Guard settings.
