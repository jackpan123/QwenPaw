import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolPermissionInfo } from "../../../api/modules/security";
import { useAgentStore } from "../../../stores/agentStore";

const hoisted = vi.hoisted(() => ({
  apiMocks: {
    getToolPermissions: vi.fn(),
  },
}));

vi.mock("../../../api", () => ({
  default: hoisted.apiMocks,
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

import { ToolPermissionCatalog } from "./components/ToolPermissionCatalog";

const allEffects: ToolPermissionInfo[] = [
  { name: "z_read", effect: "read", allowed_for_member: true },
  { name: "a_mutate", effect: "mutate", allowed_for_member: false },
  {
    name: "external",
    effect: "external_side_effect",
    allowed_for_member: false,
  },
  { name: "unknown", effect: "unknown", allowed_for_member: false },
  {
    name: "chat",
    effect: "chat_infrastructure",
    allowed_for_member: true,
  },
];

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("ToolPermissionCatalog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.apiMocks.getToolPermissions.mockResolvedValue([]);
    useAgentStore.setState({ selectedAgent: "default" });
  });

  it("renders sorted catalog entries with their server permissions", async () => {
    hoisted.apiMocks.getToolPermissions.mockResolvedValue(allEffects);

    render(<ToolPermissionCatalog refreshToken={0} />);

    await screen.findByText(
      "security.mutationGuard.catalog.effects.externalSideEffect",
    );

    expect(
      screen.getByText("security.mutationGuard.catalog.toolName"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("security.mutationGuard.catalog.classification"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("security.mutationGuard.catalog.normalAccount"),
    ).toBeInTheDocument();
    expect(
      screen
        .getAllByTestId("tool-permission-name")
        .map((item) => item.textContent),
    ).toEqual(["a_mutate", "chat", "external", "unknown", "z_read"]);
    expect(
      screen.getByText("security.mutationGuard.catalog.effects.read"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("security.mutationGuard.catalog.effects.mutate"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("security.mutationGuard.catalog.effects.unknown"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "security.mutationGuard.catalog.effects.chatInfrastructure",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText("security.mutationGuard.catalog.allowed"),
    ).toHaveLength(2);
    expect(
      screen.getAllByText("security.mutationGuard.catalog.denied"),
    ).toHaveLength(3);
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
  });

  it("paginates more than twenty catalog entries", async () => {
    hoisted.apiMocks.getToolPermissions.mockResolvedValue(
      Array.from({ length: 21 }, (_, index) => ({
        name: `tool_${String(index + 1).padStart(2, "0")}`,
        effect: "read" as const,
        allowed_for_member: true,
      })),
    );

    render(<ToolPermissionCatalog refreshToken={0} />);

    await screen.findByText("tool_01");
    expect(screen.getByText("tool_20")).toBeInTheDocument();
    expect(screen.queryByText("tool_21")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTitle("2"));

    expect(await screen.findByText("tool_21")).toBeInTheDocument();
  });

  it("shows the catalog empty state after an empty response", async () => {
    render(<ToolPermissionCatalog refreshToken={0} />);

    expect(
      await screen.findByText("security.mutationGuard.catalog.empty"),
    ).toBeInTheDocument();
  });

  it("retries a failed catalog request", async () => {
    hoisted.apiMocks.getToolPermissions.mockRejectedValueOnce(
      new Error("network down"),
    );
    hoisted.apiMocks.getToolPermissions.mockResolvedValueOnce(allEffects);

    render(<ToolPermissionCatalog refreshToken={0} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "security.mutationGuard.loadFailed",
    );
    fireEvent.click(screen.getByRole("button", { name: "environments.retry" }));

    await screen.findByText("z_read");
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
  });

  it("reloads when the selected agent changes", async () => {
    hoisted.apiMocks.getToolPermissions
      .mockResolvedValueOnce([allEffects[0]])
      .mockResolvedValueOnce([allEffects[1]]);

    render(<ToolPermissionCatalog refreshToken={0} />);

    await screen.findByText("z_read");
    act(() => {
      useAgentStore.setState({ selectedAgent: "agent-b" });
    });

    expect(await screen.findByText("a_mutate")).toBeInTheDocument();
    expect(screen.queryByText("z_read")).not.toBeInTheDocument();
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
  });

  it("reloads when refreshToken changes", async () => {
    hoisted.apiMocks.getToolPermissions
      .mockResolvedValueOnce([allEffects[0]])
      .mockResolvedValueOnce([allEffects[1]]);

    const view = render(<ToolPermissionCatalog refreshToken={0} />);
    await screen.findByText("z_read");
    view.rerender(<ToolPermissionCatalog refreshToken={1} />);

    expect(await screen.findByText("a_mutate")).toBeInTheDocument();
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
  });

  it("does not let a stale agent request overwrite the current catalog", async () => {
    const first = deferred<ToolPermissionInfo[]>();
    const second = deferred<ToolPermissionInfo[]>();
    hoisted.apiMocks.getToolPermissions
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);

    render(<ToolPermissionCatalog refreshToken={0} />);
    act(() => {
      useAgentStore.setState({ selectedAgent: "agent-b" });
    });

    second.resolve([allEffects[1]]);
    expect(await screen.findByText("a_mutate")).toBeInTheDocument();
    first.resolve([allEffects[0]]);
    await first.promise;

    await waitFor(() => {
      expect(screen.queryByText("z_read")).not.toBeInTheDocument();
    });
    expect(screen.getByText("a_mutate")).toBeInTheDocument();
  });

  it("ignores an in-flight request after unmount", async () => {
    const pending = deferred<ToolPermissionInfo[]>();
    hoisted.apiMocks.getToolPermissions.mockReturnValueOnce(pending.promise);

    const view = render(<ToolPermissionCatalog refreshToken={0} />);
    view.unmount();
    pending.resolve(allEffects);
    await pending.promise;
    await Promise.resolve();

    expect(
      screen.queryByTestId("tool-permission-name"),
    ).not.toBeInTheDocument();
  });
});
