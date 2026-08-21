import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import type {
  MutationGuardConfig,
  ToolPermissionInfo,
} from "../../../api/modules/security";

const hoisted = vi.hoisted(() => ({
  apiMocks: {
    getMutationGuard: vi.fn(),
    getToolPermissions: vi.fn(),
    updateMutationGuard: vi.fn(),
    updateToolGuard: vi.fn(),
  },
  messageMocks: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("../../../api", () => ({
  default: hoisted.apiMocks,
}));

vi.mock("@agentscope-ai/design", async () => {
  const React = await import("react");
  const design = await import("../../../test/design-mock");
  const table = ({
    dataSource = [],
    locale = {},
  }: {
    dataSource?: { name: string }[];
    locale?: { emptyText?: ReactNode };
  }) =>
    React.createElement(
      "div",
      null,
      dataSource.length
        ? dataSource.map((item: { name: string }) =>
            React.createElement("span", { key: item.name }, item.name),
          )
        : locale.emptyText,
    );

  return { ...design, Table: table };
});

vi.mock("../../../hooks/useAppMessage", () => ({
  useAppMessage: () => ({ message: hoisted.messageMocks }),
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, values?: { role?: string }) =>
      values?.role ? `${key} ${values.role}` : key,
  }),
}));

import { MutationGuardTab } from "./components/MutationGuardTab";

const config: MutationGuardConfig = {
  enabled: true,
  privileged_roles: ["admin", "root"],
  intent_precheck_enabled: true,
  classifier_timeout_seconds: 8,
  deny_message: "当前账号没有权限",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("MutationGuardTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.apiMocks.getMutationGuard.mockResolvedValue(config);
    hoisted.apiMocks.getToolPermissions.mockResolvedValue([]);
    hoisted.apiMocks.updateMutationGuard.mockImplementation(
      async (body) => body,
    );
  });

  it("loads and renders all Mutation Guard fields", async () => {
    render(<MutationGuardTab />);

    expect(screen.getByText("common.loading")).toBeInTheDocument();
    await screen.findByText("security.mutationGuard.description");

    expect(hoisted.apiMocks.getMutationGuard).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("switch", {
        name: "security.mutationGuard.enabled",
      }),
    ).toBeChecked();
    expect(
      screen.getByRole("switch", {
        name: "security.mutationGuard.intentPrecheck",
      }),
    ).toBeChecked();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
    expect(
      screen.getByRole("spinbutton", {
        name: "security.mutationGuard.classifierTimeout",
      }),
    ).toHaveValue(8);
    expect(
      screen.getByRole("textbox", {
        name: "security.mutationGuard.denyMessage",
      }),
    ).toHaveValue("当前账号没有权限");
  });

  it("loads the catalog while Mutation Guard settings are still loading", async () => {
    const pendingSettings = deferred<MutationGuardConfig>();
    const catalog: ToolPermissionInfo[] = [
      {
        name: "memory_search",
        effect: "unknown",
        allowed_for_member: false,
      },
    ];
    hoisted.apiMocks.getMutationGuard.mockReturnValueOnce(
      pendingSettings.promise,
    );
    hoisted.apiMocks.getToolPermissions.mockResolvedValueOnce(catalog);

    render(<MutationGuardTab />);

    expect(screen.getByText("common.loading")).toBeInTheDocument();
    expect(await screen.findByText("memory_search")).toBeInTheDocument();
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);

    pendingSettings.resolve(config);
    expect(
      await screen.findByText("security.mutationGuard.description"),
    ).toBeInTheDocument();
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
  });

  it("saves independently without touching Tool Guard", async () => {
    const user = userEvent.setup();
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");

    const timeout = screen.getByRole("spinbutton", {
      name: "security.mutationGuard.classifierTimeout",
    });
    await user.clear(timeout);
    await user.type(timeout, "12");
    const denyMessage = screen.getByRole("textbox", {
      name: "security.mutationGuard.denyMessage",
    });
    await user.clear(denyMessage);
    await user.type(denyMessage, "只允许管理员执行变更");
    await user.click(screen.getByRole("button", { name: "common.save" }));

    await waitFor(() => {
      expect(hoisted.apiMocks.updateMutationGuard).toHaveBeenCalledWith({
        ...config,
        classifier_timeout_seconds: 12,
        deny_message: "只允许管理员执行变更",
      });
    });
    expect(hoisted.apiMocks.updateToolGuard).not.toHaveBeenCalled();
    expect(hoisted.messageMocks.success).toHaveBeenCalledWith(
      "security.mutationGuard.saveSuccess",
    );
  });

  it("refreshes the catalog after a successful save", async () => {
    const user = userEvent.setup();
    hoisted.apiMocks.getToolPermissions
      .mockResolvedValueOnce([
        { name: "shell", effect: "mutate", allowed_for_member: false },
      ])
      .mockResolvedValueOnce([
        { name: "shell", effect: "mutate", allowed_for_member: true },
      ]);
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");
    await waitFor(() => {
      expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
    });

    await user.click(screen.getByRole("button", { name: "common.save" }));

    await waitFor(() => {
      expect(hoisted.apiMocks.updateMutationGuard).toHaveBeenCalledTimes(1);
      expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(2);
    });
    expect(hoisted.messageMocks.success).toHaveBeenCalledWith(
      "security.mutationGuard.saveSuccess",
    );
  });

  it("does not refresh the catalog after a failed save", async () => {
    const user = userEvent.setup();
    hoisted.apiMocks.updateMutationGuard.mockRejectedValueOnce(
      new Error("write failed"),
    );
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "common.save" }));

    await screen.findByText("security.mutationGuard.saveFailed");
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
  });

  it("keeps Mutation Guard controls usable when catalog loading fails", async () => {
    hoisted.apiMocks.getToolPermissions.mockRejectedValueOnce(
      new Error("catalog unavailable"),
    );
    render(<MutationGuardTab />);

    await screen.findByText("security.mutationGuard.description");
    expect(
      await screen.findByText("security.mutationGuard.catalog.loadFailed"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("switch", {
        name: "security.mutationGuard.enabled",
      }),
    ).toBeEnabled();
    expect(screen.getByRole("button", { name: "common.save" })).toBeEnabled();
  });

  it("keeps a successful save successful when its catalog refresh fails", async () => {
    const user = userEvent.setup();
    hoisted.apiMocks.getToolPermissions
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new Error("catalog refresh unavailable"));
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");

    await user.click(screen.getByRole("button", { name: "common.save" }));

    await screen.findByText("security.mutationGuard.catalog.loadFailed");
    expect(hoisted.messageMocks.success).toHaveBeenCalledWith(
      "security.mutationGuard.saveSuccess",
    );
    expect(hoisted.messageMocks.error).not.toHaveBeenCalled();
  });

  it("shows a retryable load error", async () => {
    hoisted.apiMocks.getMutationGuard.mockRejectedValueOnce(
      new Error("network down"),
    );
    const user = userEvent.setup();
    render(<MutationGuardTab />);

    await screen.findByText("security.mutationGuard.loadFailed");
    hoisted.apiMocks.getMutationGuard.mockResolvedValueOnce(config);
    await user.click(
      screen.getByRole("button", { name: "environments.retry" }),
    );

    await screen.findByText("security.mutationGuard.description");
    expect(hoisted.apiMocks.getMutationGuard).toHaveBeenCalledTimes(2);
  });

  it("uses focusable localized buttons to remove roles", async () => {
    const user = userEvent.setup();
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");

    const removeAdmin = screen.getByRole("button", {
      name: "security.mutationGuard.removeRole admin",
    });
    removeAdmin.focus();
    expect(removeAdmin).toHaveFocus();
    await user.click(removeAdmin);

    expect(screen.queryByText("admin")).not.toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
  });

  it.each(["1.5", "0", "61"])(
    "rejects invalid timeout %s and disables save",
    async (invalidTimeout) => {
      const user = userEvent.setup();
      render(<MutationGuardTab />);
      await screen.findByText("security.mutationGuard.description");

      const timeout = screen.getByRole("spinbutton", {
        name: "security.mutationGuard.classifierTimeout",
      });
      await user.clear(timeout);
      await user.type(timeout, invalidTimeout);

      expect(
        screen.getByText("security.mutationGuard.timeoutInvalid"),
      ).toHaveAttribute("role", "alert");
      expect(
        screen.getByRole("button", { name: "common.save" }),
      ).toBeDisabled();
      expect(hoisted.apiMocks.updateMutationGuard).not.toHaveBeenCalled();
    },
  );

  it("keeps the last valid timeout when the input becomes empty", async () => {
    const user = userEvent.setup();
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");

    const timeout = screen.getByRole("spinbutton", {
      name: "security.mutationGuard.classifierTimeout",
    });
    await user.clear(timeout);
    expect(screen.getByRole("button", { name: "common.save" })).toBeDisabled();

    await user.type(timeout, "12");
    await user.click(screen.getByRole("button", { name: "common.save" }));

    await waitFor(() =>
      expect(hoisted.apiMocks.updateMutationGuard).toHaveBeenCalledWith({
        ...config,
        classifier_timeout_seconds: 12,
      }),
    );
  });

  it("prevents duplicate saves and disables every field while saving", async () => {
    const pending = deferred<MutationGuardConfig>();
    hoisted.apiMocks.updateMutationGuard.mockReturnValueOnce(pending.promise);
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");

    const saveButton = screen.getByRole("button", { name: "common.save" });
    fireEvent.click(saveButton);
    fireEvent.click(saveButton);

    expect(hoisted.apiMocks.updateMutationGuard).toHaveBeenCalledTimes(1);
    expect(saveButton).toBeDisabled();
    expect(
      screen.getByRole("switch", { name: "security.mutationGuard.enabled" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", {
        name: "security.mutationGuard.removeRole admin",
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: "security.mutationGuard.privilegedRoles",
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("spinbutton", {
        name: "security.mutationGuard.classifierTimeout",
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: "security.mutationGuard.denyMessage",
      }),
    ).toBeDisabled();

    pending.resolve(config);
    await waitFor(() => expect(saveButton).toBeEnabled());
  });

  it("ignores a save response after unmount", async () => {
    const pending = deferred<MutationGuardConfig>();
    hoisted.apiMocks.updateMutationGuard.mockReturnValueOnce(pending.promise);
    const view = render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");
    fireEvent.click(screen.getByRole("button", { name: "common.save" }));

    view.unmount();
    pending.resolve({ ...config, deny_message: "stale" });
    await pending.promise;
    await Promise.resolve();

    expect(hoisted.messageMocks.success).not.toHaveBeenCalled();
    expect(hoisted.messageMocks.error).not.toHaveBeenCalled();
    expect(hoisted.apiMocks.getToolPermissions).toHaveBeenCalledTimes(1);
  });

  it("ignores an initial load response after unmount", async () => {
    const pending = deferred<MutationGuardConfig>();
    hoisted.apiMocks.getMutationGuard.mockReturnValueOnce(pending.promise);
    const view = render(<MutationGuardTab />);
    expect(screen.getByText("common.loading")).toBeInTheDocument();

    view.unmount();
    pending.resolve(config);
    await pending.promise;
    await Promise.resolve();

    expect(hoisted.messageMocks.error).not.toHaveBeenCalled();
  });

  it("keeps the edited draft when saving fails", async () => {
    hoisted.apiMocks.updateMutationGuard.mockRejectedValueOnce(
      new Error("write failed"),
    );
    const user = userEvent.setup();
    render(<MutationGuardTab />);
    await screen.findByText("security.mutationGuard.description");
    const denyMessage = screen.getByRole("textbox", {
      name: "security.mutationGuard.denyMessage",
    });
    await user.clear(denyMessage);
    await user.type(denyMessage, "保留这份草稿");

    await user.click(screen.getByRole("button", { name: "common.save" }));

    await screen.findByText("security.mutationGuard.saveFailed");
    expect(denyMessage).toHaveValue("保留这份草稿");
    expect(hoisted.messageMocks.error).toHaveBeenCalledWith(
      "security.mutationGuard.saveFailed",
    );
  });
});
