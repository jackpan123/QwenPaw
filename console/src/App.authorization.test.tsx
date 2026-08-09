import React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { useAuthorizationStore } from "./stores/authorizationStore";

const mocks = vi.hoisted(() => ({
  getStatus: vi.fn(),
  verify: vi.fn(),
  getApiToken: vi.fn(),
  clearAuthToken: vi.fn(),
  fetchUploadLimit: vi.fn(),
}));

vi.mock("@agentscope-ai/design", () => ({
  ConfigProvider: ({ children }: { children: React.ReactNode }) => children,
  bailianDarkTheme: {},
  bailianTheme: {},
}));

vi.mock("./api/modules/auth", () => ({
  authApi: {
    getStatus: mocks.getStatus,
    verify: mocks.verify,
  },
}));

vi.mock("./api/config", () => ({
  getApiUrl: (path: string) => `/api${path}`,
  getApiToken: mocks.getApiToken,
  clearAuthToken: mocks.clearAuthToken,
}));

vi.mock("./layouts/MainLayout", () => ({
  default: () => <div data-testid="main-layout" />,
}));

vi.mock("./utils/lazyWithRetry", () => ({
  lazyImportWithRetry: () => () => <div data-testid="login-page" />,
}));

vi.mock("./contexts/ThemeContext", () => ({
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
  useTheme: () => ({ isDark: false }),
}));

vi.mock("./plugins/PluginContext", () => ({
  PluginProvider: ({ children }: { children: React.ReactNode }) => children,
  usePlugins: () => ({ loading: false }),
}));

vi.mock("./contexts/ApprovalContext", () => ({
  ApprovalProvider: ({ children }: { children: React.ReactNode }) => children,
}));

vi.mock("./contexts/DesktopUpdateContext", () => ({
  DesktopUpdateProvider: ({ children }: { children: React.ReactNode }) =>
    children,
}));

vi.mock("./components/UpdateTakeoverPage", () => ({
  UpdateTakeoverGate: ({ children }: { children: React.ReactNode }) => children,
}));

vi.mock("./tauri/CloseWindowPrompt", () => ({ default: () => null }));
vi.mock("./utils/openExternalLink", () => ({
  isDesktopTauriRuntime: () => false,
}));
vi.mock("./utils/interceptBlankLinkClicks", () => ({
  interceptBlankLinkClicks: vi.fn(),
}));
vi.mock("./api/modules/language", () => ({
  languageApi: { getLanguage: vi.fn().mockResolvedValue({ language: "en" }) },
}));
vi.mock("./stores/uploadLimitStore", () => ({
  useUploadLimitStore: {
    getState: () => ({ fetch: mocks.fetchUploadLimit }),
  },
}));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    i18n: {
      language: "en",
      resolvedLanguage: "en",
      changeLanguage: vi.fn(),
      on: vi.fn(),
      off: vi.fn(),
    },
  }),
}));

describe("AuthGuard authorization state", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    useAuthorizationStore.getState().reset();
    mocks.getApiToken.mockReturnValue("");
    window.history.replaceState({}, "", "/chat");
  });

  afterEach(cleanup);

  it("allows local mode and explicitly enables mutation when auth is disabled", async () => {
    mocks.getStatus.mockResolvedValue({ enabled: false });

    render(<App />);

    expect(await screen.findByTestId("main-layout")).toBeInTheDocument();
    expect(useAuthorizationStore.getState()).toMatchObject({
      authEnabled: false,
      username: null,
      roles: [],
      canMutate: true,
    });
  });

  it("keeps auth-enabled users fail-closed while redirecting a missing token", async () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: false,
      username: "stale-admin",
      roles: ["admin"],
      canMutate: true,
    });
    mocks.getStatus.mockResolvedValue({ enabled: true });

    render(<App />);

    expect(await screen.findByTestId("login-page")).toBeInTheDocument();
    expect(useAuthorizationStore.getState()).toMatchObject({
      authEnabled: true,
      username: null,
      roles: [],
      canMutate: false,
    });
    expect(mocks.verify).not.toHaveBeenCalled();
  });

  it("stores only authorization claims returned by verify", async () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: true,
      username: "stale-admin",
      roles: ["admin"],
      canMutate: true,
    });
    localStorage.setItem("roles", JSON.stringify(["root"]));
    window.history.replaceState({}, "", "/chat?role=admin");
    mocks.getStatus.mockResolvedValue({ enabled: true });
    mocks.getApiToken.mockReturnValue("token");
    mocks.verify.mockResolvedValue({
      valid: true,
      username: "server-member",
      roles: ["member"],
      can_mutate: false,
    });

    render(<App />);

    expect(await screen.findByTestId("main-layout")).toBeInTheDocument();
    expect(mocks.verify).toHaveBeenCalledOnce();
    expect(useAuthorizationStore.getState()).toMatchObject({
      authEnabled: true,
      username: "server-member",
      roles: ["member"],
      canMutate: false,
    });
  });

  it("clears an invalid token and resets stale authorization", async () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: true,
      username: "stale-admin",
      roles: ["admin"],
      canMutate: true,
    });
    mocks.getStatus.mockResolvedValue({ enabled: true });
    mocks.getApiToken.mockReturnValue("expired-token");
    mocks.verify.mockRejectedValue(new Error("Invalid or expired token"));

    render(<App />);

    expect(await screen.findByTestId("login-page")).toBeInTheDocument();
    expect(mocks.clearAuthToken).toHaveBeenCalledOnce();
    expect(useAuthorizationStore.getState()).toMatchObject({
      username: null,
      roles: [],
      canMutate: false,
    });
  });

  it("fails closed when the auth status cannot be determined", async () => {
    mocks.getStatus.mockRejectedValue(new Error("offline"));

    render(<App />);

    expect(await screen.findByTestId("login-page")).toBeInTheDocument();
    expect(screen.queryByTestId("main-layout")).not.toBeInTheDocument();
    await waitFor(() =>
      expect(useAuthorizationStore.getState()).toMatchObject({
        authEnabled: true,
        username: null,
        roles: [],
        canMutate: false,
      }),
    );
    expect(mocks.clearAuthToken).not.toHaveBeenCalled();
  });
});
