import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/common_setup";
import { useAuthorizationStore } from "@/stores/authorizationStore";
import MainLayout from "./index";

const ReadPage = () => <div>read-page</div>;
const MutatePage = () => <div>mutate-page</div>;
const ImplicitPluginPage = () => <div>implicit-plugin-page</div>;

vi.mock("../../plugins/registry/hooks", () => ({
  useRoutes: () => [
    {
      id: "core.chat",
      path: "/chat/*",
      source: "core",
      capability: "read",
      Component: ReadPage,
    },
    {
      id: "core.settings",
      path: "/settings",
      source: "core",
      capability: "mutate",
      Component: MutatePage,
    },
    {
      id: "plugin.implicit",
      path: "/plugin-page",
      source: "plugin",
      Component: ImplicitPluginPage,
    },
  ],
}));

vi.mock("../Sidebar", () => ({ default: () => null }));
vi.mock("../Header", () => ({ default: () => null }));
vi.mock("../../components/ConsolePollService", () => ({ default: () => null }));
vi.mock("../../components/AgentStatusPollingController", () => ({
  AgentStatusPollingController: () => null,
}));
vi.mock("../../components/ChunkErrorBoundary", () => ({
  ChunkErrorBoundary: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock("../../stores/useSyncCodingMode", () => ({
  useSyncCodingMode: () => undefined,
}));
vi.mock("../../plugins/registry/Slot", () => ({ Slot: () => null }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

describe("MainLayout authorization", () => {
  beforeEach(() => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });
  });

  it("redirects a read-only member from a direct mutate URL to chat", async () => {
    renderWithProviders(<MainLayout />, { initialEntries: ["/settings"] });

    expect(await screen.findByText("read-page")).toBeInTheDocument();
    expect(screen.queryByText("mutate-page")).not.toBeInTheDocument();
  });

  it("still renders an explicitly readable route", async () => {
    renderWithProviders(<MainLayout />, { initialEntries: ["/chat"] });

    expect(await screen.findByText("read-page")).toBeInTheDocument();
  });

  it("redirects a read-only member from an implicit plugin route", async () => {
    renderWithProviders(<MainLayout />, {
      initialEntries: ["/plugin-page"],
    });

    expect(await screen.findByText("read-page")).toBeInTheDocument();
    expect(screen.queryByText("implicit-plugin-page")).not.toBeInTheDocument();
  });

  it("keeps mutate and implicit plugin routes for an authorized user", async () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });

    const { unmount } = renderWithProviders(<MainLayout />, {
      initialEntries: ["/settings"],
    });
    expect(await screen.findByText("mutate-page")).toBeInTheDocument();
    unmount();

    renderWithProviders(<MainLayout />, {
      initialEntries: ["/plugin-page"],
    });
    expect(await screen.findByText("implicit-plugin-page")).toBeInTheDocument();
  });

  it("keeps the existing empty result for an authorized user's unknown URL", () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });

    renderWithProviders(<MainLayout />, {
      initialEntries: ["/unknown"],
    });

    expect(screen.queryByText("read-page")).not.toBeInTheDocument();
  });
});
