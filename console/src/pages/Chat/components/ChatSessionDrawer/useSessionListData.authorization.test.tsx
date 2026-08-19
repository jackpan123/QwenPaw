import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthorizationStore } from "@/stores/authorizationStore";
import { useSessionListData } from "./useSessionListData";
import type { ExtendedChatSession } from "./useSessionListData";

const {
  mockDeleteChat,
  mockUpdateChat,
  mockArchiveChat,
  mockUnarchiveChat,
  mockGetSessionList,
  mockContextMenuShow,
} = vi.hoisted(() => ({
  mockDeleteChat: vi.fn(),
  mockUpdateChat: vi.fn(),
  mockArchiveChat: vi.fn(),
  mockUnarchiveChat: vi.fn(),
  mockGetSessionList: vi.fn().mockResolvedValue([]),
  mockContextMenuShow: vi.fn(),
}));

vi.mock("@/api/modules/chat", () => ({
  chatApi: {
    deleteChat: mockDeleteChat,
    updateChat: mockUpdateChat,
    archiveChat: mockArchiveChat,
    unarchiveChat: mockUnarchiveChat,
  },
  sessionApi: {},
}));

vi.mock("@/pages/Control/Channels/components", () => ({
  getChannelLabel: () => undefined,
}));

vi.mock("../../sessionApi", () => ({
  default: {
    getSessionList: mockGetSessionList,
    isSessionSwitching: false,
    onSessionRemoved: vi.fn(),
  },
}));

vi.mock("@/components/ContextMenu", () => ({
  ContextMenu: ({ children }: { children: React.ReactNode }) => children,
  useContextMenu: () => ({ show: mockContextMenuShow, hide: vi.fn() }),
}));

vi.mock("@/hooks/useAppMessage", () => ({
  useAppMessage: () => ({
    message: { success: vi.fn(), error: vi.fn() },
  }),
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

const session = {
  id: "session-1",
  realId: "backend-1",
  name: "Session One",
  pinned: false,
  archived: false,
} as ExtendedChatSession;

describe("useSessionListData authorization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });
  });

  it("keeps stale mutation handlers inert for a read-only member", async () => {
    const setSessions = vi.fn();
    const { result } = renderHook(() =>
      useSessionListData([session], setSessions, {
        active: false,
        currentSessionId: undefined,
        onSessionClick: vi.fn(),
      }),
    );

    act(() => result.current.handleEditStart("session-1", "Session One"));
    await act(() => result.current.handleEditSubmit());
    await act(() => result.current.handlePinToggle("session-1"));
    await act(() => result.current.handleArchiveToggle("session-1"));
    await act(() => result.current.handleDelete("session-1"));

    expect(result.current.editingSessionId).toBeNull();
    expect(mockUpdateChat).not.toHaveBeenCalled();
    expect(mockArchiveChat).not.toHaveBeenCalled();
    expect(mockUnarchiveChat).not.toHaveBeenCalled();
    expect(mockDeleteChat).not.toHaveBeenCalled();
    expect(setSessions).not.toHaveBeenCalled();
  });

  it("leaves only the non-mutating open item in the context menu", () => {
    const { result } = renderHook(() =>
      useSessionListData([session], vi.fn(), {
        active: false,
        currentSessionId: undefined,
        onSessionClick: vi.fn(),
      }),
    );

    act(() =>
      result.current.handleItemContextMenu("session-1", {
        preventDefault: vi.fn(),
      } as unknown as React.MouseEvent),
    );

    expect(result.current.contextMenuItems.map((item) => item.key)).toEqual([
      "open",
    ]);
  });
});
