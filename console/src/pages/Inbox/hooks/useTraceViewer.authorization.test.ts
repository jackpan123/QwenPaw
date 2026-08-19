import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useAuthorizationStore } from "../../../stores/authorizationStore";
import type { PushMessage } from "../types";
import { useTraceViewer } from "./useTraceViewer";

vi.mock("../../../api", () => ({
  default: { getInboxTrace: vi.fn() },
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

describe("useTraceViewer read-only viewing", () => {
  it("opens an unread message without marking it read when no marker is provided", () => {
    const message: PushMessage = {
      id: "message-1",
      channelType: "email",
      channelName: "System",
      title: "Readable",
      content: "Content",
      sender: { userId: "default", username: "Agent" },
      createdAt: new Date(1000),
      read: false,
    };
    const { result } = renderHook(() =>
      useTraceViewer(undefined as unknown as (id: string) => void),
    );
    let thrown: unknown;

    try {
      act(() => result.current.openMessageDetail(message));
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeUndefined();
    expect(result.current.detailOpen).toBe(true);
    expect(result.current.selectedMessage).toMatchObject({
      id: "message-1",
      read: false,
    });
  });

  it("re-checks authorization before a captured message viewer marks anything read", () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });
    const markMessageAsRead = vi.fn();
    const { result } = renderHook(() => useTraceViewer(markMessageAsRead));
    const staleOpenMessageDetail = result.current.openMessageDetail;
    const message: PushMessage = {
      id: "message-1",
      channelType: "email",
      channelName: "System",
      title: "Readable",
      content: "Content",
      sender: { userId: "default", username: "Agent" },
      createdAt: new Date(1000),
      read: false,
    };

    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });
    act(() => staleOpenMessageDetail(message));

    expect(markMessageAsRead).not.toHaveBeenCalled();
    expect(result.current.selectedMessage).toMatchObject({
      id: "message-1",
      read: false,
    });
  });
});
