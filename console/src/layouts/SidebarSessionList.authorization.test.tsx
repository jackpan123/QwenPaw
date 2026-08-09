import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/common_setup";
import { useAuthorizationStore } from "@/stores/authorizationStore";
import SidebarSessionList from "./SidebarSessionList";

interface MockRowProps {
  index: number;
  style: Record<string, unknown>;
  data: unknown;
}

interface MockListProps {
  children: React.ComponentType<MockRowProps>;
  itemCount: number;
  itemData: unknown;
}

interface MockSessionItemProps {
  name: string;
  sessionId: string;
  onEdit?: (sessionId: string, name: string) => void;
  onDelete?: (sessionId: string) => void;
  onPin?: (sessionId: string) => void;
  onArchive?: (sessionId: string) => void;
}

const {
  mockHandleEditStart,
  mockHandleDelete,
  mockHandlePinToggle,
  mockHandleArchiveToggle,
} = vi.hoisted(() => ({
  mockHandleEditStart: vi.fn(),
  mockHandleDelete: vi.fn(),
  mockHandlePinToggle: vi.fn(),
  mockHandleArchiveToggle: vi.fn(),
}));

vi.mock(
  "../pages/Chat/components/ChatSessionDrawer/useSessionListData",
  () => ({
    useSessionListData: () => ({
      sortedSessions: [
        {
          id: "session-1",
          name: "Session One",
          updatedAt: new Date().toISOString(),
        },
      ],
      loading: false,
      editingSessionId: null,
      editValue: "",
      handleSessionClick: vi.fn(),
      handleEditStart: mockHandleEditStart,
      handleDelete: mockHandleDelete,
      handlePinToggle: mockHandlePinToggle,
      handleArchiveToggle: mockHandleArchiveToggle,
      handleEditChange: vi.fn(),
      handleEditSubmit: vi.fn(),
      handleEditCancel: vi.fn(),
    }),
  }),
);

vi.mock("react-window", async () => {
  const React = await import("react");
  return {
    VariableSizeList: React.forwardRef<unknown, MockListProps>((props, ref) => {
      React.useImperativeHandle(ref, () => ({ resetAfterIndex: vi.fn() }));
      const Row = props.children;
      return Array.from({ length: props.itemCount }, (_, index) => (
        <Row key={index} index={index} style={{}} data={props.itemData} />
      ));
    }),
  };
});

vi.mock("@agentscope-ai/icons", () => ({
  SparkPlusLine: () => <span>plus</span>,
  SparkDownArrowLine: () => <span>down</span>,
}));

vi.mock("../pages/Control/Channels/components", () => ({
  getChannelLabel: () => undefined,
}));

vi.mock("../components/SessionItem", () => ({
  default: ({
    name,
    sessionId,
    onEdit,
    onDelete,
    onPin,
    onArchive,
  }: MockSessionItemProps) => (
    <div>
      <span>{name}</span>
      {onEdit ? (
        <button onClick={() => onEdit(sessionId, name)}>rename</button>
      ) : null}
      {onPin ? <button onClick={() => onPin(sessionId)}>pin</button> : null}
      {onArchive ? (
        <button onClick={() => onArchive(sessionId)}>archive</button>
      ) : null}
      {onDelete ? (
        <button onClick={() => onDelete(sessionId)}>delete</button>
      ) : null}
    </div>
  ),
}));

const resizeObserver = vi.fn().mockImplementation(function (
  this: unknown,
  callback: (entries: ResizeObserverEntry[]) => void,
) {
  return {
    observe: vi.fn((target: HTMLElement) =>
      callback([
        {
          target,
          contentRect: { height: 600 },
        } as unknown as ResizeObserverEntry,
      ]),
    ),
    unobserve: vi.fn(),
    disconnect: vi.fn(),
  };
});

describe("SidebarSessionList authorization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.ResizeObserver = resizeObserver;
    Object.defineProperty(HTMLElement.prototype, "clientHeight", {
      configurable: true,
      get: () => 600,
    });
  });

  it("does not expose session mutation actions to a read-only member", () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });

    renderWithProviders(<SidebarSessionList />, {
      initialEntries: ["/chat/session-1"],
    });

    expect(screen.queryByRole("button", { name: "rename" })).toBeNull();
    expect(screen.queryByRole("button", { name: "pin" })).toBeNull();
    expect(screen.queryByRole("button", { name: "archive" })).toBeNull();
    expect(screen.queryByRole("button", { name: "delete" })).toBeNull();
  });

  it("preserves session actions when mutations are allowed", async () => {
    useAuthorizationStore.getState().set({
      authEnabled: false,
      username: null,
      roles: [],
      canMutate: true,
    });
    const user = userEvent.setup();

    renderWithProviders(<SidebarSessionList />, {
      initialEntries: ["/chat/session-1"],
    });
    await user.click(screen.getByRole("button", { name: "rename" }));
    await user.click(screen.getByRole("button", { name: "pin" }));
    await user.click(screen.getByRole("button", { name: "archive" }));
    await user.click(screen.getByRole("button", { name: "delete" }));

    expect(mockHandleEditStart).toHaveBeenCalledWith(
      "session-1",
      "Session One",
    );
    expect(mockHandlePinToggle).toHaveBeenCalledWith("session-1");
    expect(mockHandleArchiveToggle).toHaveBeenCalledWith("session-1");
    expect(mockHandleDelete).toHaveBeenCalledWith("session-1");
  });
});
