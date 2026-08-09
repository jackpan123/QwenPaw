import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithProviders } from "@/test/common_setup";
import { useAuthorizationStore } from "@/stores/authorizationStore";
import type { PushMessage } from "./types";
import InboxPage from "./index";

const {
  mockMarkOne,
  mockMarkAll,
  mockDeleteOne,
  mockDeleteMany,
  mockOpenMessageDetail,
  mockUseTraceViewer,
  mockSendApprovalCommand,
  mockStopChat,
  mockToggleWobble,
} = vi.hoisted(() => ({
  mockMarkOne: vi.fn(),
  mockMarkAll: vi.fn().mockResolvedValue(1),
  mockDeleteOne: vi.fn(),
  mockDeleteMany: vi.fn().mockResolvedValue(1),
  mockOpenMessageDetail: vi.fn(),
  mockUseTraceViewer: vi.fn(),
  mockSendApprovalCommand: vi.fn().mockResolvedValue(undefined),
  mockStopChat: vi.fn().mockResolvedValue(undefined),
  mockToggleWobble: vi.fn(),
}));

const pushMessage: PushMessage = {
  id: "message-1",
  channelType: "email",
  channelName: "System",
  title: "Read me",
  content: "Message body",
  sender: { userId: "default", username: "Agent" },
  createdAt: new Date(1000),
  read: false,
  metadata: { sourceType: "cron", agentId: "default" },
};
const pushMessages = [pushMessage];

let latestApprovalProps: Record<string, unknown> | null = null;

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock("react-markdown", () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("remark-gfm", () => ({ default: () => undefined }));

vi.mock("antd", () => {
  const Descriptions = ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  );
  Descriptions.Item = ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  );
  return {
    App: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    Badge: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
    Button: ({
      children,
      icon,
      loading,
      danger,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
      icon?: React.ReactNode;
      loading?: boolean;
      danger?: boolean;
    }) => {
      void loading;
      void danger;
      return (
        <button {...props}>
          {icon}
          {children}
        </button>
      );
    },
    Checkbox: ({ children }: { children?: React.ReactNode }) => (
      <label>
        <input type="checkbox" />
        {children}
      </label>
    ),
    Collapse: () => null,
    Descriptions,
    Empty: ({ description }: { description: React.ReactNode }) => (
      <div>{description}</div>
    ),
    Modal: ({
      open,
      children,
    }: {
      open: boolean;
      children: React.ReactNode;
    }) => (open ? <div>{children}</div> : null),
    Pagination: () => <div>pagination</div>,
    Popconfirm: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    Select: (props: { placeholder?: string }) => <div>{props.placeholder}</div>,
    Spin: () => <div>loading</div>,
    Tag: ({ children }: { children: React.ReactNode }) => (
      <span>{children}</span>
    ),
    Tabs: ({
      activeKey,
      onChange,
      items,
      tabBarExtraContent,
    }: {
      activeKey: string;
      onChange: (key: string) => void;
      items: Array<{
        key: string;
        label: React.ReactNode;
        children: React.ReactNode;
      }>;
      tabBarExtraContent?: React.ReactNode;
    }) => (
      <div>
        {items.map((item) => (
          <button key={item.key} onClick={() => onChange(item.key)}>
            {item.label}
          </button>
        ))}
        {tabBarExtraContent}
        {items.find((item) => item.key === activeKey)?.children}
      </div>
    ),
    Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    message: {
      success: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      warning: vi.fn(),
    },
  };
});

vi.mock("../../contexts/ApprovalContext", () => ({
  useApprovalContext: () => ({
    approvals: [
      {
        request_id: "approval-1",
        agent_id: "default",
        owner_agent_id: "default",
        tool_name: "shell",
        tool_source: "builtin",
        severity: "high",
        findings_count: 1,
        findings_summary: "risk",
        tool_params: {},
        created_at: Date.now() / 1000,
        timeout_seconds: 60,
        session_id: "session-1",
        root_session_id: "session-1",
      },
    ],
    setApprovals: vi.fn(),
  }),
}));

vi.mock("./hooks/useInboxData", () => ({
  useInboxData: () => ({
    summary: {
      approvals: { total: 1, urgent: 1 },
      pushMessages: { total: 1, unread: 1 },
      harvests: { total: 0, active: 0 },
    },
    pushMessages,
    markMessageAsRead: mockMarkOne,
    markAllMessagesAsRead: mockMarkAll,
    deleteMessage: mockDeleteOne,
    deleteMessages: mockDeleteMany,
  }),
}));

vi.mock("./hooks/useTraceViewer", () => ({
  useTraceViewer: (markAsRead: unknown) => {
    mockUseTraceViewer(markAsRead);
    return {
      detailOpen: false,
      selectedMessage: null,
      traceLoading: false,
      traceEvents: [],
      expandedTraceMap: {},
      traceContainerRef: { current: null },
      openMessageDetail: mockOpenMessageDetail,
      closeDetail: vi.fn(),
      toggleTracePanel: vi.fn(),
      copyTraceBlock: vi.fn(),
      handleTraceScroll: vi.fn(),
    };
  },
}));

vi.mock("./components", () => ({
  PushMessageCard: (props: {
    message: PushMessage;
    onView: (id: string) => void;
    onDelete?: (id: string) => void;
    onMarkAsRead?: (id: string) => void;
    onSelectChange?: (id: string, checked: boolean) => void;
  }) => (
    <div data-testid="push-message-card">
      <button onClick={() => props.onView(props.message.id)}>
        view-message
      </button>
      {props.onDelete ? <button>delete-message</button> : null}
      {props.onMarkAsRead ? <button>mark-message-read</button> : null}
      {props.onSelectChange ? <button>select-message</button> : null}
    </div>
  ),
}));

vi.mock("../../components/ApprovalCard/ApprovalCard", () => ({
  ApprovalCard: (props: Record<string, unknown>) => {
    latestApprovalProps = props;
    return (
      <div data-testid="approval-card">
        {props.onApprove ? <button>approve-request</button> : null}
        {props.onDeny ? <button>deny-request</button> : null}
        {props.onAcknowledge ? <button>acknowledge-request</button> : null}
        {props.onCancel ? <button>cancel-request</button> : null}
      </div>
    );
  },
}));

vi.mock("../../hooks/useInboxWobble", () => ({
  useInboxWobble: () => [true, mockToggleWobble],
}));

vi.mock("../../api/modules/commands", () => ({
  commandsApi: { sendApprovalCommand: mockSendApprovalCommand },
}));

vi.mock("../../api/modules/chat", () => ({
  chatApi: { stopChat: mockStopChat },
}));

vi.mock("../Chat/sessionApi", () => ({
  default: { getRealIdForSession: vi.fn((id: string) => id) },
}));

vi.mock("../../stores/agentStore", () => ({
  useAgentStore: vi.fn((selector: (state: { agents: never[] }) => unknown) =>
    selector({ agents: [] }),
  ),
}));

vi.mock("@/components/PageHeader", () => ({
  PageHeader: () => <div>inbox-header</div>,
}));

describe("InboxPage authorization", () => {
  beforeEach(() => {
    localStorage.clear();
    latestApprovalProps = null;
    vi.clearAllMocks();
  });

  it("keeps browsing and message viewing but omits every mutation entry for read-only users", async () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });
    const user = userEvent.setup();

    renderWithProviders(<InboxPage />, { initialEntries: ["/inbox"] });

    expect(screen.getByTestId("push-message-card")).toBeInTheDocument();
    expect(screen.queryByText("inbox.batchOperation")).not.toBeInTheDocument();
    expect(screen.queryByText("inbox.markAllRead")).not.toBeInTheDocument();
    expect(screen.queryByText("delete-message")).not.toBeInTheDocument();
    expect(screen.queryByText("mark-message-read")).not.toBeInTheDocument();
    expect(mockUseTraceViewer).toHaveBeenLastCalledWith(undefined);

    await user.click(screen.getByRole("button", { name: "view-message" }));
    expect(mockOpenMessageDetail).toHaveBeenCalledWith(pushMessage);

    await user.click(screen.getByText("inbox.tabApprovals"));
    expect(await screen.findByTestId("approval-card")).toBeInTheDocument();
    expect(latestApprovalProps).not.toHaveProperty("onApprove");
    expect(latestApprovalProps).not.toHaveProperty("onDeny");
    expect(latestApprovalProps).not.toHaveProperty("onAcknowledge");
    expect(latestApprovalProps).not.toHaveProperty("onCancel");
    expect(mockMarkOne).not.toHaveBeenCalled();
  });

  it("preserves mutation entries and approval callbacks for admins", async () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });
    const user = userEvent.setup();

    renderWithProviders(<InboxPage />, { initialEntries: ["/inbox"] });

    expect(screen.getByText("inbox.batchOperation")).toBeInTheDocument();
    expect(screen.getByText("inbox.markAllRead")).toBeInTheDocument();
    expect(screen.getByText("delete-message")).toBeInTheDocument();
    expect(mockUseTraceViewer).toHaveBeenLastCalledWith(mockMarkOne);

    await user.click(screen.getByText("inbox.tabApprovals"));
    expect(latestApprovalProps).toHaveProperty("onApprove");
    expect(latestApprovalProps).toHaveProperty("onDeny");
    expect(latestApprovalProps).toHaveProperty("onAcknowledge");
    expect(latestApprovalProps).toHaveProperty("onCancel");
  });

  it("makes a captured approval callback inert after authorization is downgraded", async () => {
    useAuthorizationStore.getState().set({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });
    const user = userEvent.setup();
    renderWithProviders(<InboxPage />, { initialEntries: ["/inbox"] });
    await user.click(screen.getByText("inbox.tabApprovals"));
    const staleApprove = latestApprovalProps?.onApprove as
      | ((requestId: string, scope?: "exact" | "similar") => Promise<void>)
      | undefined;
    expect(staleApprove).toBeTypeOf("function");

    act(() => {
      useAuthorizationStore.getState().set({
        authEnabled: true,
        username: "member-user",
        roles: ["member"],
        canMutate: false,
      });
    });
    await staleApprove?.("approval-1", "exact");

    expect(mockSendApprovalCommand).not.toHaveBeenCalled();
  });
});
