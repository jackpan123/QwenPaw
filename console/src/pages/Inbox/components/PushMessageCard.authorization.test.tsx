import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { renderWithProviders } from "@/test/common_setup";
import type { PushMessage } from "../types";
import { PushMessageCard } from "./PushMessageCard";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

const message: PushMessage = {
  id: "message-1",
  channelType: "email",
  channelName: "System",
  title: "Readable title",
  content: "Readable content",
  sender: { userId: "default", username: "Agent" },
  createdAt: new Date(1000),
  read: false,
};

describe("PushMessageCard read-only rendering", () => {
  it("keeps the card viewable without rendering a delete button", () => {
    const onView = vi.fn();
    const { container } = renderWithProviders(
      <PushMessageCard message={message} onView={onView} />,
    );

    expect(screen.getByText("Readable content")).toBeInTheDocument();
    expect(container.querySelector("button")).toBeNull();

    fireEvent.click(screen.getByText("Readable content"));
    expect(onView).toHaveBeenCalledWith("message-1");
  });
});
