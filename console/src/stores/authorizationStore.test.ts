import { beforeEach, describe, expect, it } from "vitest";
import { useAuthorizationStore } from "./authorizationStore";

describe("authorizationStore", () => {
  beforeEach(() => useAuthorizationStore.getState().reset());

  it("defaults to fail-closed authorization", () => {
    expect(useAuthorizationStore.getState()).toMatchObject({
      username: null,
      roles: [],
      canMutate: false,
    });
  });

  it("stores a NocoBase member as read-only", () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });

    expect(useAuthorizationStore.getState()).toMatchObject({
      authEnabled: true,
      username: "member-user",
      roles: ["member"],
      canMutate: false,
    });
  });

  it("stores an administrator as mutable", () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });

    expect(useAuthorizationStore.getState().canMutate).toBe(true);
  });

  it("keeps mutation available when authentication is disabled", () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: false,
      username: null,
      roles: [],
      canMutate: true,
    });

    expect(useAuthorizationStore.getState()).toMatchObject({
      authEnabled: false,
      canMutate: true,
    });
  });

  it("reset discards stale privileges and fails closed", () => {
    useAuthorizationStore.getState().setAuthorization({
      authEnabled: true,
      username: "admin-user",
      roles: ["admin"],
      canMutate: true,
    });

    useAuthorizationStore.getState().reset();

    expect(useAuthorizationStore.getState()).toMatchObject({
      username: null,
      roles: [],
      canMutate: false,
    });
  });
});
