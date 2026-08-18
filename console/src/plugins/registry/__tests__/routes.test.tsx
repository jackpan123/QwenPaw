/**
 * routes.test.tsx — RouteRegistry behaviour.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { filterRoutesForAuthorization, routeRegistry } from "../store";
import { auditStore } from "../audit";

const Base = () => <div data-testid="base">base</div>;
const PluginPage = () => <div data-testid="plugin">plugin</div>;

function getRouteComponent(id: string) {
  const route = routeRegistry.snapshot().find((item) => item.id === id);
  if (!route) throw new Error(`Expected route ${id} to be registered`);
  return route.Component;
}

beforeEach(() => {
  routeRegistry.__resetForTests();
  auditStore.clear();
});

describe("routeRegistry.add", () => {
  it("registers and snapshots", () => {
    routeRegistry.add("core", { id: "r1", path: "/r1", component: Base });
    const snap = routeRegistry.snapshot();
    expect(snap.map((r) => r.id)).toContain("r1");
  });

  it("rejects duplicate id with conflict audit", () => {
    routeRegistry.add("core", { id: "r1", path: "/a", component: Base });
    routeRegistry.add("p1", { id: "r1", path: "/b", component: Base });
    expect(routeRegistry.snapshot().filter((r) => r.id === "r1")).toHaveLength(
      1,
    );
    expect(
      auditStore.overrides().some((r) => r.kind === "route.conflict"),
    ).toBe(true);
  });

  it("rejects duplicate path with conflict audit", () => {
    routeRegistry.add("core", { id: "r1", path: "/x", component: Base });
    routeRegistry.add("p1", { id: "r2", path: "/x", component: Base });
    expect(routeRegistry.snapshot().map((r) => r.path)).toEqual(["/x"]);
    expect(
      auditStore
        .overrides()
        .some((r) => r.kind === "route.conflict" && r.targetId === "r2"),
    ).toBe(true);
  });

  it("preserves the declared route capability in snapshots", () => {
    routeRegistry.add("core", {
      id: "read-route",
      path: "/read",
      component: Base,
      capability: "read",
    });

    expect(routeRegistry.snapshot()[0].capability).toBe("read");
  });

  it("leaves a plugin route without a declared capability undefined", () => {
    routeRegistry.add("plugin", {
      id: "implicit-plugin-route",
      path: "/plugin",
      component: PluginPage,
    });

    expect(routeRegistry.snapshot()[0].capability).toBeUndefined();
  });
});

describe("routeRegistry.replace", () => {
  it("LIFO winner; rendered Component reflects override", () => {
    routeRegistry.add("core", { id: "p", path: "/p", component: Base });
    routeRegistry.replace("p1", "p", PluginPage);
    const Comp = getRouteComponent("p");
    expect(Comp).toBeTruthy();
    const { getByTestId } = render(<Comp />);
    expect(getByTestId("plugin")).toBeInTheDocument();
  });

  it("dispose restores base", () => {
    routeRegistry.add("core", { id: "p", path: "/p", component: Base });
    const d = routeRegistry.replace("p1", "p", PluginPage);
    d.dispose();
    const Comp = getRouteComponent("p");
    const { getByTestId } = render(<Comp />);
    expect(getByTestId("base")).toBeInTheDocument();
  });

  it("cannot elevate the base route capability", () => {
    routeRegistry.add("core", {
      id: "p",
      path: "/p",
      component: Base,
      capability: "mutate",
    });
    // @ts-expect-error replacements intentionally accept components only
    routeRegistry.replace("p1", "p", PluginPage, { capability: "read" });

    expect(routeRegistry.snapshot()[0].capability).toBe("mutate");
  });
});

describe("routeRegistry.wrap — onion composition", () => {
  it("later wrap is outermost", () => {
    routeRegistry.add("core", { id: "p", path: "/p", component: Base });
    routeRegistry.wrap("p1", "p", (Inner) => () => (
      <div data-testid="outer-p1">
        <Inner />
      </div>
    ));
    routeRegistry.wrap("p2", "p", (Inner) => () => (
      <div data-testid="outer-p2">
        <Inner />
      </div>
    ));
    const Comp = getRouteComponent("p");
    const { getByTestId, container } = render(<Comp />);
    // p2 should wrap p1 (p2 is last registered → outermost)
    const outerP2 = getByTestId("outer-p2");
    const outerP1 = getByTestId("outer-p1");
    expect(outerP2.contains(outerP1)).toBe(true);
    expect(container.querySelector("[data-testid='base']")).toBeInTheDocument();
  });

  it("replace + wrap: wrap sees the override, not the base", () => {
    routeRegistry.add("core", { id: "p", path: "/p", component: Base });
    routeRegistry.replace("p1", "p", PluginPage);
    routeRegistry.wrap("p2", "p", (Inner) => () => (
      <div data-testid="wrap">
        <Inner />
      </div>
    ));
    const Comp = getRouteComponent("p");
    const { queryByTestId } = render(<Comp />);
    expect(queryByTestId("wrap")).toBeInTheDocument();
    expect(queryByTestId("plugin")).toBeInTheDocument();
    expect(queryByTestId("base")).not.toBeInTheDocument();
  });

  it("disposing wrap removes it from chain", () => {
    routeRegistry.add("core", { id: "p", path: "/p", component: Base });
    const d = routeRegistry.wrap("p1", "p", (Inner) => () => (
      <div data-testid="wrap">
        <Inner />
      </div>
    ));
    d.dispose();
    const Comp = getRouteComponent("p");
    const { queryByTestId } = render(<Comp />);
    expect(queryByTestId("wrap")).not.toBeInTheDocument();
    expect(queryByTestId("base")).toBeInTheDocument();
  });

  it("cannot elevate the base route capability", () => {
    routeRegistry.add("core", {
      id: "p",
      path: "/p",
      component: Base,
      capability: "mutate",
    });

    // @ts-expect-error wrappers intentionally accept component transforms only
    routeRegistry.wrap("p1", "p", (Inner) => Inner, {
      capability: "read",
    });

    expect(routeRegistry.snapshot()[0].capability).toBe("mutate");
  });
});

describe("filterRoutesForAuthorization", () => {
  it("keeps every route when mutation is authorized", () => {
    routeRegistry.add("core", {
      id: "read",
      path: "/read",
      component: Base,
      capability: "read",
    });
    routeRegistry.add("core", {
      id: "mutate",
      path: "/mutate",
      component: Base,
      capability: "mutate",
    });

    expect(
      filterRoutesForAuthorization(routeRegistry.snapshot(), true).map(
        (route) => route.id,
      ),
    ).toEqual(["read", "mutate"]);
  });

  it("keeps only explicit read routes for a read-only member", () => {
    routeRegistry.add("core", {
      id: "read",
      path: "/read",
      component: Base,
      capability: "read",
    });
    routeRegistry.add("plugin", {
      id: "implicit-plugin-route",
      path: "/plugin",
      component: PluginPage,
    });
    routeRegistry.add("core", {
      id: "mutate",
      path: "/mutate",
      component: Base,
      capability: "mutate",
    });

    expect(
      filterRoutesForAuthorization(routeRegistry.snapshot(), false).map(
        (route) => route.id,
      ),
    ).toEqual(["read"]);
  });
});

describe("routeRegistry.removeBySource", () => {
  it("removes base, replacement and wrapper registrations", () => {
    routeRegistry.add("plugin", {
      id: "plugin-page",
      path: "/plugin",
      component: PluginPage,
    });
    routeRegistry.add("core", { id: "core-page", path: "/", component: Base });
    routeRegistry.replace("plugin", "core-page", PluginPage);
    routeRegistry.wrap("plugin", "core-page", (Inner) => () => (
      <div data-testid="wrap">
        <Inner />
      </div>
    ));

    routeRegistry.removeBySource("plugin");

    expect(routeRegistry.snapshot().map((route) => route.id)).toEqual([
      "core-page",
    ]);
    const Component = routeRegistry.snapshot()[0].Component;
    const { queryByTestId } = render(<Component />);
    expect(queryByTestId("base")).toBeInTheDocument();
    expect(queryByTestId("plugin")).not.toBeInTheDocument();
    expect(queryByTestId("wrap")).not.toBeInTheDocument();
  });
});
