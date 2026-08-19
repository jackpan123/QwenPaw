import { describe, expect, it } from "vitest";
import { filterMenuItemsForAuthorization } from "./adapter";
import type { MenuItem, ResolvedRoute } from "../../plugins/registry/types";

const Component = () => null;

const routes: ResolvedRoute[] = [
  {
    id: "core.read",
    path: "/read",
    source: "core",
    capability: "read",
    Component,
  },
  {
    id: "core.mutate",
    path: "/mutate",
    source: "core",
    capability: "mutate",
    Component,
  },
  {
    id: "plugin.implicit",
    path: "/plugin",
    source: "plugin",
    Component,
  },
];

type MenuItemWithChildren = MenuItem & { __children?: MenuItem[] };

describe("filterMenuItemsForAuthorization", () => {
  it("keeps every menu item for a user who can mutate", () => {
    const items: MenuItem[] = [
      { id: "implicit", label: "Implicit", route: "plugin.implicit" },
      { id: "mutate", label: "Mutate", route: "core.mutate" },
    ];

    expect(
      filterMenuItemsForAuthorization(items, routes, true).map(
        (item) => item.id,
      ),
    ).toEqual(["implicit", "mutate"]);
  });

  it("inherits authorization from a referenced route", () => {
    const items: MenuItem[] = [
      { id: "read", label: "Read", route: "core.read" },
      { id: "mutate", label: "Mutate", route: "core.mutate" },
      { id: "implicit", label: "Implicit", route: "plugin.implicit" },
    ];

    expect(
      filterMenuItemsForAuthorization(items, routes, false).map(
        (item) => item.id,
      ),
    ).toEqual(["read"]);
  });

  it("requires an explicit read capability for a menu item without a route", () => {
    const items: MenuItem[] = [
      {
        id: "read-link",
        label: "Read link",
        href: "https://example.com/read",
        capability: "read",
      },
      {
        id: "implicit-link",
        label: "Implicit link",
        href: "https://example.com/implicit",
      },
    ];

    expect(
      filterMenuItemsForAuthorization(items, routes, false).map(
        (item) => item.id,
      ),
    ).toEqual(["read-link"]);
  });

  it("removes empty groups after filtering restricted children", () => {
    const items: MenuItemWithChildren[] = [
      {
        id: "read-group",
        label: "Read group",
        isGroup: true,
        capability: "read",
        __children: [
          { id: "read", label: "Read", route: "core.read" },
          { id: "mutate", label: "Mutate", route: "core.mutate" },
        ],
      },
      {
        id: "empty-group",
        label: "Empty group",
        isGroup: true,
        capability: "read",
        __children: [
          { id: "implicit", label: "Implicit", route: "plugin.implicit" },
        ],
      },
    ];

    const filtered = filterMenuItemsForAuthorization(items, routes, false);

    expect(filtered.map((item) => item.id)).toEqual(["read-group"]);
    expect(
      (filtered[0] as MenuItemWithChildren).__children?.map((item) => item.id),
    ).toEqual(["read"]);
  });

  it("removes a readable group that has no children", () => {
    const items: MenuItem[] = [
      {
        id: "empty-group",
        label: "Empty group",
        isGroup: true,
        capability: "read",
      },
    ];

    expect(filterMenuItemsForAuthorization(items, routes, false)).toEqual([]);
  });
});
