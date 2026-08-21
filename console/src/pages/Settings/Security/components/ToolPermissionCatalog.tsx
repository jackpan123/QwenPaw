import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Tag } from "@agentscope-ai/design";
import { Table } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import api from "../../../../api";
import type {
  ToolPermissionEffect,
  ToolPermissionInfo,
} from "../../../../api/modules/security";
import { useAgentStore } from "../../../../stores/agentStore";
import styles from "../index.module.less";

interface ToolPermissionCatalogProps {
  refreshToken: number;
}

const effectPresentation: Record<
  ToolPermissionEffect,
  { color: string; key: string }
> = {
  read: { color: "green", key: "read" },
  mutate: { color: "orange", key: "mutate" },
  external_side_effect: {
    color: "volcano",
    key: "externalSideEffect",
  },
  unknown: { color: "gold", key: "unknown" },
  chat_infrastructure: {
    color: "blue",
    key: "chatInfrastructure",
  },
};

// eslint-disable-next-line react-refresh/only-export-components
export function useRequestGenerationGuard() {
  const mountedRef = useRef(false);
  const generationRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
    };
  }, []);

  const begin = useCallback(() => ++generationRef.current, []);
  const isCurrent = useCallback(
    (generation: number) =>
      mountedRef.current && generation === generationRef.current,
    [],
  );

  return { begin, isCurrent };
}

export function ToolPermissionCatalog({
  refreshToken,
}: ToolPermissionCatalogProps) {
  const { t } = useTranslation();
  const selectedAgent = useAgentStore((state) => state.selectedAgent);
  const [items, setItems] = useState<ToolPermissionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const { begin, isCurrent } = useRequestGenerationGuard();

  const load = useCallback(async () => {
    const generation = begin();
    setLoading(true);
    setError(false);

    try {
      const loaded = await api.getToolPermissions();
      if (!isCurrent(generation)) {
        return;
      }
      setItems(loaded);
    } catch {
      if (isCurrent(generation)) {
        setError(true);
      }
    } finally {
      if (isCurrent(generation)) {
        setLoading(false);
      }
    }
  }, [begin, isCurrent]);

  useEffect(() => {
    void load();
  }, [load, refreshToken, selectedAgent]);

  const columns: ColumnsType<ToolPermissionInfo> = [
    {
      title: t("security.mutationGuard.catalog.toolName"),
      dataIndex: "name",
      key: "name",
      render: (name: string) => (
        <code
          className={styles.toolPermissionName}
          data-testid="tool-permission-name"
        >
          {name}
        </code>
      ),
    },
    {
      title: t("security.mutationGuard.catalog.classification"),
      dataIndex: "effect",
      key: "effect",
      render: (effect: ToolPermissionEffect) => {
        const presentation = effectPresentation[effect];
        return (
          <Tag color={presentation.color}>
            {t(`security.mutationGuard.catalog.effects.${presentation.key}`)}
          </Tag>
        );
      },
    },
    {
      title: t("security.mutationGuard.catalog.normalAccount"),
      dataIndex: "allowed_for_member",
      key: "allowed_for_member",
      render: (allowedForMember: boolean) => (
        <Tag color={allowedForMember ? "green" : "red"}>
          {t(
            allowedForMember
              ? "security.mutationGuard.catalog.allowed"
              : "security.mutationGuard.catalog.denied",
          )}
        </Tag>
      ),
    },
  ];

  const sortedItems = [...items].sort((left, right) =>
    left.name.localeCompare(right.name),
  );

  return (
    <section className={styles.toolPermissionCatalog}>
      <h3>{t("security.mutationGuard.catalog.title")}</h3>
      <p>{t("security.mutationGuard.catalog.description")}</p>
      {error ? (
        <div className={styles.toolPermissionState}>
          <span role="alert">
            {t("security.mutationGuard.catalog.loadFailed")}
          </span>
          <Button onClick={() => void load()}>
            {t("security.mutationGuard.catalog.retry")}
          </Button>
        </div>
      ) : (
        <Table<ToolPermissionInfo>
          columns={columns}
          dataSource={sortedItems}
          loading={loading}
          locale={{ emptyText: t("security.mutationGuard.catalog.empty") }}
          pagination={{
            pageSize: 20,
            showSizeChanger: false,
            hideOnSinglePage: true,
          }}
          rowKey="name"
          size="small"
        />
      )}
    </section>
  );
}
