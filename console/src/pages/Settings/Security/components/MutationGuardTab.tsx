import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Input, InputNumber, Switch, Tag } from "@agentscope-ai/design";
import { useTranslation } from "react-i18next";
import api from "../../../../api";
import type { MutationGuardConfig } from "../../../../api/modules/security";
import { useAppMessage } from "../../../../hooks/useAppMessage";
import styles from "../index.module.less";

export function MutationGuardTab() {
  const { t } = useTranslation();
  const { message } = useAppMessage();
  const [draft, setDraft] = useState<MutationGuardConfig | null>(null);
  const [roleInput, setRoleInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeoutValue, setTimeoutValue] = useState<number | null>(null);
  const [timeoutInvalid, setTimeoutInvalid] = useState(false);
  const mountedRef = useRef(false);
  const loadGenerationRef = useRef(0);
  const saveGenerationRef = useRef(0);
  const savingRef = useRef(false);
  const draftRevisionRef = useRef(0);

  const load = useCallback(async () => {
    const generation = ++loadGenerationRef.current;
    setLoading(true);
    setError(null);
    try {
      const loaded = await api.getMutationGuard();
      if (!mountedRef.current || generation !== loadGenerationRef.current) {
        return;
      }
      setDraft(loaded);
      setTimeoutValue(loaded.classifier_timeout_seconds);
      setTimeoutInvalid(false);
      draftRevisionRef.current += 1;
    } catch {
      if (mountedRef.current && generation === loadGenerationRef.current) {
        setError("security.mutationGuard.loadFailed");
      }
    } finally {
      if (mountedRef.current && generation === loadGenerationRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void load();
    return () => {
      mountedRef.current = false;
      loadGenerationRef.current += 1;
      saveGenerationRef.current += 1;
      savingRef.current = false;
    };
  }, [load]);

  const updateDraft = useCallback((updates: Partial<MutationGuardConfig>) => {
    draftRevisionRef.current += 1;
    setDraft((current) => (current ? { ...current, ...updates } : current));
  }, []);

  const addRole = useCallback(() => {
    if (savingRef.current) return;
    const role = roleInput.trim().toLocaleLowerCase();
    if (!role || !draft) return;
    if (!draft.privileged_roles.includes(role)) {
      updateDraft({
        privileged_roles: [...draft.privileged_roles, role],
      });
    }
    setRoleInput("");
  }, [draft, roleInput, updateDraft]);

  const removeRole = useCallback(
    (role: string) => {
      if (!draft || savingRef.current) return;
      updateDraft({
        privileged_roles: draft.privileged_roles.filter(
          (item) => item !== role,
        ),
      });
    },
    [draft, updateDraft],
  );

  const save = useCallback(async () => {
    if (
      !draft ||
      draft.privileged_roles.length === 0 ||
      timeoutInvalid ||
      savingRef.current
    ) {
      return;
    }
    const snapshot: MutationGuardConfig = {
      ...draft,
      privileged_roles: [...draft.privileged_roles],
    };
    const revision = draftRevisionRef.current;
    const generation = ++saveGenerationRef.current;
    savingRef.current = true;
    setSaving(true);
    setError(null);
    try {
      const saved = await api.updateMutationGuard(snapshot);
      if (!mountedRef.current || generation !== saveGenerationRef.current) {
        return;
      }
      if (draftRevisionRef.current === revision) {
        setDraft(saved);
        setTimeoutValue(saved.classifier_timeout_seconds);
        setTimeoutInvalid(false);
        draftRevisionRef.current += 1;
      }
      message.success(t("security.mutationGuard.saveSuccess"));
    } catch {
      if (mountedRef.current && generation === saveGenerationRef.current) {
        setError("security.mutationGuard.saveFailed");
        message.error(t("security.mutationGuard.saveFailed"));
      }
    } finally {
      if (mountedRef.current && generation === saveGenerationRef.current) {
        savingRef.current = false;
        setSaving(false);
      }
    }
  }, [draft, message, t, timeoutInvalid]);

  if (loading) {
    return (
      <div className={styles.mutationGuardState}>{t("common.loading")}</div>
    );
  }

  if (!draft) {
    return (
      <div className={styles.mutationGuardState}>
        <span role="alert">{error ? t(error) : null}</span>
        <Button onClick={() => void load()}>{t("environments.retry")}</Button>
      </div>
    );
  }

  const dependentDisabled = saving || !draft.enabled;

  return (
    <div className={styles.tabContent}>
      <p className={styles.tabDescription}>
        {t("security.mutationGuard.description")}
      </p>

      <div className={styles.mutationGuardForm}>
        <div className={styles.mutationGuardRow}>
          <label htmlFor="mutation-guard-enabled">
            {t("security.mutationGuard.enabled")}
          </label>
          <Switch
            id="mutation-guard-enabled"
            aria-label={t("security.mutationGuard.enabled")}
            checked={draft.enabled}
            disabled={saving}
            onChange={(enabled) => updateDraft({ enabled })}
          />
        </div>

        <div className={styles.mutationGuardField}>
          <label htmlFor="mutation-guard-role-input">
            {t("security.mutationGuard.privilegedRoles")}
          </label>
          <div className={styles.mutationGuardRoleInput}>
            <div className={styles.mutationGuardRoles}>
              {draft.privileged_roles.map((role) => (
                <Tag key={role}>
                  <span>{role}</span>
                  <button
                    type="button"
                    className={styles.mutationGuardRemoveRole}
                    aria-label={t("security.mutationGuard.removeRole", {
                      role,
                    })}
                    disabled={dependentDisabled}
                    onClick={() => removeRole(role)}
                  >
                    ×
                  </button>
                </Tag>
              ))}
            </div>
            <Input
              id="mutation-guard-role-input"
              aria-label={t("security.mutationGuard.privilegedRoles")}
              value={roleInput}
              placeholder={t("security.mutationGuard.rolesPlaceholder")}
              disabled={dependentDisabled}
              onChange={(event) => setRoleInput(event.target.value)}
              onBlur={addRole}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === ",") {
                  event.preventDefault();
                  addRole();
                }
              }}
            />
          </div>
        </div>

        <div className={styles.mutationGuardRow}>
          <label htmlFor="mutation-guard-precheck">
            {t("security.mutationGuard.intentPrecheck")}
          </label>
          <Switch
            id="mutation-guard-precheck"
            aria-label={t("security.mutationGuard.intentPrecheck")}
            checked={draft.intent_precheck_enabled}
            disabled={dependentDisabled}
            onChange={(intent_precheck_enabled) =>
              updateDraft({ intent_precheck_enabled })
            }
          />
        </div>

        <div className={styles.mutationGuardField}>
          <label htmlFor="mutation-guard-timeout">
            {t("security.mutationGuard.classifierTimeout")}
          </label>
          <InputNumber
            id="mutation-guard-timeout"
            aria-label={t("security.mutationGuard.classifierTimeout")}
            min={1}
            max={60}
            value={timeoutValue}
            disabled={dependentDisabled || !draft.intent_precheck_enabled}
            onChange={(value: unknown) => {
              const eventValue = (
                value as { target?: { value?: string } } | null
              )?.target?.value;
              const rawValue = eventValue ?? value;
              const parsedValue =
                rawValue === null || rawValue === "" ? null : Number(rawValue);
              const nextValue =
                parsedValue !== null && Number.isFinite(parsedValue)
                  ? parsedValue
                  : null;
              setTimeoutValue(nextValue);
              const valid =
                nextValue !== null &&
                Number.isInteger(nextValue) &&
                nextValue >= 1 &&
                nextValue <= 60;
              setTimeoutInvalid(!valid);
              if (valid) {
                updateDraft({ classifier_timeout_seconds: nextValue });
              }
            }}
          />
          {timeoutInvalid && (
            <span role="alert" className={styles.mutationGuardFieldError}>
              {t("security.mutationGuard.timeoutInvalid")}
            </span>
          )}
        </div>

        <div className={styles.mutationGuardField}>
          <label htmlFor="mutation-guard-deny-message">
            {t("security.mutationGuard.denyMessage")}
          </label>
          <Input.TextArea
            id="mutation-guard-deny-message"
            aria-label={t("security.mutationGuard.denyMessage")}
            rows={3}
            value={draft.deny_message}
            disabled={dependentDisabled}
            onChange={(event) =>
              updateDraft({ deny_message: event.target.value })
            }
          />
        </div>
      </div>

      {error && <div className={styles.mutationGuardError}>{t(error)}</div>}
      <div className={styles.mutationGuardActions}>
        <Button
          type="primary"
          onClick={() => void save()}
          aria-disabled={
            saving || timeoutInvalid || draft.privileged_roles.length === 0
          }
          disabled={
            saving || timeoutInvalid || draft.privileged_roles.length === 0
          }
        >
          {t("common.save")}
        </Button>
      </div>
    </div>
  );
}
