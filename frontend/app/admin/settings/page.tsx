'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Lock, RotateCcw, Save } from 'lucide-react';
import { adminFetch, errorMessage } from '@shared/lib/adminApi';
import { useConfirm } from '@shared/ui/Confirm';
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { BrandPreview } from './BrandPreview';

type Value = number | boolean | string | string[];

interface SettingRow {
  key: string;
  label: string;
  help: string;
  type: 'int' | 'bool' | 'text' | 'color' | 'apps';
  min: number | null;
  max: number | null;
  unit: string | null;
  maxLength: number | null;
  multiline: boolean;
  editableBy: 'admin' | 'platform';
  applies: 'immediately' | 'new-sign-ins' | 'new-tokens';
  choices: Array<{ id: string; label: string }> | null;
  value: Value;
  defaultValue: Value;
  source: 'default' | 'stored';
  updatedAt: string | null;
  updatedBy: string | null;
  canEdit: boolean;
}

interface Group {
  id: string;
  title: string;
  description: string;
  settings: SettingRow[];
}

interface SettingsData {
  viewerIsPlatformAdmin: boolean;
  groups: Group[];
  csrf: string;
}

const APPLIES_LABEL: Record<SettingRow['applies'], string> = {
  immediately: 'Applies immediately',
  'new-sign-ins': 'Applies to new sign-ins',
  'new-tokens': 'Applies to tokens issued from now on',
};

/** These change who can get in, for how long, or what is deleted: the person is asked to confirm before they are saved. */
const NEEDS_CONFIRM = new Set([
  'password.minLength', 'password.blockCommon', 'lockout.enabled', 'lockout.threshold', 'lockout.minutes', 'mfa.requireForAdmins',
  'ttl.accessTokenSeconds', 'ttl.idTokenSeconds', 'ttl.refreshTokenHours', 'ttl.ssoSessionHours', 'ttl.portalSessionHours', 'retention.loginEventDays',
]);

const same = (a: Value, b: Value) => JSON.stringify(a) === JSON.stringify(b);

/** A quick check so an obviously wrong value is flagged while typing; the server's answer is the authority. */
function localProblem(row: SettingRow, v: Value): string | null {
  if (row.type === 'int') {
    if (typeof v !== 'number' || !Number.isInteger(v)) return 'Enter a whole number.';
    if (row.min !== null && v < row.min) return `At least ${row.min}${row.unit ? ` ${row.unit}` : ''}.`;
    if (row.max !== null && v > row.max) return `At most ${row.max}${row.unit ? ` ${row.unit}` : ''}.`;
  }
  if (row.type === 'text' && typeof v === 'string' && row.maxLength !== null && v.length > row.maxLength) return `At most ${row.maxLength} characters.`;
  if (row.type === 'color' && !(typeof v === 'string' && /^#[0-9a-f]{6}$/i.test(v))) return 'Use a colour like #166534.';
  return null;
}

function show(row: SettingRow, v: Value): string {
  if (row.type === 'bool') return v ? 'On' : 'Off';
  if (row.type === 'apps') {
    const ids = v as string[];
    return ids.length === 0 ? 'None' : ids.map((id) => row.choices?.find((c) => c.id === id)?.label ?? id).join(', ');
  }
  if (row.type === 'text') return (v as string) === '' ? '(empty)' : String(v);
  return `${v}${row.unit ? ` ${row.unit}` : ''}`;
}

function Control({ row, value, onChange, disabled, error, describedBy }: { row: SettingRow; value: Value; onChange: (v: Value) => void; disabled: boolean; error: string | null; describedBy: string }) {
  const id = `set-${row.key}`;
  switch (row.type) {
    case 'bool':
      return (
        <label className="ui-switch">
          <input id={id} type="checkbox" checked={Boolean(value)} disabled={disabled} onChange={(e) => onChange(e.target.checked)} aria-describedby={describedBy} />
          <span className="track" aria-hidden="true" />
          <span>{value ? 'On' : 'Off'}</span>
        </label>
      );
    case 'int':
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input
            id={id}
            type="number"
            className="ui-input"
            style={{ maxWidth: 140 }}
            value={Number.isNaN(value as number) ? '' : String(value)}
            min={row.min ?? undefined}
            max={row.max ?? undefined}
            step={1}
            disabled={disabled}
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
            onChange={(e) => onChange(e.target.value === '' ? Number.NaN : Number(e.target.value))}
          />
          {row.unit ? <span className="sub">{row.unit}</span> : null}
        </div>
      );
    case 'color':
      return (
        <div className="color-row">
          <input type="color" aria-label={`${row.label}: pick a colour`} value={typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value) ? value : '#000000'} disabled={disabled} onChange={(e) => onChange(e.target.value)} />
          <input id={id} className="ui-input" style={{ maxWidth: 130, fontFamily: 'ui-monospace, monospace' }} value={String(value)} disabled={disabled} maxLength={7} aria-invalid={error ? true : undefined} aria-describedby={describedBy} onChange={(e) => onChange(e.target.value)} />
        </div>
      );
    case 'apps': {
      const selected = new Set(value as string[]);
      return (
        <div className="choice-list" role="group" aria-label={row.label}>
          {(row.choices ?? []).map((c) => (
            <label key={c.id}>
              <input
                type="checkbox"
                checked={selected.has(c.id)}
                disabled={disabled}
                onChange={(e) => {
                  const next = new Set(selected);
                  if (e.target.checked) next.add(c.id);
                  else next.delete(c.id);
                  onChange([...next].sort());
                }}
              />
              {c.label}
            </label>
          ))}
        </div>
      );
    }
    default:
      return row.multiline ? (
        <textarea id={id} className="ui-input" rows={3} value={String(value)} maxLength={row.maxLength ?? undefined} disabled={disabled} aria-invalid={error ? true : undefined} aria-describedby={describedBy} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input id={id} className="ui-input" value={String(value)} maxLength={row.maxLength ?? undefined} disabled={disabled} aria-invalid={error ? true : undefined} aria-describedby={describedBy} onChange={(e) => onChange(e.target.value)} />
      );
  }
}

function SettingItem({ row, draft, onDraft, busy, onSave, onReset, serverError }: {
  row: SettingRow;
  draft: Value | undefined;
  onDraft: (key: string, v: Value | undefined) => void;
  busy: boolean;
  onSave: (row: SettingRow, v: Value) => void;
  onReset: (row: SettingRow) => void;
  serverError: string | null;
}) {
  const value = draft === undefined ? row.value : draft;
  const dirty = draft !== undefined && !same(draft, row.value);
  const local = dirty ? localProblem(row, value) : null;
  const error = local ?? serverError;
  const describedBy = `${row.key}-help ${row.key}-err`;
  const readOnly = !row.canEdit;
  return (
    <div className="setting-row">
      <div className="setting-meta">
        <h3>
          <label htmlFor={`set-${row.key}`}>{row.label}</label>
          {readOnly ? <span className="ui-chip lock"><Lock size={11} aria-hidden="true" /> Platform administrator only</span> : null}
          <span className="ui-chip live">{APPLIES_LABEL[row.applies]}</span>
        </h3>
        <p id={`${row.key}-help`}>{row.help}</p>
        <span className="ui-ref">
          {row.source === 'stored'
            ? `Changed${row.updatedBy ? ` by ${row.updatedBy}` : ''}${row.updatedAt ? ` on ${new Date(row.updatedAt).toLocaleString()}` : ''}`
            : 'Using the default'}
        </span>
      </div>
      <div className="setting-control">
        <Control row={row} value={value} onChange={(v) => onDraft(row.key, v)} disabled={readOnly || busy} error={error} describedBy={describedBy} />
        <p id={`${row.key}-err`} className="ui-field-error" role={error ? 'alert' : undefined}>{error}</p>
        <span className="setting-default">Default: {show(row, row.defaultValue)}</span>
        {!readOnly ? (
          <div className="setting-actions">
            <button type="button" className="admin-btn" disabled={!dirty || busy || Boolean(local)} onClick={() => onSave(row, value)}>
              <Save size={14} aria-hidden="true" /> Save
            </button>
            {dirty ? (
              <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => onDraft(row.key, undefined)}>Discard</button>
            ) : null}
            {row.source === 'stored' && !dirty ? (
              <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => onReset(row)}>
                <RotateCcw size={14} aria-hidden="true" /> Reset to default
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const query = useQuery({ queryKey: ['admin-settings'], queryFn: () => adminFetch<SettingsData>('/api/v1/admin/settings'), staleTime: 0 });
  const [groupId, setGroupId] = useState('branding');
  const [drafts, setDrafts] = useState<Record<string, Value>>({});
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  // The token a mutation must echo back. GET issues one and every mutation issues the next.
  const csrf = useRef('');
  useEffect(() => { if (query.data) csrf.current = query.data.csrf; }, [query.data]);

  const setDraft = useCallback((key: string, v: Value | undefined) => {
    setDrafts((d) => {
      const next = { ...d };
      if (v === undefined) delete next[key];
      else next[key] = v;
      return next;
    });
    setErrors((e) => {
      if (!(key in e)) return e;
      const next = { ...e };
      delete next[key];
      return next;
    });
  }, []);

  // Unsaved edits are lost on navigation: say so.
  const dirtyCount = useMemo(() => {
    const rows = query.data?.groups.flatMap((g) => g.settings) ?? [];
    return rows.filter((r) => drafts[r.key] !== undefined && !same(drafts[r.key] as Value, r.value)).length;
  }, [drafts, query.data]);
  useEffect(() => {
    if (dirtyCount === 0) return;
    const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirtyCount]);

  async function mutate(row: SettingRow, method: 'PUT' | 'DELETE', value?: Value) {
    setBusy(true);
    try {
      const out = await adminFetch<{ csrf: string }>(`/api/v1/admin/settings/${encodeURIComponent(row.key)}`, {
        method,
        body: method === 'PUT' ? { value, csrf: csrf.current } : { csrf: csrf.current },
      });
      csrf.current = out.csrf;
      setDraft(row.key, undefined);
      await queryClient.invalidateQueries({ queryKey: ['admin-settings'] });
      // The root layout read the branding when this page loaded; a reload applies a branding change to the console itself.
      toast.success(method === 'PUT' ? `${row.label} saved` : `${row.label} reset to the default`);
    } catch (err) {
      setErrors((e) => ({ ...e, [row.key]: errorMessage(err) }));
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function save(row: SettingRow, value: Value) {
    if (NEEDS_CONFIRM.has(row.key)) {
      const ok = await confirm({
        title: `Change “${row.label}”?`,
        message: (
          <>
            <p>From <strong>{show(row, row.value)}</strong> to <strong>{show(row, value)}</strong>.</p>
            <p>{APPLIES_LABEL[row.applies]}. People who are already signed in are not signed out by this.</p>
            {row.key === 'retention.loginEventDays' ? <p>Sign-in records older than the new limit are deleted at the next hourly clean-up, and cannot be recovered.</p> : null}
            {row.key === 'lockout.enabled' && value === false ? <p>With the lock off, anyone can keep guessing a password; only the rate limits slow them down.</p> : null}
            <p>The change is written to the audit log.</p>
          </>
        ),
        confirmLabel: 'Save change',
        danger: row.key === 'lockout.enabled' && value === false,
      });
      if (!ok) return;
    }
    await mutate(row, 'PUT', value);
  }

  async function reset(row: SettingRow) {
    const ok = await confirm({
      title: `Reset “${row.label}”?`,
      message: <p>It goes back to the default, <strong>{show(row, row.defaultValue)}</strong>. The change is written to the audit log.</p>,
      confirmLabel: 'Reset to default',
    });
    if (ok) await mutate(row, 'DELETE');
  }

  if (query.isPending) return <PageSkeleton rows={2} />;
  if (query.isError) return <ErrorState error={query.error} onRetry={() => query.refetch()} title="Settings could not be loaded" />;

  const data = query.data;
  const group = data.groups.find((g) => g.id === groupId) ?? data.groups[0] as Group;
  const brandingValue = (key: string, fallback: string): string => {
    const row = data.groups.flatMap((g) => g.settings).find((r) => r.key === key);
    const v = drafts[key] ?? row?.value ?? fallback;
    return String(v);
  };

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Settings</h1>
          <p>
            Policy and branding for the whole sign-in service. Each change is validated, applied straight away where it says so, and written to the audit log.
            {!data.viewerIsPlatformAdmin ? ' Settings marked “Platform administrator only” are shown read-only to you.' : ''}
          </p>
        </div>
        {dirtyCount > 0 ? <span className="ui-badge ui-badge-warning" role="status">{dirtyCount} unsaved change{dirtyCount === 1 ? '' : 's'}</span> : null}
      </div>

      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Setting groups">
          {data.groups.map((g) => (
            <button key={g.id} type="button" aria-current={g.id === group.id ? 'true' : undefined} onClick={() => setGroupId(g.id)}>{g.title}</button>
          ))}
        </nav>
        <div>
          <label className="ui-field settings-nav-select">
            <span className="sub">Group</span>
            <select className="ui-input" value={group.id} onChange={(e) => setGroupId(e.target.value)}>
              {data.groups.map((g) => <option key={g.id} value={g.id}>{g.title}</option>)}
            </select>
          </label>
          <div className="admin-card">
            <h2 className="admin-section-title" style={{ marginTop: 0 }}>{group.title}</h2>
            <p className="admin-hint" style={{ marginTop: 0 }}>{group.description}</p>
            {group.settings.map((row) => (
              <SettingItem key={row.key} row={row} draft={drafts[row.key]} onDraft={setDraft} busy={busy} onSave={save} onReset={reset} serverError={errors[row.key] ?? null} />
            ))}
          </div>
          {group.id === 'branding' ? (
            <BrandPreview
              productName={brandingValue('branding.productName', 'Example Corp Identity')}
              tagline={brandingValue('branding.tagline', '')}
              accent={brandingValue('branding.accentColor', '#166534')}
              accentDark={brandingValue('branding.accentColorDark', '#22c55e')}
              notice={brandingValue('branding.loginNotice', '')}
              support={brandingValue('branding.supportContact', '')}
              footer={brandingValue('branding.footerText', '')}
            />
          ) : null}
        </div>
      </div>
    </>
  );
}
