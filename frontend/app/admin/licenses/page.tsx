'use client';

import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { CalendarPlus, Save, Trash2 } from 'lucide-react';
import { ApiError, adminFetch, errorMessage } from '@shared/lib/adminApi';
import { useConfirm } from '@shared/ui/Confirm';
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { STATE_BADGE, STATE_LABEL, formatDate, plural, type LicenseState } from '@shared/lib/license';

interface ModuleDef { key: string; label: string; description: string }

interface LicenseRecord {
  system: 'sso' | 'gms' | 'dms';
  customer: string;
  expiresAt: string | null;
  graceDays: number;
  warnDays: number;
  maxUsers: number | null;
  modules: string[] | null;
  notes: string;
  version: number;
  updatedAt: string;
  updatedBy: string;
}

interface Computed { state: LicenseState; daysRemaining: number | null; expiresAt: string | null; graceEndsAt: string | null; readOnly: boolean }

interface LicenseEvent {
  id: number;
  action: 'create' | 'update' | 'extend' | 'revoke';
  actor: string;
  version: number;
  before: LicenseRecord | null;
  after: LicenseRecord | null;
  createdAt: string;
}

interface SystemEntry {
  system: 'sso' | 'gms' | 'dms';
  label: string;
  modules: ModuleDef[];
  license: LicenseRecord | null;
  computed: Computed;
  events: LicenseEvent[];
}

interface LicensesData {
  systems: SystemEntry[];
  enforcement: 'enforce' | 'warn' | 'off';
  serverTime: string;
  csrf: string;
}

/** The form's own state: strings for the number boxes so a half-typed value is not rewritten under the cursor. */
interface Draft {
  customer: string;
  never: boolean;
  date: string;
  graceDays: string;
  warnDays: string;
  unlimited: boolean;
  maxUsers: string;
  allModules: boolean;
  modules: string[];
  notes: string;
}

const DEFAULT_GRACE = '14';
const DEFAULT_WARN = '30';
const QUICK_EXTEND = [30, 90, 365];

function initialDraft(entry: SystemEntry): Draft {
  const l = entry.license;
  return {
    customer: l?.customer ?? '',
    never: l ? l.expiresAt === null : false,
    date: l?.expiresAt ? l.expiresAt.slice(0, 10) : '',
    graceDays: String(l?.graceDays ?? DEFAULT_GRACE),
    warnDays: String(l?.warnDays ?? DEFAULT_WARN),
    unlimited: l ? l.maxUsers === null : true,
    maxUsers: l?.maxUsers != null ? String(l.maxUsers) : '',
    allModules: l ? l.modules === null : true,
    modules: l?.modules ?? [],
    notes: l?.notes ?? '',
  };
}

const isWholeIn = (s: string, min: number, max: number) => /^\d+$/.test(s.trim()) && Number(s) >= min && Number(s) <= max;

/** A quick check so an obviously wrong value is flagged while typing; the server's answer is the authority. */
function problems(d: Draft): Record<string, string> {
  const p: Record<string, string> = {};
  if (d.customer.trim() === '') p.customer = 'Enter the customer’s name.';
  else if (d.customer.trim().length > 200) p.customer = 'At most 200 characters.';
  if (!d.never && !/^\d{4}-\d{2}-\d{2}$/.test(d.date)) p.date = 'Choose the last day of the licence, or switch on “Never expires”.';
  if (!isWholeIn(d.graceDays, 0, 365)) p.graceDays = 'A whole number from 0 to 365.';
  if (!isWholeIn(d.warnDays, 0, 365)) p.warnDays = 'A whole number from 0 to 365.';
  if (!d.unlimited && !isWholeIn(d.maxUsers, 1, 10_000_000)) p.maxUsers = 'A whole number, at least 1.';
  if (d.notes.length > 2000) p.notes = 'At most 2000 characters.';
  return p;
}

/** What to send: everything for a new licence, only the fields that changed for an existing one (the server merges). */
function payloadOf(entry: SystemEntry, d: Draft): Record<string, unknown> {
  const init = initialDraft(entry);
  const isNew = entry.license === null;
  const out: Record<string, unknown> = {};
  const put = (key: string, value: unknown, changed: boolean) => { if (isNew || changed) out[key] = value; };
  put('customer', d.customer.trim(), d.customer.trim() !== init.customer);
  put('expiresAt', d.never ? null : d.date, d.never !== init.never || (!d.never && d.date !== init.date));
  put('graceDays', Number(d.graceDays), d.graceDays !== init.graceDays);
  put('warnDays', Number(d.warnDays), d.warnDays !== init.warnDays);
  put('maxUsers', d.unlimited ? null : Number(d.maxUsers), d.unlimited !== init.unlimited || (!d.unlimited && d.maxUsers !== init.maxUsers));
  if (entry.modules.length > 0) {
    const changed = d.allModules !== init.allModules || (!d.allModules && [...d.modules].sort().join() !== [...init.modules].sort().join());
    put('modules', d.allModules ? null : d.modules, changed);
  }
  put('notes', d.notes, d.notes !== init.notes);
  return out;
}

const ACTION_LABEL: Record<LicenseEvent['action'], string> = { create: 'Created', update: 'Changed', extend: 'Extended', revoke: 'Removed' };

/** One line saying what an event changed, from its before and after records. */
function describeEvent(e: LicenseEvent, labelOf: (key: string) => string): string {
  const { before, after } = e;
  if (e.action === 'revoke' || !after) return 'The licence was removed; the system returned to “no licence”.';
  const expiry = (l: LicenseRecord) => (l.expiresAt ? formatDate(l.expiresAt) : 'never');
  const seats = (l: LicenseRecord) => (l.maxUsers === null ? 'unlimited' : String(l.maxUsers));
  const mods = (l: LicenseRecord) => (l.modules === null ? 'all' : l.modules.length ? l.modules.map(labelOf).join(', ') : 'none');
  if (!before) return `${after.customer}: expires ${expiry(after)}, grace ${after.graceDays} d, warning ${after.warnDays} d, seats ${seats(after)}, modules ${mods(after)}.`;
  const changes: string[] = [];
  if (before.customer !== after.customer) changes.push(`customer ${before.customer} to ${after.customer}`);
  if (before.expiresAt !== after.expiresAt) changes.push(`expiry ${expiry(before)} to ${expiry(after)}`);
  if (before.graceDays !== after.graceDays) changes.push(`grace ${before.graceDays} to ${after.graceDays} d`);
  if (before.warnDays !== after.warnDays) changes.push(`warning ${before.warnDays} to ${after.warnDays} d`);
  if (before.maxUsers !== after.maxUsers) changes.push(`seats ${seats(before)} to ${seats(after)}`);
  if (JSON.stringify(before.modules) !== JSON.stringify(after.modules)) changes.push(`modules ${mods(before)} to ${mods(after)}`);
  if (before.notes !== after.notes) changes.push('notes');
  return changes.length ? `${changes.join('; ')}.` : 'No visible change.';
}

function LicenseCard({ entry, enforcement, getCsrf, onChanged }: {
  entry: SystemEntry;
  enforcement: LicensesData['enforcement'];
  getCsrf: () => string;
  onChanged: (nextCsrf: string) => Promise<void>;
}) {
  const confirm = useConfirm();
  const [draft, setDraft] = useState<Draft>(() => initialDraft(entry));
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const license = entry.license;
  const init = initialDraft(entry);
  const found = problems(draft);
  const payload = payloadOf(entry, draft);
  const dirty = license === null ? touched : Object.keys(payload).length > 0;
  const valid = Object.keys(found).length === 0;
  const labelOf = (key: string) => entry.modules.find((m) => m.key === key)?.label ?? key;
  const idp = `lic-${entry.system}`;

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    setTouched(true);
    setServerError(null);
    setDraft((d) => ({ ...d, [key]: value }));
  };

  async function run(label: string, method: 'PUT' | 'POST' | 'DELETE', path: string, body: Record<string, unknown>) {
    setBusy(true);
    setServerError(null);
    try {
      const out = await adminFetch<{ csrf: string }>(path, { method, body: { ...body, csrf: getCsrf() } });
      toast.success(label);
      await onChanged(out.csrf);
    } catch (err) {
      setServerError(errorMessage(err));
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const save = () => run(license ? `${entry.system.toUpperCase()} licence saved` : `${entry.system.toUpperCase()} licence created`, 'PUT', `/api/v1/admin/licenses/${entry.system}`, payload);

  async function extend(days: number) {
    if (dirty) return;
    await run(`Extended by ${plural(days, 'day')}`, 'POST', `/api/v1/admin/licenses/${entry.system}/extend`, { days });
  }

  async function revoke() {
    const ok = await confirm({
      title: `Remove the ${entry.system.toUpperCase()} licence?`,
      message: (
        <>
          <p>{entry.system.toUpperCase()} goes back to <strong>no licence</strong>: nothing is enforced and everything works as before. The history below and the audit log keep the record.</p>
          <p>You can create a new licence at any time.</p>
        </>
      ),
      confirmLabel: 'Remove licence',
      danger: true,
    });
    if (ok) await run('Licence removed', 'DELETE', `/api/v1/admin/licenses/${entry.system}`, {});
  }

  const c = entry.computed;
  const shown = (key: string) => (touched || license !== null ? found[key] : undefined);

  return (
    <section className="admin-card license-card" aria-labelledby={`${idp}-title`}>
      <header className="license-head">
        <div>
          <h2 id={`${idp}-title`}>{entry.label}</h2>
          <p className="license-sub">
            {license
              ? `${license.customer} · ${license.expiresAt ? `expires ${formatDate(license.expiresAt)}` : 'never expires'}${c.daysRemaining !== null ? ` (${c.daysRemaining >= 0 ? `${plural(c.daysRemaining, 'day')} left` : `${plural(-c.daysRemaining, 'day')} ago`})` : ''}`
              : 'No licence is configured, so nothing is enforced.'}
          </p>
        </div>
        <span className={`ui-badge ${STATE_BADGE[c.state]}`}>{STATE_LABEL[c.state]}</span>
      </header>

      {license && c.graceEndsAt && (c.state === 'grace' || c.state === 'expired') ? (
        <p className="admin-hint" role="status">
          The grace period {c.state === 'grace' ? 'ends' : 'ended'} on {formatDate(c.graceEndsAt)}.
          {c.state === 'expired' ? ' The system is read-only until the licence is extended.' : ''}
        </p>
      ) : null}
      {entry.system === 'sso' && enforcement !== 'enforce' ? (
        <p className="admin-hint" role="note">LICENSE_ENFORCEMENT is “{enforcement}” on this server: SSO shows its state but does not refuse anything.</p>
      ) : null}
      {entry.system !== 'sso' ? (
        <p className="admin-hint">{entry.system.toUpperCase()} picks a change up within a few minutes (its own polling interval) and enforces it itself.</p>
      ) : null}

      <div className="license-form">
        <div className="ui-field license-wide">
          <label className="sub" htmlFor={`${idp}-customer`}>Customer</label>
          <input id={`${idp}-customer`} className="ui-input" value={draft.customer} maxLength={200} disabled={busy} aria-invalid={shown('customer') ? true : undefined} onChange={(e) => set('customer', e.target.value)} />
          {shown('customer') ? <p className="ui-field-error" role="alert">{shown('customer')}</p> : null}
        </div>

        <div className="ui-field">
          <label className="sub" htmlFor={`${idp}-date`}>Expires (last day)</label>
          <input id={`${idp}-date`} type="date" className="ui-input" value={draft.date} disabled={busy || draft.never} aria-invalid={shown('date') ? true : undefined} onChange={(e) => set('date', e.target.value)} />
          <label className="ui-switch" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={draft.never} disabled={busy} onChange={(e) => set('never', e.target.checked)} />
            <span className="track" aria-hidden="true" />
            <span>Never expires</span>
          </label>
          {shown('date') ? <p className="ui-field-error" role="alert">{shown('date')}</p> : <p className="ui-field-hint">Valid through the end of this day (UTC).</p>}
        </div>

        <div className="ui-field">
          <label className="sub" htmlFor={`${idp}-grace`}>Grace days</label>
          <input id={`${idp}-grace`} type="number" min={0} max={365} step={1} className="ui-input" value={draft.graceDays} disabled={busy} aria-invalid={shown('graceDays') ? true : undefined} onChange={(e) => set('graceDays', e.target.value)} />
          {shown('graceDays') ? <p className="ui-field-error" role="alert">{shown('graceDays')}</p> : <p className="ui-field-hint">After expiry, full function continues this long, then read-only.</p>}
        </div>

        <div className="ui-field">
          <label className="sub" htmlFor={`${idp}-warn`}>Warn days</label>
          <input id={`${idp}-warn`} type="number" min={0} max={365} step={1} className="ui-input" value={draft.warnDays} disabled={busy} aria-invalid={shown('warnDays') ? true : undefined} onChange={(e) => set('warnDays', e.target.value)} />
          {shown('warnDays') ? <p className="ui-field-error" role="alert">{shown('warnDays')}</p> : <p className="ui-field-hint">Banner starts this many days before expiry.</p>}
        </div>

        <div className="ui-field">
          <label className="sub" htmlFor={`${idp}-seats`}>Seat limit</label>
          <input id={`${idp}-seats`} type="number" min={1} step={1} className="ui-input" value={draft.maxUsers} disabled={busy || draft.unlimited} placeholder="Unlimited" aria-invalid={shown('maxUsers') ? true : undefined} onChange={(e) => set('maxUsers', e.target.value)} />
          <label className="ui-switch" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={draft.unlimited} disabled={busy} onChange={(e) => set('unlimited', e.target.checked)} />
            <span className="track" aria-hidden="true" />
            <span>Unlimited seats</span>
          </label>
          {shown('maxUsers') ? <p className="ui-field-error" role="alert">{shown('maxUsers')}</p> : <p className="ui-field-hint">{entry.system === 'sso' ? 'Recorded and shown in SSO’s status; SSO does not refuse accounts itself.' : 'Blocks creating or enabling accounts past the limit; nobody is switched off.'}</p>}
        </div>

        {entry.modules.length > 0 ? (
          <fieldset className="license-wide license-modules" disabled={busy}>
            <legend className="sub">Modules</legend>
            <label className="ui-switch">
              <input type="checkbox" checked={draft.allModules} onChange={(e) => set('allModules', e.target.checked)} />
              <span className="track" aria-hidden="true" />
              <span>All modules (including any added later)</span>
            </label>
            <div className="choice-list license-module-list" role="group" aria-label={`${entry.system.toUpperCase()} modules`}>
              {entry.modules.map((m) => (
                <label key={m.key} title={m.description}>
                  <input
                    type="checkbox"
                    checked={draft.allModules || draft.modules.includes(m.key)}
                    disabled={draft.allModules}
                    onChange={(e) => set('modules', e.target.checked ? [...draft.modules, m.key] : draft.modules.filter((k) => k !== m.key))}
                  />
                  <span><strong>{m.label}</strong> <span className="license-module-desc">{m.description}</span></span>
                </label>
              ))}
            </div>
          </fieldset>
        ) : (
          <p className="admin-hint license-wide">SSO has no modules that can be switched off: its licence controls expiry and the seat limit only.</p>
        )}

        <div className="ui-field license-wide">
          <label className="sub" htmlFor={`${idp}-notes`}>Notes (internal)</label>
          <textarea id={`${idp}-notes`} className="ui-input" rows={2} value={draft.notes} maxLength={2000} disabled={busy} onChange={(e) => set('notes', e.target.value)} />
        </div>
      </div>

      {serverError ? <p className="ui-field-error" role="alert">{serverError}</p> : null}

      <div className="license-actions">
        <button type="button" className="admin-btn" disabled={busy || !dirty || !valid} onClick={() => void save()}>
          <Save size={14} aria-hidden="true" /> {license ? 'Save changes' : 'Create licence'}
        </button>
        {dirty && license ? (
          <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => { setDraft(init); setTouched(false); setServerError(null); }}>Discard</button>
        ) : null}
        {license && license.expiresAt !== null ? (
          <span className="license-extend" role="group" aria-label="Extend the licence">
            <CalendarPlus size={14} aria-hidden="true" />
            {QUICK_EXTEND.map((days) => (
              <button key={days} type="button" className="admin-btn secondary" disabled={busy || dirty} title={dirty ? 'Save or discard your edits first' : `Add ${days} days (from today if it has already lapsed)`} onClick={() => void extend(days)}>
                +{days} days
              </button>
            ))}
          </span>
        ) : null}
        {license ? (
          <button type="button" className="admin-btn danger license-revoke" disabled={busy} onClick={() => void revoke()}>
            <Trash2 size={14} aria-hidden="true" /> Remove licence
          </button>
        ) : null}
      </div>

      {license ? (
        <p className="ui-ref">Version {license.version} · last changed {new Date(license.updatedAt).toLocaleString()} by {license.updatedBy === 'platform' ? 'the platform administrator' : license.updatedBy}</p>
      ) : null}

      <details className="license-history">
        <summary>History ({entry.events.length}{entry.events.length === 20 ? '+' : ''})</summary>
        {entry.events.length === 0 ? (
          <p className="admin-hint">Nothing has been changed yet.</p>
        ) : (
          <ol>
            {entry.events.map((e) => (
              <li key={e.id}>
                <span className="ui-ref">{new Date(e.createdAt).toLocaleString()} · v{e.version} · {e.actor === 'platform' ? 'platform administrator' : e.actor}</span>
                <div><strong>{ACTION_LABEL[e.action]}.</strong> {describeEvent(e, labelOf)}</div>
              </li>
            ))}
          </ol>
        )}
      </details>
    </section>
  );
}

export default function LicensesPage() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ['admin-licenses'],
    queryFn: () => adminFetch<LicensesData>('/api/v1/admin/licenses'),
    staleTime: 0,
    retry: false,
  });
  // The token a mutation must echo back. GET issues one and every mutation issues the next.
  const csrf = useRef('');
  useEffect(() => { if (query.data) csrf.current = query.data.csrf; }, [query.data]);

  async function changed(nextCsrf: string) {
    csrf.current = nextCsrf;
    // The banner above every page reads SSO's own status.
    await Promise.all([queryClient.invalidateQueries({ queryKey: ['admin-licenses'] }), queryClient.invalidateQueries({ queryKey: ['license-status'] })]);
  }

  if (query.isPending) return <PageSkeleton rows={3} />;

  if (query.isError) {
    if (query.error instanceof ApiError && query.error.code === 'ERR-PLATFORM-ADMIN-ONLY') {
      return (
        <>
          <div className="admin-page-header"><div><h1>Licences</h1></div></div>
          <div className="admin-card" role="note">
            <p className="admin-hint" style={{ margin: 0 }}>
              Licences are managed by the platform administrator only: they decide what each system is allowed to do and for how long, so this page sits above the IdP administrator group.
            </p>
          </div>
        </>
      );
    }
    return <ErrorState error={query.error} onRetry={() => query.refetch()} title="Licences could not be loaded" />;
  }

  const data = query.data;
  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Licences</h1>
          <p>
            One licence per system, issued here and checked by each system. When one expires there is a warning, then a grace period, then the system becomes read-only:
            nothing is ever deleted or switched off. A system with no licence is not restricted at all.
          </p>
        </div>
      </div>
      <div className="license-grid">
        {data.systems.map((entry) => (
          // Remounted whenever the licence changes (new version), so the form always starts from what the server now holds.
          <LicenseCard key={`${entry.system}:${entry.license?.version ?? 'none'}`} entry={entry} enforcement={data.enforcement} getCsrf={() => csrf.current} onChanged={changed} />
        ))}
      </div>
    </>
  );
}
