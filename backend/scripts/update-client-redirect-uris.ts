/**
 * Updates the redirect and post-logout addresses of EXISTING relying-party clients in
 * `idp_clients` from the current environment configuration, and nothing else.
 *
 * Why this exists: seedClients() (src/oidc/clients.ts) only overwrites a client's addresses
 * while its stored secret is still a dev default. After that, editing EDAMS_REDIRECT_URIS,
 * EDAMS_LOGOUT_URIS, GMS_REDIRECT_URIS, GMS_LOGOUT_URIS (or IDP_ISSUER, which the portal
 * client's addresses are built from) changes nothing for an already-registered client; SSO
 * only logs a warning at boot. This is the supported way to apply the new addresses.
 *
 * What it changes: `redirect_uris` and `post_logout_redirect_uris` of the clients named by
 * --client=<id>[,<id>] (default: every configured client). It NEVER touches the client secret,
 * scope, grant types or active flag. A client not yet registered is skipped (boot registers it).
 *
 * DRY RUN unless --apply: prints stored vs configured per client. With --apply it updates in one
 * transaction and writes an audit row per changed client (actor `script:client-uris`).
 * In mirror or production --apply additionally demands I_UNDERSTAND_THIS_UPDATES=<database name>.
 *
 * Restart the SSO backend afterwards: oidc-provider reads the client list at boot.
 *
 * Usage (from backend; mirror/production MUST use the npm launchers or this targets DEV):
 *   npm run client:uris                       # dev, dry run
 *   npm run client:uris -- --client=edams --apply
 *   npm run client:uris:mirror -- --apply     # needs I_UNDERSTAND_THIS_UPDATES=idpprod
 *   npm run client:uris:prod                  # dry run against production env
 */
import pg from 'pg';
import { IDP_CONFIG } from '../src/config.js';
import { sameUriSet } from '../src/oidc/clients.js';
import { writeAudit } from '../src/admin/audit.js';

const APPLY = process.argv.includes('--apply');
const arg = (name: string): string | undefined =>
  process.argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);

async function main() {
  const dbName = new URL(IDP_CONFIG.databaseUrl).pathname.slice(1);
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  if (APPLY && (nodeEnv === 'production' || nodeEnv === 'mirror') && process.env.I_UNDERSTAND_THIS_UPDATES !== dbName) {
    console.error(`\n  Refusing to UPDATE "${dbName}" (NODE_ENV=${nodeEnv}) without I_UNDERSTAND_THIS_UPDATES=${dbName}.\n`);
    process.exit(2);
  }

  const wanted = (arg('client') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const known = IDP_CONFIG.clientSeed.map((c) => c.client_id);
  const unknown = wanted.filter((w) => !known.includes(w));
  if (unknown.length) {
    console.error(`\n  Unknown client id(s): ${unknown.join(', ')}. Configured clients: ${known.join(', ')}.\n`);
    process.exit(2);
  }
  const targets = IDP_CONFIG.clientSeed.filter((c) => wanted.length === 0 || wanted.includes(c.client_id));

  console.log(`Database: ${dbName}  (NODE_ENV=${nodeEnv})  ${APPLY ? 'APPLY' : 'DRY RUN (add --apply to write)'}`);

  const db = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await db.connect();
  const changed: { clientId: string; before: unknown; after: unknown }[] = [];
  try {
    await db.query('BEGIN');
    for (const c of targets) {
      const { rows } = await db.query<{ redirect_uris: string[]; post_logout_redirect_uris: string[] | null }>(
        'SELECT redirect_uris, post_logout_redirect_uris FROM idp_clients WHERE client_id = $1 FOR UPDATE',
        [c.client_id],
      );
      const stored = rows[0];
      if (!stored) {
        console.log(`- ${c.client_id}: not registered yet (SSO registers it at boot); skipped.`);
        continue;
      }
      const wantRedirect = c.redirect_uris;
      const wantLogout = c.post_logout_redirect_uris ?? [];
      const same = sameUriSet(stored.redirect_uris, wantRedirect) && sameUriSet(stored.post_logout_redirect_uris, wantLogout);
      if (same) {
        console.log(`- ${c.client_id}: already matches the configuration.`);
        continue;
      }
      console.log(`- ${c.client_id}: DIFFERS`);
      console.log(`    redirect_uris stored    : ${JSON.stringify(stored.redirect_uris)}`);
      console.log(`    redirect_uris configured: ${JSON.stringify(wantRedirect)}`);
      console.log(`    post_logout stored      : ${JSON.stringify(stored.post_logout_redirect_uris ?? [])}`);
      console.log(`    post_logout configured  : ${JSON.stringify(wantLogout)}`);
      changed.push({
        clientId: c.client_id,
        before: { redirect_uris: stored.redirect_uris, post_logout_redirect_uris: stored.post_logout_redirect_uris ?? [] },
        after: { redirect_uris: wantRedirect, post_logout_redirect_uris: wantLogout },
      });
      if (APPLY) {
        await db.query(
          'UPDATE idp_clients SET redirect_uris = $2, post_logout_redirect_uris = $3, updated_at = NOW() WHERE client_id = $1',
          [c.client_id, wantRedirect, wantLogout],
        );
      }
    }
    await db.query(APPLY ? 'COMMIT' : 'ROLLBACK');
  } catch (err) {
    await db.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    await db.end();
  }

  if (APPLY) {
    const fakeReq = { ip: '', get: () => '' } as never;
    for (const ch of changed) {
      await writeAudit(fakeReq, 'script:client-uris', 'client.redirect_uris', ch.clientId, { before: ch.before, after: ch.after });
    }
    console.log(changed.length ? `\nUpdated ${changed.length} client(s). Restart the SSO backend to load them.` : '\nNothing to update.');
  } else if (changed.length) {
    console.log(`\n${changed.length} client(s) differ. Re-run with --apply to update them.`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
