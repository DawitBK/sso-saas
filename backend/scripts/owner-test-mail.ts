/**
 * Owner verification: prove that the emailed code really reaches your mailbox from THIS environment's mail settings (SMTP_*).
 *
 *   npm run owner:test-mail                                               (development)
 *   node scripts/run-with-env.cjs mirror npx tsx scripts/owner-test-mail.ts
 *   node scripts/run-with-env.cjs production npx tsx scripts/owner-test-mail.ts
 *
 * It sends one clearly-labelled test message, through the relay configured in the env file that environment reads, to the mailbox sealed in the owner
 * store, and says whether the relay accepted it. It needs no terminal prompt and no vault password, changes nothing, and shows no secret: the address
 * is masked and only the relay's host and port are named (never its user or password). Use it after every change to SMTP_* (the settings are read when SSO
 * starts, so restart SSO after changing them) and on every machine or server where owner verification is used.
 */
import '../src/config.js';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { currentMailer, maskAddress, smtpConfigured } from '../src/owner/mailer.js';
import { readStore, relayChangedSinceEnrolment } from '../src/owner/store.js';

async function main(): Promise<void> {
  const store = await readStore();
  if (store.state !== 'ok') {
    console.error(store.state === 'none' ? '\n  Nobody is enrolled in this database yet: run "npm run owner:enroll" first.\n' : `\n  The owner store cannot be opened (${store.reason}). Check OWNER_STORE_KEY_FILE.\n`);
    process.exit(1);
  }
  if (!smtpConfigured()) {
    console.error('\n  SMTP is not configured in this environment (SMTP_HOST and SMTP_FROM or SMTP_USER). The emailed code is unavailable here: a recovery code is used instead.\n');
    process.exit(1);
  }
  const smtp = IDP_CONFIG.smtp;
  console.log(`\n  mail relay:     ${smtp.host}:${smtp.port}${smtp.secure ? ' (TLS)' : ''}`);
  console.log(`  mailbox:        ${maskAddress(store.doc.email.address)}`);
  if (relayChangedSinceEnrolment(store.doc)) console.log('  note:           this relay differs from the one recorded at enrolment; the emailed code uses the relay above.');
  try {
    await currentMailer().send({
      to: store.doc.email.address,
      subject: 'Owner verification: mail delivery test',
      text:
        'This is a test of the mail relay used for your owner verification codes.\n\n' +
        'It contains no code. If you received it, the emailed code will reach you from this environment.\n' +
        'If you did not ask for it, someone ran the test on the server: check who has access.\n',
    });
  } catch (err) {
    console.error(`\n  The relay did NOT accept the message (${(err as Error)?.name ?? 'error'}${(err as { code?: string })?.code ? `, ${(err as { code?: string }).code}` : ''}). Check SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS and SMTP_FROM, then restart SSO.\n`);
    process.exit(1);
  }
  console.log('  result:         the relay accepted the message. Check the mailbox (and the spam folder) to confirm it arrived.\n');
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
