/**
 * Owner verification: change the mailbox that receives the emailed code, or re-confirm it after the mail relay (SMTP_*) changed. Run it yourself, at a
 * terminal on the SSO server, with the SMTP settings already in place.
 *
 *   npm run owner:change-email
 *   node scripts/run-with-env.cjs production npx tsx scripts/owner-change-email.ts
 *
 * Needs the platform vault password AND a current code from your authenticator app (for an enrolment made without the authenticator: the three security
 * answers instead, so it is never fewer proofs), then proves the new mailbox by emailing it a code. Nothing else in the store changes (questions,
 * authenticator and recovery codes stay as they are).
 */
import '../src/config.js';
import crypto from 'node:crypto';
import { pool } from '../src/db/pool.js';
import { changeEmail, emailProblem } from '../src/owner/enrol.js';
import { verifyTotp } from '../src/auth/totp.js';
import { acceptTotpStep } from '../src/owner/limiter.js';
import { codeMail, currentMailer, smtpConfigured } from '../src/owner/mailer.js';
import { verifyAllAnswers } from '../src/owner/questions.js';
import { authenticatorRequired, readStore } from '../src/owner/store.js';
import { askHidden, askVisible, requireTerminal, vaultPasswordIsCorrect } from './lib/terminal.js';

async function main(): Promise<void> {
  requireTerminal();
  const store = await readStore();
  if (store.state !== 'ok') {
    console.error('\n  The store is not set up or cannot be opened. Use "npm run owner:enroll" or "npm run owner:recover".\n');
    process.exit(1);
  }
  if (!smtpConfigured()) {
    console.error('\n  SMTP is not configured (SMTP_* in this environment\'s env file). Set it first so the new mailbox can be proved. Nothing was changed.\n');
    process.exit(1);
  }
  if (!(await vaultPasswordIsCorrect(await askHidden('  Vault password: ')))) {
    console.error('\n  Wrong vault password (the vault counted it). Nothing was changed.\n');
    process.exit(1);
  }
  if (authenticatorRequired(store.doc)) {
    const secret = store.doc.totp?.secret;
    const step = secret ? verifyTotp(secret, (await askHidden('  Current 6-digit code from your authenticator app: ')).trim()) : null;
    if (step === null || !(await acceptTotpStep(step))) {
      console.error('\n  That authenticator code is not accepted. Nothing was changed.\n');
      process.exit(1);
    }
  } else {
    // This enrolment has no authenticator: the three security answers take its place here.
    const answers: string[] = [];
    for (const q of store.doc.questions) answers.push(await askHidden(`  Answer to "${q.prompt}": `));
    if (!(await verifyAllAnswers(store.keys, answers, store.doc.questions.map((q) => q.hash)))) {
      console.error('\n  Those answers are not accepted. Nothing was changed.\n');
      process.exit(1);
    }
  }
  const address = (await askVisible('  New mailbox address (or the same one, to re-confirm after an SMTP change): ')).trim();
  const problem = emailProblem(address);
  if (problem) {
    console.error(`\n  ${problem} Nothing was changed.\n`);
    process.exit(1);
  }
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  try {
    await currentMailer().send(codeMail(address, code, 'confirming the owner mailbox', 10));
  } catch {
    console.error('\n  The test email could not be sent. Check the SMTP_* settings. Nothing was changed.\n');
    process.exit(1);
  }
  if ((await askHidden('  Type the code from that email: ')).trim() !== code) {
    console.error('\n  That is not the code that was sent. Nothing was changed.\n');
    process.exit(1);
  }
  await changeEmail(store.keys, store.doc, address);
  console.log('\n  Done. The emailed code goes to that mailbox through the current mail relay.\n');
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
