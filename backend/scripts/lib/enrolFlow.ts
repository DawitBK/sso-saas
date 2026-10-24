/**
 * The interactive part shared by `owner:enroll` and `owner:recover`: choose the three questions and answers, the mailbox address, confirm the mailbox
 * by sending a test code, set up the authenticator (only while OWNER_AUTHENTICATOR_REQUIRED is not false) and show the recovery codes once. Nothing typed here
 * is ever echoed, logged or kept. The factors the enrolment is made with are recorded in the sealed store.
 */
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateTotpSecret, otpauthUri, verifyTotp } from '../../src/auth/totp.js';
import { codeMail, currentMailer, smtpConfigured } from '../../src/owner/mailer.js';
import { DEFAULT_QUESTION_PROMPTS, emailProblem, enrolOwner, isInside } from '../../src/owner/enrol.js';
import { answerProblem } from '../../src/owner/questions.js';
import { acceptTotpStep } from '../../src/owner/limiter.js';
import { authenticatorRequiredForNewEnrolment } from '../../src/owner/runtime.js';
import type { StoreKeys } from '../../src/owner/seal.js';
import { repoRootFrom } from './repoRoot.js';
import { askHidden, askHiddenTwice, askVisible } from './terminal.js';

const here = path.dirname(fileURLToPath(import.meta.url));
/** The repository root (the nearest folder with a .git entry; without one, backend's parent). A key file anywhere under it is refused. */
export const REPO_ROOT = repoRootFrom(here, path.resolve(here, '../../..'));

export async function chooseKeyFile(current: string): Promise<string> {
  if (current) return current;
  console.log('  OWNER_STORE_KEY_FILE is not set. Choose where the key file goes: a path OUTSIDE the repository, readable only by the account that runs SSO.');
  const p = (await askVisible('  Key file path (for example C:\\secrets\\owner-store.key): ')).trim();
  if (!p) {
    console.error('  No path given. Nothing was changed.');
    process.exit(1);
  }
  return p;
}

export function refuseInsideRepo(file: string): void {
  if (isInside(file, REPO_ROOT)) {
    console.error('\n  The key file would be inside the repository. Choose a path outside it. Nothing was changed.\n');
    process.exit(1);
  }
}

export async function runEnrolment(keys: StoreKeys, accountId: string): Promise<void> {
  const withAuthenticator = authenticatorRequiredForNewEnrolment();
  const total = withAuthenticator ? 4 : 3;
  if (!withAuthenticator) {
    console.log('\n  OWNER_AUTHENTICATOR_REQUIRED is false: this enrolment has NO phone authenticator.');
    console.log('  Owner-only operations will need two proofs: the three security questions, then the emailed code (or one offline recovery code when email cannot be used).');
  }
  console.log(`\n  Step 1 of ${total}: the three security questions.`);
  console.log('  Press ENTER to keep a suggested question, or type your own wording. Then type the answer (hidden). Only a slow hash is stored.\n');
  const questions: Array<{ prompt: string; answer: string }> = [];
  for (let i = 0; i < DEFAULT_QUESTION_PROMPTS.length; i += 1) {
    const def = DEFAULT_QUESTION_PROMPTS[i] as string;
    const typed = (await askVisible(`  Question ${i + 1} [${def}]: `)).trim();
    const prompt = typed || def;
    for (;;) {
      const answer = await askHiddenTwice(`  Answer to "${prompt}"`);
      if (answer === null) continue;
      const problem = answerProblem(answer);
      if (problem) {
        console.error(`    ${problem}`);
        continue;
      }
      questions.push({ prompt, answer });
      break;
    }
  }

  console.log(`\n  Step 2 of ${total}: your mailbox.`);
  let emailAddress = '';
  for (;;) {
    emailAddress = (await askVisible('  Mailbox address that will receive verification codes: ')).trim();
    const problem = emailProblem(emailAddress);
    if (!problem) break;
    console.error(`    ${problem}`);
  }
  if (smtpConfigured()) {
    process.stdout.write('  Sending a test code to that mailbox...\n');
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    try {
      await currentMailer().send(codeMail(emailAddress, code, 'enrolment test', 10));
    } catch {
      console.error('\n  The test email could not be sent. Check the SMTP_* settings and try again. Nothing was changed.\n');
      process.exit(1);
    }
    const typed = (await askHidden('  Type the code from that email: ')).trim();
    if (typed !== code) {
      console.error('\n  That is not the code that was sent. Nothing was changed.\n');
      process.exit(1);
    }
  } else {
    console.log('  SMTP is not configured here, so the emailed code cannot be sent yet. Until SMTP is set up and "npm run owner:change-email" has been run,');
    console.log('  one offline recovery code takes the place of the emailed code at every verification.');
  }

  let secret: string | undefined;
  let step: number | null = null;
  if (withAuthenticator) {
    console.log('\n  Step 3 of 4: the phone authenticator.');
    secret = generateTotpSecret();
    console.log('  In your authenticator app add a new account by typing this key (time based, 6 digits):\n');
    console.log(`    ${secret.match(/.{1,4}/g)?.join(' ')}\n`);
    console.log(`  Or open this link on the phone:  ${otpauthUri('owner', secret)}\n`);
    for (let tries = 0; tries < 5 && step === null; tries += 1) {
      const typed = (await askHidden('  Type the 6-digit code the app shows now: ')).trim();
      step = verifyTotp(secret, typed);
      if (step === null) console.error('    That code is not right. Check the phone clock and try again.');
    }
    if (step === null) {
      console.error('\n  The authenticator could not be confirmed. Nothing was changed.\n');
      process.exit(1);
    }
  }

  const { codes } = await enrolOwner({ keys, accountId, questions, emailAddress, ...(withAuthenticator ? { totpSecret: secret } : { authenticator: false }) });
  if (step !== null) await acceptTotpStep(step);

  console.log(`\n  Step ${total} of ${total}: your offline recovery codes. THIS IS THE ONLY TIME THEY ARE SHOWN.`);
  console.log('  Write them on paper and keep the paper somewhere only you can reach. Each works once, and only when the emailed code cannot be used.\n');
  for (const c of codes) console.log(`    ${c}`);
  for (;;) {
    const ok = (await askVisible('\n  Type SAVED when you have written them down: ')).trim();
    if (ok === 'SAVED') break;
  }
  // Push the codes out of the visible scrollback.
  process.stdout.write('\u001b[2J\u001b[3J\u001b[H');
  console.log('\n  Owner verification is set up. Run "npm run owner:status" to check it (it shows no secret).');
  if (!withAuthenticator) console.log('  This enrolment has no authenticator: anyone who knows the answers AND controls the mailbox can act as the owner. To add one later, set OWNER_AUTHENTICATOR_REQUIRED=true and run owner:recover.');
  console.log('');
}
