/**
 * Terminal helpers for the owner tools. Everything secret is read from a REAL terminal with echo off; nothing is accepted from argv, the
 * environment, a file or a pipe, so nothing automated (a script, CI, an AI agent) can drive these tools. Same approach as platform-vault.ts.
 */
import pg from 'pg';
import { IDP_CONFIG } from '../../src/config.js';

export function requireTerminal(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error('\n  This tool needs an interactive terminal. Answers and codes are never accepted from a pipe, a file or an argument.\n');
    process.exit(2);
  }
}

export function askHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n' || c === '\u0004') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(buf);
          return;
        }
        if (c === '\u0003') {
          stdin.setRawMode(false);
          process.stdout.write('\n');
          process.exit(130);
        }
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1);
        else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

export function askVisible(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.once('data', (d) => {
      process.stdin.pause();
      resolve(String(d).trim());
    });
  });
}

/** Ask for a secret twice; returns null (after saying why) if the two differ. */
export async function askHiddenTwice(prompt: string): Promise<string | null> {
  const a = await askHidden(`${prompt}: `);
  const b = await askHidden('    Type it again to confirm: ');
  if (a !== b) {
    console.error('    The two entries differ.');
    return null;
  }
  return a;
}

/**
 * Check the platform vault password (the one `platform-vault.ts set` chose) without keeping the vault open: unlock, then lock at once.
 * A wrong password is counted by the vault itself, exactly as with the vault tool.
 */
export async function vaultPasswordIsCorrect(password: string): Promise<boolean> {
  const client = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await client.connect();
  try {
    const ok = (await client.query('SELECT platform_vault_unlock($1, 1) AS ok', [password])).rows[0]?.ok === true;
    if (ok) await client.query('SELECT platform_vault_lock()');
    return ok;
  } finally {
    await client.end();
  }
}
