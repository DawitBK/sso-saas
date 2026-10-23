/**
 * Sending the owner's emailed code, straight through SSO's own SMTP settings (SMTP_*). SSO had no mailer before this: nothing else here sends mail.
 *
 * The code is passed to the transport and never logged; the mailbox address is never logged either (a masked form is shown to the owner). The
 * email factor is AVAILABLE whenever SMTP is configured in the running environment, and the code is always sent through the relay configured there NOW
 * (owner decision 2026-10-21: change SMTP_* in the env file and restart SSO; it works on the server, a development machine or anywhere else). If SMTP is
 * removed altogether the factor is unavailable and an offline recovery code takes its place. The fingerprint (host, port, TLS, user: not the password) of the
 * relay at enrolment is still recorded, and a later difference is only logged as a notice. `npm run owner:test-mail` proves delivery from any environment.
 */
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import { smtpSettings, type SmtpSettings } from './runtime.js';

export interface OwnerMail {
  to: string;
  subject: string;
  text: string;
}
export interface OwnerMailer {
  send(mail: OwnerMail): Promise<void>;
}

let injected: OwnerMailer | null = null;
/** Test-only: a fake transport. */
export function __setOwnerMailerForTests(m: OwnerMailer | null): void {
  if (process.env.NODE_ENV !== 'test') throw new Error('__setOwnerMailerForTests is for tests only');
  injected = m;
}

export function smtpConfigured(s: SmtpSettings = smtpSettings()): boolean {
  return Boolean(s.host && (s.from || s.user));
}

/** Identifies the relay without any secret: a change of host, port, TLS or account changes it. */
export function smtpFingerprint(s: SmtpSettings = smtpSettings()): string {
  if (!smtpConfigured(s)) return '';
  return crypto.createHash('sha256').update(`smtp\n${s.host.toLowerCase()}\n${s.port}\n${s.secure}\n${s.user.toLowerCase()}`).digest('hex').slice(0, 32);
}

export function realMailer(s: SmtpSettings = smtpSettings()): OwnerMailer {
  const transport = nodemailer.createTransport({
    host: s.host,
    port: s.port,
    secure: s.secure,
    ...(s.user ? { auth: { user: s.user, pass: s.pass } } : {}),
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 15_000,
  });
  return {
    async send(mail) {
      await transport.sendMail({ from: s.from || s.user, to: mail.to, subject: mail.subject, text: mail.text });
    },
  };
}

export function currentMailer(): OwnerMailer {
  return injected ?? realMailer();
}

/** `d***@g***.com`: enough for the owner to recognise their mailbox, not enough to be useful to anyone else. */
export function maskAddress(address: string): string {
  const at = address.lastIndexOf('@');
  if (at < 1) return '***';
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  const dot = domain.lastIndexOf('.');
  const host = dot > 0 ? domain.slice(0, dot) : domain;
  const tld = dot > 0 ? domain.slice(dot) : '';
  return `${local[0]}***@${host[0] ?? ''}***${tld}`;
}

export function codeMail(to: string, code: string, label: string, minutes: number): OwnerMail {
  return {
    to,
    subject: 'Your owner verification code',
    text:
      `Your owner verification code is: ${code}\n\n` +
      `It was asked for to authorise: ${label}.\n` +
      `It works once and expires in ${minutes} minutes.\n\n` +
      'If you did not just ask for this, do not enter it anywhere. Someone may be using your session: sign out everywhere and tell the person who runs the server.\n',
  };
}
