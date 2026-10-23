/**
 * The owner-verification settings as the rest of the module reads them: from IDP_CONFIG, with a test-only override so a unit test can switch the
 * requirement on and point the store at a throwaway key file without reloading the configuration. The override refuses to work outside NODE_ENV=test.
 */
import { IDP_CONFIG } from '../config.js';

export interface SmtpSettings {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

interface Overrides {
  required?: boolean;
  authenticatorRequired?: boolean;
  storeKeyFile?: string;
  smtp?: SmtpSettings;
}
let overrides: Overrides = {};

export function __setOwnerRuntimeForTests(o: Overrides): void {
  if (process.env.NODE_ENV !== 'test') throw new Error('__setOwnerRuntimeForTests is for tests only');
  overrides = o;
}

/** Whether an owner-only operation needs an owner ticket right now. */
export function ownerVerificationRequired(): boolean {
  return overrides.required ?? IDP_CONFIG.ownerVerificationRequired;
}

/** Whether a NEW enrolment includes the authenticator (an existing enrolment is verified by the factors recorded in its own store, never by this). */
export function authenticatorRequiredForNewEnrolment(): boolean {
  return overrides.authenticatorRequired ?? IDP_CONFIG.ownerAuthenticatorRequired;
}

export function storeKeyFile(): string {
  return overrides.storeKeyFile ?? IDP_CONFIG.ownerStoreKeyFile;
}

export function smtpSettings(): SmtpSettings {
  return overrides.smtp ?? IDP_CONFIG.smtp;
}
