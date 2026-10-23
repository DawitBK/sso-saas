import pino from "pino";
import path from "node:path";
import fs from "node:fs";

/**
 * Fields that must never reach a log file, wherever they appear (top level, or one level down in a logged object such as a request
 * body, a token response or an error's context). The log is kept for weeks and read by people who must not be able to sign in as
 * someone: passwords and hashes, two-factor secrets and recovery codes, every kind of token and authorization code, client secrets, CSRF tokens,
 * the cookie header (which carries the session), and the shared keys other systems present to SSO.
 */
export const LOG_REDACT_PATHS: string[] = [
  "req.headers.authorization", 'req.headers["x-owner-authorisation"]', "req.headers.cookie", 'req.headers["x-internal-api-key"]', 'req.headers["x-metrics-key"]', 'req.headers["set-cookie"]',
  "res.headers['set-cookie']",
  ...["password", "passwordHash", "password_hash", "current_password", "new_password", "confirm_password", "totpSecret", "totp_secret", "recoveryCode", "recovery_code", "authorization_code",
    "answers", "ticket", "recoveryCodes", "refreshToken", "refresh_token", "accessToken", "access_token", "idToken", "id_token", "logout_token", "client_secret", "clientSecret", "secret", "csrf", "authorization", "cookie"]
    .flatMap((k) => [k, `*.${k}`]),
];

const loggerOptions: pino.LoggerOptions = {
  name: "sso-backend",
  level: process.env.LOG_LEVEL ?? "info",
  redact: LOG_REDACT_PATHS,
  // Pino only auto-serializes a key literally named `err` (message/stack are
  // non-enumerable on Error instances, so `logger.error({ error }, ...)` —
  // this codebase's usual pattern — silently logged `{}` for every real
  // thrown Error). Serialize `error` the same way instead of rewriting every
  // call site.
  serializers: {
    err: pino.stdSerializers.err,
    error: pino.stdSerializers.err,
  },
};

// Production runs as a bare `node dist/main.js` in a console window (no
// Docker, no PM2 — see SERVER-INFRASTRUCTURE-AUDIT.md), so stdout with no
// configured destination means these logs only ever existed in that
// window's scrollback and were lost the moment it closed — the identity
// provider for the whole platform was logging to nowhere durable. Mirrors
// GMS's logger.ts file-transport pattern (logs/gms.log + error.log).
export const logger =
  process.env.NODE_ENV === "production"
    ? (() => {
        const logDir = path.join(process.cwd(), "logs");
        if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
        // pino-roll rotates from inside the process — this box has no
        // process supervisor (no PM2/Docker/NSSM) to signal a reopen after
        // an external rename, so plain pino/file would just grow forever.
        // 20MB/file, daily, 14 kept.
        return pino(
          loggerOptions,
          pino.transport({
            targets: [
              { target: "pino-roll", level: "info", options: { file: path.join(logDir, "sso"), size: "20m", frequency: "daily", limit: { count: 14 }, mkdir: true } },
              { target: "pino-roll", level: "error", options: { file: path.join(logDir, "error"), size: "20m", frequency: "daily", limit: { count: 14 }, mkdir: true } },
            ],
          }),
        );
      })()
    : pino(loggerOptions);
