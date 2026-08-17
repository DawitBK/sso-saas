import pino from "pino";

export const logger = pino({
  name: "sso-backend",
  level: process.env.LOG_LEVEL ?? "info",
  redact: ["req.headers.authorization", "password", "passwordHash", "totpSecret", "refreshToken"],
  // Pino only auto-serializes a key literally named `err` (message/stack are
  // non-enumerable on Error instances, so `logger.error({ error }, ...)` —
  // this codebase's usual pattern — silently logged `{}` for every real
  // thrown Error). Serialize `error` the same way instead of rewriting every
  // call site.
  serializers: {
    err: pino.stdSerializers.err,
    error: pino.stdSerializers.err,
  },
});
