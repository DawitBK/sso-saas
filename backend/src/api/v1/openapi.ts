/**
 * OpenAPI spec for SSO's own custom API surface (Directive §6.11, §7.2).
 *
 * Scope: only the hand-rolled routes SSO owns itself. OIDC's own protocol
 * endpoints (/authorize, /token, /userinfo, /jwks, /.well-known/openid-
 * configuration, etc.) are already self-describing per the OIDC/OAuth2 spec
 * and are deliberately NOT re-documented here - that would duplicate a
 * standard, machine-readable contract oidc-provider already exposes, exactly
 * the "silently drift from the real endpoints" risk §7.2 warns about. The
 * admin/portal/interaction/bridge routes are browser-navigated view-model
 * pages (see PLATFORM-GAP-008's resolution), not a documented external API
 * surface, so they're out of scope here too - this documents the two-request-
 * class machine-to-machine surface: platform health/metrics, and the
 * internal GMS role-grant API.
 *
 * Kept as a plain object literal (not swagger-jsdoc route-comment scanning)
 * to match GMS's own src/api/swagger.ts pattern for platform consistency.
 */
import { IDP_CONFIG } from '../../config.js';

export const openApiSpec = {
  openapi: '3.0.0',
  info: {
    title: 'SSO Platform API',
    version: '1.0.0',
    description:
      'SSO/IdP\'s own custom API surface: platform health/metrics and the ' +
      'internal GMS role-grant API. OIDC\'s own endpoints (authorize, token, ' +
      'userinfo, jwks, discovery) are not documented here - see ' +
      '/.well-known/openid-configuration, which is already self-describing ' +
      'per the OIDC spec.',
  },
  // Prefixed with publicBasePath (same pattern as admin/csrf.ts's cookie
  // paths) so Swagger UI's "Try it out" resolves through the Apache /sso
  // prefix in production instead of a bare, unreachable /api/v1.
  servers: [{ url: `${IDP_CONFIG.publicBasePath}/api/v1`, description: 'Versioned platform API' }],
  components: {
    securitySchemes: {
      internalApiKey: {
        type: 'apiKey',
        in: 'header',
        name: 'x-internal-api-key',
        description:
          'Shared secret for service-to-service calls (SSO_ROLES_API_KEY). ' +
          'Required on every /internal/gms/* route; constant-time compared.',
      },
    },
    schemas: {
      ApiError: {
        type: 'object',
        properties: {
          error: {
            type: 'object',
            properties: {
              code: { type: 'string', example: 'ERR-DEPENDENCY-UNAVAILABLE' },
              message: { type: 'string' },
              details: {
                type: 'array',
                nullable: true,
                items: {
                  type: 'object',
                  properties: {
                    field: { type: 'string', nullable: true },
                    message: { type: 'string' },
                  },
                },
              },
            },
          },
          meta: {
            type: 'object',
            properties: { requestId: { type: 'string' } },
          },
        },
      },
      InternalApiError: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          error: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              details: {
                type: 'array',
                nullable: true,
                items: {
                  type: 'object',
                  properties: {
                    field: { type: 'string', nullable: true },
                    message: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  paths: {
    '/health': {
      get: {
        summary: 'Liveness check',
        description: 'Always returns 200 if the process is up; does not check dependencies.',
        tags: ['Platform'],
        responses: {
          '200': {
            description: 'OK',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    data: {
                      type: 'object',
                      properties: {
                        status: { type: 'string', example: 'ok' },
                        issuer: { type: 'string', example: IDP_CONFIG.issuer },
                        gmsBridge: { type: 'boolean' },
                      },
                    },
                    meta: { type: 'object', properties: { requestId: { type: 'string' } } },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/health/ready': {
      get: {
        summary: 'Readiness check',
        description:
          'ready: everything works. degraded: SSO is signing people in but something around it is unwell (Redis, DMS, GMS, a pending migration, stuck sign-out notices, ' +
          'an unexplained break in the audit chain); still HTTP 200 so a monitor keeps sending traffic. not_ready (HTTP 503): the database or the active signing key is unusable. ' +
          'The body carries state words only.',
        tags: ['Platform'],
        responses: {
          '200': {
            description: 'Ready',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    data: {
                      type: 'object',
                      properties: {
                        status: { type: 'string', enum: ['ready', 'degraded', 'not_ready'], example: 'ready' },
                        db: { type: 'string', enum: ['ok', 'unreachable'] },
                        checks: { type: 'object', additionalProperties: { type: 'string', enum: ['ok', 'degraded', 'down', 'off'] } },
                      },
                    },
                  },
                },
              },
            },
          },
          '503': {
            description: 'Not ready: the database or the active signing key is unusable',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
          },
        },
      },
    },
    '/metrics': {
      get: {
        summary: 'Platform metrics snapshot',
        description:
          'Counts of users, active sessions (SSO/portal/gateway), login attempts in the ' +
          'last hour, and active signing keys. Not rate-limited; not cached (cache-control: no-store). Needs a signed-in console administrator, the x-metrics-key header, ' +
          'or ENABLE_PUBLIC_METRICS_ROUTE. JSON by default; with ?format=prometheus (or an Accept header asking for text/plain or OpenMetrics) the same facts plus jobs, ' +
          'readiness checks, the audit chain, supervision and request timings as Prometheus text exposition 0.0.4.',
        tags: ['Platform'],
        parameters: [{ name: 'format', in: 'query', required: false, schema: { type: 'string', enum: ['prometheus', 'json'] } }],
        responses: {
          '200': {
            description: 'OK',
            content: {
              'text/plain': { schema: { type: 'string', example: '# TYPE sso_up gauge\nsso_up 1\n' } },
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    data: {
                      type: 'object',
                      properties: {
                        users_total: { type: 'integer' },
                        users_active: { type: 'integer' },
                        users_mfa_enrolled: { type: 'integer' },
                        sessions_sso_active: { type: 'integer' },
                        sessions_portal_active: { type: 'integer' },
                        sessions_gateway_active: { type: 'integer' },
                        logins_attempted_1h: { type: 'integer' },
                        logins_failed_1h: { type: 'integer' },
                        signing_keys_active: { type: 'integer' },
                      },
                    },
                  },
                },
              },
            },
          },
          '503': {
            description: 'Database unreachable',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } },
          },
        },
      },
    },
    '/auth/password-reset-request': {
      post: {
        summary: 'Ask the administrators to reset a password (no email is sent)',
        description:
          'Public. Always answers the same way, whether or not the address has an account, so it cannot be used to find out who has one. A request is recorded only for an ' +
          'active local account; the administrators see it under Admin > Users and reset the password by hand. Five a quarter hour per address. Off when the setting ' +
          'password.allowResetRequests is off.',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email'],
                properties: { email: { type: 'string', format: 'email' }, note: { type: 'string', maxLength: 200 } },
              },
            },
          },
        },
        responses: {
          '200': { description: 'The same answer for every address', content: { 'application/json': { schema: { type: 'object', properties: { data: { type: 'object', properties: { message: { type: 'string' } } } } } } } },
          '429': { description: 'Too many requests from this address', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
        },
      },
    },
    '/internal/gms/users/{email}/roles': {
      get: {
        summary: "Read a user's current GMS role grant",
        description:
          'Returns the explicit per-user grant only (idp_client_user_roles), NOT the ' +
          'fully-resolved role (which also considers AD group mapping and the guest ' +
          'default - see resolveGmsRoles in auth/client-role-claims.ts). An empty array ' +
          'means no explicit grant exists; resolution falls through to group mapping.',
        tags: ['GMS role grants (internal)'],
        security: [{ internalApiKey: [] }],
        parameters: [
          {
            name: 'email',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'email' },
          },
        ],
        responses: {
          '200': {
            description: 'OK',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        roles: { type: 'array', items: { type: 'string' }, example: ['reception'] },
                      },
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid email',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/InternalApiError' } } },
          },
          '401': {
            description: 'Missing or invalid x-internal-api-key',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/InternalApiError' } } },
          },
        },
      },
      put: {
        summary: "Replace a user's entire GMS role grant set",
        description:
          'Full replace, not incremental add/remove - matches GMS admin UI\'s own PATCH ' +
          '/:id/roles semantics. Every role name is validated against the gms client\'s ' +
          'role catalog (idp_client_roles) before anything is written; if any role in the ' +
          'array is invalid, nothing is written (all-or-nothing).',
        tags: ['GMS role grants (internal)'],
        security: [{ internalApiKey: [] }],
        parameters: [
          {
            name: 'email',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'email' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['roles'],
                properties: {
                  roles: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Empty array revokes every grant (falls through to group mapping/default).',
                    example: ['reception', 'host'],
                  },
                  grantedBy: {
                    type: 'string',
                    description: "Defaults to 'gms' if omitted.",
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'OK - returns the resulting grant set',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: { roles: { type: 'array', items: { type: 'string' } } },
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid email, malformed body, or a role name not in the catalog',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/InternalApiError' } } },
          },
          '401': {
            description: 'Missing or invalid x-internal-api-key',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/InternalApiError' } } },
          },
        },
      },
    },
    '/licenses/public/{system}': {
      get: {
        summary: 'Signed licence token for one system (GMS or DMS)',
        description:
          'Unauthenticated and rate-limited (60 a minute per address). Returns a compact JWS signed with the OIDC signing key (header typ "kcms-license+jwt", no exp claim) ' +
          'carrying the licence terms for that system; GMS and DMS poll it and verify it against /jwks. 404 means no licence is configured for the system, which every ' +
          'consumer treats as "nothing to enforce". See docs/operations/PLATFORM-LICENSING.md.',
        tags: ['Licensing'],
        parameters: [{ name: 'system', in: 'path', required: true, schema: { type: 'string', enum: ['sso', 'gms', 'dms'] } }],
        responses: {
          '200': {
            description: 'The signed licence token',
            content: { 'application/json': { schema: { type: 'object', properties: { token: { type: 'string' } } } } },
          },
          '404': { description: 'No licence configured for this system (or an unknown system)' },
          '429': { description: 'Rate limit exceeded' },
        },
      },
    },
    '/licenses/status': {
      get: {
        summary: "SSO's own licence status",
        description:
          'Needs a signed-in portal session of the platform administrator. Also served at /license/status. Returns the state (unconfigured, active, expiring, grace, expired), the dates, ' +
          'whether SSO is read-only because of it, and the seat and module terms.',
        tags: ['Licensing'],
        responses: {
          '200': { description: 'Licence status' },
          '401': { description: 'Not signed in' },
          '403': { description: 'Not the platform administrator' },
        },
      },
    },
  },
};
