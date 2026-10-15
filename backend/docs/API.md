# SSO Backend JSON API Documentation

## Overview

The SSO backend provides JSON API endpoints for the Next.js frontend. All endpoints return standardized JSON responses with proper error handling.

## Base URL

```
http://localhost:7300/api/v1
```

## Response Format

### Success Response

```json
{
  "data": { /* response data */ },
  "meta": {
    "requestId": "uuid-v4"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "ERR-CODE",
    "message": "Human readable error message",
    "details": [ /* optional field-level errors */ ]
  },
  "meta": {
    "requestId": "uuid-v4"
  }
}
```

## Authentication

Most endpoints require an authenticated session via the `idp_portal` cookie. This cookie is set by the OIDC login flow.

## Endpoints

All mutation endpoints (POST/PUT/DELETE) require CSRF token validation. Include the CSRF token in the request body as `csrf` field.

### Platform Endpoints

#### GET /api/v1/health

Health check endpoint.

**Response:**
```json
{
  "data": {
    "status": "ok",
    "issuer": "https://sso.example.com",
    "gmsBridge": true
  }
}
```

#### GET /api/v1/health/ready

Readiness check with database connectivity.

**Response:**
```json
{
  "data": {
    "status": "ready",
    "dependencies": {
      "database": "ok"
    }
  }
}
```

#### GET /api/v1/metrics   (and GET /metrics on the backend's own port)

System metrics and statistics. Not public: a signed-in console administrator, a caller sending `METRICS_API_KEY` as the `x-metrics-key` header, or anyone if
`ENABLE_PUBLIC_METRICS_ROUTE=true`.

**Two formats, one route.** The JSON below is the default (curl, a browser, the console). A scraper gets **Prometheus text exposition (version 0.0.4)**
with `?format=prometheus`, or by sending an `Accept` header that asks for `text/plain` or OpenMetrics and not JSON (Prometheus does this itself).
The text carries the same facts as the System page: `sso_up`, `sso_build_info`, process memory and uptime, `sso_supervised` and restart counts,
`sso_readiness_status` / `sso_readiness_check{check,state}`, users and sessions, sign-ins in the last hour, `sso_job_*` (runs, failures, last success,
overdue), `sso_password_checks*` (running, waiting, refused), `sso_notifications_*`, `sso_peer_up`, `sso_circuit_breaker_*`, `sso_db_pool_connections`,
`sso_audit_chain_*` (valid, open breaks, acknowledged breaks, last verified) and `sso_http_requests_total` / `sso_http_request_duration_seconds`
(labelled by a fixed set of areas and the status class only). No user data, no secrets. Scrape the backend's own port (7300; 9300 on the mirror):

```yaml
- job_name: sso
  metrics_path: /metrics
  params: { format: [prometheus] }
  static_configs: [{ targets: ['127.0.0.1:7300'] }]
  # send the header x-metrics-key: <METRICS_API_KEY> (set it in .env.production first)
```

**Response:**
```json
{
  "data": {
    "users_total": 150,
    "users_active": 142,
    "users_mfa_enrolled": 89,
    "sessions_sso_active": 45,
    "sessions_portal_active": 23,
    "sessions_gateway_active": 12,
    "logins_attempted_1h": 67,
    "logins_failed_1h": 3,
    "signing_keys_active": 2
  }
}
```

---

### Authentication Endpoints

#### GET /api/v1/auth/session

Get current authenticated user session.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "authenticated": true,
    "user": {
      "accountId": "user-uuid",
      "name": "John Doe",
      "email": "john@example.com",
      "isAdmin": false
    }
  }
}
```

**Errors:**
- `401 ERR-NOT-AUTHENTICATED`: No active session

#### GET /api/v1/auth/check

Quick authentication status check.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "authenticated": true
  }
}
```

---

### Portal Endpoints

#### GET /api/v1/portal

Get portal data including user info and entitled applications.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "user": {
      "name": "John Doe",
      "email": "john@example.com",
      "isAdmin": false
    },
    "apps": [
      {
        "rp": "edams",
        "name": "EDAMS — Document Management",
        "url": "http://localhost:7100/api/v1/auth/oidc/authorize",
        "mode": "Open"
      },
      {
        "rp": "gms",
        "name": "GMS — Guest Management",
        "url": "/bridge/gms/start",
        "mode": "Open"
      }
    ],
    "csrf": "csrf-token-hex"
  }
}
```

**Errors:**
- `401 ERR-NOT-AUTHENTICATED`: No active session

---

### Admin Endpoints

All admin endpoints require membership in the admin group.

#### GET /api/v1/admin/stats

Get dashboard statistics.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "adminEmail": "admin@example.com",
    "userCount": 150,
    "groupCount": 42,
    "dmsConnected": true,
    "stats": {
      "sso": 45,
      "portal": 23,
      "fails": 7,
      "audits": 234
    },
    "alerts": [
      {
        "email": "user@example.com",
        "failures": 8
      }
    ]
  }
}
```

**Errors:**
- `401 ERR-NOT-AUTHENTICATED`: No active session
- `403 ERR-FORBIDDEN`: Not an admin user

#### GET /api/v1/admin/users

List users with pagination and search.

**Authentication:** Required (Admin)

**Query Parameters:**
- `q` (optional): Search query (filters by email)
- `page` (optional): Page number (default: 1)

**Response:**
```json
{
  "data": {
    "users": [
      {
        "id": "user-uuid",
        "email": "john@example.com",
        "given_name": "John",
        "family_name": "Doe",
        "is_active": true,
        "source": "local",
        "last_login_at": "2026-07-26T10:30:00Z",
        "group_count": 3
      }
    ],
    "pagination": {
      "page": 1,
      "pageSize": 20,
      "total": 150,
      "totalPages": 8
    },
    "query": "",
    "adminEmail": "admin@example.com"
  }
}
```

#### GET /api/v1/admin/users/:id

Get detailed user information.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "user": {
      "id": "user-uuid",
      "email": "john@example.com",
      "email_verified": true,
      "given_name": "John",
      "family_name": "Doe",
      "is_active": true,
      "source": "local",
      "must_change_password": false,
      "totp_enabled": true,
      "failed_logins": 0,
      "locked_until": null,
      "last_login_at": "2026-07-26T10:30:00Z",
      "created_at": "2026-01-15T08:00:00Z",
      "updated_at": "2026-07-26T10:30:00Z"
    },
    "groups": [
      "CN=DMS-Users,OU=Groups,DC=examplecorp,DC=com"
    ],
    "isAdmin": false,
    "liveDms": {
      "exists": true,
      "id": "dms-user-id",
      "roles": ["CLERK"],
      "officeId": null,
      "active": true,
      "error": null
    },
    "history": [
      {
        "actor_email": "admin@example.com",
        "action": "user.create",
        "detail": {},
        "created_at": "2026-01-15T08:00:00Z"
      }
    ],
    "adminEmail": "admin@example.com",
    "csrf": "csrf-token-hex"
  }
}
```

**Errors:**
- `404 ERR-USER-NOT-FOUND`: User not found

#### GET /api/v1/admin/groups

List all groups in the system. `?q=` narrows by a piece of the group name (case-insensitive); `?page=` and `?limit=` (up to 200) page the result.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "groups": [
      { "dn": "CN=DMS-Users,OU=Groups,DC=examplecorp,DC=com", "memberCount": 12, "apps": [{ "rp": "edams", "label": "EDAMS (DMS)" }] },
      { "dn": "CN=GMS-Staff,OU=Groups,DC=examplecorp,DC=com", "memberCount": 4, "apps": [] }
    ],
    "filters": { "q": "" },
    "pagination": { "page": 1, "pageSize": 50, "total": 2, "totalPages": 1 },
    "adminEmail": "admin@example.com",
    "csrf": "csrf-token-hex"
  }
}
```

#### Applications (clients): `/api/v1/admin/clients`

| Method and path | Who | What |
|---|---|---|
| `GET /api/v1/admin/clients` | any console administrator | Every client: `clientId`, `name`, `active`, `scopes`, `grantTypes`, `redirectUris`, `postLogoutRedirectUris`, `urisDrift`, `secretIsDevDefault`, `secretRotatedAt`, `usage`, `entitledUsers`, `secretNote`. Never the secret. Also `viewerIsPlatformAdmin`, `protectedClients`, `csrf`. |
| `GET /api/v1/admin/clients/:clientId` | any console administrator | One client. 404 for an id that is not one of the deployment's clients. |
| `GET /api/v1/admin/clients/:clientId/users` | any console administrator | The people who may open the application. |
| `PUT /api/v1/admin/clients/:clientId/uris` | platform administrator | `{ redirectUris, postLogoutRedirectUris, csrf }`. https only (http on a loopback host outside production), no wildcard, no fragment, at most 20. The GMS bridge's own callback must stay registered. |
| `POST /api/v1/admin/clients/:clientId/restore-uris` | platform administrator | Put the configured addresses back. |
| `PUT /api/v1/admin/clients/:clientId/active` | platform administrator | `{ active, csrf }`. Switching off also deletes the client's grants and tokens. |
| `POST /api/v1/admin/clients/:clientId/rotate-secret` | platform administrator | `{ confirm: "<clientId>", csrf }`. Returns the new `secret` once. |

The `portal` client answers 409 `ERR-CLIENT-PROTECTED` to edit, switch-off and rotate. Every change is audited (`client.uris.update`,
`client.uris.restore`, `client.enable`, `client.disable`, `client.secret.rotate`; the secret itself is never logged or audited).
Changes apply on the next request, no restart.

#### GET /api/v1/admin/sessions

List active SSO sessions.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "sessions": [
      {
        "id": "session-id",
        "kind": "Session",
        "account_id": "user-uuid",
        "email": "john@example.com",
        "created_at": "2026-07-26T10:30:00Z",
        "expires_at": "2026-07-27T10:30:00Z"
      }
    ],
    "adminEmail": "admin@example.com",
    "csrf": "csrf-token-hex"
  }
}
```

#### GET /api/v1/admin/logins

Login history with pagination.

**Authentication:** Required (Admin)

**Query Parameters:**
- `page` (optional): Page number (default: 1)

**Response:**
```json
{
  "data": {
    "logins": [
      {
        "id": 12345,
        "email": "john@example.com",
        "success": true,
        "reason": "",
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "created_at": "2026-07-26T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "pageSize": 50,
      "total": 5420,
      "totalPages": 109
    },
    "adminEmail": "admin@example.com"
  }
}
```

#### GET /api/v1/admin/keys

List signing keys.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "keys": [
      {
        "kid": "key-id-1",
        "alg": "RS256",
        "use": "sig",
        "isActive": true,
        "createdAt": "2026-01-01T00:00:00Z",
        "retiredAt": null
      }
    ],
    "adminEmail": "admin@example.com",
    "csrf": "csrf-token-hex"
  }
}
```

#### GET /api/v1/admin/audit

Audit log with pagination.

**Authentication:** Required (Admin)

**Query Parameters:**
- `limit` (optional): Number of entries (1-100, default: 50)
- `offset` (optional): Offset for pagination (default: 0)

**Response:**
```json
{
  "data": {
    "entries": [
      {
        "id": 12345,
        "actor_email": "admin@example.com",
        "action": "user.create",
        "target": "john@example.com",
        "detail": {},
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "created_at": "2026-07-26T10:30:00Z"
      }
    ],
    "pagination": {
      "limit": 50,
      "offset": 0
    },
    "adminEmail": "admin@example.com"
  }
}
```

#### GET /api/v1/admin/role-catalog

Get available roles for DMS and GMS.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "dmsRoles": ["CLERK", "SUPERVISOR", "MANAGER"],
    "gmsRoles": ["STAFF", "RECEPTIONIST"],
    "gmsOfficeScopedRoles": ["OFFICE_MANAGER"],
    "dmsConnected": true,
    "limits": { "email": 254, "name": 100, "passwordMinLength": 12, "passwordMaxLength": 200 },
    "csrf": "csrf-token"
  }
}
```

`limits` is what the create-user form's inputs stop at. The server enforces the same numbers (`admin/user-input.ts`) and so does the database (migration 023), so the form reads them here instead of keeping its own copy; `passwordMinLength` is the live platform setting.

#### GET /api/v1/admin/offices

Get GMS offices list.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "offices": [
      {
        "id": 1,
        "name": "Main Office"
      },
      {
        "id": 2,
        "name": "Branch Office"
      }
    ]
  }
}
```

**Errors:**
- `503 ERR-GMS-NOT-CONFIGURED`: GMS internal API key not configured
- `503 ERR-GMS-UNAVAILABLE`: Cannot reach GMS internal API

---

## Error Codes

| Code | Description |
|------|-------------|
| `ERR-NOT-AUTHENTICATED` | No active session, authentication required |
| `ERR-FORBIDDEN` | User lacks required permissions |
| `ERR-USER-NOT-FOUND` | Requested user does not exist |
| `ERR-GMS-NOT-CONFIGURED` | GMS integration not configured |
| `ERR-GMS-UNAVAILABLE` | GMS service unavailable |
| `ERR-DEPENDENCY-UNAVAILABLE` | Database or other dependency unavailable |
| `ERR-VALIDATION-FAILED` | Input refused; `error.details` is a list of `{ field, message }`, one per field (create user: `email`, `given_name`, `family_name`, `office_id`) |
| `ERR-INVALID-JSON` | The request body is not valid JSON (400) |
| `ERR-PAYLOAD-TOO-LARGE` | The request is larger than the server accepts (413) |
| `ERR-UNSUPPORTED-MEDIA-TYPE` | Content type, encoding or character set not supported (415) |
| `ERR-VALUE-TOO-LONG`, `ERR-VALUE-OUT-OF-RANGE` | A value reached the database and was refused for its size (400). Means a validator and the schema disagree; logged at warn |
| `ERR-REQUIRED-FIELD` | A required value was missing at the database (400) |
| `ERR-CONSTRAINT-VIOLATION` | A value the table does not allow (422) |
| `ERR-DUPLICATE`, `ERR-REFERENCE` | A duplicate, or a record still used by another (409) |
| `ERR-RATE-LIMITED`, `ERR-NOT-FOUND`, `ERR-METHOD-NOT-ALLOWED`, `ERR-CONFLICT`, `ERR-UNPROCESSABLE` | The standard answer for a 429, 404, 405, 409 or 422 raised outside a route's own handling |
| `ERR-INTERNAL` | A fault (500). The message never carries the cause; it is in the log under the request id |

## CORS Configuration

The API supports cross-origin requests from the Next.js frontend. Ensure the following headers are set:

```
Access-Control-Allow-Origin: http://localhost:7301
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

## Rate Limiting

The following endpoints have rate limiting applied:

- Authentication endpoints: 20 requests/minute
- Token endpoint: 60 requests/minute

## Development

### Testing Endpoints

Use curl or similar tools:

```bash
# Get session (requires cookie)
curl -b cookies.txt http://localhost:7300/api/v1/auth/session

# Get portal data
curl -b cookies.txt http://localhost:7300/api/v1/portal

# Get admin stats
curl -b cookies.txt http://localhost:7300/api/v1/admin/stats
```

### Adding New Endpoints

1. Create or update router file in `src/api/v1/`
2. Use `sendOk()` and `sendError()` helper functions
3. Follow standardized response format
4. Add authentication/authorization as needed
5. Update this documentation

## Migration Notes

The backend now provides both:
1. **View model responses** (for the Next.js sign-in and portal pages): `application/vnd.sso.view+json`
2. **JSON API responses** (for the console and other callers): standard JSON

The `viewModelMiddleware` intercepts `res.render()` calls and converts them to JSON when requested with the appropriate header. The server-rendered
admin console that once used the same renders was removed on 2026-10-11; only the interaction and portal pages still go through it.


---

### Admin Mutation Endpoints

All mutation endpoints require admin authentication and CSRF token validation.

#### POST /api/v1/admin/users

Create a new user.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token",
  "email": "john@example.com",
  "given_name": "John",
  "family_name": "Doe",
  "password": "secure-password-123",
  "dms_role": "CLERK",
  "gms_role": "STAFF",
  "office_id": 1
}
```

**Response:**
```json
{
  "data": {
    "userId": "user-uuid",
    "email": "john@example.com"
  }
}
```

**Errors:**
- `400 ERR-VALIDATION-FAILED`: Invalid input
- `409 ERR-USER-EXISTS`: Email already in use

#### PUT /api/v1/admin/users/:id

Update user details.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token",
  "given_name": "John",
  "family_name": "Smith",
  "is_active": true
}
```

**Response:**
```json
{
  "data": {
    "success": true
  }
}
```

#### POST /api/v1/admin/users/:id/reset-password

Reset user password (forces change on next login).

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token",
  "password": "new-password-123"
}
```

**Response:**
```json
{
  "data": {
    "success": true
  }
}
```

**Side Effects:**
- All user sessions revoked
- `must_change_password` flag set to true

#### POST /api/v1/admin/users/:id/groups

Add user to a group.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token",
  "group_dn": "CN=DMS-Users,OU=Groups,DC=examplecorp,DC=com"
}
```

**Response:**
```json
{
  "data": {
    "success": true
  }
}
```

**Side Effects:**
- All user sessions revoked

#### DELETE /api/v1/admin/users/:id/groups/:dn

Remove user from a group.

**Authentication:** Required (Admin)

**Query Parameters:**
- `csrf`: CSRF token (required for DELETE)

**Response:**
```json
{
  "data": {
    "success": true
  }
}
```

**Side Effects:**
- All user sessions revoked

#### POST /api/v1/admin/sessions/revoke

Revoke a session.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token",
  "session_id": "session-uuid"
}
```

**Response:**
```json
{
  "data": {
    "success": true,
    "revoked": true
  }
}
```

#### POST /api/v1/admin/keys/generate

Generate a new signing key.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token"
}
```

**Response:**
```json
{
  "data": {
    "kid": "key-uuid"
  }
}
```

**Side Effects:**
- New key immediately active for signing
- Old keys remain for verification

#### POST /api/v1/admin/keys/:kid/retire

Retire a signing key.

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "csrf": "csrf-token"
}
```

**Response:**
```json
{
  "data": {
    "success": true
  }
}
```

**Errors:**
- `400 ERR-CANNOT-RETIRE-KEY`: Cannot retire the current signing key

---

## Additional Error Codes for Mutations

| Code | Description |
|------|-------------|
| `ERR-INVALID-CSRF` | CSRF token missing or invalid (403) |
| `ERR-VALIDATION-FAILED` | Request validation failed |
| `ERR-EMAIL-EXISTS` | A user with that email already exists (409) |
| `ERR-CANNOT-RETIRE-KEY` | Cannot retire the current signing key (409) |


---

## Added 2026-10-11

### Audit chain: `GET /api/v1/admin/audit/verify` and `POST /api/v1/admin/audit/chain-acknowledgements`

`GET` recomputes the whole admin audit chain (any console administrator; read-only) and now reports **every** problem, not just the first:

```json
{ "data": {
  "chain": { "valid": false, "checked": 120, "legacyCount": 0, "openBreaks": 1, "acknowledgedBreaks": 1, "truncated": false, "brokenAtSequence": "88",
             "message": "...",
             "breaks": [ { "sequenceNumber": "88", "kind": "hash", "message": "Entry 88 was modified: ...", "acknowledgeable": true },
                         { "sequenceNumber": "5", "kind": "hash", "message": "...", "acknowledgeable": true,
                           "acknowledged": { "by": "platform", "at": "2026-10-11T08:00:00.000Z", "reason": "..." } } ] },
  "viewerIsPlatformAdmin": false, "minReasonLength": 20, "csrf": "..." } }
```

`kind` is `hash` (an entry was edited), `linkage` (one is missing or inserted), `ordering`, `head` (the start was deleted), `tail` (the end was deleted or the last entry
edited) or `empty`. `valid` is true when every problem is acknowledged. The server-side pin (hashes and content fingerprint) is never sent.

`POST` (**platform administrator only**, CSRF) `{ sequenceNumber, kind, reason, csrf }` records that one currently-reported break is known and harmless. The reason must be
20 to 2000 characters. Only `hash`, `linkage`, `ordering` and `head` can be acknowledged; `tail` and `empty` mean recent entries are missing (restore from a backup). The
acknowledgement is pinned to the row as it is (a row altered again later is a new open break) and is itself appended to the chain in the same transaction. Errors:
`403 ERR-PLATFORM-ADMIN-ONLY`, `403 ERR-INVALID-CSRF`, `404 ERR-CHAIN-BREAK-NOT-FOUND`, `409 ERR-CHAIN-BREAK-ACKNOWLEDGED`, `422 ERR-CHAIN-BREAK-NOT-ACKNOWLEDGEABLE`,
`400 ERR-VALIDATION-FAILED`.

### Password reset requests (no email)

| Method and path | Who | What |
|---|---|---|
| `POST /api/v1/auth/password-reset-request` | anyone (rate limited: 5 per 15 minutes per address, `RESET_REQUEST_RATE_LIMIT`) | `{ email, note? }`. **Always** the same answer, whether or not the address has an account. A request is recorded only for an active local account with a password; one open request per person (asking again refreshes it). Off when the setting `password.allowResetRequests` is off. |
| `GET /api/v1/admin/password-reset-requests` | any console administrator | The open requests, oldest first: `id`, `userId`, `email`, `name`, `note`, `requestedAt`, plus `csrf`. |
| `POST /api/v1/admin/password-reset-requests/:id/dismiss` | any console administrator | `{ csrf }`. Audited as `password_reset_request.dismiss`. `404 ERR-REQUEST-NOT-FOUND` if it is not open. |

Resetting the person's password (`POST /api/v1/admin/users/:id/reset-password`) closes their open request. That route and user creation now apply the platform
password rules (`password.minLength`, common-password list) to the temporary password; they used to accept anything of 8 characters.
`GET /api/v1/public/branding` carries `passwordResetRequests` (whether the sign-in page offers "Forgot your password?").
