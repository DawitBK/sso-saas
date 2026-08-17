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

#### GET /api/v1/metrics

System metrics and statistics.

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

List all groups in the system.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "groups": [
      { "dn": "CN=DMS-Users,OU=Groups,DC=examplecorp,DC=com" },
      { "dn": "CN=GMS-Staff,OU=Groups,DC=examplecorp,DC=com" }
    ],
    "adminEmail": "admin@example.com",
    "csrf": "csrf-token-hex"
  }
}
```

#### GET /api/v1/admin/clients

List OAuth clients with session counts.

**Authentication:** Required (Admin)

**Response:**
```json
{
  "data": {
    "clients": [
      {
        "client_id": "edams",
        "session_count": 23
      },
      {
        "client_id": "gms",
        "session_count": 12
      }
    ],
    "adminEmail": "admin@example.com"
  }
}
```

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
    "gmsOfficeScopedRoles": ["OFFICE_MANAGER"]
  }
}
```

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
1. **View model responses** (for legacy EJS): `application/vnd.sso.view+json`
2. **JSON API responses** (for Next.js): Standard JSON

The `viewModelMiddleware` intercepts `res.render()` calls and converts them to JSON when requested with the appropriate header.


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

#### POST /api/v1/admin/users/:id/disable-mfa

Disable two-factor authentication for a user.

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
| `ERR-INVALID-CSRF` | CSRF token missing or invalid |
| `ERR-VALIDATION-FAILED` | Request validation failed |
| `ERR-USER-EXISTS` | User with email already exists |
| `ERR-CANNOT-RETIRE-KEY` | Cannot retire the current signing key |

