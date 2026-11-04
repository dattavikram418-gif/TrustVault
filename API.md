# TrustVault API authorization reference

All protected endpoints require `Authorization: Bearer <JWT>`. Roles are resolved from the user row, not trusted solely from frontend state. Document access is based on owner identity or a live per-document permission row.

| Method + path | Authentication / authorization |
|---|---|
| POST `/api/auth/login` | Public; credentials verified |
| GET `/api/auth/me` | Any active authenticated user |
| POST `/api/users` | Admin only |
| POST `/api/documents` | Owner role only |
| GET `/api/documents` | Any active user; response is filtered to owned or explicitly granted docs |
| GET `/api/documents/{id}` | Document owner, read grantee or edit grantee |
| GET `/api/documents/{id}/download` | Document owner, read grantee or edit grantee; rechecked at download time |
| PATCH `/api/documents/{id}` | Owner or edit grantee |
| PUT `/api/documents/{id}/permissions/{username}` | Document owner only |
| DELETE `/api/documents/{id}/permissions/{username}` | Document owner only |
| DELETE `/api/documents/{id}` | Document owner or admin |
| GET `/api/admin/audit` | Admin only |
| GET `/api/admin/audit/verify` | Admin only |
| GET `/api/admin/users` | Admin only |

Unauthorized document operations return 404 to avoid confirming another user's document ID. Authentication failures return 401; role failures return 403.
