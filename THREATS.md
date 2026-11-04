# TrustVault threat model

## Security boundary and permission model
- Every API request authenticates a bearer token and resolves the active user from the database.
- The owner has full control of their document. Named users receive only `read` or `edit` grants for one document. `edit` implies read. Viewers cannot upload; owners can upload. Admins manage users and inspect audit records, but do **not** automatically receive document content access.
- A grant is checked against the current permissions table for every metadata, download and update request. There are no public URLs, folder inheritance, or long-lived signed links. Revocation therefore applies to the next request immediately. A download already in progress cannot be recalled.

## Threats considered and mitigations
| Threat | Mitigation | Residual risk / test |
|---|---|---|
| Guess another document UUID | Random UUID plus server-side permission check; unauthorized responses use 404 | UUID is not authorization. `test_ungranted_user...` |
| Call download endpoint directly | Authorization occurs in download handler before FileResponse | Test direct HTTP download, not just UI visibility |
| Enumerate documents through list/search | SQL query returns only owned or explicitly granted records | Cross-user list test |
| Reuse link after revocation | No public links; each download checks current DB grant | Grant/revoke test |
| Viewer edits metadata | Edit permission required; read grant insufficient | Non-owner update test |
| Viewer grants access to another user | Only document owner may change grants | Add explicit denial test before production |
| Malicious extension / spoofed MIME | Extension allowlist and file-signature checks; server-generated storage name | TXT signature is inherently weak; DOCX is only checked as ZIP container |
| Oversized upload | Read capped at configured maximum plus one byte | Add rate limiting and streaming quotas for production |
| Path traversal in filename | Original name reduced to basename; storage uses random generated name | Platform-specific filename handling should be reviewed |
| Token theft / replay | Short-lived JWT, HTTPS required in deployment, active-user lookup each request | No refresh-token rotation or device/session revocation yet |
| User disabled after login | Active flag checked against DB on every API request | Admin disable endpoint is not implemented in this starter |
| Audit row edited/deleted in DB | HMAC hash chain detects alteration when verified; secret kept outside DB | A privileged host attacker with both DB and secret can forge history; use remote WORM storage/KMS in production |
| Audit event insertion race | SQLite serializes writes in normal local operation | Production needs transactional sequence/locking in PostgreSQL |
| Audit secret compromise | Secret separated from DB and supplied via environment | Rotate secret and anchor chain head externally; no rotation workflow yet |
| SQL injection | Parameterized SQL for user values; dynamic update columns come from a fixed Pydantic field allowlist | Continue code review and dependency scanning |
| XSS through filename/category | UI escapes displayed text | Add CSP and stronger frontend templating controls |
| CSRF | API uses Authorization header rather than cookie auth | CORS is not configured; keep API same-origin or add strict allowlist |
| Admin account compromise | Separate admin role; password hashing | Add MFA, rate limiting, alerting and admin action approvals |
| File storage exposure | Private storage directory outside static web root; random names | Host filesystem permissions, encrypted disks and backups are operational requirements |
| Deleted file recovery | Delete removes stored object and cascades grants | No recycle bin/versioning in this MVP; backup retention is external |

## Known limitations / accepted risks
1. This is a seven-day MVP, not a certified compliance product. Do not store regulated production records without a security review.
2. Hash chaining is tamper-evident, not immutable. A host/root attacker who obtains the audit secret can rewrite the database and recompute the chain. Production should stream signed events to an independently administered append-only/WORM service and periodically publish a chain checkpoint.
3. Revocation cannot stop bytes already downloaded or a response already in flight. The guarantee is that subsequent server requests fail.
4. Upload validation is basic. DOCX is identified as a ZIP container, not fully parsed or malware-scanned. Add antivirus scanning, decompression limits and content-disarm/reconstruction.
5. No folder inheritance, external guest identities, bulk sharing, version history, retention policies, MFA, SSO, password reset, rate limiting or malware scanning.
6. The demo UI is intentionally thin. API authorization is the security boundary; hiding UI controls is not relied upon.
7. SQLite is appropriate for local demonstration only. A multi-instance production deployment should use PostgreSQL and object storage with private access, plus a transactional outbox for audit events.

## Attack checklist for reviewers
- Try another user's document ID against detail, download, update, delete and permission endpoints.
- Revoke a grant, then repeat an earlier download request.
- Change role claims in a JWT; signature verification must reject the token.
- Try inactive/nonexistent users, expired tokens and malformed tokens.
- Try filename traversal, extension spoofing, oversized files and empty files.
- Attempt to access the private storage path over HTTP.
- Modify an audit row and run `/api/admin/audit/verify`.
- Attempt to grant access as a viewer or as a different owner.
