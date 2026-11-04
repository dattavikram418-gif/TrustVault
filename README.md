# TrustVault
<<<<<<< HEAD

A security-first document-sharing MVP built with FastAPI, SQLite and private filesystem storage.

## 1. Run locally

Requirements: Python 3.10+.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env
# On macOS/Linux use: cp .env.example .env
uvicorn app.main:app --reload
```

Open:
- App: http://127.0.0.1:8000
- Swagger API docs: http://127.0.0.1:8000/docs

The app creates the database and demo users on first startup.

## 2. Demo credentials

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@12345` |
| Document owner | `owner` | `Owner@12345` |
| Viewer | `viewer` | `Viewer@12345` |

**Change demo passwords and secrets before deployment.** The demo users are seeded only if the users table is empty. Do not expose these credentials publicly.

## 3. Permission model

- **Admin:** create users, inspect audit events and verify audit-chain integrity. Admin does not automatically receive document-content access.
- **Owner:** upload, read, edit metadata, delete their own documents, grant/revoke named users.
- **Viewer:** read/download only documents explicitly shared with them.
- **Edit grant:** includes read/download and metadata editing.
- No folder-level inheritance and no public/share URLs.
- Permission is looked up in the database on every protected request. Revocation blocks the next request; bytes already downloaded or an in-flight response cannot be recalled.

## 4. API summary

| Endpoint | Allowed caller | Purpose |
|---|---|---|
| `POST /api/auth/login` | Anyone | Login |
| `GET /api/auth/me` | Authenticated | Current user |
| `POST /api/users` | Admin | Create a named user |
| `POST /api/documents` | Owner | Upload |
| `GET /api/documents` | Authenticated | List only owned/shared documents |
| `GET /api/documents/{id}` | Owner or read/edit grantee | Metadata |
| `GET /api/documents/{id}/download` | Owner or read/edit grantee | Download |
| `PATCH /api/documents/{id}` | Owner or edit grantee | Update metadata |
| `PUT /api/documents/{id}/permissions/{username}` | Owner only | Grant read/edit |
| `DELETE /api/documents/{id}/permissions/{username}` | Owner only | Revoke |
| `DELETE /api/documents/{id}` | Owner or admin | Delete |
| `GET /api/admin/audit` | Admin | Audit log |
| `GET /api/admin/audit/verify` | Admin | Verify HMAC chain |
| `GET /api/admin/users` | Admin | List users |

Unauthorized document IDs return 404 to reduce resource enumeration. Missing/invalid authentication returns 401.

## 5. Run tests

```bash
pytest -q
```

The tests call API endpoints directly using different users' tokens. They cover cross-user listing, metadata and download, immediate revocation, role restrictions, upload validation and audit verification.

## 6. Database and storage

- SQLite database: `./data/trustvault.db` by default.
- Private files: `./private_storage` by default.
- Neither path is mounted as a public static directory.
- Override locations using environment variables in `.env`.

The schema is initialized automatically by `app/db.py`. The SQL schema is also provided in `schema.sql`.

## 7. Docker

```bash
docker compose up --build
```

Set strong secrets in `.env` first. Docker volumes persist the database and private files.

## 8. Deployment checklist

1. Use HTTPS behind a trusted reverse proxy.
2. Set long random `JWT_SECRET` and `AUDIT_SECRET`; never commit `.env`.
3. Replace demo passwords; use unique passwords of at least 12 characters.
4. Restrict filesystem permissions on database and storage directories.
5. Back up database and files together; test restore.
6. Put audit events in an independently administered append-only/WORM destination for production.
7. Add MFA, rate limiting, malware scanning, PostgreSQL, object storage and monitoring before handling sensitive production data.
8. Do not deploy with demo credentials or default development secrets.

## 9. Deliverables / remaining work

See `THREATS.md` for the threat model and accepted risks, and `PROMPTS.md` for the AI prompt log. The prompt log contains commit placeholders: replace them with real commit URLs as you work; do not invent hashes. Record additional dated entries and commits throughout development.

This is a runnable MVP and interview/demo foundation, not a claim of production security certification. Review the limitations in `THREATS.md` before real use.
=======
TrustVault is a secure document-sharing platform built with Python and FastAPI. It features role-based access control, secure authentication, document upload and management, read/edit permissions, access control, and audit logging to track user activities and protect sensitive documents.
>>>>>>> 75006397e51a8a69571f450c5485675d133c8ecd
