# AI development prompt log

> Keep this file updated during the week. Replace each `COMMIT: TODO` with the real commit URL after making the corresponding reviewed change. Do not claim a commit exists until it does.

## 2026-11-01 — Initial architecture and permission model
- **Prompt / request:** Design a small FastAPI document vault with admin, owner and viewer roles; document-scoped read/edit grants; private file storage; immediate revocation; audit events; and tests.
- **Produced:** A FastAPI + SQLite design with explicit per-document grants and backend permission checks.
- **What was wrong / checked:** A role-only check would have allowed every viewer to access every document. I rejected that design. The final authorization helper checks ownership or a row in `permissions` for the exact document and user.
- **What I did instead:** Implemented `permission_for()` and `authorize()` and added cross-user list/detail/download tests.
- **Commit:** TODO — add the actual commit URL after committing this change.

## 2026-11-01 — Download authorization review
- **Prompt / request:** Review the download endpoint for IDOR, public-file, stale-link and revocation risks.
- **Produced:** Recommendations to keep files outside static hosting and authorize every download.
- **What was wrong / checked:** A signed URL or a UI-only check would remain usable after revocation. I did not use public or pre-signed links. `download_document()` loads the document and checks the live permission table before returning the file.
- **What I did instead:** Added a direct endpoint test proving an ungranted user receives 404 and a grant/revoke test proving the next download fails after revocation.
- **Commit:** TODO — add the actual commit URL after committing this change.

## 2026-11-01 — Audit integrity review
- **Prompt / request:** Propose a tamper-evident audit trail that records successful and denied document access.
- **Produced:** A chained audit record design using a keyed HMAC over event fields and the previous event hash.
- **What was wrong / checked:** A plain hash chain alone is not immutable; a database administrator could recompute it. I documented the residual risk and kept the HMAC secret outside the database.
- **What I did instead:** Added `/api/admin/audit/verify` and explicit limitations recommending independent WORM storage and external checkpoints for production.
- **Commit:** TODO — add the actual commit URL after committing this change.

## 2026-11-01 — Upload validation review
- **Prompt / request:** Suggest upload validation for a small document platform.
- **Produced:** Extension allowlist, size limit and file signature checks.
- **What was wrong / checked:** Client-provided MIME type is untrusted, and ZIP magic does not prove a DOCX is safe. I used server-side extension/signature checks and explicitly documented that malware scanning and safe DOCX parsing remain unfinished.
- **What I did instead:** Added upload rejection tests for disallowed extensions and mismatched PDF signatures.
- **Commit:** TODO — add the actual commit URL after committing this change.

## 2026-11-01 — Cross-user security test review
- **Prompt / request:** Generate negative tests for cross-user document access and permission escalation.
- **Produced:** Tests for listing, reading, downloading, modifying, uploading, grant/revoke and unauthenticated access.
- **What was wrong / checked:** A test that only checks a hidden button would not exercise the security boundary. Tests call the HTTP API directly with different users' bearer tokens.
- **What I did instead:** Kept the tests at the API boundary and documented that each threat should have a corresponding test before release.
- **Commit:** TODO — add the actual commit URL after committing this change.

## Reusable AI context
- Treat every document ID as attacker-controlled.
- Never rely on frontend visibility, unguessable IDs, folder membership or a previously issued URL as authorization.
- Every read, download, edit, delete and permission mutation must make a server-side decision using the authenticated user and current database grant.
- Do not silently broaden access. AI suggestions, if added later, must require explicit owner confirmation and be audited.
- When proposing security, list assumptions, residual risks and a negative test that would fail if the authorization check were removed.
