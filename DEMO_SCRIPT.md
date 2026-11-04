# Five-minute demo video script

1. **0:00–0:40 — Intro:** Explain the problem: folder-level sharing and unverifiable access. Show TrustVault and the three seeded roles.
2. **0:40–1:30 — Upload:** Sign in as `owner`, upload a sample PDF/TXT, point out the generated document ID and private storage.
3. **1:30–2:20 — Grant:** Grant `viewer` read permission for that one document. Sign in as viewer and show that only the granted document appears and can be downloaded.
4. **2:20–3:00 — Attack:** Try a different owner's document ID or a guessed ID via Swagger. Show 404. Attempt a metadata edit as read-only viewer and show it is denied.
5. **3:00–3:40 — Revoke:** As owner revoke viewer access. As viewer repeat the same download request; it now fails because authorization is rechecked against the live database.
6. **3:40–4:30 — Audit:** Sign in as admin. Show successful/denied events and run audit-chain verification.
7. **4:30–5:00 — Close:** Show `THREATS.md`, tests, and explain accepted limitations: in-flight downloads, host compromise, no malware scanning/MFA/WORM integration yet.

Use a fresh database and harmless sample documents. Never show real confidential documents or production secrets.
