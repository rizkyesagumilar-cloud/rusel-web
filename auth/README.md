# Rusel authentication gateway

The live Rusel site is protected by a Traefik `forwardAuth` middleware backed by this small Python service.

Allowed Google identities:
- `esa@rhayagroup.com`
- `kolspecialistruselco@gmail.com`

Flow:
1. Unauthenticated requests are sent to `/auth/signin`.
2. The user chooses “Masuk dengan Google”.
3. Google authentication is handled by the dedicated Apps Script login deployment.
4. Apps Script redirects back to `/auth/callback` with a one-time code.
5. This gateway exchanges that code server-to-server, validates the allowlist, then issues a signed 12-hour HTTP-only session cookie.
6. Traefik blocks all normal site routes unless that session is valid.

The session signing secret lives only in the VPS service environment and is not stored in this repository.
