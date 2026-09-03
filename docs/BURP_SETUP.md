# Burp setup for defensive verification

Use Burp only against the authorized local instance at `http://127.0.0.1:5000`.

## Browser proxy

1. Start Burp Suite and use its browser, or configure the browser proxy as `127.0.0.1:8080`.
2. Open `http://127.0.0.1:5000`.
3. Register a team and capture the `accessToken` from `POST /api/game/register`.
4. Add the token to protected requests:

```http
Authorization: Bearer <accessToken>
```

## Safe verification workflow

1. Send one legitimate request to Repeater.
2. Change only one security-relevant value at a time, such as the object ID or a forbidden property.
3. Confirm the request is rejected with the status documented in `STUDENT_CHEAT_SHEET.md`.
4. Do not target third-party hosts. `/api/fetch-url` is default-deny and verification must use blocked local/link-local examples only.
5. Keep request volume low; the goal is to verify a hard `429`, not to create a denial of service.

Admin and webhook secrets are intentionally separate from team access tokens. Do not paste real secrets into screenshots or reports.
