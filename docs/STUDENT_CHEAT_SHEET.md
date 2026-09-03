# Hardened API verification sheet

## 1. Register and capture the token

```http
POST /api/game/register
Content-Type: application/json

{"teamName":"Alpha","members":["Student"]}
```

Copy `accessToken` and `profileId` from the response. Protected requests require:

```http
Authorization: Bearer <accessToken>
```

`X-Team-Name` is not authentication and is ignored.

## 2. Expected defensive results

| Verification | Expected result |
|---|---|
| Own `GET /api/user/{profileId}` | `200` |
| Another profile ID | `403` |
| Forged or expired JWT | `401` |
| Update `role` or `balance` | `400` |
| More than five limited requests per minute | persistent `429` |
| Team token on an admin route | `401` |
| Negative transfer amount | `400` |
| Transfer without `Idempotency-Key` | `400` |
| Link-local or non-allowlisted fetch | `400` or `403` |
| `/api/debug?crash=1` | `404` without a traceback |
| `/api/v1/users` | `410` without user records |
| Unsigned webhook | `401` |
| Replayed valid webhook | `409` |

## 3. Retired functions

The exploit-proof submission and final aggregation endpoints are no longer part of the game flow:

- `POST /api/game/submit-flag` → `410`
- `POST /api/ultimate-challenge` → `410`

Use the Arabic security report for the before/after evidence and remediation details.
