# Perceptron Auth Service

This service provides a lightweight authentication layer for the blog authoring experience. Deploy it separately (for example, on Render) and point the main site at its public URL.

## Environment variables

| Variable | Description |
| --- | --- |
| `PORT` | Optional port for local development (defaults to `4000`). |
| `ADMIN_SECRET_KEY` | Secret passphrase required to mint authoring tokens. Keep this value private. |
| `AUTH_TOKEN_SECRET` | Secret used to sign verification tokens. Defaults to the same value as `ADMIN_SECRET_KEY` if omitted, but separating them is recommended. |
| `TOKEN_EXPIRY` | Optional token lifetime (e.g. `30m`). |
| `ALLOWED_ORIGINS` | Comma-separated list of origins allowed to call the API (e.g. `http://localhost:3000`). Leave empty to allow any origin during development. |

## Scripts

- `npm run dev` – start the service with automatic restarts via `nodemon`.
- `npm start` – start the service with Node.

## Endpoints

- `POST /auth/login` – accepts `{ "secretKey": "..." }` and returns `{ token, expiresIn }` when the secret matches.
- `POST /auth/verify` – accepts `{ token }` and responds with `{ valid, decoded }` for server-side validation.
- `GET /health` – simple liveness probe.

## Deployment

1. Install dependencies: `npm install` inside the `backend` folder.
2. Provide the environment variables above in your hosting provider.
3. Expose the service publicly and set `NEXT_PUBLIC_AUTH_SERVICE_URL` in the Next.js app to point to it.
