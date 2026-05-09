# Perceptron Auth Service

This service provides authentication and content APIs for the blog authoring experience. Deploy it separately (for example, on Render) and point the main site at its public URL.

## Environment variables

| Variable | Description |
| --- | --- |
| `PORT` | Optional port for local development (defaults to `4000`). |
| `ADMIN_SECRET_KEY` | Secret passphrase required to mint authoring tokens. Keep this value private. |
| `AUTH_TOKEN_SECRET` | Secret used to sign verification tokens. Defaults to the same value as `ADMIN_SECRET_KEY` if omitted, but separating them is recommended. |
| `TOKEN_EXPIRY` | Optional token lifetime (e.g. `30m`). |
| `ALLOWED_ORIGINS` | Comma-separated list of origins allowed to call the API (e.g. `http://localhost:3000`). Leave empty to allow any origin during development. |
| `MONGODB_URI` | MongoDB connection string (e.g. provided by MongoDB Atlas). Required for persisting blog posts. |

## Scripts

- `npm run dev` – start the service with automatic restarts via `nodemon`.
- `npm start` – start the service with Node.

## Endpoints

- `POST /auth/login` – accepts `{ "secretKey": "..." }` and returns `{ token, expiresIn }` when the secret matches.
- `POST /auth/verify` – accepts `{ token }` and responds with `{ valid, decoded }` for server-side validation.
- `GET /blogs` – returns `{ posts }` containing all blog posts sorted by publish date (optional `?limit=` query parameter).
- `GET /blogs/:slug` – returns `{ post }` for the requested slug or `404` when missing.
- `POST /blogs` – persists a new blog post. Requires a `Bearer` token minted via `/auth/login` and accepts the same payload used by the admin dashboard.
- `GET /health` – simple liveness probe.

## Deployment

Infrastructure lives in `infra/terraform` and provisions ECR, ECS/Fargate, an ALB, Secrets Manager placeholders, and an OIDC deploy role for GitHub Actions.

1. Set `github_repo` in `infra/terraform/terraform.tfvars` to the GitHub repository in `owner/repo` form.
2. Apply Terraform from `infra/terraform`.
3. Populate the Secrets Manager values shown by `terraform output secret_arns`.
4. Add the Terraform output `github_deploy_role_arn` as the GitHub repository secret `AWS_DEPLOY_ROLE_ARN`.
5. Optional: add the GitHub repository variable `PRODUCTION_HEALTHCHECK_URL` with the full health endpoint, for example `https://api.example.com/health`.
6. Push to `main` or run the `Deploy to Amazon ECS` workflow manually.

The `CI` workflow validates pull requests and `main` pushes with `npm ci`, `npm run check`, and a Docker image build. The deploy workflow repeats the app validation, builds and pushes a SHA-tagged image plus `latest` to ECR, updates the existing ECS task definition image, and waits for the ECS service to stabilize.

Terraform state is currently local. Move it to the commented S3 backend in `infra/terraform/main.tf` before automating Terraform applies from CI.
