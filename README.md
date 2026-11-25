# VisionX Auth Microservice

This project is a standalone ASP.NET Core 10 authentication service for the VisionX platform stack. It is intentionally restricted to authentication, authorization, and session management only.

## What it includes

- ASP.NET Core 10 Web API
- ASP.NET Core Identity with PostgreSQL persistence
- JWT access tokens and refresh tokens
- OTP-based signup verification
- Admin session revocation support
- Admin DB explorer endpoints (table/row read-write for auth tables)
- Swagger/OpenAPI docs
- Docker + Docker Compose setup for a Debian/Linux host

## Database model overview

The service uses PostgreSQL and creates the tables automatically on app startup through `EnsureCreated()` for local development.

### Users

- `id`
- `email`
- `password_hash`
- `email_verified`
- `immunity`
- `banned`
- `created_at`
- `user_details` (JSON)

### Sessions

- `id`
- `user_id`
- `refresh_token_hash`
- `device_info`
- `created_at`
- `expires_at`
- `revoked_at`

### OTP challenges

- `id`
- `user_id`
- `email`
- `otp_hash`
- `expires_at`
- `attempts`
- `used_at`

### Config

- `allowed_domains`
- stored as a JSON array such as `["college.edu", "student.college.edu"]`

## Domain parsing

When the supplied email matches an allowed domain, the service extracts the local-part pattern such as:

- `25ds-ibtisam@college.edu`

and stores details in `user_details`:

- `admissionYear: 2025`
- `department: ds`
- `firstName: ibtisam`
- `emailLocalPart: 25ds-ibtisam`

## Local development

1. Copy the example environment file:

   ```bash
   cp Auth/.env.example Auth/.env
   ```

2. Update the values in `Auth/.env` with your real secrets.
3. Start the service and PostgreSQL:

   ```bash
   cd Auth
   docker compose up --build
   ```

4. Open the Swagger docs at:

   - http://localhost:6509/swagger

5. Check service metadata endpoint:

   - http://localhost:6509/api/meta/version

## Runtime environment source

This service reads runtime settings through Docker Compose env injection. In your server setup, values are loaded from an external env file.

Example deployment env source:

- `/opt/visionx/secrets/.env.auth`

Keep this external env file as the source of truth for production values.

## Production deployment notes

- Use strong JWT keys and database credentials.
- Keep `.env` files out of Git by using the workspace `.gitignore`.
- Do not commit real secrets.
- For GitHub pushes, initialize a repo and push only the project files; the `.env` file stays local.

## OTP delivery

This starter uses a console log fallback so it works with no external mail provider configured yet. In production, replace the in-memory/console OTP output with an SMTP provider or a transactional email backend.

Common options:

- SMTP via MailKit or System.Net.Mail
- SendGrid
- Resend
- Postmark

Add your email provider in the OTP service and store the credentials in `.env` only.

## Admin session management

Once the admin user is created from the `Admin:Email` / `Admin:Password` values, use a JWT from that account to access:

- `GET /api/admin/config/domains`
- `POST /api/admin/config/domains`
- `GET /api/admin/users/{userId}/sessions`
- `POST /api/admin/users/{userId}/sessions/{sessionId}/revoke`

Additional admin endpoints:

- `GET /api/admin/endpoints`
- `GET /api/admin/db/tables`
- `GET /api/admin/db/tables/{table}/rows?limit=50&offset=0`
- `POST /api/admin/db/tables/{table}/rows`
- `PUT /api/admin/db/tables/{table}/rows`
- `DELETE /api/admin/db/tables/{table}/rows`

Exposed DB tables in admin explorer:

- `AspNetUsers`
- `AspNetRoles`
- `AspNetUserRoles`
- `AspNetUserClaims`
- `AspNetUserLogins`
- `AspNetUserTokens`
- `AspNetRoleClaims`
- `Sessions`
- `OtpChallenges`
- `AppConfigs`

## Authorization behavior

- Admin policy uses role `admin`.
- Access tokens include role claim `role`.
- Admin recognition in token minting supports:
   - persisted user claim `role=admin`, or
   - `ADMIN_EMAIL` match (case-insensitive fallback).

If admin requests return `403`, log out and sign in again so a fresh token is minted.

If admin explorer endpoints return `404`, the running auth deployment is older than the admin panel and needs redeploy.

## Version and startup logs

- Service version is sourced from `AUTH_APP_VERSION` (mapped as `App__Version`).
- `GET /api/meta/version` returns service/version/environment/UTC.
- Startup logs include configured CORS origins and configured admin email presence checks.

## Security notes

- Access tokens are valid for 60 minutes.
- Refresh tokens last 30 days.
- Refresh tokens are hashed before storage.
- OTPs expire after 10 minutes.
- Sessions can be revoked by admin users or logout flows.

## Git repository reminder

```bash
cd /home/ibtisam/Desktop/ProjectFiles/VisionX
git add Backend/Auth
git commit -m "Add VisionX auth microservice"
```

The `.gitignore` file already excludes `.env` and local secrets.
