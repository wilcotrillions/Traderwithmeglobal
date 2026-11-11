# TradeWithMe Global — Cloudflare Pages authentication

This repository is a **static Cloudflare Pages site with Pages Functions and D1**. It is not a Next.js project. The authentication changes here preserve that architecture.

## Included

- `/register/` — customer registration (new accounts start as `pending`)
- `/login/` — login and secure server-side session cookie
- `/forgot-password/` and `/reset-password/` — single-use, 30-minute reset links
- `/api/auth/register`, `/login`, `/logout`, `/me`, `/forgot-password`, `/reset-password`
- PBKDF2-SHA-256 password hashing (310,000 iterations, unique random salt)
- Random 256-bit session tokens; only SHA-256 token hashes are stored in D1
- HTTP-only, Secure, SameSite=Lax, host-only session cookie
- Password changes revoke all existing sessions for that account
- D1 migration for phone number and password reset tokens

## 1. Cloudflare Pages configuration

In Cloudflare Dashboard → Workers & Pages → your Pages project → Settings:

1. Confirm the project is connected to the intended GitHub repository and production branch.
2. Add a D1 database binding named **`DB`** for both Production and Preview environments.
3. The site must deploy the `functions/` directory alongside the static assets.
4. Keep the production site on HTTPS. The `__Host-` cookie intentionally requires Secure cookies.

Do not create a second database or change the binding name if the existing project already has a populated D1 database bound as `DB`.

## 2. Apply the database migration

Back up the production D1 database before changing its schema.

For an existing database, apply `migrations/0002_auth_completion.sql` once:

```bash
npx wrangler d1 migrations apply YOUR_D1_DATABASE_NAME --remote
```

If your project does not use Wrangler migrations yet, you can execute the SQL in `migrations/0002_auth_completion.sql` once using the D1 Console. Do **not** run it twice: `ALTER TABLE users ADD COLUMN phone` will fail if `phone` already exists.

For a brand-new database, use `schema.sql` instead of the incremental migration.

## 3. Configure password-reset email

Password recovery sends email through Resend. Configure these values in the Pages project's Production and Preview environment settings as appropriate:

- `RESEND_API_KEY` — **secret**
- `AUTH_FROM_EMAIL` — verified sender address, e.g. `TradeWithMe Global <support@your-verified-domain>`
- `PUBLIC_APP_URL` — public HTTPS origin, e.g. `https://www.traderwithmeglobal.com`

The sending domain must be verified with Resend and authorized for the sender address. Never put the API key in frontend JavaScript or commit it to Git.

Without `RESEND_API_KEY` and `AUTH_FROM_EMAIL`, forgot-password intentionally returns a configuration error; it does not pretend an email was sent.

## 4. Administrator approval

New customer accounts are deliberately created with `status = 'pending'`. They cannot log in until an authorized administrator reviews and approves them.

After verifying the customer's identity and eligibility, an administrator can activate one account in the D1 Console:

```sql
UPDATE users
SET status = 'active', updated_at = CURRENT_TIMESTAMP
WHERE email = 'verified-customer@example.com'
  AND role = 'customer'
  AND status = 'pending';
```

Do not expose this SQL as a public API. Do not make users self-assign the `admin` role. Existing admin access should be granted only through a controlled, audited process.

## 5. Deployment and protection

1. Commit the files to a feature branch and deploy a Preview build first.
2. Add a Cloudflare rate-limiting/WAF rule for `/api/auth/login`, `/api/auth/register`, `/api/auth/forgot-password`, and `/api/auth/reset-password`. Tune thresholds for legitimate users and monitor false positives.
3. Test on the HTTPS Preview URL with a new test account.
4. Apply the migration to Production only after Preview tests pass and a backup exists.
5. Merge the feature branch into the configured production branch.

## 6. Manual acceptance tests

- Register with valid details: expect HTTP 201 and `pending` status.
- Register the same email again: expect HTTP 409.
- Try a weak password: expect HTTP 400.
- Try to log in while pending: expect HTTP 403 with an approval message.
- Activate the test account using the controlled D1 process, then log in: expect a session cookie and redirect to `/dashboard/`.
- Load `/api/auth/me` in the same browser: expect the authenticated user profile.
- Log out: expect the session to be deleted and cookie cleared.
- Load the dashboard after logout: it should redirect to `/login/`.
- Configure Resend, request a reset, use the email link once, then verify the old password fails and the new password works.
- Reuse or wait for expiry of a reset link: expect it to be rejected.
- Confirm password reset invalidates all existing sessions.

## Important security boundary

The dashboard HTML is a static shell. Any API that returns private customer, balance, deposit, withdrawal, trading, or admin data must independently call `currentUser(request, env)` and enforce role/ownership checks on the server. Hiding a page or button is not authorization.

This implementation provides account authentication only. It does not establish brokerage authorization, custody, payment processing, trade execution, regulatory permissions, or guaranteed investment returns.
