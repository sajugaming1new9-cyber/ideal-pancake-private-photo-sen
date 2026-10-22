# VOID — Private One-Time Photo Vault

A small Cloudflare Worker + D1 app with a dark terminal UI.

## Features
- Server-side master password (`MASTER_PASSWORD` Worker secret)
- Signed, HttpOnly admin session cookie (8 hours)
- Photo stored as a private D1 BLOB (max 4 MiB; JPEG/PNG/WebP/GIF)
- Per-link random secret URL + generated six-digit passcode
- Link expires after 24 hours
- Passcode hash uses PBKDF2-SHA-256 (210,000 iterations)
- Successful access is atomically claimed using a conditional `UPDATE ... RETURNING`
- No third-party analytics\n- Six incorrect passcode attempts lock a link for 15 minutes\n- View watermark and blur-on-tab-switch deterrents

## Requirements
Node.js current LTS, npm, a Cloudflare account, and Wrangler.

## Deploy
1. Create a GitHub repository. Upload these files, including `src/worker.js`, `public/`, `schema.sql`, and `wrangler.toml`.
2. Install Wrangler locally:
   ```sh
   npm install -D wrangler
   npx wrangler login
   ```
3. Create the D1 database:
   ```sh
   npx wrangler d1 create secret-photo-vault-db
   ```
   Copy the `database_id` into `wrangler.toml`, replacing `REPLACE_WITH_D1_DATABASE_ID`.
4. Initialize schema:
   ```sh
   npx wrangler d1 execute secret-photo-vault-db --remote --file=./schema.sql
   ```
5. Set secrets (use a long unique password, not the sample numeric code):
   ```sh
   npx wrangler secret put MASTER_PASSWORD
   npx wrangler secret put SESSION_SECRET
   ```
   For SESSION_SECRET, enter a random value with at least 32 characters. Store it privately. Do not commit secrets.
6. Deploy:
   ```sh
   npx wrangler deploy
   ```
7. Open the Worker URL, log in using `MASTER_PASSWORD`, and upload your image. Generate a link and securely share both link and separate passcode.

## GitHub connection
You can connect a GitHub repo to Cloudflare Workers Builds in the Cloudflare dashboard, select the repository, and configure deployment with Wrangler. Or use the CLI deploy above. Keep Cloudflare secrets in Worker settings, not GitHub files. `wrangler.toml` must contain your actual D1 database ID.

## Important security notes
- Six incorrect passcode attempts trigger a 15-minute lock on that link. This basic control is not a full IP/global rate limiter; add edge rate limiting/WAF rules and monitor abuse before public exposure.
- The master password comparison is direct string equality. Use a long unique master password; do not use a short numeric code for a public-facing deployment.
- D1's single-use claim is atomic. A valid view request consumes the link before the photo is returned; if the connection fails after consumption, that link is still spent.
- View route returns the private photo bytes only after successful code validation. A person who gets the URL alone cannot fetch it without the passcode.
- Images are held in D1, not in the public asset directory.
- Watermark, context-menu/drag deterrents, shortcut interception, and blur-on-tab-switch are friction only. A browser may retain the displayed image; screenshots, recording, developer tools, alternate browsers, and camera capture cannot be reliably blocked.
- A one-time link guarantees one successful redemption, not one human or one eyeball. The recipient could copy the image after viewing.
- Back up data privately. Deleting a D1 photo does not delete copies a recipient may have made.
- This project is a useful baseline, not a formal security audit. Before using highly sensitive photos, add rate limiting/abuse protection and review the implementation.
