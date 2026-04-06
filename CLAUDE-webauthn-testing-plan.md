# WebAuthn Tests + Usernameless Login Fix (Issue #5)

## Context

The WebAuthn/passkey implementation (PR1-PR3) is complete but missing tests. Additionally, the login flow unnecessarily requires the user to type their username before clicking "Sign in with Passkey" — WebAuthn discoverable credentials already contain a userHandle that identifies the user, making the username field redundant for passkey auth. This plan adds comprehensive tests (Perl unit + Playwright E2E) and fixes the usernameless login flow.

---

## Part 1: Security Fix — Usernameless Passkey Login

### Problem

`generate_authentication_options` (WebAuthn.pm:232) hard-requires `$data->{username}`, forcing the user to type their username before the passkey button works. This is unnecessary — WebAuthn discoverable credentials contain a userHandle that identifies the user. It also leaks user existence info (different errors for "no user" vs "no credentials").

### Changes

**`server/lib/NicToolServer/WebAuthn.pm`**

1. **`generate_authentication_options` (line 229)**: Make `$data->{username}` optional. When absent:
   - Skip user lookup and credential filtering
   - Insert challenge with `nt_user_id = NULL` (column already allows NULL)
   - Return empty `allowCredentials` array → triggers browser's resident credential picker

2. **`_consume_challenge` (line 425)**: Handle NULL user ID. Current SQL uses `AND nt_user_id = ?` which fails for NULL (SQL: `NULL = NULL` is false). Split into two branches:
   - When `$uid` is defined: `AND nt_user_id = ?`
   - When `$uid` is undef: `AND nt_user_id IS NULL`

3. **`verify_authentication` (line 337-341)**: Currently calls `_consume_challenge($challenge, 'authentication', $cred->{nt_user_id})`. For usernameless flow, the challenge has `nt_user_id = NULL`. Try consuming with NULL first (usernameless flow), then fall back to user-bound challenge (username-provided flow).

**`client/htdocs/nt-webauthn.js`**

4. **`authenticate` (line 166)**: Change signature to `authenticate(csrfToken, username)` with username optional. When absent, omit `username` from both AJAX payloads.

**`client/templates/login.html`**

5. **`ntPasskeyLogin` (line 53-58)**: Remove the `if (!username) { alert(...); return; }` gate. Pass username only when non-empty. Update call: `NtWebAuthn.authenticate(csrfToken, username || undefined)`.

---

## Part 2: Perl Unit Tests

**New file**: `server/t/05_webauthn.t`

Follows the `01_data.t` pattern: `use lib 't'; use NicToolTest;`, connect to real DB via `NicToolServer->new(undef, undef, $dbh)`, then instantiate `NicToolServer::WebAuthn->new(undef, undef, $dbh)`.

### Test Sections (~40 test cases)

**T1: Module loading** (1 test)
- `use_ok('NicToolServer::WebAuthn')`

**T2: Challenge generation** (5 tests)
- `_generate_challenge()` returns base64url string
- Decoded length is 32 bytes (encoded length ~43 chars)
- No `+`, `/`, or `=` characters (valid base64url)
- 100 challenges are all unique

**T3: Challenge lifecycle** (10 tests)
- Insert challenge via `exec_query`, consume with `_consume_challenge` → succeeds
- Replay: consume same challenge again → returns undef
- Expired: insert with `expires_at` in the past → returns undef
- Wrong ceremony type → returns undef
- Wrong `nt_user_id` → returns undef
- NULL `nt_user_id` challenge: insert with NULL, consume with undef → succeeds
- `_cleanup_expired_challenges` removes expired rows

**T4: `generate_registration_options`** (6 tests)
- Missing `nt_user_id` → error 301
- Unconfigured (no `webauthn_rp_id` in nt_options) → error 600
- Nonexistent user → error 404
- Valid call → returns `error_code => 200`, `options` is valid JSON
- Options JSON contains `challenge`, `rp.id`, `user.id`, `pubKeyCredParams`
- `user.id` decodes to packed user ID

**T5: `generate_authentication_options` WITH username** (5 tests)
- Unconfigured → error 600
- Nonexistent user → error 403 (generic message, no user enumeration)
- User with no credentials → error 403
- Valid call (after inserting test credential) → returns options with `allowCredentials`
- `allowCredentials[0].id` matches the test credential_id

**T6: `generate_authentication_options` WITHOUT username** (4 tests)
- Returns `error_code => 200` (no error even without username)
- Options JSON has empty `allowCredentials` array
- Challenge stored in DB with `nt_user_id IS NULL`
- Challenge is consumable with `_consume_challenge($challenge, 'authentication', undef)`

**T7: Credential CRUD** (8 tests)
- `get_user_credentials` returns empty list initially
- After inserting a test credential: returns list with 1 entry
- Correct fields in returned credential (friendly_name, credential_id, etc.)
- `revoke_credential` sets `revoked = 1`, credential disappears from list
- `rename_credential` updates `friendly_name`
- Missing `nt_user_id` → error 301 for each method
- Missing `nt_webauthn_credential_id` → error 301 for revoke/rename
- User isolation: user B can't see user A's credentials

**T8: `verify_registration` error paths** (4 tests)
- Missing required fields → error 301
- Invalid/expired challenge → error 403

**T9: `verify_authentication` error paths** (5 tests)
- Missing required fields → error 301
- Unknown `credential_id_b64` → error 403
- Revoked credential → error 403
- Invalid/expired challenge → error 403

**T10: Cleanup**
- Delete all test credentials, challenges from DB

### Test Data Setup

Insert `webauthn_rp_id` and `webauthn_origin` into `nt_options` at test start (if not present). Use `nt_user_id = 1` (root user). Insert fake credentials directly via `exec_query` with known base64url values. Clean up in END block.

---

## Part 3: Playwright E2E Tests

**New file**: `client/t/e2e/webauthn.spec.ts`

Uses CDP virtual authenticator for browser WebAuthn ceremonies:

```typescript
const cdpSession = await page.context().newCDPSession(page);
await cdpSession.send('WebAuthn.enable');
const { authenticatorId } = await cdpSession.send(
  'WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    }
});
```

### Test Groups

**W1: WebAuthn API CSRF protection** (3 tests)
- POST with wrong `csrf_token` → 403
- POST with missing `csrf_token` → 403
- GET request → 405

**W2: Session requirement** (1 test)
- Authenticated endpoint (`webauthn_get_user_credentials`) without session cookie → 403

**W3: Login page** (2 tests)
- Passkey button is visible (not `display:none`) when page loads
- Passkey button works without entering username (after fix)

**W4: Registration ceremony** (1 test)
- Log in with password, navigate to user profile, register passkey via virtual authenticator, verify credential appears in list

**W5: Passkey login** (1 test)
- Register passkey (setup), logout, click "Sign in with Passkey" without entering username, browser shows credential picker (virtual authenticator auto-selects), verify session created and redirected

**W6: Credential management** (2 tests)
- Rename credential, verify new name in list
- Revoke credential, verify removed from list

**W7: Revoked credential rejected** (1 test)
- Register passkey, revoke it, attempt passkey login → fails

**W8: WebAuthn not configured** (1 test)
- If `webauthn_rp_id` is not set, registration returns clear error

### Test Data Lifecycle

Each test group uses `test.beforeAll` to log in and get session/csrf cookies. Virtual authenticator is created per test that needs it (in the test body, not beforeAll, since CDP sessions are tied to pages). Cleanup revokes all test credentials in `test.afterAll`.

---

## Part 4: helpers.ts Additions

**File**: `client/t/e2e/helpers.ts`

```typescript
// JSON POST to webauthn.cgi
export async function webauthnPost(
  playwright: any, action: string, data: Record<string, any>,
  csrfCookie: string, sessionCookie?: string
): Promise<{ res: any; json: any }>

// List user's passkeys
export async function listPasskeys(
  playwright: any, cookies: string, ntUserId: string | number
): Promise<any[]>

// Revoke a specific passkey
export async function revokePasskey(
  playwright: any, cookies: string,
  ntUserId: string | number, credentialDbId: string | number
): Promise<void>

// Cleanup: revoke all passkeys for a user
export async function revokeAllPasskeys(
  playwright: any, cookies: string, ntUserId: string | number
): Promise<void>

// Create CDP virtual authenticator on a page
export async function setupVirtualAuthenticator(page: Page):
  Promise<{ cdpSession: any; authenticatorId: string }>

// Tear down virtual authenticator
export async function teardownVirtualAuthenticator(
  cdpSession: any, authenticatorId: string
): Promise<void>
```

---

## Critical Files

| File | Action |
|------|--------|
| `server/lib/NicToolServer/WebAuthn.pm` | Fix usernameless flow (3 methods) |
| `client/htdocs/nt-webauthn.js` | Make username optional in `authenticate()` |
| `client/templates/login.html` | Remove username gate on passkey button |
| `server/t/05_webauthn.t` | New: ~40 Perl unit tests |
| `client/t/e2e/webauthn.spec.ts` | New: ~12 Playwright E2E tests |
| `client/t/e2e/helpers.ts` | Add 6 WebAuthn helper functions |

## Verification

1. `cd server && perl -c t/05_webauthn.t` — syntax check
2. Docker: `make -C server test` — runs Perl unit tests including new webauthn.t
3. Docker: `cd client/t/e2e && npx playwright test webauthn.spec.ts` — E2E tests
4. Manual: login page passkey button works without typing username
5. Manual: password login still works unchanged
