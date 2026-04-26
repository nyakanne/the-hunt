# HackerOne Submission — Missing PKCE in OAuth 2.0 Allows Authorization Code Interception

**Program:** Whatnot  
**Weakness:** Improper Authentication  
**Severity:** High  
**Asset:** whatnot.com (OAuth authorization server)  

---

## Summary

Whatnot's OAuth 2.0 authorization code flow does not implement PKCE (Proof Key for Code Exchange, RFC 7636). For mobile and public clients connecting third-party apps to Whatnot seller accounts, this means an authorization code can be intercepted by a malicious application sharing the same custom URL scheme and exchanged for a full access + refresh token — resulting in complete account takeover of the seller's Whatnot integration.

---

## Steps to Reproduce

### Step 1 — Confirm PKCE is absent in the authorization URL

Initiate a Whatnot OAuth authorization request (as a registered third-party app). Observe the authorization URL:

```
https://www.whatnot.com/oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=myapp%3A%2F%2Foauth%2Fcallback
  &response_type=code
  &scope=read%3Ainventory+write%3Ainventory
  &state=RANDOM_STATE_VALUE
```

**Note:** There is no `code_challenge` or `code_challenge_method` parameter. The authorization server accepts this request without requiring PKCE.

---

### Step 2 — Register a second application with the same redirect URI scheme

On Android, any app can declare an intent filter for a custom URL scheme. Register a test app with `android:scheme="myapp"` to intercept the callback.

On iOS, custom URL schemes are also first-come-first-served — the OS can deliver the callback to the wrong app.

---

### Step 3 — Intercept the authorization code

When the victim completes the OAuth flow in the legitimate app:
1. Whatnot redirects to `myapp://oauth/callback?code=AUTH_CODE&state=...`
2. The malicious app receives the callback (OS delivers to the competing app)
3. Malicious app extracts `AUTH_CODE`

---

### Step 4 — Exchange the code for tokens (no PKCE verification possible)

```bash
curl -s -X POST https://api.whatnot.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_STEP_3" \
  -d "redirect_uri=myapp://oauth/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

Without PKCE, the server cannot verify this exchange originates from the same client that started the flow. The response returns a valid `access_token` and `refresh_token` for the victim's account.

---

### Step 5 — Confirm access

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_<STOLEN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ me { id username email } }"}'
```

If the response contains the victim's account details, the attack is successful.

---

## Proof of Concept (minimal)

The missing PKCE can be confirmed without a second device simply by testing that the authorization server accepts requests without `code_challenge`:

```bash
# This request should be REJECTED by a properly secured OAuth server
# If it returns an authorization code, PKCE enforcement is absent
curl -v "https://www.whatnot.com/oauth/authorize?\
client_id=YOUR_APP_CLIENT_ID\
&redirect_uri=YOUR_REDIRECT_URI\
&response_type=code\
&scope=read:inventory\
&state=test123"
# Absence of code_challenge= in the URL is the indicator
# If server responds 200 and proceeds to authorization, PKCE is not enforced
```

---

## Expected Result

Authorization server should return an error for public clients that omit `code_challenge`:
```json
{"error": "invalid_request", "error_description": "code_challenge required for public clients"}
```

## Actual Result

Authorization proceeds normally without `code_challenge`, allowing code exchange without PKCE verification.

---

## Impact

- Complete account takeover of any Whatnot seller that authorizes a third-party OAuth app
- Access to all granted scopes: `read:inventory`, `write:inventory`, `read:orders`, `write:orders`, `read:customers`
- Refresh token obtained — persistent access even after victim revokes app in UI (if revocation is not properly propagated)
- Affects all mobile users of Whatnot-integrated third-party apps

---

## Evidence

The open-source `oauth2-whatnot` provider (https://github.com/acip/oauth2-whatnot) implements Whatnot's full OAuth flow and contains no `code_challenge` parameter — confirming PKCE is not implemented or enforced by Whatnot's authorization server.

---

## Recommended Fix

- Require PKCE (S256 method) for all public/mobile OAuth clients
- Reject authorization requests lacking `code_challenge` from public clients
- Reference: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), [OAuth 2.0 Security BCP §2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-latest)
