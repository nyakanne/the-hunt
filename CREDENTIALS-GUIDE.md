# What Accounts & Credentials You Need

## TL;DR — Do These Right Now (Zero Accounts)

```bash
pip install requests
python3 test_runner.py
```

This runs 8 tests with no login needed: S3 bucket, user enumeration, staging exposure,
WebSocket endpoints, CSWSH, OAuth PKCE check, and infrastructure probes.

---

## Account Setup Guide

### Level 1 — No Account (8 tests run automatically)
Findings covered: S3 bucket, user enumeration, staging API, WebSocket discovery, CSWSH, OAuth PKCE

Nothing to create. Run `python3 test_runner.py` right now.

---

### Level 2 — 1 Buyer Account (adds 5 more tests)

**Create at:** https://www.whatnot.com/register  
**Requirements:** Just an email address. Takes 2 minutes. Free.

```bash
python3 test_runner.py --email your@email.com --password YourPassword1!
```

**Unlocks:**
- GraphQL introspection test (Finding #4)
- GraphQL batching / rate limit bypass (Finding #8)
- Field suggestion schema enumeration (Finding #9)
- Mass assignment via mutations (Finding #12)
- SSRF via product image URL (Finding #14)

---

### Level 3 — 2 Buyer Accounts (adds IDOR tests — highest bounty)

Create a **second** Whatnot account with a different email.  
Add a payment method (credit card) to Account B so it has `paymentCards` data.

```bash
python3 test_runner.py \
  --email account-a@email.com --password PasswordA1! \
  --email2 account-b@email.com --password2 PasswordB1!
```

**Unlocks:**
- IDOR: Payment card + billing address (Finding #1) — **Critical, $5k–$15k**
- IDOR: Alias-based auth bypass (Finding #10)
- User enumeration uses your real email for comparison

---

### Level 4 — 2 Seller Accounts (adds stream/RTMP tests)

Seller accounts require applying through: https://www.whatnot.com/seller  
- Need government-issued ID
- Need a 30–60 second product video
- Takes 5–14 days to approve

Once approved on both accounts, start a livestream on Account B then:

```bash
python3 test_runner.py \
  --email seller-a@email.com --password PasswordA1! \
  --email2 seller-b@email.com --password2 PasswordB1!
```

**Unlocks:**
- Stream token IDOR / hijacking (Finding #2) — **High, $2k–$6k**
- Multicast RTMP key IDOR (Finding #17) — **High, $2k–$8k**

---

### Level 5 — SSRF Callback Detection

For the SSRF test to detect blind server-side fetches:

```bash
# Install interactsh (free, open source)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start it — it gives you a URL like abc123.oast.fun
interactsh-client

# Pass the URL to the test runner
python3 test_runner.py \
  --email your@email.com --password YourPass1! \
  --ssrf-callback https://abc123.oast.fun
```

When Whatnot's server fetches your product image URL, interactsh records the hit.
That DNS/HTTP interaction is your SSRF proof for HackerOne.

---

## Confirmed Endpoints (No Auth Needed)

| Endpoint | Method | Purpose |
|---|---|---|
| `https://whatnot-public.s3.amazonaws.com/` | GET | S3 bucket (CONFIRMED PUBLIC) |
| `https://api.whatnot.com/api/login` | POST | Login — user enum test |
| `https://api.stage.whatnot.com/seller-api/graphql` | POST | Staging GraphQL |
| `https://api.whatnot.com/seller-api/rest/oauth/authorize` | GET | OAuth authorize — PKCE test |
| `https://api.whatnot.com/socket/websocket` | GET+Upgrade | WebSocket probe |

## Confirmed Endpoints (Auth Required)

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `https://api.whatnot.com/seller-api/graphql` | POST | Bearer token | Main GraphQL API |
| `https://api.whatnot.com/graphql` | POST | Bearer token | Internal GraphQL API |
| `https://api.whatnot.com/api/verify` | POST | None | OTP verification |
| `https://api.whatnot.com/seller-api/rest/oauth/token` | POST | client_id+secret | Token exchange |

## Required Headers for All API Requests

```
Content-Type: application/json
Authorization: Bearer wn_access_tk_<your_token>
Apollographql-Client-Name: web
Apollographql-Client-Version: 20230710-1529
X-Whatnot-App: whatnot-web
Origin: https://www.whatnot.com
Referer: https://www.whatnot.com/
```

## Token Format

| Environment | Prefix |
|---|---|
| Production | `wn_access_tk_` |
| Staging | `wn_access_tk_test_` |

## OAuth URLs (Confirmed)

| Step | URL |
|---|---|
| Authorization | `https://api.whatnot.com/seller-api/rest/oauth/authorize` |
| Token exchange | `https://api.whatnot.com/seller-api/rest/oauth/token` |
| Staging authorize | `https://api.stage.whatnot.com/seller-api/rest/oauth/authorize` |
| Staging token | `https://api.stage.whatnot.com/seller-api/rest/oauth/token` |

---

## Quick Test Checklist

```
[ ] Run: python3 test_runner.py               (zero accounts — do this first)
[ ] Check: S3 bucket 200 → file Finding #13 immediately
[ ] Check: User enum body/status difference → file Finding #7
[ ] Create 1 buyer account at whatnot.com/register
[ ] Run: python3 test_runner.py --email x --password y
[ ] Check: GraphQL introspection → file Finding #4
[ ] Check: Batching returns array of 10 results → file Finding #8
[ ] Add payment card to Account B
[ ] Create 2nd buyer account
[ ] Run: python3 test_runner.py --email a --password p1 --email2 b --password2 p2
[ ] Check: IDOR payment data returned → file Finding #1 (Critical)
[ ] Apply for seller account (for stream/RTMP tests — highest effort)
[ ] Set up interactsh for SSRF blind detection
```
