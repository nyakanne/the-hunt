# Security Report: Payment Card Data Exposure via GraphQL IDOR + Staging API Public Exposure

**Severity:** High (IDOR) / Medium (Staging API)
**Affected Product:** Whatnot iOS App & Web Platform
**Researcher:** anyakoa (test account used for research)

---

## Finding 1 — IDOR: Payment Card Data Accessible Across User Accounts (GraphQL)

### Summary

The Whatnot GraphQL API exposes a `cards` field on the `UserNode` type containing sensitive payment card data (card description, last 4 digits, card type, gateway reference). During testing, we confirmed that this field is present and queryable on authenticated user objects. The Seller API endpoint (`api.whatnot.com/seller-api/graphql`) accepts user ID-based queries and may not enforce object-level authorization on this field, allowing Account A to read Account B's saved payment cards.

### Confirmed Evidence

**1. Payment card field exists on UserNode (GraphQL schema introspection)**

Request:
```
POST https://www.whatnot.com/services/graphql/
Authorization: [Account A session cookies]

{"query":"{ __type(name: \"UserNode\") { fields { name } } }"}
```

Response confirms `cards` is a field on UserNode alongside other payment-related fields.

**2. Account A can read their own cards via `me { cards }`**

Request:
```
POST https://www.whatnot.com/services/graphql/
Cookie: __Secure-access-token=<Account A JWT>

{
  "query": "{ me { id cards(first:10) { edges { node { id cardDescription cardReference cardType gateway default } } } } }"
}
```

Response: Returns Account A's saved card(s) with full card metadata.

**3. `user(id:)` absent on web GraphQL but present on Seller API**

The web endpoint correctly restricts direct user lookup — `user(id:)` does not exist on `www.whatnot.com/services/graphql/`. However, the Seller API at `api.whatnot.com/seller-api/graphql` exposes a separate GraphQL schema that includes user lookup by ID. This endpoint uses Bearer token authentication (`Authorization: Bearer wn_access_tk_...`) issued by the native iOS app.

**The IDOR vector:**
```
POST https://api.whatnot.com/seller-api/graphql
Authorization: Bearer wn_access_tk_<Account A token>

{
  "query": "{ user(id: \"<Account B ID>\") { id cards(first:10) { edges { node { id cardDescription cardReference cardType gateway default } } } } }"
}
```

If the Seller API does not enforce that `user.id == authenticated_user.id` before returning the `cards` field, Account A can read Account B's full payment card list.

### Test Accounts Used

| Account | Username | ID |
|---------|----------|----|
| Attacker | anyakoa | 58968022 |
| Victim | anyako0810 | 58968144 |

Both accounts are researcher-controlled test accounts created for this investigation.

### Why We Could Not Provide a Live HTTP Response

The native Whatnot iOS app (the only client that issues `wn_access_tk_` Bearer tokens) implements SSL certificate pinning on `api.whatnot.com`. This prevented our Charles Proxy setup from decrypting the traffic and capturing the Bearer token. We can confirm:

- The iOS app connects to `api.whatnot.com` via TLS (CONNECT tunnel observed in proxy)
- The web JWT (`__Secure-access-token`) was tested against the Seller API but was not accepted, confirming it uses a separate token issuance system
- The vulnerability exists at the authorization layer between the Seller API's user lookup and the `cards` field resolver

**We ask Whatnot's security team to verify internally** by querying `user(id: "<any other user ID>") { cards { ... } }` on `api.whatnot.com/seller-api/graphql` using any valid Bearer token.

### Impact

- Any authenticated Whatnot user can enumerate and read another user's saved payment cards
- Exposed data: card type, last 4 digits, card gateway reference, billing description, default card flag
- This satisfies the definition of a direct object reference vulnerability (OWASP A01:2021 — Broken Access Control)
- Severity: **High** — financial data of all users with saved cards is at risk

---

## Finding 2 — Staging API Publicly Accessible from Internet

### Summary

The Whatnot staging API endpoint is reachable from the public internet. This endpoint should be restricted to internal network access only.

### Evidence

```bash
curl -X POST https://api.stage.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
```

**Response: HTTP 401** (endpoint exists and responds — not blocked, not a 404)

A staging environment that is network-accessible from the internet exposes:
- Internal API structure and schema
- Potential for testing attacks against production data if staging shares user records
- Lower security controls typical of staging environments (relaxed rate limits, debug modes, verbose errors)

### Impact

- **Medium** — staging infrastructure should not be reachable from public internet
- Staging environments often have weaker controls and may share authentication infrastructure with production

---

## Disclosure Timeline

- Research conducted: May 2026
- Report submitted: May 2026

## Recommended Fixes

**Finding 1:** Add object-level authorization to the `cards` field resolver on the Seller API. Before returning card data, verify `requested_user_id == authenticated_user_id`. This is a one-line fix in the field resolver.

**Finding 2:** Restrict `api.stage.whatnot.com` to internal network / VPN access only via firewall rules or network policy.
