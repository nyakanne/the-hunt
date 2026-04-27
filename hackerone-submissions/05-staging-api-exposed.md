# HackerOne Submission — Staging API Publicly Accessible from Internet

**Program:** Whatnot  
**Weakness:** Information Disclosure / Security Misconfiguration  
**Severity:** Medium  
**Asset:** api.stage.whatnot.com  

---

## Summary

Whatnot's staging GraphQL API endpoint (`https://api.stage.whatnot.com/seller-api/graphql`) is reachable from the public internet. Staging environments commonly have reduced security controls, verbose error messages, disabled rate limiting, and may contain real user data or test credentials. External access to the staging API allows attackers to probe for vulnerabilities with less risk of detection, bypass WAF/rate-limit rules that only apply to production, and potentially access sensitive data if staging shares data stores with production.

---

## Steps to Reproduce

### Step 1 — Confirm the staging endpoint is reachable

```bash
curl -v https://api.stage.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}'
```

If the response is anything other than a network error or IP block (e.g., a GraphQL response, a 401, a 403 with a JSON body), the endpoint is publicly reachable.

---

### Step 2 — Test for relaxed security controls

#### a) Test introspection without authentication:
```bash
curl -s https://api.stage.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

#### b) Test for verbose error messages:
```bash
curl -s -X POST https://api.stage.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ invalidFieldThatDoesNotExist }"}'
```

Look for stack traces, internal service names, database error strings, or file paths in the response.

#### c) Test for disabled rate limiting:
Send 100 rapid requests in a loop and observe if any rate-limit response (429) is returned:
```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST https://api.stage.whatnot.com/seller-api/graphql \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __typename }"}' &
done
wait
```

If all requests return 200/401 (never 429), rate limiting is absent on staging.

---

### Step 3 — Test staging token registration

Attempt to create a staging account and generate a `wn_access_tk_test_` token:

```bash
curl -s -X POST https://api.stage.whatnot.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD","device_id":"test-001","app_type":"web"}'
```

If a `wn_access_tk_test_` token is returned, staging login is fully functional from the public internet.

---

### Step 4 — Test if staging GraphQL introspection is enabled

With a staging token:
```bash
curl -s -X POST https://api.stage.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_test_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name } } } }"}'
```

Introspection on staging reveals all mutations including internal/admin operations not exposed to production clients.

---

## Expected Result

`api.stage.whatnot.com` should be inaccessible from the public internet, returning a network timeout or IP-based block.

## Actual Result (if vulnerable)

The endpoint is reachable and responds with GraphQL-formatted responses, confirming it is publicly accessible.

---

## Impact

- Staging environment used as a low-friction platform for probing vulnerabilities without production-level monitoring
- Verbose errors reveal internal architecture (database schema, service names, stack traces)
- Absent rate limiting allows unlimited authentication attempts, enumeration, and fuzzing
- If staging shares data infrastructure with production, data exposure is a direct risk
- Internal GraphQL mutations discoverable via introspection on staging, then exploitable on production

---

## Recommended Fix

- Restrict `api.stage.whatnot.com` to internal network / VPN access only (firewall/security group rule)
- Apply equivalent WAF, rate limiting, and logging to staging as production
- Ensure staging data is fully synthetic (no real PII or financial data)
- Disable verbose error output in staging API responses
