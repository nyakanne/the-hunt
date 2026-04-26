# Whatnot Bug Bounty — Master Index of Findings
**Target:** https://hackerone.com/whatnot  
**Submit at:** https://hackerone.com/whatnot/reports/new?type=team&report_type=vulnerability  
**Total findings:** 17  
**Research dates:** 2026-04-26  

---

## Priority Queue (Submit in this order)

| # | File | Title | Severity | Est. Bounty | Needs Accounts? |
|---|---|---|---|---|---|
| 1 | `12-mass-assignment-graphql-mutations.md` | Mass Assignment via GraphQL Mutations → Privilege Escalation | **Critical** | $5k–$20k | 1 account |
| 2 | `01-idor-payment-data.md` | IDOR: Payment card + billing address via GraphQL | **Critical** | $5k–$15k | 2 accounts |
| 3 | `14-ssrf-via-product-image-url.md` | SSRF via product image URL fetch (→ AWS metadata) | **High** | $3k–$10k | 1 seller account |
| 4 | `17-multicast-rtmp-key-disclosure.md` | RTMP stream keys exposed via multicast API IDOR | **High** | $2k–$8k | 2 seller accounts |
| 5 | `02-stream-token-hijack.md` | Stream token disclosure → livestream hijacking | **High** | $2k–$6k | 2 seller accounts |
| 6 | `11-graphql-subscription-websocket-auth-bypass.md` | Unauthenticated GraphQL subscription via WebSocket | **High** | $2k–$5k | 0 (unauthenticated) |
| 7 | `08-graphql-batching-rate-limit-bypass.md` | GraphQL batching bypasses rate limiting → OTP brute force | **High** | $1.5k–$4k | 1 account |
| 8 | `10-graphql-alias-authorization-bypass.md` | Alias-based GraphQL authorization bypass | **High** | $1.5k–$4k | 2 accounts |
| 9 | `15-cross-site-websocket-hijacking.md` | Cross-Site WebSocket Hijacking (CSWSH) | **High** | $1.5k–$4k | victim in browser |
| 10 | `03-missing-pkce-oauth.md` | Missing PKCE in OAuth 2.0 → auth code interception | **High** | $1k–$3k | 1 OAuth app |
| 11 | `13-s3-bucket-public-exposure.md` | Public S3 bucket exposes internal documents | **Medium** | $500–$2k | 0 (no auth needed) |
| 12 | `16-cloudflare-origin-ip-bypass.md` | Cloudflare WAF bypass via origin IP discovery | **Medium** | $500–$2k | 0 (OSINT) |
| 13 | `04-graphql-introspection.md` | GraphQL introspection enabled on production | **Medium** | $500–$1.5k | 1 account |
| 14 | `09-graphql-field-suggestion-schema-leak.md` | Schema enumeration via GraphQL field suggestions | **Medium** | $300–$1k | 1 account |
| 15 | `05-staging-api-exposed.md` | Staging API publicly accessible from internet | **Medium** | $300–$1k | 0 (unauthenticated) |
| 16 | `06-secret-max-bid-oracle.md` | Secret Max Bid oracle attack (auction manipulation) | **Medium** | $300–$800 | 2 accounts |
| 17 | `07-user-enumeration.md` | User enumeration via login endpoint | **Low** | $0–$300 | 0 (no auth needed) |

---

## Quick Wins (No Account Needed — Test These First)

These can be tested in under 10 minutes right now:

### 1. S3 Bucket (Finding #13)
```bash
curl -sI "https://whatnot-public.s3.amazonaws.com/regulatory_notices/Candidate+Privacy+Notice+(GDPR)+(DRAFT+8.11)+(ACP).docx.pdf"
# 200 OK = confirmed, file it immediately
```

### 2. User Enumeration (Finding #17)
```bash
# Compare these two responses:
curl -s -w "HTTP:%{http_code}\n" -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"zzz99fake@notreal.xyz","password":"x","device_id":"x","app_type":"web"}'

curl -s -w "HTTP:%{http_code}\n" -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"YOUR_REAL_EMAIL","password":"wrongpass","device_id":"x","app_type":"web"}'
```

### 3. WebSocket Endpoint Discovery (Finding #11)
```bash
for path in "/socket/websocket" "/graphql/websocket" "/subscriptions"; do
  r=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://api.whatnot.com${path}")
  echo "${path} -> $r"
done
```

### 4. CSWSH Origin Check (Finding #15)
```bash
curl -sv -H "Origin: https://evil.com" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://api.whatnot.com/socket/websocket?vsn=2.0.0" 2>&1 | grep "< HTTP"
# 101 = vulnerable, 403 = safe
```

---

## Tech Stack Reference

| Component | Detail |
|---|---|
| Backend | Elixir / Phoenix |
| API | Apollo GraphQL + REST |
| Real-time | Phoenix Channels / Absinthe subscriptions |
| Mobile | React Native (`com.whatnot_mobile`) |
| Cloud | AWS (confirmed) |
| CDN/WAF | Cloudflare |
| Secrets | Doppler (3,000+ secrets, 14 systems, 8 envs) |
| Payments | Stripe |
| Token format | `wn_access_tk_` (prod) / `wn_access_tk_test_` (staging) |
| GraphQL prod | `https://api.whatnot.com/seller-api/graphql` |
| GraphQL staging | `https://api.stage.whatnot.com/seller-api/graphql` |
| Login | `POST https://api.whatnot.com/api/login` |
| Verify | `POST https://api.whatnot.com/api/verify` |
| S3 bucket | `whatnot-public.s3.amazonaws.com` (public) |
| Known subdomains | status.whatnot.com, help.whatnot.com, selleracademy.whatnot.com |

---

## Apollo Client Headers (required for API requests)
```
Content-Type: application/json
Authorization: Bearer wn_access_tk_<token>
Apollographql-Client-Name: web
Apollographql-Client-Version: 20230710-1529
X-Whatnot-App: whatnot-web
Origin: https://www.whatnot.com
```

---

## Tools You'll Need

| Tool | Purpose | Install |
|---|---|---|
| `curl` | HTTP requests | built-in |
| `websocat` | WebSocket testing | `cargo install websocat` |
| `wscat` | WebSocket testing | `npm install -g wscat` |
| `interactsh-client` | SSRF/blind callback detection | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| `clairvoyance` | GraphQL field suggestion enumeration | `pip install clairvoyance` |
| Burp Suite | Full proxy/intercept | https://portswigger.net/burp |
| `ffmpeg` | Stream token PoC | `apt install ffmpeg` |

---

## Estimated Total Bounty Range

Conservative: **~$15,000–$25,000**  
Optimistic (if SSRF hits AWS metadata, mass assignment confirmed): **$40,000–$80,000+**
