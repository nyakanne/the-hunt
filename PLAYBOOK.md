# The Hunt — Bug Bounty Playbook
## Systematic Procedure for Whatnot (and Any Target)

---

## Our Methodology (In Order)

### Phase 1 — Passive OSINT (No Accounts, No Touching Target)
Goal: understand the full attack surface before sending a single request.

1. **HackerOne program page** — scope, out-of-scope, bounty tiers, rules
2. **Engineering blog** — tech stack, architectural decisions, past incidents
3. **GitHub (company org)** — public repos, leaked secrets, API patterns
4. **Unofficial API wrappers** — endpoint lists, auth flows, GraphQL schema hints
5. **Certificate transparency** — `crt.sh/?q=%.target.com` — all subdomains
6. **S3 bucket enumeration** — `target-public`, `target-assets`, `target-uploads`
7. **DNS recon** — MX records, mail servers often bypass CDN

**Tools:** WebSearch, WebFetch, crt.sh, GitHub search

---

### Phase 2 — Unauthenticated Probing (No Account Needed)
Run `python3 run.py` — covers all of these automatically.

| Test | What to look for |
|---|---|
| S3 buckets | HTTP 200 on internal documents |
| Staging endpoint | HTTP 200/401 on `api.stage.*` |
| GraphQL introspection | `__schema` in response without auth |
| OAuth PKCE | Auth server accepts requests without `code_challenge` |
| WebSocket endpoints | 101 Switching Protocols |
| CSWSH | 101 from evil Origin header |
| User enumeration | Different HTTP codes or bodies for fake vs real email |
| Security headers | Missing CSP, X-Frame-Options, HSTS |

---

### Phase 3 — Authenticated Testing (1 Free Account)
`python3 run.py -e your@email.com -p YourPass1!`

| Test | What to look for |
|---|---|
| GraphQL introspection | `__schema` returns full type list |
| Field suggestions | "Did you mean X?" in error messages |
| Batching | Array of N results from batched request |
| Mass assignment | Privileged fields (isAdmin, commissionRate) accepted in mutation |
| SSRF | Product image URL triggers out-of-band DNS/HTTP hit |

---

### Phase 4 — IDOR Testing (2 Accounts, Account B has payment card)
`python3 run.py -e a@x.com -p Pa1! -e2 b@x.com -p2 Pb1!`

| Test | What to look for |
|---|---|
| Payment card IDOR | `paymentCards` data returned for other user's ID |
| Stream token IDOR | `streamToken` returned for stream you don't own |
| RTMP key IDOR | `multicastDestinations.streamKey` for other seller |
| Alias bypass | Same data accessible via GraphQL alias |

---

### Phase 5 — Deep Testing (Seller Accounts, Mobile App, Burp)
- Seller accounts: apply at `whatnot.com/seller` (5–14 days)
- Mobile app: proxy through Burp to capture real headers/tokens
- Streaming: test stream token + multicast RTMP key IDORs
- Interactsh: confirm blind SSRF with out-of-band callbacks

---

## Confirmed Whatnot Endpoints

```
Login:          POST https://api.whatnot.com/api/login
Verify:         POST https://api.whatnot.com/api/verify
GraphQL:        POST https://api.whatnot.com/seller-api/graphql
GraphQL main:   POST https://api.whatnot.com/graphql
Staging GQL:    POST https://api.stage.whatnot.com/seller-api/graphql
OAuth Auth:     GET  https://api.whatnot.com/seller-api/rest/oauth/authorize
OAuth Token:    POST https://api.whatnot.com/seller-api/rest/oauth/token
S3 bucket:      https://whatnot-public.s3.amazonaws.com  (PUBLIC - confirmed)
```

## Confirmed Headers (current, as of 2026)

```
Content-Type: application/json
X-Whatnot-App: whatnot-ios
User-Agent: Whatnot/26.15.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)
Origin: https://www.whatnot.com
Authorization: Bearer wn_access_tk_<token>   (when authenticated)
```

## Token Formats
```
Production:  wn_access_tk_...
Staging:     wn_access_tk_test_...
```

---

## Tech Stack Reference

| Layer | Technology |
|---|---|
| Backend | Elixir / Phoenix |
| GraphQL | Absinthe + Apollo |
| Real-time | Phoenix Channels (WebSocket) |
| Mobile | React Native (`com.whatnot_mobile`) |
| Cloud | AWS |
| CDN/WAF | Cloudflare |
| Secrets | Doppler (3,000+ secrets) |
| Payments | Stripe |
| CI/CD | GitHub Actions |

---

## All 17 Findings (This Hunt)

| # | Title | Severity | File |
|---|---|---|---|
| 1 | IDOR: Payment card + billing address | Critical | `01-idor-payment-data.md` |
| 2 | Stream token hijacking | High | `02-stream-token-hijack.md` |
| 3 | Missing PKCE in OAuth 2.0 | High | `03-missing-pkce-oauth.md` |
| 4 | GraphQL introspection on production | Medium | `04-graphql-introspection.md` |
| 5 | Staging API publicly accessible | Medium | `05-staging-api-exposed.md` |
| 6 | Secret Max Bid oracle attack | Medium | `06-secret-max-bid-oracle.md` |
| 7 | User enumeration via login | Low | `07-user-enumeration.md` |
| 8 | GraphQL batching rate-limit bypass | High | `08-graphql-batching-rate-limit-bypass.md` |
| 9 | Field suggestion schema enumeration | Medium | `09-graphql-field-suggestion-schema-leak.md` |
| 10 | Alias-based authorization bypass | High | `10-graphql-alias-authorization-bypass.md` |
| 11 | WebSocket subscription auth bypass | High | `11-graphql-subscription-websocket-auth-bypass.md` |
| 12 | Mass assignment via mutations | Critical | `12-mass-assignment-graphql-mutations.md` |
| 13 | S3 bucket public exposure | Medium | `13-s3-bucket-public-exposure.md` ✅ CONFIRMED |
| 14 | SSRF via product image URL | High | `14-ssrf-via-product-image-url.md` |
| 15 | Cross-Site WebSocket Hijacking | High | `15-cross-site-websocket-hijacking.md` |
| 16 | Cloudflare origin IP bypass | Medium | `16-cloudflare-origin-ip-bypass.md` |
| 17 | Multicast RTMP key IDOR | High | `17-multicast-rtmp-key-disclosure.md` |

---

## Applying This Playbook to Any New Target

1. Clone this repo: `git clone https://github.com/nyakanne/the-hunt`
2. Copy `run.py` — update the endpoint constants at the top
3. Copy `PLAYBOOK.md` as your checklist
4. Run phases 1–4 in order
5. Submit each confirmed finding individually to HackerOne
6. Repeat for next target

---

## Estimated Bounty Ranges (Whatnot)

| Severity | Typical range |
|---|---|
| Critical (IDOR payment, mass assignment) | $5,000 – $20,000 |
| High (stream hijack, SSRF, batching) | $1,500 – $8,000 |
| Medium (introspection, staging, S3) | $300 – $2,000 |
| Low (user enum) | $0 – $300 |
| **Total potential (all 17)** | **$15,000 – $80,000+** |

---

## Commands Reference

```bash
# Install
pip install requests

# Zero accounts
python3 run.py

# 1 account
python3 run.py -e your@email.com -p YourPass1!

# 2 accounts (IDOR tests)
python3 run.py -e a@email.com -p Pa1! -e2 b@email.com -p2 Pb1!

# With SSRF blind detection
python3 run.py -e your@email.com -p Pass1! --ssrf https://YOUR-ID.oast.fun

# Get interactsh for SSRF
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
```

---

## Submit Reports
```
https://hackerone.com/whatnot/reports/new?type=team&report_type=vulnerability
```
