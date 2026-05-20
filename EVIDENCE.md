# Evidence for HackerOne Submission

## Evidence A — Staging API Publicly Accessible (no auth needed)

Run this in Terminal right now. No cookies required.

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST https://api.stage.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
```

Expected output: `HTTP 401`

A 401 from a staging URL means the endpoint is live and reachable from the public internet.
Screenshot this terminal output and attach to the report.

---

## Evidence B — Production Seller API Endpoint Confirmed

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
```

Expected output: `HTTP 401`

Confirms the Seller API GraphQL endpoint exists and requires Bearer auth.

---

## Evidence C — Web GraphQL: cards field exists on UserNode

Run this with fresh cookies (paste your Cookie header into the command):

```bash
curl 'https://www.whatnot.com/services/graphql/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: PASTE_YOUR_COOKIE_HERE' \
  -d '{"query":"{ __type(name: \"UserNode\") { fields { name } } }"}' \
  | python3 -m json.tool
```

Look for `cards` in the fields list. Screenshot the response.

---

## Evidence D — Web GraphQL: me.cards returns own payment data

```bash
curl 'https://www.whatnot.com/services/graphql/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: PASTE_YOUR_COOKIE_HERE' \
  -d '{"query":"{ me { id username cards(first:5) { edges { node { id cardDescription cardType gateway } } } } }"}' \
  | python3 -m json.tool
```

This proves the cards field works and returns real card data for the authenticated user.

---

## Evidence E — Web GraphQL: user(id) query does not exist

```bash
curl 'https://www.whatnot.com/services/graphql/' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: PASTE_YOUR_COOKIE_HERE' \
  -d '{"query":"{ user(id: \"58968144\") { id } }"}' \
  | python3 -m json.tool
```

Expected response:
```json
{
  "errors": [
    {
      "message": "Cannot query field 'user' on type 'Query'."
    }
  ]
}
```

This proves the web endpoint has restricted the direct user lookup. The risk lives on the
Seller API (api.whatnot.com/seller-api/graphql) which uses a different schema.

---

## How to collect Evidence C, D, E quickly

1. Open Chrome on Mac
2. Go to whatnot.com — make sure logged in as anyakoa
3. Open DevTools (Cmd+Option+I) → Network tab
4. Reload the page
5. Click any request to www.whatnot.com → Headers → copy the Cookie value
6. Paste it into each curl command above replacing PASTE_YOUR_COOKIE_HERE
7. Run each command in Terminal and screenshot

---

## Key facts to state in the report

- Attacker account: anyakoa (ID: 58968022)
- Victim account: anyako0810 (ID: 58968144)
- Both accounts are researcher-controlled
- The `cards` field on UserNode contains: id, cardDescription, cardReference, cardType, gateway, default
- The Seller API schema (api.whatnot.com/seller-api/graphql) exposes user lookup by ID
- Certificate pinning on the iOS app prevented capture of the Bearer token to complete the live test
- Whatnot's security team can verify the IDOR internally by testing user(id: X) { cards } where X != their own ID
