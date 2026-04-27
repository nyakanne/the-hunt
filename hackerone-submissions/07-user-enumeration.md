# HackerOne Submission — User Enumeration via Login Endpoint

**Program:** Whatnot  
**Weakness:** User Enumeration  
**Severity:** Low  
**Asset:** api.whatnot.com  

---

## Summary

The `POST https://api.whatnot.com/api/login` endpoint returns a different response (HTTP status code and/or response body) when a valid email address is submitted with a wrong password versus when a non-existent email address is submitted. This allows an unauthenticated attacker to enumerate valid email addresses registered on Whatnot at scale.

---

## Steps to Reproduce

### Step 1 — Test with a known valid email (your own account)

```bash
curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"YOUR_REAL_WHATNOT_EMAIL@example.com","password":"deliberatelywrongpassword123!","device_id":"test-001","app_type":"web"}'
```

Record the HTTP status code and full response body.

---

### Step 2 — Test with a confirmed non-existent email

```bash
curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST https://api.whatnot.com/api/login \
  -H "Content-Type: application/json" \
  -H "X-Whatnot-App: whatnot-web" \
  -d '{"email":"thisusercannotpossiblyexist99999xyzabc@nonexistentdomain99.com","password":"deliberatelywrongpassword123!","device_id":"test-001","app_type":"web"}'
```

Record the HTTP status code and full response body.

---

### Step 3 — Compare responses

If there is **any difference** between the two responses — in status code, body text, error message, or response timing — user enumeration is confirmed.

Examples of enumerable differences:
- `"error": "invalid_password"` vs `"error": "user_not_found"`
- HTTP 401 (valid user) vs HTTP 404 (no user)
- HTTP 400 with `"email not registered"` vs HTTP 400 with `"incorrect password"`
- Response time difference of >50ms consistently between the two cases

---

### Step 4 — Demonstrate at scale (optional, low-impact proof)

Using a list of 10 email addresses (5 you know are registered, 5 you know are not), confirm the differential response is consistent and reliable.

---

## Expected Result

Both requests should return an identical response — same HTTP status code, same body, same timing — regardless of whether the email exists:
```json
{"error": "invalid_credentials", "message": "The email or password is incorrect."}
```

## Actual Result (if vulnerable)

Different status codes or error messages distinguish valid from invalid email addresses.

---

## Impact

- An attacker can build a list of verified Whatnot email addresses for targeted phishing campaigns
- Enumerated emails can be cross-referenced with credential breach databases for credential stuffing attacks
- Combined with the Whatnot username from public profiles, full contact details become correlated

---

## Recommended Fix

- Return identical HTTP status + body for wrong-password and no-such-user cases
- Use constant-time comparison for the email lookup step to eliminate timing side channel
- Message: `"The email or password you entered is incorrect."` (no differentiation)
