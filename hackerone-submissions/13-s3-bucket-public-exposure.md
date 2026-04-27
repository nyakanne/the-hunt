# HackerOne Submission — Public S3 Bucket Exposes Internal Documents

**Program:** Whatnot  
**Weakness:** Information Disclosure / Misconfigured Cloud Storage  
**Severity:** Medium  
**Asset:** whatnot-public.s3.amazonaws.com  

---

## Summary

The S3 bucket `whatnot-public.s3.amazonaws.com` is publicly accessible and contains internal Whatnot documents including a GDPR Candidate Privacy Notice (marked as DRAFT) and GST tax forms. While some content may be intentionally public, the bucket's directory listing, naming conventions, and document metadata may expose sensitive internal information. Additionally, the bucket may contain more files than those currently indexed, including internal HR documents, legal drafts, financial records, or configuration files that were accidentally uploaded to the wrong bucket.

---

## Confirmed Publicly Accessible Files

These URLs return documents **without any authentication**:

```
https://whatnot-public.s3.amazonaws.com/regulatory_notices/Candidate+Privacy+Notice+(GDPR)+(DRAFT+8.11)+(ACP).docx.pdf

https://whatnot-public.s3.amazonaws.com/Whatnot+gst506+%5BUsers+Name%5D.pdf
```

---

## Steps to Reproduce

### Step 1 — Confirm public access to known documents

```bash
# Check GDPR Privacy Notice
curl -sI "https://whatnot-public.s3.amazonaws.com/regulatory_notices/Candidate+Privacy+Notice+(GDPR)+(DRAFT+8.11)+(ACP).docx.pdf"

# Expected vulnerable response:
# HTTP/1.1 200 OK
# Content-Type: application/pdf
# x-amz-request-id: ...

# Check GST form
curl -sI "https://whatnot-public.s3.amazonaws.com/Whatnot+gst506+%5BUsers+Name%5D.pdf"
```

---

### Step 2 — Test for bucket directory listing

```bash
# Check if the bucket allows listing all objects (ACL misconfiguration)
curl -s "https://whatnot-public.s3.amazonaws.com/?list-type=2&max-keys=1000" \
  | python3 -m xml.etree.ElementTree - 2>/dev/null || \
  curl -s "https://whatnot-public.s3.amazonaws.com/"

# Also try the REST API listing endpoint
curl -s "https://s3.amazonaws.com/whatnot-public?list-type=2"
```

**Vulnerable response** — XML listing all files:
```xml
<ListBucketResult>
  <Contents>
    <Key>regulatory_notices/...</Key>
    <Key>internal/...</Key>
    <Key>finance/...</Key>
  </Contents>
</ListBucketResult>
```

---

### Step 3 — Enumerate additional file paths

```bash
# Try common internal document paths
for path in \
  "internal/" \
  "finance/" \
  "legal/" \
  "config/" \
  "exports/" \
  "backups/" \
  "employee-data/" \
  "user-exports/" \
  "db-backups/" \
  "env/" \
  ".env" \
  "config.json" \
  "secrets.json"; do
  
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://whatnot-public.s3.amazonaws.com/${path}")
  echo "${path} -> HTTP ${status}"
done
```

---

### Step 4 — Check for sensitive file types in the regulatory_notices prefix

```bash
# Enumerate the regulatory_notices/ prefix
for fname in \
  "Employee+Privacy+Notice" \
  "User+Data+Policy" \
  "Data+Breach+Report" \
  "Security+Audit" \
  "PCI+Compliance" \
  "Financial+Report" \
  "Salary+Data"; do

  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://whatnot-public.s3.amazonaws.com/regulatory_notices/${fname}.pdf")
  echo "${fname} -> HTTP ${status}"
done
```

---

### Step 5 — Check for publicly writable bucket

```bash
# Test if the bucket allows unauthenticated uploads (critical if true)
echo "test" | curl -s -X PUT \
  "https://whatnot-public.s3.amazonaws.com/test-probe-$(date +%s).txt" \
  -H "Content-Type: text/plain" \
  --data-binary @-

# Check if the upload succeeded
curl -sI "https://whatnot-public.s3.amazonaws.com/test-probe-*.txt"
```

If the upload succeeds, the bucket allows public writes — a critical vulnerability enabling malware hosting, phishing page hosting, or content injection.

---

## Expected Result

Only intentionally public files should be accessible. Bucket listing should be disabled. No writes permitted without authentication.

## Actual Result

At minimum, draft internal documents (GDPR privacy notice in DRAFT state, GST tax forms) are publicly accessible. Full extent of exposure requires bucket enumeration.

---

## Impact

| Scenario | Impact |
|---|---|
| GDPR Privacy Notice (DRAFT) publicly accessible | Legal exposure — draft privacy policies may contain incorrect commitments; GDPR Art. 13/14 compliance risk |
| Tax forms publicly accessible | Financial document disclosure |
| Bucket listing enabled | Full inventory of all stored documents exposed to public |
| Bucket publicly writable | Attacker can host malware, phishing pages, or inject malicious content under whatnot-public.s3.amazonaws.com domain |
| Internal exports/backups in bucket | User PII, financial records, or database exports exposed |

---

## Recommended Fix

- Audit all files in `whatnot-public` bucket — remove anything not intentionally public
- Disable public bucket listing (Block Public Access settings in AWS Console)
- Disable public write access — enforce bucket ACL: `private` with explicit public-read grants only for specific keys
- Move draft/internal documents to a private bucket
- Enable S3 access logging to detect past unauthorized access
- Reference: [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
