# [SEVERITY] Title of the finding

<!--
Public summary only. How much to publish depends on patch status:
  - unpatched / under embargo        -> do not create this file; leave "report" empty in findings.json (shows `redacted`)
  - patched, fix not widely deployed -> advisory-level summary, no payloads or runnable PoC
  - patched and widely deployed      -> full details and PoC are fine
The detailed report stays in Notion; link it under "References" when it is safe to share.
-->

```text
id        : W2-000
target    : <product or program / asset>
cve       : <CVE-YYYY-NNNNN>            (CVEs only)
platform  : <HackerOne / Bugcrowd / ...> (bug bounty only)
severity  : <critical / high / medium / low>  (CVSS x.x — <vector>)
class     : <CWE-xxx: IDOR / SSRF / XSS / auth bypass / ...>
affected  : <versions>
fixed     : <version>
status    : <fixed / triaged / disclosed>
date      : YYYY-MM-DD
```

## Summary

One paragraph: what is broken and what an attacker gains.

## Root cause

Which check is missing or wrong, and where. Describe the flaw, not the exploit.

## Impact

What data or action is exposed, who is affected, preconditions (auth required? user interaction? default config?).

## Fix

Fixed version or mitigation. What users of the product should do.

## Proof of concept

Withheld until the fix is widely deployed.

```text
sha256(poc) : <hash of the PoC file, to prove prior possession>
```

## Timeline

- YYYY-MM-DD — reported
- YYYY-MM-DD — confirmed / triaged
- YYYY-MM-DD — fixed
- YYYY-MM-DD — CVE published / disclosed

## References

- Vendor advisory: <url>
- NVD: <url>
- Detailed writeup: <Notion url>

> Redact tokens, cookies, personal data and anything the vendor or program has not approved for disclosure.
