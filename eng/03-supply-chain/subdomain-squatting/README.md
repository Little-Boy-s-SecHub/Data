---
schema_version: 1
id: WEB-A03-SUBDOMAIN-SQUATTING
title: "Domain/Subdomain Squatting & Lookalike Domains"
slug: subdomain-squatting
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A03:2025
cwe:
  - CWE-1007
  - CWE-451
content_status: technical-review
payload_status: none
last_verified: null
---

# Domain/Subdomain Squatting & Lookalike Domains

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain domain/subdomain squatting, typosquatting, and homoglyph/lookalike by root cause rather than just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to potentially confuse users. 
- Perform controlled testing in a local lab and distinguish expected results from false positives. 
- Choose the root control, deploy the fix, and retest with positive, negative, and boundary cases.

## 2. Prerequisites

- DNS, eTLD+1, subdomain, IDN/punycode and how the browser displays the host.

- Asset inventory for domains, subdomains, certificates, email senders, and redirect allowlists.

- Distinguish squatting/lookalike domains from dangling DNS leading to subdomain takeover.

## 3. Background Knowledge

Imagine a legitimate brand using `a-shop.lab.test` for sales and `help.a-shop.lab.test` for customer support. Users often glance quickly at the address bar, email, or link in a message; they can trust a domain just because it looks similar to the real brand.

**Domain/subdomain squatting** occurs when an actor controls a domain, subdomain, or namespace that appears to be related to a brand but is not actually part of the valid inventory. Common variants include:

- **Typosquatting:** change, add, or remove characters to create typing errors such as `a-sh0p.lab.test` or `ashop-support.lab.test`.
- **Homoglyph/lookalike:** use Unicode characters that look like Latin characters, for example `а-shop.lab.test` where the first character is Cyrillic `а`.
- **Subdomain lookalike:** use name structures that mislead users, for example `login.a-shop.example-owner.lab.test` is not a subdomain of `a-shop.lab.test`.

```yaml
# Local fixture only: canonical inventory and suspicious candidates
canonical_domains:
  - a-shop.lab.test
approved_subdomains:
  - www.a-shop.lab.test
  - help.a-shop.lab.test
  - checkout.a-shop.lab.test
review_candidates:
  - a-sh0p.lab.test
  - ashop-support.lab.test
  - а-shop.lab.test
  - login.a-shop.example-owner.lab.test
```

## 4. Description and Root Cause

The flaw in this lesson is not about taking over the orphan DNS resource. The root cause here is **a user or system being led to a domain/subdomain that appears legitimate but is not under control or authorized to represent the brand**.

Common causes:

- The inventory of domains/subdomains is incomplete, so applications, emails, SSO, or internal documents may mistakenly accept external domains. 
- UI only displays the brand label or part of the host, without clarifying the eTLD+1/canonical domain when users are about to perform sensitive actions. 
- Redirect allowlist, CORS, OAuth callback, or email-link validator checks by substring like `contains("a-shop")` instead of allowing standardized hosts in the allowlist. 
- The detection process for lookalike, homoglyph, and punycode does not exist or is not included in the review before campaign release.

Subdomain takeover by dangling DNS is a related lesson but with a different mechanism: takeover requires DNS to still point to a provider resource that has been released and the provider allows another actor to reclaim that binding. This lesson only mentions takeover to distinguish it, not to teach the process of claiming or exploiting the binding. [S2]

> **Mapping note:** metadata uses CWE-1007 for cases where the interface does not adequately distinguish homoglyph/punycode, and CWE-451 for cases where domain/brand presentation causes users to misunderstand important information. This is the closest mapping for user/domain misrepresentation, not covering all types of domain abuse. [S3], [S4]

## 5. Threat Model and Exploitation Conditions

- **Assets:** canonical domain, approved subdomain, user trust, email sender, redirect URI, OAuth callback, and domain inventory synthetic.

- **Actor:** offline reviewer in the lab; does not register a domain, does not claim a subdomain, does not send emails or traffic to the Internet.

- **Trust boundary:** where a user or system decides whether a host represents the brand: browser UI, email template, redirect handler, CORS/OAuth allowlist, and internal documentation.

- **Necessary condition:** candidate domain/subdomain causes confusion with the brand or valid host, while the system/UI/process does not sufficiently distinguish between the real host and the lookalike.

- **Environment:** list of domains `.lab.test`, offline classification script and local redirect fixture; do not public DNS.

Just seeing a string of 'similar' names is not enough to conclude a risk. Evidence must clearly specify the canonical host, candidate host, the matching rule that failed, the location where the user sees the domain, and the sensitive action that could be affected.

## 6. Attack Mechanism

Lookalike domains target the user's trust decision or the application's allowlist logic. If the system only checks substrings, truncates hosts in UI, or does not clearly display punycode/homoglyphs, users can mistake a candidate for a valid domain; the application may also accept redirects or callbacks that are not part of the inventory. This mechanism is different from subdomain takeover because it does not require DNS of the organization to point incorrectly to a deprovisioned resource.

## 7. Testing in an Authorized Lab

1. **Setup:** create canonical inventory `.lab.test`, list of synthetic candidates and local redirect fixture; do not configure resolver/public DNS.
2. **Baseline:** verify valid hosts like `a-shop.lab.test` and `help.a-shop.lab.test` are correctly recognized after normalization IDNA/lowercase/trailing dot.
3. **Action:** check typosquatting, homoglyph, and subdomain lookalike candidates using offline script; check redirect handler only accepts exact allowlist.
4. **Expected result:** candidates not in inventory are warned or rejected; UI displays full/punycode domain when there is IDN or sensitive action.
5. **Boundary:** check mixed case, trailing dot, punycode, multi-level subdomain, hyphen, numbers replacing letters, and hosts with brand in a label not being eTLD+1.
6. **Cleanup:** remove local fixture and test output; do not register domain, do not claim tenant, do not send real email.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples in the exact context noted in the annotation. Before use, compare the expected result and risk; only run in an authorized local fixture. This lesson does not provide payloads for domain registration, service claiming, or phishing.

```yaml
# Synthetic domain review cases for offline validation
case_id: WEB-A03-SUBDOMAIN-SQUATTING-001
canonical:
  - a-shop.lab.test
approved:
  - www.a-shop.lab.test
  - help.a-shop.lab.test
candidates:
  - host: a-sh0p.lab.test
    reason: digit-substitution typo
  - host: ashop-support.lab.test
    reason: brand-plus-suffix lookalike
  - host: а-shop.lab.test
    reason: Cyrillic homoglyph for Latin a
  - host: login.a-shop.example-owner.lab.test
    reason: brand appears in a non-authoritative label
expected_result: candidates require review or rejection unless explicitly approved in inventory
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: substring matching trusts unrelated lookalike hosts.
from urllib.parse import urlparse

BRAND_FRAGMENT = "a-shop"

def is_trusted_redirect(url):
    host = urlparse(url).hostname or ""
    return BRAND_FRAGMENT in host
```

```python
# SECURE: trust only exact normalized hosts from the owned inventory.
from urllib.parse import urlparse

ALLOWED_HOSTS = {
    "a-shop.lab.test",
    "www.a-shop.lab.test",
    "help.a-shop.lab.test",
}

def normalize_host(host):
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return ""

def is_trusted_redirect(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    host = normalize_host(parsed.hostname or "")
    return host in ALLOWED_HOSTS
```
The host allowlist must be based on the standardized canonical inventory, not on substrings, vague regex, or brand keywords. For IDN, UI, the full domain should be displayed and punycode/homoglyph clarified before sensitive actions. [S3], [S4]

## 10. Detection

- Cross-check URL in the email template, redirect allowlist, OAuth callback, CORS origin, certificate inventory, and public documents with the canonical domain inventory.

- Flag candidates with edit distance close to the brand, numbers replacing letters, unusual hyphen/suffix support, punycode or Unicode homoglyph.

- Check UI on the sensitive screen to see if it displays the full host, not just the brand label or logo.

- In the lab, only use the synthetic list; do not resolve public DNS, do not send emails, and do not register a domain to demonstrate.

## 11. Defense

### Compulsory control

- Maintain a canonical domain/subdomain inventory with owner, purpose, related email/cert/SSO, and review date.

- Match redirect, OAuth callback, CORS origin, and email-link validation using an exact normalized host allowlist instead of a substring.

- Display the full domain or the Punycode clearly during login, payment, OAuth authorization, and sensitive actions.

### Defense-in-depth

- Monitor lookalike/homoglyph domains from authorized sources and include them in the brand response process.

- Use SPF, DKIM, DMARC, and the review template to reduce the likelihood of phishing emails making users trust domains outside the inventory.

- Train operators to distinguish between valid domains, lookalike subdomains, and subdomain takeover due to dangling DNS.

## 12. Retest

- **Positive:** The approved canonical host and subdomain still function correctly after normalization.

- **Negative:** typosquatting, homoglyph, unusual punycode, and hosts containing unauthorized brand labels are rejected or warned.

- **Boundary:** mixed case, trailing dot, multiple levels of subdomain, IDN, brand fragment in path/query and redirect URL encoded.

- **Telemetry:** store candidate, normalized host, decision rule, screen/context, and owner inventory without collecting actual user data.

## 13. Common Mistakes

- Equate subdomain squatting with dangling DNS/subdomain takeover.

- Use `contains("brand")` to identify a trustworthy domain.

- Only look at the domain with the naked eye without normalizing IDNA/punycode.

- Only check the main domain but ignore the sender email, OAuth redirect, CORS, and user documentation.

- Register a real domain or claim a real tenant while the lab only requires a synthetic fixture.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Domain squatting:** controlling a domain that misleadingly appears to belong to or be authorized by another brand.

- **Subdomain squatting:** using a subdomain or namespace with a structure that causes confusion about the real owner, for example a brand under a parent domain that does not belong to the organization.

- **Typosquatting:** creating similar variants by typing errors, replacing letters with numbers, adding/removing hyphens, or changing TLD.

- **Homoglyph:** a character with a different Unicode code but looks like a familiar character, which can cause users to misread the domain.

- **Lookalike domain:** a domain/subdomain that looks like a legitimate domain due to typos, homoglyphs, brand suffixes, or misleading label layout.

- **Punycode/IDNA:** a mechanism for representing Unicode domains in the form ASCII; useful for detecting and displaying suspicious IDN.

- **Subdomain takeover:** a related lesson but with a different mechanism; occurs when an organization's DNS still points to a released provider resource and another actor is able to claim that binding. [S2]

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)
- Subdomain takeover/dangling DNS — related lesson but with a different mechanism, focusing on the lifecycle DNS/provider binding instead of user/domain misrepresentation.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** Microsoft Learn — Prevent dangling DNS entries and avoid subdomain takeover. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover — updated: 2026-01-12; accessed: 2026-07-18.
- **[S3]** CWE-1007 — Insufficient Visual Distinction of Homoglyphs Presented to User. https://cwe.mitre.org/data/definitions/1007.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** CWE-451 — User Interface (UI) Misrepresentation of Critical Information. https://cwe.mitre.org/data/definitions/451.html — version/status: current version; accessed: 2026-07-18.