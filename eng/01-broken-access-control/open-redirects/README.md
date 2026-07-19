---
schema_version: 1
id: WEB-A01-OPEN-REDIRECTS
title: "Open Redirects"
slug: open-redirects
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-601
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Open Redirects

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Open Redirects by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- HTTP 3xx and `Location` school.

- The framework for analyzing relative URL, absolute URL, and authority.

- Allowlist redirect target according to use case.

## 3. Background Knowledge

Imagine you are shopping at a large mall and want to find the restroom. You see a sign that says: 'Restroom: Go straight.' You trust and follow that sign. But if a malicious person sneaks in and sticks over the sign with an arrow pointing to the emergency exit that leads straight into a dark alley full of traps behind the building, you would unintentionally walk straight into the trap while still thinking you are going the right way. [S3]

In the online world, this redirect action is carried out through the **HTTP redirect mechanism (HTTP redirects)** with status codes such as `301` or `302`. When you access a link (for example: after logging in, returning to the previous page), the web server sends a response to the browser with an `Location` header containing the next target address. Your browser will fully trust this and automatically take you to that address without asking again. The **Open Redirect** vulnerability occurs when developers design the system to accept a redirect address entered by the user (for example, via the `?next=...` parameter) without checking where that address leads. The server blindly places this address into the `Location` header, causing the browser to automatically take the user to any website, including malicious sites. [S3]

For prevention, the application needs to use the URL structural analysis functions to extract and verify that the target domain belongs to the allowed list, or enforce allowing only relative paths starting with a single slash. [S3]

```python
# Safe redirection verifying host and scheme using Django utility to prevent Open Redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest

def safe_redirect(request):
    """
    Redirection view verifying that the 'next' URL parameter points to a trusted host.
    """
    # Retrieve the redirection destination parameter (defaults to home path '/')
    redirect_target = request.GET.get('next', '/')

    # Secure: Validate that the redirect URL has a safe scheme and points to our own host
    is_safe = url_has_allowed_host_and_scheme(
        url=redirect_target,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure()
    )

    if is_safe:
        # Perform HTTP 302 redirect if the target is verified as safe
        return redirect(redirect_target)
    else:
        # Reject redirection requests to untrusted external domains
        return HttpResponseBadRequest("Invalid redirect target: Access Denied.")
```

## 4. Description and Root Cause

The Open Redirects vulnerability occurs when an application redirects users to an external website without verifying whether the website is safe. [S3]

The most dangerous aspect of this vulnerability does not lie in complex attack techniques, but in the **art of psychological manipulation** (phishing). The attacker will create a link starting with an extremely reputable and familiar domain to you (for example: `https://bank.lab.test/login?next=https://callback.lab.test/steal`). When users look at the link, they see the legitimate domain and feel completely safe clicking on it and logging in. But immediately after a successful login, the server "accidentally" redirects them to the attacker’s malicious website, which has an interface identical to the bank's site, to trick them into entering the PIN code, credit card information, or automatically downloading malware onto their device. The victim is deceived without realizing it because they started their journey from a completely legitimate website. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** The origin login trust and user data may be mistakenly entered at a different origin.

- **Actor:** user not logged in using Chromium can be pinned; does not use real credentials.

- **Trust boundary:** redirect/next parameter goes into Django 5.x response Location.

- **Necessary condition:** server allows absolute URL or parsing error allowlist; browser follows redirect.

- **Environment:** trusted-bank.lab.test and callback.lab.test both map loopback; proxy records redirect chain.

Only conclude open redirect when the server sends a Location to an origin outside the allowlist; links containing URL are unusual but being rejected is not a vulnerability. [S1]

## 6. Attack Mechanism

The application puts the destination provided by the client into the Location without parsing/allowlisting the correct origin. The browser follows 3xx from a trusted origin to an untrusted callback. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run two loopback origins using Django 5.x, pin Chromium and clear history/cache.
2. **Baseline:** next=/dashboard internal redirect after synthetic login.
3. **Action:** send destination callback.lab.test then monitor final Location and origin; do not enter secret.
4. **Expected result:** bug sent to callback lab; fix rejects absolute destination but still accepts valid relative path.
5. **Boundary:** test scheme-relative, mixed case, userinfo and percent encoding according to fixed scenario.
6. **Cleanup:** delete cookies/history and stop both origins.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The attacker detects a trusted website that has a post-login redirect function through the parameter `next` (for example: `https://bank.lab.test/login?next=/dashboard`).
Step 2: The attacker creates a link pointing to the real website but with the parameter `next` leading to a fake website: `https://bank.lab.test/login?next=https://callback.lab.test/steal`.
Step 3: The attacker sends this link to the victim. The victim clicks on it, sees the login interface of `bank.lab.test`, and trusts it to enter their information.
Step 4: After successful login, the server redirects the victim to `https://callback.lab.test/steal`. This page mimics a banking interface displaying a transaction error to trick the victim into entering the PIN code or card information. [S3]

### Example HTTP request illustrating Open Redirect:<!-- payload-id: WEB-A01-OPEN-REDIRECTS-001 -->
<!-- context: HTTP/1.1; Django 5.x fixture; trusted-bank.lab.test and callback.lab.test resolve to loopback; redirect validation model [S3] -->
<!-- prerequisites: run both origins locally with no Internet route; browser history and network log are cleared before each case -->
<!-- encoding: ASCII absolute HTTPS URL in the query; reserved characters remain percent-safe; raw harness emits CRLF -->
<!-- expected-result: vulnerable fixture returns Location to callback.lab.test; fixed fixture rejects it and accepts only a local relative path -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# The visible request starts on the trusted lab origin
GET /login?next=https://callback.lab.test/fake-login HTTP/1.1
Host: trusted-bank.lab.test

# The vulnerable server reflects an unvalidated destination:
HTTP/1.1 302 Found
Location: https://callback.lab.test/fake-login
# The browser is redirected to the untrusted lab origin
```

## 9. Vulnerable Code and Secure Code

```python
from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest

def redirect_vulnerable(request):
    # BAD: the client controls the destination
    return redirect(request.GET.get('next', '/'))

def redirect_secure(request):
    next_url = request.GET.get('next', '/')
    # GOOD: compare against a server-controlled canonical host
    if url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={settings.CANONICAL_HOST},
        require_https=True,
    ):
        return redirect(next_url)
    return HttpResponseBadRequest("Invalid redirect target")
```

## 10. Detection

- Check valid relative path, absolute URL outside the allowlist and authority variants; observe `Location`. [S3]

- Review all places where redirects are made from query/form/header and the framework's helper validation. [S3], [S4]

- Log redirect class, normalized destination, and allow/deny decision; avoid logging tokens.

## 11. Defense

### Compulsory control

- Use a fixed target or a narrow allowlist; validate the scheme/host after parsing URL using the appropriate helper. [S3]

- For internal flows, only accept safe relative paths and do not allow `//host` to bypass policy. [S3], [S4]

### Defense-in-depth

- The warning page only supports users, it does not replace validation.

- Do not place sensitive tokens in the query of URL redirect.

## 12. Retest

- **Positive:** valid relative path correctly redirects to internal page.

- **Negative:** external host and scheme outside policy are denied.

- **Boundary:** check `//host`, userinfo, mixed case, encoded separator and port.

- **Telemetry:** log the canonical target and the selected policy branch.

## 13. Common Mistakes

- Check URL with `startsWith` on the raw string.

- Allowlist substring instead of the parsed scheme/host/port.

- Forget protocol-relative or userinfo variants.

- Consider the confirmation page as the original measure.

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

- **HTTP redirect:** 3xx responses usually provide the URI destination via the `Location` field. [S3]

- **Target allowlist:** set of schemes/hosts/ports or relative paths allowed by the business flow. [S3]

- **Canonical URL:** URL after being normalized by the parser framework to match the policy. [S3], [S4]

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** OWASP Unvalidated Redirects and Forwards Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** Django 5.2 documentation — `url_has_allowed_host_and_scheme`. https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme — version: Django 5.2; accessed: 2026-07-18.