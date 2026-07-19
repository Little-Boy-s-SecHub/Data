---
schema_version: 1
id: WEB-A05-XSS
title: "Cross-Site Scripting (XSS)"
slug: xss
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site Scripting (XSS)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Site Scripting (XSS) by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose the root control, implement a fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of a Cross-Site Scripting (XSS) scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Browsers interpret HTML and JavaScript according to the document context. XSS arises when untrusted data enters a sink, causing the browser to interpret it as code instead of data; the actual impact depends on the context, CSP, the permissions of the origin, and the data that scripts can access. Output encoding must match the exact context, while API DOM is safe or auto-escaping only protects within the extent guaranteed by the framework. [S4] [S5]

```python
# Normal operation: HTML template with proper auto-escaping
from flask import Flask, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    # SAFE: Jinja2 auto-escaping converts HTML metacharacters to entities
    # Use ordinary fixture text here; executable inputs belong in section 8
    name = escape("Alice & Bob")
    return render_template_string('<h1>Hello, {{ name }}!</h1>', name=name)
```

## 4. Description and Root Cause

The XSS vulnerability occurs when a web application receives information from a user and then directly displays that information on a page without properly sanitizing or encoding it. This is similar to allowing strangers to write anything on the application's public bulletin board, including dangerous code. When another user reads the bulletin board, their browser will execute the malicious code. An attacker could exploit XSS to secretly steal login tokens (session cookies) to hijack accounts, record your keystrokes (keylogging), forge the interface to defraud users (defacement), or spread malware to other users.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** DOM, aggregated session and user-rendered content.  
- **Actor, authentication, and role:** public actor or role user providing input; victim is the logged-in user.  
- **Exploitation conditions:** input goes into sink HTML, attribute, URL or JavaScript in the wrong context.  
- **Browser, proxy, framework, and version:** Chromium pinned with Node.js 20/Express on victim/untrusted .lab.test; no outbound; must save actual image/package version along with evidence.  
- **Mandatory evidence:** along with correlation ID must link input, control decisions, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For XSS, input goes to sink HTML, attribute, URL, or JavaScript in the wrong context. Positive cases must demonstrate that the input reaches the correct sink and produces the described effect; negative cases, when native control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium bundled with Node.js 20/Express on victim/untrusted .lab.test; no outbound; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input of the XSS use case; save raw request/response, decide policy and asset status before testing.
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and adhere to the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs prove the mechanism “input enters sink HTML, attribute, URL or JavaScript wrong context”; secure fixture must block before side effect and boundary input must fail closed.
5. **Cleanup:** delete XSS data, markers, and logs; revoke related session/cache, revert snapshot, and confirm no remaining test callback/process.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

There are 3 main types:

1. **Stored XSS** — payload stored permanently in the database, attacks multiple victims
2. **Reflected XSS** — payload in URL/request, only attacks victims who click the link
3. **DOM-based XSS** — exploits in client-side JS, does not go through the server

Example payload:

<!-- payload-id: WEB-A05-XSS-001 -->
<!-- context: pinned Chromium renders isolated HTML, attribute and URL-context marker cases separately -->
<!-- prerequisites: victim.lab.test loopback page; no cookies/secrets; each case only sets data-lab-executed or calls alert with LAB -->
<!-- encoding: UTF-8 payload is encoded for transport once, then intentionally decoded into the documented sink context -->
<!-- expected-result: vulnerable case sets the local marker; secure context encoding renders text and no marker changes -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
<script>document.body.dataset.labExecuted='script'</script>
<img src=x onerror="document.body.dataset.labExecuted='img'">
<svg onload="document.body.dataset.labExecuted='svg'"></svg>
javascript:document.body.dataset.labExecuted='url'
"><script>document.body.dataset.labExecuted='breakout'</script>
```
Refer to the details of each type:
- Stored XSS → [stored/README.md](stored/README.md)
- Reflected XSS → [reflected/README.md](reflected/README.md)
- DOM-based XSS → [dom-based/README.md](dom-based/README.md)
- XSSI → [xssi/README.md](xssi/README.md)

## 9. Vulnerable Code and Secure Code

```python
# Vulnerable: reflecting user input without encoding
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # DANGEROUS: directly embedding user input into HTML response
    return f'<h1>Search results: {query}</h1>'

# Secure: use template engine auto-escaping
from markupsafe import escape

@app.route('/search-safe')
def search_safe():
    query = request.args.get('q', '')
    # SAFE: markupsafe escapes HTML special characters automatically
    return f'<h1>Search results: {escape(query)}</h1>'
```

```html
<!-- Secure CSP header to block inline scripts -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none';">
```

```javascript
// Safe DOM manipulation using textContent instead of innerHTML
// DANGEROUS: element.innerHTML = userInput; (executes scripts)
// SAFE: element.textContent = userInput; (treats as plain text)
document.getElementById('output').textContent = userInput;

// When HTML is needed, use DOMPurify to sanitize first
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Cross-Site Scripting (XSS), the policy results, and correlation ID; do not log secrets or the full token.  
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact.  
- Scanner or WAF alert is only a signal for investigation; it is not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Encode the output context correctly and use safe DOM API/template auto-escaping.
- Apply the same controls to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With Cross-Site Scripting (XSS), the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Encode output according to the display context, set Content Security Policy (CSP), and protect cookies with the HttpOnly flag.
- **Detailed steps**:
  - Output encoding: HTML entity encoding when rendering user data into HTML.
  - Content Security Policy (CSP): prohibit inline scripts, only allow trusted sources.
  - HttpOnly cookie: prevent XSS from stealing session cookies via `document.cookie`.
  - Input validation: whitelist characters, reject dangerous tags.
  - DOMPurify: sanitize HTML before setting `innerHTML`.

## 12. Retest

- **Positive case:** with Cross-Site Scripting (XSS), the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but with an actor or context not allowed is rejected without leaking sensitive details.  
- **Boundary case:** test empty values, extreme values, different encoding, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Re-test:** keep a minimal script reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Cross-Site Scripting (XSS) without confirming side effects and logs. 
- Use a payload with correct syntax but incorrect DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another root control. 
- Only fix one route while the same sink/policy is used in another route. 
- Conclude that the vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **XSS (Cross-Site Scripting)**: A vulnerability that allows the injection of malicious scripts (usually JavaScript) to run in the user's browser.
- **Execution Context**: The context in which the browser compiles and executes commands.
- **Browser Trust Model**: The browser's default trust model for scripts running from the same origin.
- **HTML Entity Encoding**: Converting special HTML characters into a safe display form (such as `<` into `&lt;`).
- **Session Cookie**: A cookie file that stores authentication codes to maintain the user's login state.

## 16. Related Lessons and Further Reading

- [Stored XSS](stored/) — Permanent storage attack in the database
- [Reflected XSS](reflected/) — Attack via URL/form submit
- [DOM-based XSS](dom-based/) — Attack in client-side JavaScript
- [XSSI](xssi/) — Cross-Site Script Inclusion via JSONP

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/cross-site-scripting — version/status: current version; accessed: 2026-07-17. 
- **[S2]** OWASP. https://owasp.org/www-community/attacks/xss/ — version/status: current version; accessed: 2026-07-17. 
- **[S3]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17. 
- **[S4]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — version/status: current version; accessed: 2026-07-17. 
- **[S5]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.