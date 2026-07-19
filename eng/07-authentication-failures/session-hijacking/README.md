---
schema_version: 1
id: WEB-A07-SESSION-HIJACKING
title: "Session Hijacking"
slug: session-hijacking
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-384
  - CWE-613
  - CWE-614
  - CWE-1004
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Session Hijacking

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Session Hijacking by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow in a Session Hijacking scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local lab isolated, with synthetic data, observable logs, and clearly defined testing permissions.

## 3. Background Knowledge

Imagine the HTTP protocol of the Internet as a restaurant waiter with short-term memory loss (**stateless**). Every time you place an order, this waiter completely does not remember who you are or what you just ordered a moment ago. To solve this problem, after you successfully log in, the server issues you a table card with a unique random number on it (called **Session ID**). This card is kept by your browser in a small compartment called a Cookie.

Whenever you send a subsequent request (such as viewing the cart or checking out), the browser will automatically present this table card (Session ID) for the server to see. The server only needs to match the number on the card with the notebook at the counter to know who you are and serve the correct order. This table card is the unique "key" to prove that you are logged in. If anyone picks up or copies this card of yours, they can freely sit at your table and place orders, pay with your money without needing to know the password.

```python
# Normal session management flow with Flask-Session 0.8.x
from datetime import datetime, timezone
from flask import Flask, redirect, request, session
from flask_session import Session

app = Flask(__name__)
app.config.update(
    SECRET_KEY="load-from-secret-manager",
    SESSION_TYPE="redis",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Replace pre-authentication data before rotating the server-side SID
        session.clear()
        session['user_id'] = user.id
        session['login_time'] = datetime.now(timezone.utc).isoformat()
        app.session_interface.regenerate(session)
        return redirect('/dashboard')
    return "Invalid credentials", 401
```
For example, using Flask-Session 0.8.x because the built-in Flask session is client-side signed cookies and does not have API `session.regenerate()`. With server-side session, the application calls `app.session_interface.regenerate(session)` after creating a new login state. Session ID needs entropy from CSPRNG and the cookie requires `Secure`, `HttpOnly`, `SameSite` suitable for the use case. [S5] [S6]

## 4. Description and Root Cause

Session Hijacking vulnerability occurs when an attacker attempts to steal, predict, or forge a valid user's Session ID ID to take over their session.

The danger of this vulnerability is very high because it allows attackers to bypass all security steps (including passwords and 2FA) to directly access the victim's account. Attackers can do this by injecting malicious JavaScript code (XSS) to steal cookies, eavesdrop on unencrypted network traffic (sniffing) at public Wi-Fi points, or predict the Session code ID if the system generates these codes in an overly simple pattern.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4], [S5], [S6].

> **Mapping note:** this topic does not have a single CWE that is sufficiently accurate. Metadata maps common mechanisms in the lesson: session fixation/lifecycle (CWE-384, CWE-613) and cookie flags that reduce the risk of theft/replay (CWE-614, CWE-1004); each actual finding still needs to be mapped according to the observed root cause. [S3], [S7], [S8], [S9]

## 5. Threat Model and Exploitation Conditions

- **Assets:** authenticated cookie and server-side session state.
- **Actor, authentication, and role:** actor replaying a composite cookie; victim role is user.
- **Exploitation conditions:** bearer session copied is still valid due to weak transport/cookie/lifecycle control.
- **Browser, proxy, framework, and version:** Flask-Session 0.8 or Express session, Chromium and TLS .lab.test proxy pinned; must save actual image/package version along with evidence.
- **Required evidence:** with correlation ID, must link input, control decisions, and impact on the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For session hijacking, a copied bearer session is still valid due to weak transport/cookie/lifecycle control. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when origin control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start Flask-Session 0.8 or Express session, Chromium, and TLS .lab.test proxy pinned; only load synthetic data, enable application/proxy/datastore logs and attach correlation ID.
2. **Baseline:** send a valid input of the session hijacking use case; save raw request/response, decide policy and asset state before the test.
3. **Input and action:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** consider a vulnerable fixture positive only when log shows that the "bearer session copied is still valid due to weak transport/cookie/lifecycle control" mechanism; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete session hijacking data, markers, and logs; revoke related session/cache, revert snapshot and verify no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real target, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. XSS-based Session Theft — cookie theft via JavaScript:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-001 -->
<!-- context: Chromium pinned by the local browser harness; synthetic non-HttpOnly lab_session cookie -->
<!-- prerequisites: loopback-only fixture; no callback; no real cookie or localStorage content -->
<!-- encoding: UTF-8 inline script; cookie name is ASCII and DOM dataset receives only true/false -->
<!-- expected-result: page records whether the synthetic cookie is script-readable; no value leaves the page -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- The server fixture exposes only a boolean synthetic marker; no cookie value is read. -->
<script>
document.body.dataset.labCookieReadable = window.__LAB_COOKIE_READABLE__ === true
    ? 'true'
    : 'false';
</script>
```
**2. Network Sniffing — eavesdropping on HTTP without encryption:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-002 -->
<!-- context: tcpdump captures plain HTTP only inside an isolated network namespace interface lab0 -->
<!-- prerequisites: synthetic client/server and cookie LAB_SESSION_ONLY; maximum 20 packets; no physical interface or sudo -->
<!-- encoding: pcap bytes are decoded only for local ASCII HTTP headers; capture filter is port 8080 on lab0 -->
<!-- expected-result: capture contains the synthetic Cookie header on HTTP; TLS fixture exposes no cookie plaintext -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Capture at most 20 packets on the isolated lab namespace interface.
tcpdump -i lab0 -c 20 -A -s 0 'tcp port 8080 and host victim.lab.test'

# Or using Wireshark filter to capture session cookies:
# http.cookie contains "session"

# Captured fixture value: Cookie: session=LAB_SESSION_ONLY
# A second synthetic client demonstrates replay only inside this namespace.
```
**3. Session Fixation — forcing the victim to use the already known session ID:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-003 -->
<!-- context: intentionally vulnerable fixture accepts SESSIONID from query and fails to rotate at login -->
<!-- prerequisites: two synthetic browser contexts and attacker_known_id only; one login/replay; loopback -->
<!-- encoding: SESSIONID query is ASCII and percent-encoded once; Set-Cookie framing is generated by fixture -->
<!-- expected-result: old ID accesses victim fixture only on vulnerable route; secure login rotates and invalidates old ID -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
// Step 1: Attacker gets a valid session ID from target site
GET /login HTTP/1.1
Response: Set-Cookie: SESSIONID=attacker_known_id

// Step 2: Attacker sends victim a link with fixed session
https://victim.lab.test/login?SESSIONID=attacker_known_id

// Step 3: Victim logs in using attacker's session ID
// Step 4: Attacker uses the SAME session ID — now authenticated as victim
```

**4. Predictable Session IDs:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-004 -->
<!-- context: Python 3.12 demonstrates timestamp-plus-username MD5 IDs in a local generator -->
<!-- prerequisites: synthetic username fixture-admin; search window capped at 20 timestamps; no HTTP target -->
<!-- encoding: f-string is UTF-8, timestamp is decimal ASCII and md5 output is lowercase hexadecimal -->
<!-- expected-result: bounded guesses reproduce the fixture ID; secrets.token_urlsafe generator cannot be reproduced by this model -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# VULNERABLE: predictable session ID generation
import time, hashlib

def generate_session_id(username):
    # Session based on timestamp + username — attacker can guess
    raw = f"{username}{int(time.time())}"
    return hashlib.md5(raw.encode()).hexdigest()

# The harness knows fixture username and tests only a 20-second window.
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: no cookie flags, predictable session, no regeneration
app.config['SESSION_COOKIE_HTTPONLY'] = False   # JS can read cookie
app.config['SESSION_COOKIE_SECURE'] = False     # Sent over HTTP
app.config['SESSION_COOKIE_SAMESITE'] = None    # No CSRF protection

@app.route('/login', methods=['POST'])
def login_unsafe():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # No session regeneration — fixation possible
        session['user_id'] = user.id
        return redirect('/dashboard')
    return "Failed", 401
```

```python
# SECURE: Flask-Session 0.8.x cookie flags and server-side SID rotation
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_COOKIE_NAME='__Host-sid',
)

@app.route('/login', methods=['POST'])
def login_safe():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Clear pre-authentication state, create authenticated state, then rotate SID
        session.clear()
        session['user_id'] = user.id
        session['created'] = datetime.now(timezone.utc).isoformat()
        app.session_interface.regenerate(session)
        return redirect('/dashboard')
    return "Invalid credentials", 401

@app.route('/logout', methods=['POST'])
def logout():
    # Delete authenticated state and expire the current cookie
    session.clear()
    return redirect('/login')
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Session Hijacking, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Protect cookies via TLS and rotate, revoke, monitor the entire session lifecycle.
- Apply the same controls to all routes, operations, and equivalent processing paths; failure must stop before any side effects.

### Defense-in-depth

With Session Hijacking, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for original controls.

- **Summary**: Prevent session hijacking by using cookie security flags (HttpOnly, Secure, SameSite), regenerate session ID upon login, and enforce HTTPS. 
- **Detailed steps**:
  - **Cookie security flags**: Set `HttpOnly` to prevent JavaScript from reading cookies, `Secure` to send only over HTTPS, and choose `SameSite=Lax`/`Strict` according to the application flow; SameSite is a defense-in-depth for CSRF.
  - **Session regeneration**: Create a new session ID after login (to prevent fixation) and after each privilege change.
  - **HTTPS everywhere**: Force all traffic through HTTPS with HSTS header to prevent network sniffing.
  - **Session risk signals**: IP/User-Agent can change legitimately or be spoofed, so use it as an alert/step-up signal rather than hard-lock the session in every application.
  - **Cryptographic session IDs**: Use CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) to generate session ID of 128-bit or higher.

## 12. Retest

- **Positive case:** with Session Hijacking, the valid flow still works correctly for the actor and permitted data.  
- **Negative case:** the same input/resource but for an actor or context not allowed is rejected without leaking sensitive details.  
- **Boundary case:** check empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effect match correlation ID.  
- **Recheck:** save a minimal scenario that reproduces the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Session Hijacking without verifying side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another original control.  
- Only fix one route while the same sink/policy is used on another route.  
- Conclude that the vulnerability exists without saving the source, fixture version, and observable proof.

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

- **Stateless (Stateless)**: HTTP does not automatically associate the current request with previous requests; the application can still maintain state using cookies, server-side sessions, or tokens. 
- **Session (Session)**: A mechanism to maintain the state of interaction between a user and a web application over a period of time, storing user login information and activities on the server side. 
- **Session ID (Session ID)**: A unique random string used as a key to map a user's request to the corresponding session data stored on the server. 
- **XSS (Cross-Site Scripting)**: A security vulnerability that allows attackers to inject malicious script code (usually JavaScript) into a website and execute it in other users' browsers. 
- **Sniffing (Network Eavesdropping)**: The act of intercepting and monitoring data packets transmitted over a network to collect sensitive information (such as Session ID sent via unencrypted HTTP). 
- **Session Hijacking (Session Theft)**: The act of hackers stealing a valid user's Session ID to impersonate them and gain unauthorized access to an application without requiring login credentials.

## 16. Related Lessons and Further Reading

- [Stored XSS](../../05-injection/xss/stored/) — The attacker uses the stored XSS vulnerability to inject malicious JavaScript code to steal session cookies from the victim's browser.

## 17. References

- **[S1]** OWASP WSTG — Testing for Session Hijacking. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking — version/status: latest; accessed: 2026-07-18. 
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Session_hijacking_attack — version/status: current version; accessed: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/384.html — version/status: current version; accessed: 2026-07-18. 
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S5]** OWASP Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18. 
- **[S6]** Flask-Session 0.8.0 API. https://flask-session.readthedocs.io/en/latest/api.html — version/date: 0.8.0; accessed: 2026-07-18. 
- **[S7]** CWE-613 — Insufficient Session Expiration. https://cwe.mitre.org/data/definitions/613.html — version/status: current version; accessed: 2026-07-18. 
- **[S8]** CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute. https://cwe.mitre.org/data/definitions/614.html — version/status: current version; accessed: 2026-07-18. 
- **[S9]** CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag. https://cwe.mitre.org/data/definitions/1004.html — version/status: current version; accessed: 2026-07-18.