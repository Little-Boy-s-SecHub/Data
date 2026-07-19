---
schema_version: 1
id: WEB-A07-CREDENTIAL-STUFFING
title: "Credential Stuffing & Brute Force"
slug: credential-stuffing
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-307
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Credential Stuffing & Brute Force

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Credential Stuffing & Brute Force by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in Credential Stuffing & Brute Force scenarios and how to apply handling of input across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine a thief trying to break into a house. 
- If he stands in front of the door, holding a multi-tool kit and patiently tries thousands of different keys to open the lock, that is a manual password guessing attack (**Brute Force**). 
- But if the thief scours the 'black market', buys a box containing millions of real keys from other houses that have been previously broken into, and then goes around trying the box on houses in the neighborhood in the hope that lazy homeowners use the same lock, that is a leaked information injection attack (**Credential Stuffing**).

The reason this attack is successful is due to human habits: about 65% of us use the same account/password combination for multiple websites (such as Facebook, Gmail, shopping accounts). When a small, poorly secured website is hacked and its password database is leaked, hackers will immediately use that list to 'knock on the doors' of larger services like banks, e-wallets, or social networks.

```python
# Normal login endpoint (simplified)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return redirect('/dashboard')

    # Generic error message (good practice)
    return render_template('login.html', error='Invalid credentials')
```
The endpoint works correctly for each request, but without a rate limiting mechanism, an attacker can send thousands of requests per minute to try combinations of credentials.

## 4. Description and Root Cause

This vulnerability occurs when the website's authentication system is too lenient, allowing anyone to send thousands of continuous login requests without any prevention measures or rate limiting.

The danger of this vulnerability is very clear: attackers use automated tools (scripts) to test millions of leaked accounts or try to guess passwords in a very short time. If not blocked, they will certainly find accounts using weak passwords or reusing old passwords, thereby stealing customers' personal information and assets without encountering any barriers.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare against the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** aggregated accounts and automatic login control.  
- **Actor, authentication, and role:** anonymous tries a maximum of three credential fixtures; no role yet.  
- **Exploitation conditions:** credential reuse can be tested when normalization, aggregate throttling, or detection is missing.  
- **Browser, proxy, framework, and version:** Python 3.12 requests to login proxy/app loopback with DB snapshot; must save actual image/package version along with evidence.  
- **Mandatory evidence:** with correlation ID must link input, control decisions, and impact on the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For credential stuffing, reused credentials are tested when normalization, aggregate throttling, or detection is lacking. A positive case must demonstrate that the input reaches the correct sink and creates the described impact; a negative case, when native controls are enabled, must be blocked before any side effect. Conclusions apply only to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12 requests to login proxy/app loopback with DB snapshot; only load aggregate data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the credential stuffing use case; save raw request/response, decide policy and asset status before the test.
3. **Input and actions:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** consider the vulnerable fixture as positive only when the log proves the "credential reuse can be tried when lacking normalization, aggregate throttling, or detection" mechanism; secure fixture must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of credential stuffing; revoke related session/cache, revert snapshot, and confirm no remaining test callback/process.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Simulating Credential Stuffing with synthetic data:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-001 -->
<!-- context: Python 3.12 requests client against a login fixture bound to 127.0.0.1:9002 -->
<!-- prerequisites: exactly three synthetic credentials owned by the fixture; database snapshot; no breach data; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded generated by requests from Unicode strings -->
<!-- expected-result: exactly three attempts are logged; one designated fixture account succeeds and no real credential is printed -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
import requests

LAB_CREDENTIALS = [
    ("fixture-a@victim.lab.test", "Wrong-Lab-Password-1"),
    ("fixture-b@victim.lab.test", "Fixture-Match-2"),
    ("fixture-c@victim.lab.test", "Wrong-Lab-Password-3"),
]

def try_login(cred):
    email, password = cred
    resp = requests.post('http://127.0.0.1:9002/login', data={
        'username': email, 'password': password
    }, allow_redirects=False, timeout=2)

    # Check for successful login indicators
    if resp.status_code == 302 and '/dashboard' in resp.headers.get('Location', ''):
        print(f"[LAB MATCH] {email}")
        return email
    return None

# Keep the fixture test sequential and bounded
results = [try_login(cred) for cred in LAB_CREDENTIALS]
```
**2. Check identity and source normalization at the rate limit layer:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-002 -->
<!-- context: HTTP/1.1 login requests pass through a loopback reverse proxy and authentication fixture -->
<!-- prerequisites: synthetic account only; trusted-proxy configuration documented; maximum three requests per normalization case; database snapshot; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded usernames; percent-decoding and case normalization are logged before policy evaluation -->
<!-- expected-result: untrusted forwarding headers do not change client identity, equivalent usernames share one counter, and malformed usernames are rejected consistently -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
// Case 1: untrusted forwarding headers must not replace the proxy identity
X-Forwarded-For: 192.0.2.10
X-Real-IP: 192.0.2.11
X-Originating-IP: 192.0.2.12

// Case 2: equivalent username forms must share the same policy identity
POST /login  → username=Admin@victim.lab.test
POST /login  → username=admin@victim.lab.test
POST /login  → username=ADMIN@victim.lab.test

// Case 3: malformed or padded usernames must be rejected consistently
POST /login  → username=admin%00@victim.lab.test
POST /login  → username= admin@victim.lab.test
```
**3. Password Spraying — try 1 password for multiple users:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-003 -->
<!-- context: Python 3.12 reuses try_login against the loopback login fixture -->
<!-- prerequisites: exactly two synthetic users and one synthetic password; fixture lockout threshold is documented; database snapshot; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded generated by requests -->
<!-- expected-result: exactly two failed attempts are logged and the fixture's per-account plus aggregate controls are observable without reaching lockout -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Bounded spray simulation with fixture-owned accounts only
lab_password = 'Synthetic-Wrong-Password'
usernames = ['fixture-a', 'fixture-b']

for username in usernames:
    try_login((username, lab_password))
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: no rate limiting, no lockout
@app.route('/login', methods=['POST'])
def login_unsafe():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and check_password(user, request.form['password']):
        return login_user(user)
    # Attacker can try unlimited times
    return "Invalid credentials", 401
```

```python
# SECURE: rate limiting + progressive lockout + breach detection
from flask_limiter import Limiter
import hashlib, requests as req

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # IP-based rate limit
def login_safe():
    username = request.form['username']
    password = request.form['password']

    # Check if account is temporarily locked
    lockout = get_lockout_status(username)
    if lockout and lockout.locked_until > datetime.utcnow():
        remaining = (lockout.locked_until - datetime.utcnow()).seconds
        return jsonify({"error": f"Account locked. Retry in {remaining}s"}), 429

    user = User.query.filter_by(username=username.lower().strip()).first()
    if user and check_password(user, password):
        clear_failed_attempts(username)
        return login_user(user)

    # Progressive lockout: 3→1min, 6→5min, 10→30min
    failures = increment_failed_attempts(username)
    if failures >= 10:
        lock_account(username, minutes=30)
    elif failures >= 6:
        lock_account(username, minutes=5)
    elif failures >= 3:
        lock_account(username, minutes=1)

    return jsonify({"error": "Invalid credentials"}), 401
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Credential Stuffing & Brute Force, the policy result and correlation ID; do not log secrets or the entire token.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not there was an impact.  
- Scanner or WAF alert is just an investigation signal; it is not the sole proof that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Combine MFA, breached-password prevention, normalized account/aggregate controls, and detection. 
- Apply the same controls to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With Credential Stuffing & Brute Force, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used to replace the original controls.

- **Summary**: Prevent Credential Stuffing by implementing rate limiting, temporary account lockout (progressive lockout), CAPTCHA, and leaked password detection. 
- **Detailed steps**:
  - **Rate limiting**: Limit 5-10 attempts per IP per minute, using token bucket or sliding window algorithm.
  - **Account lockout**: Temporarily lock the account after N failed attempts (progressive delay: 1 minute → 5 minutes → 30 minutes).
  - **CAPTCHA**: Require CAPTCHA after 3 consecutive failures.
  - **Breach password detection**: Check new passwords against known breach databases (HaveIBeenPwned API).
  - **MFA enforcement**: Enabling 2FA renders credential stuffing ineffective even if the password is correct.

## 12. Retest

- **Positive case:** with Credential Stuffing & Brute Force, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource, if the actor or context is not allowed, it should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save a minimal scenario that reproduces the old error and prove that the fix does not rely on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Credential Stuffing & Brute Force without verifying side effects and logs.
- Use payloads with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for a different root control.
- Only fix one route while the same sink/policy is used in another route.
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **Brute Force**: A method of trying all possible password combinations until the correct password is found, usually performed automatically by software.  
- **Credential Stuffing**: An automated attack that uses a list of account and password pairs leaked from another website to try logging into the target website.  
- **Password Spraying**: A technique of testing a few very common passwords (such as `123456`, `Password123`) on a long list of different user accounts to avoid account lockout.  
- **Rate Limiting**: A mechanism to control and limit the number of requests that an IP address or account is allowed to send to the server within a certain period of time.  
- **Account Lockout**: A security mechanism that automatically temporarily or permanently locks a user account after detecting a certain number of consecutive failed login attempts.  
- **Data Breach**: A cybersecurity incident in which sensitive, confidential, or protected information is accessed, viewed, or copied by an unauthorized individual or organization.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/authentication/password-based — version/status: current version; accessed: 2026-07-18.  
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Credential_stuffing — version/status: current version; accessed: 2026-07-18.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/307.html — version/status: current version; accessed: 2026-07-18.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.