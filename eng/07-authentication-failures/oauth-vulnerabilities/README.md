---
schema_version: 1
id: WEB-A07-OAUTH-VULNERABILITIES
title: "OAuth 2.0 Vulnerabilities"
slug: oauth-vulnerabilities
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
  - A07:2025
cwe:
  - CWE-601
  - CWE-287
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# OAuth 2.0 Vulnerabilities

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain OAuth 2.0 Vulnerabilities by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the flaw to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of OAuth 2.0 Vulnerabilities scenarios and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing rights.

## 3. Background Knowledge

Imagine you stay at a luxury hotel. Instead of giving you the master key to the entire building, the hotel provides you with a room key card (Access Token). This card only allows you to open your own room and the gym during your stay. You don't need to know the hotel management's door password to enter your room. This authorization protocol is similar to how **OAuth 2.0** works.

OAuth 2.0 is a standard authorization framework that allows third-party applications (such as a gaming website) to access some limited information about you (such as your friends list or email address) on another application (such as Google or Facebook) without you having to disclose your Google/Facebook login password to that gaming website.

The participating components include:
- **Resource Owner**: That's you, the account owner.
- **Client**: The application that wants to request access (such as a gaming website).
- **Authorization Server**: The authorization server (like Google, Facebook), where you are authenticated and a token is issued.
- **Resource Server**: The server containing the actual data (such as API containing your email, photos).

The usual process for obtaining an authorization code:

```
1. User clicks "Login with Google"
2. Browser redirects to: https://oauth.provider.lab.test/authorize?
     response_type=code&
     client_id=APP_ID&
     redirect_uri=https://myapp.lab.test/callback&
     scope=profile email&
     state=random_csrf_token

3. User approves → Google redirects to:
     https://myapp.lab.test/callback?code=AUTH_CODE&state=random_csrf_token

4. Server exchanges code for access_token (server-to-server)
5. Server uses access_token to fetch user profile
```

```python
# Normal OAuth callback handler
@app.route('/callback')
def oauth_callback():
    # Verify state parameter to prevent CSRF
    if request.args.get('state') != session.get('oauth_state'):
        return "CSRF detected", 403

    code = request.args.get('code')

    # Exchange authorization code for access token (server-side)
    token_response = requests.post('https://oauth.provider.lab.test/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    })

    access_token = token_response.json()['access_token']
    user_info = fetch_user_profile(access_token)
    return login_user(user_info)
```
OAuth works correctly when all parameters are strictly validated, but misconfiguring any component can create a serious vulnerability.

## 4. Description and Root Cause

OAuth 2.0 vulnerabilities occur when the process of setting up and exchanging authentication parameters between parties is misconfigured or lax.

The danger of this vulnerability is extremely serious: an attacker can secretly modify the card receiving address (redirect URI) to trick the server into sending the authorization code to their machine. They can also exploit the lack of anti-forgery parameters (`state`) to force your account to link with their social media account, or steal your token through website redirection errors (Open Redirect). Once they possess your Access Token or Refresh Token, the attacker can access your personal data indefinitely without needing to know your password.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** authorization code/token and account-link state.
- **Actor, authentication, and role:** untrusted client/origin initiates the flow; victim user authenticates at the mock provider.
- **Exploitation conditions:** redirect, state, PKCE or code lifecycle not bound to the exact client session.
- **Browser, proxy, framework, and version:** provider/client pinned on .lab.test with Chromium, loopback callback and PKCE S256; must save actual image/package version along with evidence.
- **Mandatory evidence:** with correlation ID must link input, control decisions, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

Regarding oauth vulnerabilities, redirect, state, PKCE or code lifecycle not binding to the exact client session. A positive case must prove that the input reaches the correct sink and creates the described impact; a negative case, when native controls are enabled, must be blocked before the side effect. Conclusions only apply to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start the provider/client pinned on .lab.test with Chromium, loopback callback, and PKCE S256; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the oauth vulnerabilities use case; record raw request/response, decide policy and asset state before the test.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and adhere to the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when the log proves the mechanism of “redirect, state, PKCE, or code lifecycle not bound to exact client session”; secure fixture must block prior to side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of oauth vulnerabilities; revoke related session/cache, revert snapshot, and confirm no remaining callback/test process.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use targets, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Redirect URI Manipulation — stealing authorization code:** If the Authorization Server allows relative matching or wildcard for `redirect_uri`, an attacker can redirect to their server to steal the code.

<!-- payload-id: WEB-A07-OAUTH-VULNERABILITIES-001 -->
<!-- context: OAuth authorization request sent only to the mock provider at oauth.provider.lab.test -->
<!-- prerequisites: provider and redirect origins resolve to local fixtures; synthetic client APP_ID; one request; no outbound network -->
<!-- encoding: redirect_uri is shown decoded for readability and must be percent-encoded once by the test client -->
<!-- expected-result: intentionally vulnerable provider accepts the unregistered redirect; fixed provider rejects it before issuing a code -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
https://oauth.provider.lab.test/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://untrusted.lab.test/oauth-callback&scope=profile
```
**2. Missing State Parameter — CSRF to link attacker's account:** If the `state` parameter is not used to prevent CSRF, an attacker can trick the victim into clicking on an OAuth link containing the attacker's code, linking the victim's account to the attacker's social media information.

**3. Implicit Flow Token Leakage:**
The implicit flow returns the access token in the fragment. The fragment is not sent in requests or; the main risk is that the token can be accessed by code running on the redirect page, extensions, client-side logs, or the storage/history mechanisms of the user agent. For new applications, prioritize Authorization Code + and avoid tokens in the front-channel.

**4. Token Theft via Open Redirect Chain:**  
Even if the server configures `redirect_uri` correctly for the fixture (e.g., `https://myapp.lab.test/callback`), an open redirect after the callback can redirect the browser to an untrusted origin. Whether the authorization code or token is actually leaked also depends on the response mode, data location, Referrer-Policy, and callback-side code; it must be observed in a browser harness, not inferred from a single redirect.<!-- payload-id: WEB-A07-OAUTH-VULNERABILITIES-002 -->
<!-- context: OAuth authorization-code flow using local .lab.test provider, client callback and untrusted redirect fixtures -->
<!-- prerequisites: synthetic client and one-time code; all .lab.test names map to loopback; outbound network disabled; one authorization attempt -->
<!-- encoding: nested redirect_uri and next values must each be percent-encoded by their owning request layer -->
<!-- expected-result: vulnerable client redirects to untrusted.lab.test after callback; fixed client rejects next; logs confirm whether any code-bearing request reached the untrusted fixture -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
https://oauth.provider.lab.test/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://myapp.lab.test/callback?next=https://untrusted.lab.test/collect
```
**5. Scope Escalation:**  
The attacker intercepts the authorization request and changes the parameter `scope` (for example, from `scope=read` to `scope=read+write+admin`). If the Authorization Server does not clearly display these elevated privileges to the browsing user, or if the Client Application implicitly trusts the token's scope without re-verification, the attacker will gain unauthorized access.

**6. Authorization Code Replay:**
The Authorization Code is only allowed to be used once to exchange for an Access Token. If the Authorization Server has a logic error and does not revoke the code after use, an attacker can intercept and reuse that code to generate a new Access Token.

**7. Refresh Token Abuse:** Refresh Tokens often have a very long lifespan. If the system does not implement a rotation mechanism (Refresh Token Rotation - RTR) and an attacker steals a Refresh Token, they can create new Access Tokens indefinitely to take control of the account without any interaction with the user.

### PKCE Bypass (OAuth 2.1)
PKCE (Proof Key for Code Exchange) requires the client to send `code_challenge` (SHA-256 hash of `code_verifier`) along with the request. Some faulty implementations:
- Accept `code_challenge_method=plain` instead of `S256` (attacker can intercept the verifier)
- Do not check `code_challenge` if not present in the request (optional mismatch)
- `state` parameter can be bypassed when the server accepts any value

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
# 1. Vulnerable to Open Redirect Chain
@app.route('/callback')
def oauth_callback_unsafe():
    code = request.args.get('code')
    # Unvalidated 'next' parameter causes an open redirect; whether data leaks
    # must be established from the browser/network trace, not assumed.
    next_url = request.args.get('next', '/dashboard')

    token = exchange_code(code)
    session['token'] = token
    return redirect(next_url)

# 2. Vulnerable to Scope Escalation (trusts token scopes blindly without server-side check)
@app.route('/api/admin/settings')
def admin_settings_unsafe():
    # Dangerous: client application trusts the scope claim inside the JWT without validating
    # with the Resource Server's access control policy
    token = request.headers.get('Authorization').split(" ")[1]
    payload = jwt.decode(token, verify=False)
    if 'admin' in payload.get('scope', ''):
        return get_admin_settings()
    return "Unauthorized", 403
```

```python
# === SECURE CODE ===
# 1. Secure Redirect and Single-use Code Verification
@app.route('/callback')
def oauth_callback_safe():
    # Verify state to prevent CSRF
    if request.args.get('state') != session.pop('oauth_state', None):
        return "CSRF detected", 403

    code = request.args.get('code')

    # Exchange code (Authorization Server enforces single-use and exact redirect_uri match)
    token_response = requests.post('https://oauth.provider.lab.test/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': FIXED_REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    })

    if token_response.status_code != 200:
        return "Failed to exchange code", 400

    # Safe redirect to a hardcoded dashboard or validated local path only
    return redirect('/dashboard')

# 2. Refresh Token Rotation (RTR) logic
def rotate_refresh_token(user_id, client_refresh_token):
    stored_token = db.get_refresh_token(user_id)

    # If the presented refresh token has already been used, trigger compromise detection
    if stored_token.is_used and stored_token.token_value == client_refresh_token:
        db.revoke_all_sessions(user_id) # Revoke all active tokens for the user
        raise SecurityException("Replay of refresh token detected! Revoking all sessions.")

    # Generate new access token and new refresh token (Rotation)
    new_access_token = generate_access_token(user_id)
    new_refresh_token = generate_new_refresh_token(user_id)

    # Mark old token as used and store new one
    db.mark_token_used(client_refresh_token)
    db.save_refresh_token(user_id, new_refresh_token)

    return new_access_token, new_refresh_token
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to OAuth 2.0 Vulnerabilities, policy results, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had an impact. 
- Scanner or WAF alerts are only signals for investigation; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Exact redirect matching, session-bound state, PKCE S256, single-use code and token rotation.
- Apply the same controls to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With OAuth 2.0 Vulnerabilities, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used to replace the original controls.

- **Summary**: Secure the OAuth process by enforcing an absolute match check for redirect URI, requiring the use of a random state parameter, and applying the Authorization Code flow + PKCE.  
- **Detailed steps**:  
  - **Strict redirect URI validation**: Compare exact match (do not use wildcard or partial match) for `redirect_uri`.  
  - **Always use `state` parameter**: Generate a random value, store it in the session, and verify it upon receiving the callback.  
  - **Use Authorization Code + PKCE**: Replace the implicit flow with the Authorization Code flow combined with PKCE for all client types.  
  - **Fix Open Redirects**: Ensure callback endpoints do not freely redirect based on client input.  
  - **Scope Whitelisting & Validation**: The resource server must always check the scopes associated with the access token for each request API.  
  - **Single-use Authorization Code**: Ensure that the code is automatically invalidated immediately after the first exchange.  
  - **Refresh Token Rotation (RTR)**: Each time a Refresh Token is used to obtain a new Access Token, the old Refresh Token must be invalidated and a new Refresh Token issued. If the old Refresh Token is reused, immediately invalidate the entire session of that user.

## 12. Retest

- **Positive case:** with OAuth 2.0 Vulnerabilities, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but the actor or context is not permitted should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save a minimal scenario that reproduces the old bug and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of OAuth 2.0 Vulnerabilities without verifying side effects and logs.
- Use a syntactically correct payload but with the wrong DBMS, browser, framework, protocol, or injection context.
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for another original control.
- Only fix one route while the same sink/policy is used in other routes.
- Conclude a vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **OAuth 2.0**: The standard authorization protocol that allows applications to share resources with each other securely without needing to share login information directly (such as passwords).
- **Access Token**: A short-lived code string representing the access rights granted to an application to call API and retrieve user data.
- **Refresh Token**: A long-lived code string used to request the server to issue a new Access Token after the old Access Token has expired without requiring the user to log in again from the beginning.
- **Redirect URI**: The URL address where the authorization server will send the user's browser back along with the authentication code after the user consents to grant permission.
- **PKCE (Proof Key for Code Exchange)**: A security extension for OAuth 2.0, using a random cryptographic string to verify that the application requesting the token is the same application that requested the original code.
- **Open Redirect**: A security vulnerability that occurs when a website automatically redirects users to another URL address entered by the user without checking the safety of that address.

## 16. Related Lessons and Further Reading

- [Session Fixation](../session-fixation/README.md)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/oauth — version/status: current edition; access: 2026-07-18. 
- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses — version/status: current edition; access: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/601.html — version/status: current edition; access: 2026-07-18. 
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current edition; access: 2026-07-18. 
- **[S5]** CWE-287. https://cwe.mitre.org/data/definitions/287.html — version/status: current edition; access: 2026-07-18.