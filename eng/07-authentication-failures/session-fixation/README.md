---
schema_version: 1
id: WEB-A07-SESSION-FIXATION
title: "Session Fixation"
slug: session-fixation
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
content_status: technical-review
payload_status: none
last_verified: null
---

# Session Fixation

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Session Fixation by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Session Fixation scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local lab isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you walk into a hotel. Instead of having the receptionist give you a random, brand-new room key after you check-in (authenticate), you pick up an old key that was discarded right in front of the lobby and hand it to the receptionist: "I want to use this key for my room." If the receptionist agrees and immediately associates your room with that key without suspicion, you have fallen into a trap. A malicious person deliberately left that key in the lobby and prepared an identical duplicate in advance. As soon as you put your luggage in the room, they can simply use the duplicate key to enter and clean out your belongings. This is exactly the vulnerability called **Session Fixation**.

To safely manage the system, developers need to strictly control **the lifecycle of sessions and cookies**. A cookie is like a room key card stored by the browser. To prevent this card from being stolen, it needs to be set with strict protection attributes:
- **HttpOnly**: Prevents scripts (JavaScript) from reading the contents of the card (protects against XSS).
- **Secure**: Only allows the card to be transmitted over encrypted HTTPS channels.
- **SameSite**: Restricts sending the card from other websites (protects against CSRF).

In particular, the golden rule in **session lifecycle management** is: immediately after a user successfully logs in or escalates privileges, the server must **discard the old token** and **issue a completely new, random token**. This will completely cut off any chance for an attacker who wants to hijack using the previously known key. Additionally, the server also needs to automatically revoke the token if the user is inactive for a period of time (idle timeout) to ensure maximum security.

```javascript
const express = require('express');
const app = express();

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.authenticate(username, password);

    if (!user) {
        return res.status(401).send("Invalid credentials");
    }

    // Keep temporary session data before destroying the old session
    const tempCart = req.session.cart;

    // Regenerate session ID immediately on privilege elevation (login)
    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).send("Session regeneration failed");
        }

        // Populate the new session with authenticated user details
        req.session.userId = user.id;
        req.session.cart = tempCart;

        // Explicitly save the session to prevent write/read race conditions
        req.session.save((saveErr) => {
            if (saveErr) {
                return res.status(500).send("Failed to save secure session");
            }
            return res.json({ status: "Logged in and session regenerated successfully" });
        });
    });
});
```

## 4. Description and Root Cause

Session Fixation vulnerability occurs when a web application allows a user to continue using an old session identifier (Session ID) after they have successfully logged in.

The danger of this vulnerability lies in the fact that an attacker can proactively create a valid Session code ID, and find a way to implant this code into the victim's browser (for example, via a link containing the session parameter ID). When the victim clicks on it and successfully logs in, the server links the victim's account to that code ID. Since the attacker has already possessed this code beforehand, they can easily access the victim's account directly without needing to know the username or password.

> **Reference:** technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** session identifier before and after authentication.  
- **Actor, authentication, and role:** actor preset ID; victim then logs in with user role.  
- **Exploitation conditions:** server keeps ID unchanged across authentication boundary.  
- **Browser, proxy, framework, and version:** Flask/Express session store and two Chromium contexts pinned on .lab.test; must record actual image/package version along with evidence.  
- **Mandatory evidence:** the same correlation ID must connect input, control decision, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For session fixation, the server keeps ID unchanged across the authentication boundary. A positive case must prove that the input reaches the correct sink and produces the described effect; a negative case, when origin control is enabled, must be blocked before the side effect. Conclusions only apply to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the Flask/Express session store and two Chromium contexts pinned on .lab.test; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the session fixation use case; save raw request/response, decide policy and asset state before testing.
3. **Input and operation:** use exactly one script/input variable described in section 8; change one variable at a time and adhere to the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism “server keeps ID across the authentication boundary”; secure fixture must block before side effect and boundary input must fail closed.
5. **Cleanup:** delete session fixation data, markers, and logs; revoke related session/cache, revert snapshot, and confirm no test callbacks/processes remain.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real target, credentials, or data; OOB/DoS/state-changing tests must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The attacker (Mal) accesses the target website and obtains an unlogged valid Session ID (e.g., `SID=XYZ123`). 
Step 2: Mal sends the victim (Vic) a link to the target website with the Session ID included in the query string: `https://victim.lab.test/login?session_id=XYZ123`.
Step 3: Vic clicks on the link and logs in using their account. The application accepts the available Session ID `XYZ123` from URL and links Vic's login session to this code ID.
Step 4: Since Mal already knows the code ID `XYZ123`, Mal configures their browser to use the cookie `SID=XYZ123` and directly accesses the system to take control of Vic's account.

## 9. Vulnerable Code and Secure Code

The following two handlers use Express 4.x and `express-session` 1.18.x for the same login flow. Attaching identity to the existing session keeps the ID session unchanged before authentication; the secure version regenerates the session before saving the identity and explicitly selected pre-login data. [S2] [S3]

### Not safe (vulnerable): elevate existing session privileges

```javascript
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (!user) return res.status(401).send('Invalid credentials');

  // Vulnerable: the pre-authentication session ID remains authenticated
  req.session.userId = user.id;
  res.send('Logged in');
});
```
### Security (secure): regenerate session when changing authentication level

```javascript
// User login endpoint in Express
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (user) {
    const tempCart = req.session.cart;
    // Regenerate session ID to prevent Session Fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).send('Session error');
      req.session.userId = user.id;
      req.session.cart = tempCart;
      // Fix: Explicitly save session to prevent write/read race conditions
      req.session.save((err) => {
        if (err) return res.status(500).send('Session error');
        res.send('Logged in successfully');
      });
    });
  } else {
    res.status(401).send('Invalid credentials');
  }
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Session Fixation, policy results, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Rotate session ID atomically when logging in/changing privileges and invalidate the old ID. 
- Apply the same control to every route, operation, and corresponding processing path; failure must stop before side effects.

### Defense-in-depth

With Session Fixation, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for the original control.

- **Summary**: Session fixation is an attack where a malicious user forces another user's session identifier to a predetermined value, allowing them to hijack the session after authentication. Mitigation requires generating a new session identifier immediately upon any privilege level change, specifically during login.
- **Detailed steps**:
  - Always invalidate the existing session and generate a new session identifier (session ID) immediately upon successful user login.
  - Implement proper session timeout mechanisms (both idle timeout and absolute timeout).
  - Secure cookies containing session identifiers by setting attributes: HttpOnly (prevent JS access), Secure (force HTTPS), and SameSite=Strict or SameSite=Lax.
  - Ensure session IDs are random, cryptographically strong, and generated by the server's security framework rather than accepted from client input.

## 12. Retest

- **Positive case:** with Session Fixation, the valid flow still works correctly for the actor and permitted data.  
- **Negative case:** the same input/resource but for an actor or context not allowed should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save a minimal scenario that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Session Fixation without verifying side effects and logs. 
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another primary control. 
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

- **Session Fixation**: A security vulnerability that occurs when the application allows users to retain the same session identifier (Session ID) after logging in, enabling attackers to take over the session using the predetermined code ID. 
- **Session ID (Session ID)**: A unique random string generated by the server to identify the current session of a specific user on the web application. 
- **HttpOnly Cookie**: A security attribute of a cookie that prevents scripts running in the browser (such as JavaScript) from accessing the cookie's value, helping to reduce the risk of cookie theft through XSS vulnerabilities. 
- **Secure Cookie**: An attribute that requires the browser to transmit this cookie to the server only over a securely encrypted connection HTTPS. 
- **SameSite Cookie**: An attribute that controls whether cookies are sent along with requests from third-party websites, helping to prevent CSRF attacks. 
- **Session Lifecycle Management**: The process of controlling the entire lifecycle of a session, from initiation, extension, to complete termination when the user logs out or the session expires.

## 16. Related Lessons and Further Reading

- [OAuth 2.0 Vulnerabilities](../oauth-vulnerabilities/README.md)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-384. https://cwe.mitre.org/data/definitions/384.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** Express session — Session.regenerate. https://github.com/expressjs/session#sessionregeneratecallback — version/status: express-session 1.18.x; accessed: 2026-07-18.