---
schema_version: 1
id: WEB-A07-USER-ENUMERATION
title: "User Enumeration"
slug: user-enumeration
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-204
  - CWE-200
content_status: technical-review
payload_status: none
last_verified: null
---

# User Enumeration

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain User Enumeration by root cause instead of only describing the consequences. 
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited. 
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the User Enumeration scenario and how to apply input handling across trust boundaries. 
- Differentiate between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you go to knock on the door of an office to look for a person named 'Nam'.
- If the security guard checks the list and immediately replies: 'There is no one named Nam here,' you immediately know that this person does not work here.
- But if there is a person named Nam, the security guard has to go into the room, call Nam out, confirm the information, which takes about 5 minutes.

Hackers can exploit this difference through a response time attack (**Timing Attack**). When logging in, if the account exists, the server will execute a very complex and slow password hashing algorithm (such as `bcrypt.compare`) to verify the password, taking about a few hundred milliseconds. But if the account does not exist, the server immediately returns an error at the search step without hashing anything. By measuring this tiny response time, hackers will know exactly which emails are registered on your system.

To prevent this, developers use a dummy hash technique (**Dummy Hash**). If a user is not found in the database, the server will not immediately report an error but will automatically pull out a fake password string to hash against the password entered by the user. This makes the server spend roughly the same amount of time as it would when verifying a real account. As a result, whether the account exists or not, the response time is the same, and the server displays a generic message that is identical in both cases (such as "Email or password is incorrect").

```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// A generic dummy hash conforming to bcrypt's standard format
const DUMMY_HASH = "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');

    // Always use a generic message to prevent authentication disclosure
    const genericMessage = "Invalid email or password.";

    try {
        const user = await db.findUserByEmail(email);

        // Determine whether a valid hash exists for the fetched user
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;

        // If user doesn't exist, use the DUMMY_HASH to prevent timing differences
        const passwordHash = hasValidHash ? user.passwordHash : DUMMY_HASH;

        // Always execute the hashing function (bcrypt.compare) to ensure equal timing
        const isMatch = await bcrypt.compare(passwordStr, passwordHash);

        if (!user || !hasValidHash || !isMatch) {
            return res.status(401).json({ success: false, message: genericMessage });
        }

        // Handle successful login and issue token
        const token = generateToken(user);
        return res.json({ success: true, token });
    } catch (error) {
        return res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 4. Description and Root Cause

User Enumeration occurs when an application accidentally reveals whether a username or email exists in the system through different error messages or through the server's response time delay.

The danger of this vulnerability lies in the fact that it allows attackers to easily scan and create a list containing all the real customer accounts. This is an ideal stepping stone for them to carry out subsequent attacks such as mass password guessing (Brute-Force), targeted phishing attacks (Phishing), or extortion by threatening to reveal the identities of users of a sensitive service.

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** existence of a consolidated account and auth/reset response. 
- **Actor, authentication, and role:** anonymous tries a limited fixture username list. 
- **Exploitation conditions:** differences in body, status, or work factor create a stable oracle. 
- **Browser, proxy, framework, and version:** Node.js 20, bcrypt cost, and Express timing harness pinned; loopback; must store actual image/package version along with evidence. 
- **Required evidence:** with correlation ID, must connect input, decide control, and impact the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For user enumeration, differences in body, status, or work factor create a stable oracle. The positive case must demonstrate that the input reaches the correct sink and creates the described effect; the negative case when native control is enabled must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start Node.js 20, pin bcrypt cost and Express timing harness; loopback; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the user enumeration use case; record raw request/response, determine policy and asset state before testing.
3. **Input and operations:** use exactly one scenario/input variable described in section 8; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs show the mechanism of "different body, status, or work factor creates a stable oracle"; secure fixture must block before any side effect and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of user enumeration; revoke related session/cache, revert snapshot, and verify no remaining test callbacks/processes.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use real target, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker sends a list of login emails to the application's login, registration, or password recovery page. If the login page reports "Account does not exist" instead of a generic message like "Invalid login information", the attacker will immediately know whether the email is registered or not. Similarly, if the server hashes passwords using a slow algorithm (such as bcrypt) when the account is found but skips hashing when the account does not exist, the attacker can measure the response time (Timing Attack) to determine the presence of a user.

## 9. Vulnerable Code and Secure Code

The following two endpoints use Express 4.x and bcrypt 5.x for the same login flow. Responses that differ or skip password hashing when the user does not exist can create a content or timing oracle; the secure version uses a common message and still runs a bcrypt comparison with a valid dummy hash. [S2]

### Not safe (vulnerable): different responses and control flow

```javascript
app.post('/api/login', async (req, res) => {
    const user = await db.findUserByEmail(req.body.email);
    if (!user) {
        // Vulnerable: distinct response and early return disclose account existence
        return res.status(404).json({ message: 'Account does not exist' });
    }
    const match = await bcrypt.compare(String(req.body.password || ''), user.passwordHash);
    if (!match) return res.status(401).json({ message: 'Wrong password' });
    res.json({ success: true, token: generateToken(user) });
});
```
### Security (secure): consistent general response and bcrypt path

```javascript
const bcrypt = require('bcrypt');

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');

    // Use a generic message for all authentication failures
    const genericMessage = "Invalid email or password.";

    try {
        const user = await db.findUserByEmail(email);
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;
        const passwordHash = hasValidHash ? user.passwordHash : "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";

        const match = await bcrypt.compare(passwordStr, passwordHash);

        if (!user || !hasValidHash || !match) {
            return res.status(401).json({ success: false, message: genericMessage });
        }

        // Successful authentication logic
        res.json({ success: true, token: generateToken(user) });
    } catch (error) {
        res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to User Enumeration, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use consistent status/body/work factors and rate/detect enumeration. 
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before any side effect.

### Defense-in-depth

With User Enumeration, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used as a substitute for original controls.

- **Summary**: Prevent account enumeration by using uniform response messages, synchronize processing time with dummy hashes for non-existent accounts, and implement rate limiting.
- **Detailed steps**:
  - Return a general, identical error message (e.g., 'Invalid email or password' or 'If the email exists, a recovery link has been sent') for both existing and non-existing accounts.
  - Ensure that all server processing flows have equivalent time delays by using a dummy hash with a complexity (work factor) equal to the real hash when the account does not exist.
  - Implement rate limiting on all authentication-related endpoints to prevent large-scale automated scanning.
  - Avoid returning different status codes (such as 200 vs 404 Not Found) or different interface displays based on the existence of the user.

## 12. Retest

- **Positive case:** with User Enumeration, the valid flow still works correctly for the allowed actor and data.  
- **Negative case:** with the same input/resource but an unauthorized actor or context, it is denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** keep the minimal scenario reproducing the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of User Enumeration without verifying side effects and logs. 
- Use payloads with correct syntax but incorrect DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another original control. 
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

- **User Enumeration**: A vulnerability that allows an attacker to determine whether a specific user account or email exists on the system by analyzing differences in the application's responses. 
- **Timing Attack**: An indirect attack method by measuring the amount of time the server takes to process different requests, thereby deducing the logical structure or the presence of internal data. 
- **Dummy Hash**: A technique that runs the hashing algorithm with a fake key when an account does not exist, aiming to simulate the server's processing time to match that of an actual account. 
- **Rate Limiting**: A control measure on the number of requests that a specific IP address or user is allowed to make within a time unit to prevent automated scanning. 
- **Authentication Disclosure**: A situation where the application provides too much detail about the login process (such as "incorrect password" or "account does not exist"), indirectly helping attackers narrow down their attack scope.

## 16. Related Lessons and Further Reading

- [2FA/MFA Bypass](../2fa-mfa-bypass/README.md)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-204. https://cwe.mitre.org/data/definitions/204.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — version/status: current version; accessed: 2026-07-18.