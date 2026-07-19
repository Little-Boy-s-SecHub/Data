---
schema_version: 1
id: WEB-A07-WEAK-SESSION-IDS
title: "Weak Session IDs"
slug: weak-session-ids
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A04:2025
cwe:
  - CWE-330
  - CWE-331
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Weak Session IDs

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Weak Session IDs by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Weak Session IDs scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine when you deposit money at the bank, the staff gives you a locker ticket with the number: `001`. You look around and see the person before you holding ticket number `000`, and the person after you holding ticket number `002`. You immediately recognize the pattern and only need to draw a ticket with the number `000` or `002` to access someone else's locker. This vulnerability is similar to the system using **Weak Session Identifier (Weak Session ID)**.

For the ID Session to be secure, it must be long enough, meaningless, and infeasible to predict within the stated threat model. The effective difficulty of guessing is described by **entropy**. PRNG typically does not provide guarantees against an adversary observing the output or inferring the state/seed, so it is not used to generate session secrets. CSPRNG is designed to resist output prediction when properly implemented and the seed source functions correctly; it should not be described as “completely unpredictable” under all conditions. [S4]

When creating session ID, OWASP recommends CSPRNG with a size of at least 128 bits; a well-tested framework is usually the preferred choice. Base64url or hex are just ways to represent bytes, they do not inherently increase entropy. The practical possibility of brute-force also depends on the number of active sessions, trial speed, timeout, and detection/limitation mechanisms. [S4]

```javascript
const crypto = require('crypto');

function generateSecureSessionId(byteLength = 24) {
    // Generate cryptographically secure random bytes (CSPRNG)
    // 24 bytes of entropy provides 192 bits of security
    const randomBuffer = crypto.randomBytes(byteLength);

    // Encode buffer to a URL-safe Base64 string to be used as a Session ID
    const sessionId = randomBuffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return sessionId;
}

// Example usage
const secureSessionToken = generateSecureSessionId();
console.log(`Generated Secure Session ID: ${secureSessionToken}`);
```

## 4. Description and Root Cause

Weak Session ID vulnerabilities occur when the server generates Session IDs like ID that are too short, sequentially numbered, or use standard pseudo-random number generation algorithms (PRNG) that are easy to guess.

The danger of this vulnerability is very high: an attacker only needs to register an account, analyze the system's pattern for generating Session codes ID, and then use a script to automatically create and try hundreds of ID codes of other users. If successful, they can hijack the victim's session and access their account without needing a password or passing the 2FA authentication.

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** unpredictability of session ID and mapping account.  
- **Actor, authentication, and role:** anonymous only sample session self-created in fixture.  
- **Exploitation conditions:** counter, time, or PRNG without password making ID predictable.  
- **Browser, proxy, framework, and version:** Python 3.12 generator with CSPRNG pinned and sample harness limited; must save actual image/package version along with evidence.  
- **Mandatory evidence:** together with correlation ID must link input, control decision, and impact the correct asset; individual status codes are not enough. [S1]

## 6. Attack Mechanism

For weak session IDs, counter, time, or PRNG without encryption, ID can be predicted. A positive case must demonstrate that the input reaches the correct sink and creates the described impact; a negative case, when source control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12 generator with CSPRNG pinned and a limited sample harness; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID. 
2. **Baseline:** send a valid input of the weak session ids use case; save raw request/response, determine policy and asset state before the test. 
3. **Input and operations:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with the request cap. 
4. **Expected result:** consider a fixture vulnerable as positive only when logs demonstrate the mechanism “counter, time, or PRNG without cryptography makes ID predictable”; secure fixture must block before side effects and boundary input must fail closed. 
5. **Cleanup:** delete data, markers, and logs of weak session ids; reclaim related session/cache, revert snapshot, and confirm no callbacks/processes remain from tests. 
6. **Safety limits:** only run on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing operations must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker accesses the website, looks at the session cookie value assigned to themselves (for example `session_id=142983010`), and notices that it is short and patterned. The attacker writes a script that automatically sends requests with incrementing or slightly altered cookie values like HTTP (scanning in parallel through a botnet). When hitting a valid ID session of another user who is online, the server accepts the request and allows the attacker to log in unauthorized to the victim's account.

### Python example of sequential bruteforce session ID:<!-- payload-id: WEB-A07-WEAK-SESSION-IDS-001 -->
<!-- context: Python 3.12; local fixture with deliberately sequential synthetic session IDs -->
<!-- prerequisites: fixture bound to loopback; synthetic accounts only; maximum 20 guesses -->
<!-- encoding: decimal session IDs are ASCII cookie values serialized by requests; HTTP framing is library-generated -->
<!-- expected-result: fixture identifies one adjacent synthetic session; production targets are out of scope -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
import requests

# The learner's synthetic session ID is 142983010.
# The fixture deliberately allocates adjacent sequential IDs.
known_session = 142983010

for i in range(1, 21):  # Bound the lab to 20 adjacent guesses.
    target_session = known_session + i

    response = requests.get(
        "http://127.0.0.1:8080/dashboard",
        cookies={"session_id": str(target_session)}
    )

    if response.headers.get("X-Lab-Session-Match") == "true":
        print(f"Matched synthetic session: {target_session}")
        break

# This demonstrates a predictable generator, not a generic timing claim.
```

## 9. Vulnerable Code and Secure Code

The following two configurations use Express 4.x and `express-session` 1.18.x. The ID session is time-based with a small predictable space; the safe version takes 32 bytes from CSPRNG, using a shared store and transport-protected cookie. Cookie flags do not compensate for ID being predictable. [S2] [S4]

### Not safe (vulnerable): session ID time-based

```javascript
const session = require('express-session');

app.use(session({
    secret: process.env.SESSION_SECRET,
    // Vulnerable: nearby timestamps are predictable and can collide
    genid: () => String(Date.now()),
    resave: false,
    saveUninitialized: false
}));
```
### Secure: session ID from CSPRNG and shared store

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const { randomBytes } = require('node:crypto');

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || Buffer.byteLength(sessionSecret, 'utf8') < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 UTF-8 bytes');
}

async function configureSessionMiddleware() {
    const redisClient = createClient({ url: 'redis://localhost:6379' });
    // Fail startup if the shared session store is unavailable
    await redisClient.connect();

    app.use(session({
        store: new RedisStore({ client: redisClient }),
        secret: sessionSecret,
        name: '__Host-SessionId',
        // Secure: generate 256 bits before base64url encoding
        genid: () => randomBytes(32).toString('base64url'),
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            maxAge: 30 * 60 * 1000
        }
    }));
}

// Start listening only after the shared store and middleware are ready
configureSessionMiddleware()
    .then(() => app.listen(Number(process.env.PORT || 3000)))
    .catch((error) => {
        console.error('Session middleware initialization failed', error);
        process.exitCode = 1;
    });
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Weak Session IDs, policy results, and correlation ID; do not log secrets or full tokens.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact.  
- Scanner or WAF alerts are just investigation signals; they are not sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Generate at least 128 bits using CSPRNG and keep an opaque state server-side.
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With Weak Session IDs, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for original controls.

- **Summary**: Create strong sessions ID using the CSPRNG algorithm with high entropy, assign security attributes such as HttpOnly, Secure, SameSite, and strictly manage expiration times on the server. 
- **Detailed steps**:
  - Generate session identifiers using a cryptographically secure pseudo-random number generator (CSPRNG).
  - Ensure ID sessions have a minimum length (at least 128 bits / 16 bytes of entropy) to resist brute-force attacks.
  - Set the `HttpOnly` flag on the session cookie to prevent client-side (JavaScript) scripts from accessing it, reducing the risk of theft via XSS.
  - Set the `Secure` flag to enforce that the cookie is only transmitted over encrypted TLS/HTTPS connections.
  - Set the `SameSite` attribute (such as Lax or Strict) to prevent CSRF attacks.
  - Manage session expiration (including inactivity expiration and absolute expiration) and delete session state on the server when the user logs out.

## 12. Retest

- **Positive case:** with Weak Session IDs, the valid flow still works correctly for the actor and permitted data.  
- **Negative case:** the same input/resource but for an actor or context not allowed is rejected without leaking sensitive details.  
- **Boundary case:** test empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effect match correlation ID.  
- **Recheck:** save a minimal scenario that reproduces the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Weak Session IDs without verifying side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another original control.  
- Only fix one route while the same sink/policy is used on another route.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable proof.

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

- **Session ID (Session code)**: A unique string that serves as a key to identify users on the system after they have successfully logged in.
- **Entropy**: A measure of the complexity and randomness of data. The higher the entropy, the more difficult the data string is to predict or crack.
- **PRNG (Pseudo-Random Number Generator)**: A pseudo-random number generator that uses mathematical formulas to create a sequence of numbers that appear random but are actually deterministic and periodic.
- **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)**: A pseudo-random number generator designed to resist output prediction under certain security assumptions; its security still depends on the seed, state, and implementation.
- **Base64url**: A variant of Base64 encoding that converts binary data into a text string that is safe to transmit via URL parameters or cookies without special character errors.

## 16. Related Lessons and Further Reading

- [JWT Attacks](../jwt-attacks/README.md)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-330. https://cwe.mitre.org/data/definitions/330.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE-331. https://cwe.mitre.org/data/definitions/331.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** OWASP Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.