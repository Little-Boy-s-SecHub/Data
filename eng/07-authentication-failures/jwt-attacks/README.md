---
schema_version: 1
id: WEB-A07-JWT-ATTACKS
title: "JWT Attacks"
slug: jwt-attacks
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A04:2025
  - A05:2025
  - A08:2025
cwe:
  - CWE-345
  - CWE-347
  - CWE-20
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# JWT Attacks

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain JWT attacks by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the conditions necessary for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the flow of HTTP request/response in the situation JWT Attacks and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local lab isolated, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine JWT (JSON Web Token) like a hard-plastic digital ID card. This card consists of three separate parts combined together:
1. **Header (Portrait and national emblem)**: Where it clearly states what security technology is used to sign and verify (encryption algorithm).
2. **Payload (Personal information)**: Where your full name, position, issue date, and expiration date are recorded (transmitted data).
3. **Signature (Official stamp of the police)**: The encrypted digital signature to ensure the information on the card is not tampered with.

To create this red seal, the card-issuing agency has two options for signature technology:
- **Symmetric Signing (HS256)**: Uses a single secret seal (Secret Key) both to stamp the card when issuing it and to verify using the same seal during checks.
- **Asymmetric Signing (RS256)**: Uses a private key (Private Key) securely stored at headquarters to stamp, and widely distributes a public key (Public Key) for all security checkpoints to self-verify the signature.

The system will fully trust you as an Admin if you present a card with the words 'Role: Admin' and a valid red seal. The danger begins when the security checkpoint is negligent in checking the card, or the person making the cards is careless, allowing malicious individuals to stamp a fake seal or tamper with the information on the card.

```javascript
// Normal JWT creation and verification flow
const jwt = require('jsonwebtoken');

// Server creates JWT after successful login
function generateToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600  // 1 hour expiry
    };

    // Sign with secret key (HS256) or private key (RS256)
    return jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
}

// Server verifies JWT on each request
function verifyToken(token) {
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}
```
The server trusts the content JWT if the signature is valid. But if the verification process is misconfigured, an attacker can forge the token to escalate privileges.

## 4. Description and Root Cause

The JWT Attack vulnerability (JWT Attacks) occurs when the process of verifying the token's digital signature on the server is misconfigured or not strict enough.

The danger of this vulnerability is very high: an attacker can create a fake ID card by changing the signing algorithm to `none` (requiring the server not to check the seal), use the public key to forge the card (exploiting the HS256/RS256 algorithm confusion), or trick the server into fetching an authentication seal from a malicious web address they control (JWK/JKU injection). When the server trusts this forged card, the attacker can impersonate any user or escalate their own privileges to Admin to take control of the system.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4], [S5], [S6].

## 5. Threat Model and Exploitation Conditions

- **Assets:** identity/role claim and trust of the signing key.
- **Actor, authentication, and role:** client who owns or creates a composite token targeting the admin role.
- **Exploitation conditions:** verifier trusts alg/kid/jku/jwk or lifecycle claim outside of fixed trust policy.
- **Browser, proxy, framework, and version:** Node.js 20 jsonwebtoken, JWKS local and pinned Redis; must record the actual image/package version along with evidence.
- **Mandatory evidence:** with correlation ID, must link input, control decisions, and impact the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For jwt attacks, the verifier trusts alg/kid/jku/jwk or lifecycle claims outside of the fixed trust policy. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when the root control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start Node.js 20 jsonwebtoken, JWKS local, and Redis pinned; only load aggregate data, enable application/proxy/datastore logs, and attach correlation ID.  
2. **Baseline:** send a valid input for the jwt attacks use case; save raw request/response, decide policy and asset status before the test.  
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.  
4. **Expected result:** consider the vulnerable fixture as positive only when logs prove the mechanism “verifier trusts alg/kid/jku/jwk or lifecycle claim outside fixed trust policy”; secure fixture must block side effects beforehand and boundary input must fail closed.  
5. **Cleanup:** delete jwt attacks data, marker, and logs; revoke related session/cache, revert snapshot, and confirm no remaining test callbacks/processes.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Algorithm "none" Attack — completely remove the signature:**
The attacker changes the `alg` field in the header to `none` and removes the signature to bypass the verification mechanism.

<!-- payload-id: WEB-A07-JWT-ATTACKS-001 -->
<!-- context: Python 3.12 constructs an unsigned alg=none token for a deliberately vulnerable verifier -->
<!-- prerequisites: synthetic sub/role only; loopback verifier; one token; no production key or endpoint -->
<!-- encoding: header/payload are UTF-8 JSON encoded with unpadded Base64url and an empty signature segment -->
<!-- expected-result: legacy vulnerable verifier accepts synthetic admin; fixed verifier pinned RS256 rejects before authorization -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Craft a JWT with algorithm set to "none"
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "1", "username": "admin", "role": "admin"}).encode()).decode().rstrip('=')
forged_token = f"{header}.{payload}."
# If server accepts alg:none, attacker is now admin
```
**2. HS256/RS256 Confusion — legacy behavior, not a default bypass of current PyJWT:**  
The flaw only exists when the verifier chooses the algorithm from the header itself and reuses the same key material for both RSA and HMAC. Current PyJWT refuses to use PEM/SSH asymmetric keys as an HMAC secret via `InvalidKeyError`; therefore, the call `jwt.encode(..., public_key, algorithm="HS256")` should not be presented as a payload that works on the modern version. [S7]

<!-- payload-id: WEB-A07-JWT-ATTACKS-002 -->
<!-- context: Python 3.12 with PyJWT 2.10.x checks modern handling of an RSA PEM passed to HS256 -->
<!-- prerequisites: generated lab keypair only; no token is sent to an endpoint; run once in a disposable fixture -->
<!-- encoding: claims are UTF-8 JSON; the RSA public key is PEM bytes generated only for the fixture -->
<!-- expected-result: PyJWT raises InvalidKeyError before producing a token; a separate legacy/custom fixture is required to study historical algorithm confusion -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S7 -->
<!-- last-verified: 2026-07-17 -->
```python
import jwt
from jwt.exceptions import InvalidKeyError

public_key = open('public_key.pem').read()

try:
    jwt.encode({"sub": "fixture-user"}, public_key, algorithm="HS256")
except InvalidKeyError:
    print("EXPECTED_REJECT_RSA_PEM_AS_HMAC_SECRET")
else:
    raise AssertionError("Pinned modern PyJWT unexpectedly accepted RSA PEM for HS256")
```
**3. Weak Secret Brute Force:** Using tools to look for the HS256 secret key if it is too short or easy to guess.

<!-- payload-id: WEB-A07-JWT-ATTACKS-003 -->
<!-- context: hashcat JWT mode tests a deliberately weak synthetic HS256 token -->
<!-- prerequisites: ten-entry fixture wordlist; --runtime=5; CPU-only disposable container; no leaked token/rockyou list -->
<!-- encoding: jwt_token.txt contains one ASCII compact JWT line; wordlist is UTF-8 with one candidate per line -->
<!-- expected-result: tool recovers only LAB_WEAK_SECRET within five seconds; strong-key fixture has no match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
hashcat -a 0 -m 16500 --runtime=5 jwt_token.txt fixtures/jwt-lab-wordlist.txt
```
**4. JWK Header Injection:**
The attacker directly embeds their public key into the `jwk` parameter in the JWT header and signs the token with the corresponding private key. If the server trusts this key without checking it against a trusted list, it will use the public key sent by the attacker to verify the signature.

**5. JKU Header Injection:**
The attacker creates an JWKS file containing their public key, uploads it to an independent server, and inserts that URL path into the `jku` parameter in the JWT header. The target server will send a request to fetch JWK from the attacker's URL to verify the signature.

**6. kid Parameter Injection:**
The parameter `kid` (Key ID) is used to specify which key needs to be used.
- **Unsafe Path lookup**: If the server appends `kid` to the path, the separator character could escape the key namespace. Only check with the opaque fixture ID and the synthetic key directory; do not read system files.
- **Unsafe Query**: If the server concatenates `kid` into the query, the input could change the key selection. The lesson does not release a separate injection string; fix the opaque map `kid` to the key record managed by the server using a parameterized query.

**7. Token Replay:**
`jti` is only a unique identifier of JWT; the presence of this claim by itself does not prevent replay. For a one-time designed operation, the server must record `issuer` + `audience` + `jti` atomically and reject subsequent uses until the token expires. Regular access tokens can be valid for multiple requests, so the anti-replay policy must match the token type and use case; a short lifespan only reduces the risk window. [S1]

## 9. Vulnerable Code and Secure Code

```javascript
// === VULNERABLE CODE ===
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 1. Vulnerable to JWK/JKU Header Injection
function verifyJkuUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Fetching key from external JKU URL provided by user
    if (decoded.header.jku) {
        const jwks = fetchExternalKey(decoded.header.jku); // Simulated external fetch
        const key = jwks.find(k => k.kid === decoded.header.kid);
        return jwt.verify(token, key);
    }
    return null;
}

// 2. Vulnerable to Path Traversal via kid
function verifyKidPathUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Direct file path construction using unsanitized kid
    const keyPath = path.join(__dirname, 'keys', decoded.header.kid);
    const key = fs.readFileSync(keyPath);
    return jwt.verify(token, key);
}
```

```javascript
// === SECURE CODE ===
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    // SECURE: Hardcoded trusted JWKS URI
    jwksUri: 'https://identity.provider.lab.test/.well-known/jwks.json'
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function(err, key) {
        if (err) return callback(err);
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

function verifyTokenSafe(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            // SECURE: Whitelist only RS256, reject none/HS256
            algorithms: ['RS256'],
            issuer: 'https://identity.provider.lab.test',
            audience: 'my-secure-app'
        }, (err, decoded) => {
            if (err) return reject(err);

            // Enforce one-time use only for operations whose contract requires it.
            // consumeTokenIdOnce must atomically SET NX with TTL through decoded.exp.
            if (requiresOneTimeUse(decoded)) {
                if (typeof decoded.jti !== 'string' || decoded.jti.length === 0) {
                    return reject(new Error('Missing jti for one-time token'));
                }
                const firstUse = consumeTokenIdOnce({
                    issuer: decoded.iss,
                    audience: decoded.aud,
                    jti: decoded.jti,
                    expiresAt: decoded.exp
                });
                if (!firstUse) return reject(new Error('One-time token already used'));
            }

            resolve(decoded);
        });
    });
}
```

## 10. Detection

- Log actor/session, route or operation, object/resource related to JWT Attacks, policy results, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Pin algorithm, issuer, audience, trusted key; validate header and enforce server-side lifecycle. 
- Apply the same controls to every route, operation, and equivalent processing path; failure must stop before side effects.

### Defense-in-depth

For JWT Attacks, the measures below help reduce the blast radius or increase detection capability. Rate limit, unpredictable UUID, WAF, CSP, or common validation should not be used as a substitute for original control.

- **Summary**: Protect JWT using a fixed verify algorithm, trusted key, check issuer/audience/expiration, and lifecycle policies suitable for each type of token; `jti` only supports anti-replay when the server stores state atomically. 
- **Detailed steps**:
  - **Whitelist algorithms**: Always specify a list of accepted algorithms when verifying, **never** let the server choose from the header.
  - **Strong secrets**: Use a random secret key of at least 256-bit for HS256, or an RSA key ≥ 2048-bit for RS256.
  - **Reject "none" algorithm**: Ensure the JWT library does not accept `alg: none`.
  - **JWK/JKU Validation**: Only allow loading JWK from strictly whitelisted domains, or completely forbid loading keys from the client-side.
  - **Sanitize `kid`**: Validate that `kid` does not contain strange characters (such as `/`, `\`, `'`, `"`) or use SQL parameterized queries.
  - **Token Replay Defense**: For single-use tokens, consume the key set `issuer` + `audience` + `jti` atomically and maintain state until `exp`. For multi-use access tokens, use a short lifespan, restrict the sender when the threat model requires it, and implement appropriate revocation/detection mechanisms; do not consider `jti` alone as a measure against replay.

## 12. Retest

- **Positive case:** With JWT Attacks, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** With the same input/resource but the actor or context is not allowed, it is denied without leaking sensitive details.  
- **Boundary case:** Test empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** Verify that the policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** Keep a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of JWT Attacks without verifying side effects and logs.  
- Use a payload with the correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another original control.  
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

- **JWT (JSON Web Token)**: An open-source format for securely transmitting information between parties as a JSON object, commonly used for authenticating and authorizing users in web applications.  
- **HS256 (HMAC with SHA-256)**: Symmetric digital signing algorithm that uses a single shared secret key for both generating the signature and verifying the integrity of the token.  
- **RS256 (RSA Signature with SHA-256)**: Asymmetric digital signing algorithm that uses a private key to sign and a public key to verify the signature.  
- **JWK (JSON Web Key)**: JSON data structure used to represent public cryptographic keys used in the JWT system.  
- **JKU (JSON Web Key Set URL)**: Parameter in the header of JWT containing a URL link pointing to a list of valid public keys for the server to download for signature verification.  
- **kid (Key ID)**: Key identifier parameter that helps the server know exactly which key in the database to use to verify the token’s signature.  
- **Token Replay (Replay attack)**: A type of attack where an attacker intercepts a victim’s valid token and re-sends that request to the server to impersonate the victim’s session.

## 16. Related Lessons and Further Reading

- [Weak Session IDs](../weak-session-ids/README.md)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/jwt — version/status: current version; access: 2026-07-18. 
- **[S2]** Auth0. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ — version/status: current version; access: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/345.html — version/status: current version; access: 2026-07-18. 
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; access: 2026-07-18. 
- **[S5]** CWE-347. https://cwe.mitre.org/data/definitions/347.html — version/status: current version; access: 2026-07-18. 
- **[S6]** CWE-20. https://cwe.mitre.org/data/definitions/20.html — version/status: current version; access: 2026-07-18. 
- **[S7]** PyJWT Usage — algorithm/key handling. https://pyjwt.readthedocs.io/en/stable/usage.html — version/status: PyJWT 2.10.x; access: 2026-07-18.