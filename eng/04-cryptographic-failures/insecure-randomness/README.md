---
schema_version: 1
id: WEB-A04-INSECURE-RANDOMNESS
title: "Insecure Randomness"
slug: insecure-randomness
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-330
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Randomness

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Insecure Randomness by the root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable. 
- Conduct controlled testing in a local lab and differentiate expected results from false positives. 
- Choose the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Seed, state and difference PRNG/CSPRNG.

- Python `random`, `secrets` and Node `crypto`.

- Entropy budget, encoding, and token lifecycle.

## 3. Background Knowledge

In the world of digital security, randomness acts like a master key. It is used to generate the code OTP sent to your phone, password recovery codes, session login codes (session ID), or encryption keys that protect e-wallets. If these keys are made from a predictable mold, attackers can easily forge an identical key to break into your account. [S6]

To generate random numbers, computers use two main types of "number generators":
- **PRNG (Pseudo-random number generator)**: a deterministic algorithm with state. Using the same algorithm, seed, and sequence of calls will produce the same output. `Math.random()` and Python's `random` module do not guarantee cryptographic unpredictability, so they should not be used for tokens, ID sessions, OTP, or keys. The ability to recover the state depends on the algorithm, output representation, and the number of observed samples; there is no "few samples" threshold that applies to all runtimes. [S6]
- **CSPRNG (Cryptographically secure pseudo-random number generator)**: may also be deterministic, but is designed so that its output is hard to predict without knowing the internal state and is seeded/reseeded from the operating system's entropy source. In Node.js and Python, prefer API, `node:crypto`, and `secrets` instead of designing your own generator. [S6], [S7]

```javascript
// Normal operation: generating a random number in JavaScript
const value = Math.random();  // Returns float between 0 and 1
console.log(value);           // e.g., 0.7281943042158021

// This API is suitable for non-security uses, not secrets or tokens
```
The key point here is: the PRNG algorithms typically operate on a finite state. When an attacker collects a sufficient number of output samples, they can use mathematics to restore this state and predict the future. [S6]

## 4. Description and Root Cause

The "Insecure Randomness" vulnerability occurs when developers accidentally use ordinary random number generators (PRNG) for security purposes. [S6]

For example, a password reset token generated using the PRNG time-based seed can have its search space reduced if an actor roughly knows the timing and the algorithm. Observing the token of the actor themselves does not automatically prove the ability to predict another person's token; the same generator, call order, and absence of additional secret entropy must be verified. [S6]

Or worse, the OTP codes, which only have 6 digits, if generated predictably, will quickly be broken, making two-factor authentication (2FA) useless. Similarly, ID sessions or encryption keys generated carelessly are also free passes inviting hackers into the system. [S6]


## 5. Threat Model and Exploitation Conditions

- **Assets:** reset token, session ID and OTP synthetic.

- **Actor:** observer knows the public seed or multiple outputs; no internal state CSPRNG.

- **Trust boundary:** Node.js/Python random API generates a value used as a secret.

- **Necessary condition:** the application uses PRNG to make predictions, weak seed or insufficient space/limit to try.

- **Environment:** Python 3.12 random.Random and Node.js crypto pin version, local process, no network.

Uniqueness like UUID does not mean secrecy; the session token must be opaque, have enough entropy, and be generated from OS CSPRNG. [S6], [S7]

## 6. Attack Mechanism

The application transforming output PRNG can predict it into token/OTP. When the actor knows the seed/state or a small space, the future sequence can be reproduced; OS CSPRNG with the correct lifecycle removes that assumption. [S6], [S7]

## 7. Testing in an Authorized Lab

1. **Setup:** run a local Python/Node process with a public seed fixture and no external input.  
2. **Baseline:** two CSPRNG outputs are different; format/length meets the contract.  
3. **Operation:** create two random.Random with the same seed to demonstrate matching sequences; do not brute-force the token.  
4. **Expected result:** PRNG fixture can be reproduced; fixed code uses randomBytes/secrets and regression does not rely on fixed values.  
5. **Boundary:** check entropy source errors, fork/reseed, token expiration, and separate rate limits.  
6. **Cleanup:** delete token/log fixture and terminate the process.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The core example only illustrates the repetitiveness of PRNG when the seed is exposed. It does not use real tokens, accounts, or endpoints.

<!-- payload-id: WEB-A04-INSECURE-RANDOMNESS-001 -->
<!-- context: Python 3.12 standard-library random.Random; local process; deterministic-generator behavior [S6] -->
<!-- prerequisites: no external input or network access -->
<!-- encoding: UTF-8 Python source; decimal seed is parsed as an integer; no transport or secondary decoding -->
<!-- expected-result: both sequences are equal because both generators use the same public seed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```python
import random

public_seed = 20260717
first = random.Random(public_seed)
second = random.Random(public_seed)

sequence_a = [first.randrange(1_000_000) for _ in range(4)]
sequence_b = [second.randrange(1_000_000) for _ in range(4)]
assert sequence_a == sequence_b
```

## 9. Vulnerable Code and Secure Code

```javascript
// ❌ VULNERABLE: Using Math.random() for security-sensitive values
function generateResetToken() {
    // Math.random() is NOT cryptographically secure
    const token = Math.random().toString(36).substring(2, 15);
    return token;  // The runtime does not guarantee cryptographic unpredictability
}

function generateSessionId() {
    // Timestamp-based ID - trivially guessable
    return "sess_" + Date.now().toString(36);
}

function generateOTP() {
    // The space has 1,000,000 values, but Math.random() is not a CSPRNG
    return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}
```

```javascript
// ✅ SECURE: Using crypto module for security-sensitive values
const crypto = require('crypto');

function generateResetToken() {
    // 32 bytes = 256 bits of entropy from OS CSPRNG
    return crypto.randomBytes(32).toString('hex');
    // e.g., "a1b2c3d4e5f6...64 hex chars" - unpredictable
}

function generateSessionId() {
    // Generate an opaque 256-bit session identifier from the OS CSPRNG
    return crypto.randomBytes(32).toString('base64url');
}

function generateOTP() {
    // randomInt uses the CSPRNG and avoids modulo bias
    const value = crypto.randomInt(0, 1_000_000);
    return value.toString().padStart(6, '0');
}
```

```python
# ✅ SECURE: Python equivalent using secrets module
import secrets

# Explicitly request 32 random bytes, then encode them for URLs
reset_token = secrets.token_urlsafe(32)

# A six-digit OTP has a small output space even with a CSPRNG; enforce
# short expiry, one-time use and attempt limits in the verification flow.
otp = secrets.randbelow(1000000)

# Compare tokens in constant time to prevent timing attacks
is_valid = secrets.compare_digest(user_token, stored_token)
```

## 10. Detection

- Recreate the chain from the public seed in the fixture and distinguish it from OS-backed CSPRNG. [S6], [S7]

- Review API token/key generation, how it is seeded and where the token gets truncated/encoded. [S6], [S7]

- Do not record the real token; only log length, source API and collision test synthetic.

## 11. Defense

### Compulsory control

- Generate secret using API CSPRNG of the platform and the number of bytes suitable for the threat model. [S6], [S7]

- Token lifecycle management: scope, expiry, single-use, and invalidation according to use case. [S6]

### Defense-in-depth

- Rate limiting helps reduce online guessing for OTP in a small space.

- Encoding/UUID only represents data, it does not add entropy by itself.

## 12. Retest

- **Positive:** token is of correct length and the consume/invalidate flow works.

- **Negative:** fixed seed or API non-crypto is blocked by gate/code review.

- **Boundary:** fork/process restart, truncation, concurrency, and entropy failure.

- **Telemetry:** record API/version and lifecycle event, do not record secret.

## 13. Common Mistakes

- Use `random`/`Math.random()` for the security token.

- Seed with the timestamp and then regard the output as the secret.

- Count encoded characters like the number of bits of entropy.

- Call all PRNG unsafe; CSPRNG is also often a deterministically generated set with a specialized design.

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

- **Entropy:** the uncertainty of the source used to seed/reseed the generator. [S6]

- **PRNG:** the set is certain to expand the seed into an output string. [S6]

- **CSPRNG:** the generator set is designed to produce outputs that are hard to predict when the secret state and lifecycle are correct. [S6], [S7]

## 16. Related Lessons and Further Reading

- [DNS Poisoning](../dns-poisoning/) — See more lessons about DNS Poisoning.

## 17. References

- **[S6]** Python 3.12 documentation — `random` and `secrets`. https://docs.python.org/3.12/library/random.html — version: Python 3.12; accessed: 2026-07-17.
- **[S7]** Node.js documentation — `crypto.randomBytes()` and `crypto.randomInt()`. https://nodejs.org/api/crypto.html — version/status: current version; accessed: 2026-07-17.