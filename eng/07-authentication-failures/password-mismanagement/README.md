---
schema_version: 1
id: WEB-A07-PASSWORD-MISMANAGEMENT
title: "Password Mismanagement"
slug: password-mismanagement
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A04:2025
cwe:
  - CWE-916
content_status: technical-review
payload_status: none
last_verified: null
---

# Password Mismanagement

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Password Mismanagement by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Password Mismanagement scenario and how to apply handling input across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you are running a club and need to store a list of members' passwords.
- If you choose **encryption**, it's like putting the password list into a metal box and locking it with a key. When you need to authenticate, you open the box to see the original passwords. This method has a fatal weakness: if a thief steals the key to the metal box, they can read all the passwords of everyone.
- Therefore, passwords should be stored using a slow password hashing function with a salt, such as Argon2id, scrypt, or bcrypt depending on the use case. “One-way” does not mean a weak password cannot be recovered: an adversary with a hash database can still try each candidate offline and compare the results. [S3] [S4]

To make this pile of pulp even safer, you mix into the paper a pinch of **salt** — unique random characters for each user before hashing. This helps prevent thieves from using precomputed password tables (**Rainbow Tables**) to reverse-engineer the original password.

General-purpose hashes like MD5, SHA-1, or SHA-256 are not suitable for storing passwords because an attacker can try candidates offline with high throughput. A password hashing function with adjustable cost makes each attempt take additional CPU and, with a memory-hard algorithm, memory. This increases the cost of an attack but does not make guessing weak passwords “impossible”; the parameters must be benchmarked and gradually increased according to system capability. [S3] [S4]

```python
import bcrypt
import hashlib
import base64

def hash_password_securely(password: str) -> bytes:
    # Pre-hash password with SHA-256 to overcome bcrypt's 72-byte limit
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    b64_hash = base64.b64encode(sha256_hash)

    # Generate a salt with bcrypt cost 12; benchmark this cost for the deployment.
    salt = bcrypt.gensalt(rounds=12)

    # Hash the pre-hashed password using bcrypt
    hashed = bcrypt.hashpw(b64_hash, salt)
    return hashed

def verify_password_securely(password: str, hashed: bytes) -> bool:
    # Re-calculate SHA-256 pre-hash of the input password
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    b64_hash = base64.b64encode(sha256_hash)

    # Verify using bcrypt's secure timing-safe compare
    return bcrypt.checkpw(b64_hash, hashed)
```

## 4. Description and Root Cause

The Weak Password Management vulnerability occurs when an application stores user passwords in plaintext, uses outdated and fast hashing algorithms (such as MD5, SHA1), or creates custom hashing/salting formulas that do not follow security standards.

The greatest danger of this vulnerability arises when the application's database is leaked or hacked. Attackers can easily read users' passwords directly (if stored in plain text), or use automated cracking tools with graphics cards (GPU) to reverse-engineer millions of passwords hashed with weak algorithms in just a few hours, thereby taking over users' accounts on your system and on other systems where they reuse the same passwords.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare against the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** password verifier, reset secret, and password policy. 
- **Actor, authentication, and role:** user registers/changes/resets; anonymous can attempt credentials. 
- **Exploitation conditions:** weak storage, lack of breached-password blocklist, or incorrect reset-token lifecycle. 
- **Browser, proxy, framework, and version:** Argon2id/bcrypt fixture pinned with composite account; loopback; must store actual image/package version along with evidence. 
- **Mandatory evidence:** with correlation ID, must link input, control decision, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For password mismanagement, weak storage, lack of breached-password blocklist, or incorrect reset-token lifecycle. A positive case must prove that the input reaches the correct sink and produces the described impact; a negative case, when native controls are enabled, must be blocked before the side effect. Conclusions only apply to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Argon2id/bcrypt fixture pinned with a synthetic account; loopback; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the password mismanagement use case; save raw request/response, determine policy and asset state before the test.
3. **Input and operations:** use exactly one scenario/input variable described in section 8; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider a vulnerable fixture as positive when logs demonstrate "weak storage, missing breached-password blocklist, or incorrect reset-token lifecycle" mechanism; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of password mismanagement; revoke related session/cache, revert snapshot, and confirm no remaining test callback/process.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The developer stores the password by directly combining the password with a fixed pepper string and then hashing it directly using the bcrypt library: `bcrypt.hashpw(pepper + password, salt)`.
Step 2: Since the bcrypt library has a maximum input string length limit of 72 bytes, any characters beyond this limit will be ignored when calculating the hash.
Step 3: The attacker detects this flaw and realizes that if the victim's password is `A`, which is 80 characters long, they only need to correctly guess the first 72 characters to log in successfully without needing the last 8 characters, reducing the password's entropy and security.

## 9. Vulnerable Code and Secure Code

The following two functions use Python 3.12 for the same use case of storing and verifying passwords. A fast hash without salt allows for efficient batch comparison; `argon2-cffi` 23.1.x creates a salt and stores parameters in the encoded hash for verification. Production parameters must be benchmarked on the target system according to the resource budget. [S3] [S5]

### Not safe (vulnerable): fast hash, no salt

```python
import hashlib
import hmac

def store_password_vulnerable(password):
    # Vulnerable: fast unsalted hashes make offline guessing inexpensive
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password_vulnerable(stored_hash, candidate):
    candidate_hash = hashlib.sha256(candidate.encode('utf-8')).hexdigest()
    return hmac.compare_digest(stored_hash, candidate_hash)
```
### Secure: dedicated password hashing

```python
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ph = PasswordHasher()

def store_password_secure(password):
    # Secure: Argon2id stores salt and parameters in the encoded hash
    return ph.hash(password)

def verify_password_secure(stored_hash, candidate):
    try:
        return ph.verify(stored_hash, candidate)
    except (VerificationError, InvalidHashError):
        return False
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Password Mismanagement, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use current adaptive salted hashing, breached-password blocklist, and single-use reset tokens.
- Apply the same controls to every route, operation, and equivalent processing path; failure must stop before any side effect.

### Defense-in-depth

With Password Mismanagement, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used as a substitute for original controls.

- **Summary**: Password mismanagement covers insecure storage, weak hashing, and lack of complexity policies. Mitigation involves using strong, modern cryptographic hashing algorithms (like Argon2id or bcrypt) with random salts, enforcing password complexity, and using secure communication channels.
- **Detailed steps**:
  - Hash passwords using strong, adaptive, salted hashing algorithms such as Argon2id or bcrypt with appropriate work factors.
  - Never store passwords in plaintext or using outdated, fast hash algorithms (like MD5, SHA-1, or plain SHA-256).
  - Enforce strong password complexity guidelines, including minimum length and checking against lists of known breached passwords.
  - Protect the entire password input, reset, and recovery flow using HTTPS, while also applying rate limiting to the authentication endpoint.

### Argon2id vs Argon2i vs Argon2d
According to RFC 9106, Argon2 has 3 variants:
- **Argon2id** (recommended): Combines both, resistant to side-channel and GPU attacks. Used for password hashing.
- **Argon2i**: Resistant to side-channel attacks (cache timing), but weaker against GPU attacks. Used for key derivation.
- **Argon2d**: Strong against GPU attacks but susceptible to side-channel attacks. Not used in environments with side-channel risk.

OWASP provides many minimum configurations balancing memory/iteration; this is not a fixed set of parameters for every system. Choose a profile supported by current documentation, benchmark on production-like hardware, set resource limits to avoid DoS, and save version/cost in the hash chain so it can be rehashed when logging in. [S3]

## 12. Retest

- **Positive case:** with Password Mismanagement, the valid flow still works correctly for allowed actors and data. 
- **Negative case:** with the same input/resources but disallowed actor or context, it is rejected without leaking sensitive details. 
- **Boundary case:** test empty values, extreme boundaries, different encodings, repeated requests, expired session state, and equivalent paths/operations. 
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID. 
- **Recheck:** save a minimal scenario reproducing the old bug and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Password Mismanagement without verifying side effects and logs.  
- Use a payload with the correct syntax but the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another primary control.  
- Only fix one route while the same sink/policy is used in other routes.  
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

- **Cryptographic Hashing**: A transformation that does not have a key-based decryption operation; however, an attacker can still try candidates and compare hashes, so passwords must use a dedicated hash function with salt and cost.  
- **Encryption**: The process of converting information from a readable form (plaintext) to an unreadable form (ciphertext) using an algorithm and a key. This is a two-way process and can be decrypted if the correct key is available.  
- **Salt**: A random string added to a password before hashing, ensuring that even two identical passwords will generate two different hashes in the database, protecting against precomputed hash table lookups.  
- **Work Factor**: A configuration parameter that determines the amount of resources (CPU, memory, time) that a server must expend to perform a hash, helping to slow down an attacker's password cracking process.  
- **Rainbow Table**: A database containing a list of common passwords with their precomputed corresponding hashes, used for quick lookup to crack hashed passwords.  
- **Argon2id**: A variant of Argon2 balancing resistance to side-channel attacks and parallel hardware attacks; its security depends on parameters, library, and operation, and it should not be called absolutely “the most secure”.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S2]** CWE-916. https://cwe.mitre.org/data/definitions/916.html — version/status: current version; accessed: 2026-07-18. 
- **[S3]** OWASP Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18. 
- **[S4]** NIST SP 800-63B-4 — Authentication and Authenticator Management. https://pages.nist.gov/800-63-4/sp800-63b.html — version/status: SP 800-63B-4; accessed: 2026-07-18. 
- **[S5]** argon2-cffi API Reference. https://argon2-cffi.readthedocs.io/en/23.1.0/api.html — version/status: 23.1.0; accessed: 2026-07-18.