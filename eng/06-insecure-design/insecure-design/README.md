---
schema_version: 1
id: WEB-A06-INSECURE-DESIGN
title: "Insecure Design"
slug: insecure-design
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
  - A06:2025
cwe:
  - CWE-602
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Design

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Insecure Design by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the flaw to be exploitable.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Insecure Design scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you want to build a house. The architect's initial design completely forgot to include a bathroom window, or placed a safe right next to the ground floor window without protective bars. Even if the builders later use the best bricks, the most expensive cement, and build with great care (code according to standards without syntax errors), the house is still very easy to break into. This original design flaw is similar to **Insecure Design**.

To avoid deadly mistakes from the very beginning, the software development process needs to apply the **Secure SDLC** model — that is, integrating security standards into every step, right from the idea stage.

An important tool in Secure SDLC is **Threat Modeling**, which helps developers map out potential threats to proactively prevent them before laying the first lines of code.  
In this map, drawing **Trust Boundaries** is crucial. Imagine a trust boundary like a security glass door at an airport: the outside lobby is accessible to anyone (untrusted zone - user browser), while the boarding lounge is highly secure (trusted zone - service server). A secure design must thoroughly check all passengers' luggage and documents right at the security gate. If you only rely on "do not enter" signs in the lobby without actual staff checking tickets at the security gate, malicious actors can easily sneak into the restricted area.

#### Illustration of normal operation (Normal Operation)```python
# Decorator to enforce trust boundary checks at the backend API layer
from functools import wraps
from flask import session, abort, request

def enforce_trust_boundary(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if the user is authenticated and has the correct role
            # This validation occurs right at the entry point of the trusted zone
            user_role = session.get('user_role')
            if not user_role or user_role != required_role:
                # Reject unauthorized traffic from untrusted client zone
                abort(403, "Access Denied: Insufficient privileges at trust boundary")
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

## 4. Description and Root Cause

Insecure Design vulnerabilities are serious mistakes inherent in the architecture and logical thinking of the system before the source code is written.

Its danger lies in the fact that you cannot patch this vulnerability by fixing a few lines of code. The flaw lies in the way the process operates.

A typical example is when you design a system that only hides the "Delete User" button on the regular user's web interface, but forget to configure proper permission checks on the backend server. An attacker only needs to find the hidden API path and send a direct request to delete anyone. Even if the delete feature's code is perfectly written and has no technical errors, your system can still collapse from within due to a loose process design flaw.

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** authorization and workflow invariant of the admin operation.  
- **Actor, authentication, and role:** an authenticated user role has discovered the admin operation but does not have an admin role.  
- **Exploitation conditions:** designed based on hidden UI or client order rather than authoritative server policy.  
- **Browser, proxy, framework, and version:** Flask 3.x/PostgreSQL 16 with a clear role matrix; loopback; must record the actual image/package version along with evidence.  
- **Mandatory evidence:** the same correlation ID must link input, control decision, and impact on the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For insecure design, the design relies on hidden UI or client order instead of an authoritative server policy. The positive case must demonstrate that the input reaches the correct sink and produces the described effect; the negative case, when root control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Flask 3.x/PostgreSQL 16 with a clear role matrix; loopback; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.  
2. **Baseline:** send a valid input of the insecure design use case; save raw request/response, determine policy and asset state before the test.  
3. **Input and operation:** use exactly one core payload in item 8 within the annotated context; change only one variable at a time and comply with request cap.  
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism “design relies on hidden UI or client-side order instead of an authorized server policy”; secure fixture must block before side effects and boundary inputs must fail closed.  
5. **Cleanup:** delete data, markers, and logs of the insecure design; revoke related session/cache, restore snapshot, and confirm no remaining test callbacks/processes.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing operations must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: During the design phase, developers did not perform threat modeling and did not correctly identify trust boundaries. 
Step 2: The application relies entirely on hiding action functions (such as the 'Delete User' button) on the HTML client interface for users without administrative privileges. 
Step 3: The attacker, an ordinary user, analyzes the source code HTML/JS, discovers URL API of the delete function (`/admin/delete-user`), and sends HTTP POST request directly to that API. 
Step 4: Because the backend does not check the permissions of the current session and relies only on the hidden button on the frontend, the delete action is successfully executed.

### Example HTTP request bypass frontend validation:<!-- payload-id: WEB-A06-INSECURE-DESIGN-001 -->
<!-- context: HTTP/1.1 JSON purchase request reaches a synthetic ledger without authoritative checks -->
<!-- prerequisites: authenticated normal fixture user; item 999 and zero price exist only in disposable DB; one request -->
<!-- encoding: UTF-8 application/json with Content-Length generated from exact bytes -->
<!-- expected-result: vulnerable ledger creates a zero-price order; secure service recalculates price/balance and rejects with no row -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/purchase HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 40

{"item_id":999,"quantity":100,"price":0}
```
In a fragile fixture, the server trusts `price` from the client and creates an order with price 0. A safe fixture ignores the price field sent by the client, loads the authoritative price according to `item_id`, and checks the invariant before the transaction.

## 9. Vulnerable Code and Secure Code

The following two routes use Flask 3.x for the same administrative action. Hiding a button in the interface does not create authorization on the server; every request to a sensitive route must still be decided by the server-side policy before any side effect. [S2] [S3]

### Not safe (vulnerable): only relying on the interface

```python
from flask import request

@app.post('/admin/delete-user')
def delete_user_vulnerable():
    # Vulnerable: the UI hides this action, but the backend has no authorization check
    user_id = request.form['user_id']
    user_store.delete(user_id)
    return ('', 204)
```
### Secure: check permissions at the backend

```python
from functools import wraps
from flask import abort, request, session

# Secure design enforces access controls on the backend API,
# not just hiding buttons or links on the frontend templates.
def require_privilege(needed_privilege):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_permissions = session.get('permissions', [])
            if needed_privilege not in user_permissions:
                # Terminate with unauthorized error status
                abort(403, "Access Forbidden: Insufficient Permissions")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.post('/admin/delete-user')
@require_privilege('admin_manage')
def delete_user_secure():
    # Secure: authorization runs before the state-changing operation
    user_id = request.form['user_id']
    user_store.delete(user_id)
    return ('', 204)
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Insecure Design, policy results, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload string. 
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not it had an impact. 
- Scanner or WAF alert is only an investigation signal; not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Define and enforce authorization/invariant server-side for all operations, independently of UI. 
- Apply the same controls to all routes, operations, and equivalent handling paths; failure must stop before side effects.

### Defense-in-depth

With Insecure Design, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID hard to predict, WAF, CSP, or general validation should not be used to replace the original control.

- **Summary**: Avoid unsafe design by embedding threat modeling, security design patterns, and strict access control testing throughout the software development lifecycle (SDLC).  
- **Detailed Steps**:  
  - Integrate security analysis — such as threat modeling (e.g., STRIDE) — into the initial design phase of every project.  
  - Apply the principle of least privilege, ensuring default configurations restrict access until explicitly granted.  
  - Verify authorization checks at all backend logic layers, instead of relying solely on client-side interface settings (frontend UI).  
  - Use established and verified security libraries and patterns rather than building custom security mechanisms that have not been tested.  
  - Review and enforce business logic processes to ensure users cannot bypass critical authentication steps.

## 12. Retest

- **Positive case:** with Insecure Design, the valid flow still works correctly for allowed actors and data. 
- **Negative case:** the same input/resource but disallowed actor or context is denied without leaking sensitive details. 
- **Boundary case:** check empty values, edge extremes, different encoding, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Recheck:** save the minimal scenario reproducing the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Insecure Design without verifying side effects and logs.  
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

- **Insecure Design**: A group of vulnerabilities that arise from mistakes or omissions during the planning and system architecture design process, causing the system to lack necessary security control mechanisms from the start.
- **Secure Software Development Lifecycle (SDLC)**: A software development process that integrates security testing and practices into all stages from requirements, design, implementation to testing and maintenance.
- **Threat Modeling**: A method of analyzing systems to identify potential security threats, threat actors, and propose corresponding mitigation measures during the design phase.
- **Trust Boundaries**: Points of separation in the system architecture where data transitions from a low-trust area (e.g., user-submitted data) to a high-trust area (e.g., internal database).
- **STRIDE**: A threat classification framework developed by Microsoft, representing: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **Least Privilege**: A security principle that requires granting users or processes only the minimum permissions necessary to complete their tasks, in order to limit damage if the account is compromised.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; access: 2026-07-18.
- **[S2]** CWE-602 — Client-Side Enforcement of Server-Side Security. https://cwe.mitre.org/data/definitions/602.html — version/status: CWE 4.20; access: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — version/status: CWE 4.20; access: 2026-07-18.