---
schema_version: 1
id: WEB-A01-BFLA
title: "Broken Function Level Authorization (BFLA)"
slug: bfla
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-285
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Broken Function Level Authorization (BFLA)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Broken Function Level Authorization (BFLA) using the root cause instead of just describing the consequence. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish the expected result from false positives. 
- Select the original control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- HTTP method, route mapping and middleware of Express.js 4.x.

- The difference between authentication, roles, and function permissions.

- Read the audit log and check for side effects on synthetic data.

## 3. Background Knowledge

Imagine you walk into a modern office building. To pass through the main entrance or enter your own office, you only need to swipe your regular employee card. However, to enter the server room or the HR room — where extremely sensitive information is stored — you need a card with higher privileges. In the software world, controlling who is allowed to perform which actions (such as deleting an account, upgrading permissions, or viewing revenue reports) is called **Function Level Authorization**.

Unlike checking whether you own or can view a specific record (Object Level Authorization), this mechanism focuses on the question: 'Do you have the right to perform this action?' [S5]

A typical API system separates endpoints according to roles:

```python
# Typical API structure with role-based endpoints
# Public endpoints — accessible to all authenticated users
# GET  /api/users/me              → view own profile
# PUT  /api/users/me              → update own profile

# Admin endpoints — restricted to admin role
# GET  /api/admin/users           → list all users
# DELETE /api/admin/users/:id     → delete a user
# PUT  /api/admin/users/:id/role  → change user role

# Middleware enforces role check BEFORE handler executes
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_authenticated_user(request)
        if user.role != 'admin':
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated
```
A common architecture uses **middleware** or **decorator** to check roles before executing business logic. However, a very common mistake is that developers only worry about "hiding" the Admin button on the user interface for regular users (client-side), forgetting to place real safeguards on the server-side, or only protecting some admin endpoints while overlooking others. [S5]

## 4. Description and Root Cause

The vulnerability **BFLA** (Broken Function Level Authorization) occurs when the server does not check the actor's permissions on a specific function. Guessing the route, changing the HTTP method, or seeing the admin button only helps access the testing surface; only when a low-permission request actually passes through the policy and executes a high-permission function is BFLA confirmed. [S1], [S2]

- **Try guessing a new path**: Change the address in the browser from `/api/users/` to `/api/admin/users/` to see what happens. 
- **Change the way of acting**: Instead of just requesting to view information (`GET`), they try switching to a delete command (`DELETE`) or edit (`PUT`). 
- **Send additional privilege fields**: fields like `{"role": "admin"}` are a separate mass assignment/field-level authorization test path; only classify into BFLA when the handler update for a low-permission actor truly allows performing the role change function. [S1]

Consequences of uncontrolled functionality: the actor can read, modify, or delete data beyond permissions, or invoke administrative operations. The microservice architecture does not automatically create BFLA; risks arise when the policy is not consistently enforced at each service or at an authorized gateway. [S1], [S2]


## 5. Threat Model and Exploitation Conditions

- **Assets:** administrative functions, fake user data, and audit trail of API.

- **Actor:** the user has logged in with a regular role; the admin token is only used as a positive baseline.

- **Trust boundary:** Express.js 4.x authorization middleware before routes GET, PUT, and DELETE.

- **Necessary condition:** the actor knows the route or changes the HTTP method; the server authenticates the token but does not check permissions on the correct function. [S5]

- **Environment:** fixture 127.0.0.1:9080, synthetic data, proxy/raw HTTP depending on payload; no browser needed.

Only conclude BFLA when with the same regular token you can call the admin function and the log/datastore confirms the impact; a guessed route or an UI node being hidden does not by itself prove a vulnerability. [S1]

## 6. Attack Mechanism

The router selects the correct handler from the path and method, but the middleware only authenticates the identity or skips the function's policy. The regular token therefore reaches the admin business logic; proof must link the policy decision with the side effect of the correct request. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** restore Express.js 4.x snapshot, seed two synthetic users with regular/admin tokens and enable policy/audit log.
2. **Baseline:** regular token reads its own resource; admin token performs valid admin functions.
3. **Operation:** use regular token to try GET admin and PUT role; DELETE only runs with lab-user-1042 on disposable snapshot.
4. **Expected result:** buggy version allows out-of-role operation; fix returns 403, retains data, and logs deny decision.
5. **Boundary:** repeat on equivalent route, different method, and expired token; do not brute-force route.
6. **Cleanup:** restore snapshot, revoke fixture tokens, and confirm no outbound network.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Pattern 1: URL Path Manipulation**

<!-- payload-id: WEB-A01-BFLA-001 -->
<!-- context: HTTP/1.1; Express.js 4.x fixture at 127.0.0.1:9080; regular role; synthetic users only; function-authorization model [S5] -->
<!-- prerequisites: seed regular_user_token and two synthetic users; capture application authorization log; no Internet route -->
<!-- encoding: ASCII request-target and headers; raw harness emits CRLF and recalculates Content-Length when a body is added -->
<!-- expected-result: vulnerable route returns the synthetic user list; fixed route returns 403 and records an authorization denial -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Regular user discovers admin endpoint pattern
GET /api/v1/users/me HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>

# Attacker guesses admin endpoint by modifying URL path
GET /api/v1/admin/users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>
```

**Pattern 2: HTTP Method Tampering**

<!-- payload-id: WEB-A01-BFLA-002 -->
<!-- context: HTTP/1.1; Express.js 4.x disposable fixture at 127.0.0.1:9080; regular role; synthetic user lab-user-1042; function-authorization model [S5] -->
<!-- prerequisites: restore a database snapshot before each run; seed lab-user-1042 and regular_user_token; never use production data -->
<!-- encoding: ASCII method, request-target and headers; raw harness emits CRLF; request has no body or Content-Length -->
<!-- expected-result: vulnerable fixture deletes only lab-user-1042 and returns 204; fixed fixture returns 403 and leaves the seeded record intact -->
<!-- risk: destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Regular user can view their own data
GET /api/v1/users/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>

# Attacker changes method to DELETE — server lacks method-level auth
DELETE /api/v1/users/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>
```

**Pattern 3: Privilege Escalation via PUT**

<!-- payload-id: WEB-A01-BFLA-003 -->
<!-- context: curl 8.x against Express.js 4.x fixture at 127.0.0.1:9080; regular role; own synthetic account; function-authorization model [S5] -->
<!-- prerequisites: seed regular_user_token and reset the synthetic account to role=user before each run; no Internet route -->
<!-- encoding: UTF-8 JSON with Content-Type application/json; curl calculates Content-Length -->
<!-- expected-result: vulnerable fixture changes the synthetic role; fixed fixture ignores protected fields and keeps role=user -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Attacker sends role update request using their own token
curl -X PUT http://127.0.0.1:9080/api/v1/users/me \
  -H "Authorization: Bearer <regular_user_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "is_superuser": true}'
# If server doesn't filter writable fields → privilege escalation
```

## 9. Vulnerable Code and Secure Code

```javascript
// === VULNERABLE CODE (Express.js) ===
const express = require('express');
const router = express.Router();

// BAD: No role check — any authenticated user can delete users
router.delete('/api/v1/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

// BAD: No field filtering — user can set their own role
router.put('/api/v1/users/me', authenticate, async (req, res) => {
    // Directly spreading user input into update query
    await User.findByIdAndUpdate(req.user.id, req.body);
    res.json({ message: 'Updated' });
});


// === SECURE CODE (Express.js) ===
// GOOD: The same route and method enforce admin authorization before the handler
router.delete('/api/v1/users/:id', authenticate, authorize('admin'),
    async (req, res) => {
        await User.findByIdAndDelete(req.params.id);
        audit.log(`User ${req.params.id} deleted by admin ${req.user.id}`);
        res.status(204).send();
    }
);

// GOOD: Whitelist allowed fields to prevent mass assignment
const ALLOWED_UPDATE_FIELDS = ['name', 'email', 'avatar'];

router.put('/api/v1/users/me', authenticate, async (req, res) => {
    // Only pick allowed fields from request body
    const updates = {};
    for (const field of ALLOWED_UPDATE_FIELDS) {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    }
    await User.findByIdAndUpdate(req.user.id, updates);
    res.json({ message: 'Updated' });
});

// Centralized RBAC middleware
function authorize(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}
```

## 10. Detection

- Send the operation with both the admin token and the regular token; compare the policy decision with the side effect, not just the status code. [S5]

- Review middleware on all methods/aliases of privileged functions, including bulk routes. [S5]

- Log actor, function, policy result, and correlation ID; do not record the full token.

## 11. Defense

### Compulsory control

- Check server-side function call permissions before business logic and default to deny when there is no rule allowing it. [S5]

- Apply the same policy to all HTTP methods, aliases, and equivalent admin routes. [S5]

### Defense-in-depth

- Hiding the admin button only improves UX; it does not control permissions.

- Alert when regular roles repeatedly call privileged functions.

## 12. Retest

- **Positive:** the token admin can call the function and the audit log records allow.

- **Negative:** the regular token is rejected before any side effect.

- **Boundary:** repeated on GET/PUT/DELETE, alias and bulk route.

- **Telemetry:** connect ID correlation between middleware, handler, and datastore.

## 13. Common Mistakes

- Only hide the route or admin button on the client.

- Protect GET but omit PUT, DELETE, or alias.

- Match BFLA with mass assignment when the function changes roles that were originally not allowed.

- Conclude from the status code without checking the side effect.

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

- **Function authorization:** determines whether the actor is allowed to call a specific business operation. [S5]

- **Middleware:** a layer that runs before the handler to perform authentication, authorization, or consistent logging. [S5]

- **Policy decision:** result allow/deny for actor, function, and context of the request. [S5]

## 16. Related Lessons and Further Reading

- [Broken Access Control](../broken-access-control/) — See more lessons about Broken Access Control.

## 17. References

- **[S1]** OWASP API Top 10. https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ — version/status: current version; accessed: 2026-07-17.
- **[S2]** OWASP Access Control Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17.
- **[S5]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.