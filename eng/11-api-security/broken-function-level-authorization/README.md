---
schema_version: 1
id: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION
title: "API Broken Function Level Authorization (BFLA)"
slug: broken-function-level-authorization
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API5:2023
cwe:
  - CWE-285
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Broken Function Level Authorization (BFLA)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- The API identification function is only for admin/operator but regular users can still call it. 
- Test the method/path/role matrix instead of just a single request. 
- Design policy at the gateway/service layer independently of UI.

## 2. Prerequisites

- HTTP method, route, role, and permission. 
- RBAC/ABAC basics. 
- Differences between object-level and function-level authorization.

## 3. Background Knowledge

BFLA focuses on function call permissions. A user may not be able to access another person's object but can still call admin functions like export, approve, delete, or config update if the route lacks role checks. [S1]

## 4. Description and Root Cause

The root cause is that the API route is exposed but the policy does not check the role/scope corresponding to the function. The error usually lies in the admin endpoint, rarely used methods, legacy routes, or routes that are only hidden from UI. [S1]

## 5. Threat Model and Exploitation Conditions

- **Assets:** administration function, bulk export, status transition, config change.
- **Actor:** regular user with a valid token.
- **Trust boundary:** route/method passing through the gateway and service controller.
- **Precondition:** sensitive function lacks role/scope check.
- **Environment:** local fixture with user token and admin token.

## 6. Attack Mechanism

The actor takes the endpoint from OpenAPI, mobile app, or traffic; then calls the sensitive function using a regular user's token. Evidence must record the function being executed or blocked by policy.

## 7. Testing in an Authorized Lab

1. List sensitive routes/methods in the fixture.
2. Call the baseline using the admin token.
3. Call the same request using a regular user token.
4. Expect the fix to return 403 before any side effects.
5. Cleanup state changes caused by the test.

## 8. Payloads and Scope of Applicability

**Admin export using user token**

<!-- payload-id: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION-001 -->
<!-- context: HTTP/1.1 POST against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION-001 -->
<!-- prerequisites: USER_TOKEN has role user only; endpoint requires admin:export scope in the fixed fixture -->
<!-- encoding: ASCII request target and JSON body -->
<!-- expected-result: vulnerable fixture starts an export job; fixed fixture returns 403 and no job is created -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/admin/export-users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{"format":"csv"}
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: authenticated users can call the admin function.
@app.post("/api/admin/export-users")
def export_users():
    return start_export_job()

# SECURE: function-level policy runs before the handler.
@app.post("/api/admin/export-users")
@require_scope("admin:export-users")
def export_users_secure():
    return start_export_job()
```

## 10. Detection

- Log route, method, required scope, actor role, and policy decision.
- Alert when a user with a lower role calls an admin/operator endpoint.
- Scanner only supports route discovery; finding requires side effect/policy evidence.

## 11. Defense

### Compulsory control

- Create a policy matrix according to route, method, role, and scope.
- Enforce at the server/gateway, not relying on UI.
- Test all methods equivalently to `GET/POST/PUT/DELETE/PATCH`.

### Defense-in-depth

- Separate admin API namespace and network policy.
- Audit log all sensitive functions.
- Use deny-by-default for routes without declared policy.

## 12. Retest

- **Positive:** admin calls the function successfully.
- **Negative:** user often gets 403 and does not create side effects.
- **Boundary:** method override, legacy route, batch function.
- **Telemetry:** job/audit log does not appear in the negative case.

## 13. Common Mistakes

- Hide the admin button on the frontend and consider it protected. 
- Check the role on a route but omit the route alias. 
- Do not test other methods on the same path.

## 14. Summary and Checklist

- [ ] All sensitive functions have mandatory scope/role. 
- [ ] Deny-by-default policy for new routes. 
- [ ] Tests include both admin and regular user tokens. 
- [ ] Side effects are verified after negative cases.

## 15. Glossary

- **BFLA:** Broken Function Level Authorization.
- **Scope:** specific permission attached to credential.
- **Policy matrix:** table of route/method/role/scope that is allowed.

## 16. Related Lessons and Further Reading

- [BFLA](../../01-broken-access-control/bfla/)
- [Privilege Escalation](../../01-broken-access-control/privilege-escalation/)
- [Shadow APIs](../shadow-apis/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API5 Broken Function Level Authorization. https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ — current version; access: 2026-07-18.
- **[S2]** CWE-285 — Improper Authorization. https://cwe.mitre.org/data/definitions/285.html — current version; access: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — current version; access: 2026-07-18.