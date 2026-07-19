---
schema_version: 1
id: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION
title: "Broken Object Level Authorization (BOLA)"
slug: broken-object-level-authorization
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API1:2023
cwe:
  - CWE-639
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Broken Object Level Authorization (BOLA)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- Distinguish BOLA from IDOR in general: the focus is on authorization according to each API object. 
- Test requests to change ID objects while keeping the same actor, token, and operation. 
- Design retests to demonstrate the policy checks owner/scope before reading or writing data.

## 2. Prerequisites

- HTTP method, path parameter, query parameter, and JSON body.
- Authentication vs authorization.
- How API represents the ID object using integer, UUID, or opaque key.

## 3. Background Knowledge

BOLA occurs when API believes that a user has logged in, they are allowed to access any object with a valid ID. The object ID may be located in URL, query string, header, or body. ID that is hard to guess only reduces the chance of probing, it does not replace authorization checks on the server. [S1]

## 4. Description and Root Cause

The root cause is that the handler retrieves an object according to ID sent by the client but does not bind that object to the current actor, current tenant, or the granted scope. The error often occurs at endpoints for reading details, updating profiles, downloading invoices, viewing orders, or GraphQL mutations. [S1]

## 5. Threat Model and Exploitation Conditions

- **Assets:** objects belonging to another user/tenant, such as order, invoice, ticket, or profile.
- **Actor:** a user usually has a valid token for themselves.
- **Trust boundary:** object ID coming from the client into the service/data layer.
- **Necessary condition:** API returns or modifies an object that does not belong to the actor but only relies on ID.
- **Environment:** local fixture with user A, user B, and objects specific to each user.

## 6. Attack Mechanism

The actor sends a valid request to their own object to get the baseline, then replaces object ID with another user's object. The evidence must prove that the response or side effect belongs to an object with a different owner, not just based on the status code.

## 7. Testing in an Authorized Lab

1. Seed `user-a` with `order-a` and `user-b` with `order-b`.
2. Send baseline request using token `user-a` to `order-a`.
3. Send the same method/headers but change ID to `order-b`.
4. Expect error version to return `order-b` data; fix to return 403 or 404 regardless of existence.
5. Log actor, object ID, owner in datastore and policy decision.
6. Cleanup token, object, and log fixture.

## 8. Payloads and Scope of Applicability

The payload only uses the ID synthetic object in the local fixture.

**BOLA read probe**

<!-- payload-id: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION-001 -->
<!-- context: HTTP/1.1 GET against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION-001 -->
<!-- prerequisites: seed user-a, user-b, order-a and order-b; token belongs only to user-a -->
<!-- encoding: ASCII request target and bearer token placeholder -->
<!-- expected-result: vulnerable fixture returns order-b to user-a; fixed fixture returns 403 or ownership-neutral 404 before data access -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
GET /api/orders/order-b HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer USER_A_TOKEN
Accept: application/json
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: fetches by user-controlled object ID only.
def get_order_vulnerable(order_id, current_user):
    return db.orders.find_one({"id": order_id})

# SECURE: binds object access to the authenticated principal.
def get_order_secure(order_id, current_user):
    order = db.orders.find_one({"id": order_id, "owner_id": current_user.id})
    if order is None:
        raise NotFound()
    return order
```

## 10. Detection

- Log actor, object ID, owner ID, tenant ID, and policy decision. 
- Compare the baseline allowed object with the cross-owner object. 
- Do not conclude just because ID is sequential; there must be data or illegal side effects.

## 11. Defense

### Compulsory control

- Check object authorization in every object read/write function.
- Query datastore with both object ID and owner/tenant/scope.
- Apply consistent policy in REST, GraphQL, batch, and background actions.

### Defense-in-depth

- Using ID is hard to predict, audit log and anomaly detection, but it does not replace object-level authorization.
- Hide 403/404 differences if the threat model requires reducing object enumeration.

## 12. Retest

- **Positive:** the user successfully reads/edits their own object.  
- **Negative:** the user does not read/edit another user's object.  
- **Boundary:** ID does not exist, ID belongs to another tenant, batch includes multiple ID.  
- **Telemetry:** policy decision matches datastore owner.

## 13. Common Mistakes

- Consider JWT valid as having full permissions for all objects.
- Only check UI while ignoring API directly.
- Rely on UUID/random ID instead of authorization.

## 14. Summary and Checklist

- [ ] Every object access checks owner/tenant/scope. 
- [ ] Tests have at least two actors and two objects not owned by them. 
- [ ] Both response and side effects are verified. 
- [ ] The fix does not only block a single endpoint in the PoC.

## 15. Glossary

- **BOLA:** Broken Object Level Authorization, missing permission check on each object.
- **Object ID:** resource identifier received from the client by API.
- **Tenant:** data boundary between organization/customer.

## 16. Related Lessons and Further Reading

- [IDOR](../../01-broken-access-control/idor/)
- [Broken Access Control](../../01-broken-access-control/broken-access-control/)
- [GraphQL Vulnerabilities](../graphql-vulnerabilities/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API1 Broken Object Level Authorization. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ — current version; accessed: 2026-07-18.
- **[S2]** CWE-639 — Authorization Bypass Through User-Controlled Key. https://cwe.mitre.org/data/definitions/639.html — current version; accessed: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — current version; accessed: 2026-07-18.