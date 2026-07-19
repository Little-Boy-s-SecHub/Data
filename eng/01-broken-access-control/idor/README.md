---
schema_version: 1
id: WEB-A01-IDOR
title: "Insecure Direct Object Reference (IDOR)"
slug: idor
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-639
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Direct Object Reference (IDOR)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Insecure Direct Object Reference (IDOR) using root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose the root control, implement a fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Authentication, object-level authorization, and ownership.

- The REST route has an object identifier, including UUID.

- Read the ORM query and the fixture audit log.

## 3. Background Knowledge

Imagine you park your car in a smart parking lot. After parking, the staff gives you a ticket with the number `1042` — this is the **Object Identifier** that helps identify your car. When you want to retrieve your car, you give this ticket to the staff, they match the ticket number with the corresponding car in the lot and return the car to you. [S2]

It's the same in the web world. All information such as personal profiles, orders, invoices, or your images are assigned a unique identification code (for example: `id=1042` or a long string of characters like UUID). When you want to view your order, the browser sends a request to the server along with that ID. To make the system operate safely, the server must perform a very important check: "Is the person presenting the lottery ticket `1042` really the owner of the car `1042`?" This process is called **Authorization**. If the car holder just looks at the ticket number and gives out the car without checking who is taking it, then anyone who picks up or forges a lottery ticket `1043` could take someone else's car. In modern API security, missing this verification step is called **BOLA** (Broken Object Level Authorization). [S2]

The normal procedure of a API endpoint returning order information:

```python
# Normal flow: server retrieves order by ID from authenticated user
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    user = get_authenticated_user(request)
    # Query filters by BOTH order_id AND user_id — correct behavior
    order = db.session.query(Order).filter(
        Order.id == order_id,
        Order.user_id == user.id
    ).first()
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order.to_dict())
```
The **authorization** mechanism ensures that user A cannot access resources belonging to user B, even if they know the ID of that resource. This is the most important control layer in any application that handles multi-user data. OWASP API Security calls this pattern **Broken Object Level Authorization (BOLA)** — the most common vulnerability in modern API. [S2]

## 4. Description and Root Cause

IDOR occurs when the server acts like the careless valet mentioned above: they **only rely on ID resources** sent by the user to retrieve data from the database and completely **do not verify ownership**. An attacker only needs to change the ID value in URL, request body, or query parameter to access another user's data. [S2]

This vulnerability is particularly dangerous because:
- **Easy to exploit**: no high skill needed, just change a number
- **Hard to detect with scanners**: authorization logic is business-specific
- **Wide impact**: leak PII, internal documents, financial transactions [S2]


## 5. Threat Model and Exploitation Conditions

- **Assets:** orders, documents, and synthetic profiles belonging to each user.

- **Actor:** user 500/owner 1042 has been verified; other owners and admin are controls.

- **Trust boundary:** Flask 3.x takes the object ID from the path before querying SQLAlchemy and serializes the response.

- **Necessary condition:** the actor knows another ID from the fixture and the server lacks ownership/permission checks after the query.

- **Environment:** API loopback, four synthetic users, maximum three ID tests; no brute-force.

ID being predictable or UUID being exposed are only supporting conditions; evidence IDOR is actor A reading/modifying actor B's object due to lack of authorization. [S1], [S5]

## 6. Attack Mechanism

API uses object ID as a query key but does not bind the result to the current subject. Replacing ID while keeping the token can allow the server to serialize objects of another owner. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** seed owner A/B, orders 1042-1044 and documents 500-503; enable policy/query log.
2. **Baseline:** token A reads object A; token B reads object B.
3. **Action:** keep token A and replace exactly three predefined synthetic ID in the payload.
4. **Expected result:** the bug returns object B; fix returns 403/404 consistently and does not serialize B's data.
5. **Boundary:** check non-existent object, expired token, admin route, and UUID being validly exposed.
6. **Cleanup:** delete observation file, revoke token, and stop fixture.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Pattern 1: Numeric ID Enumeration**

<!-- payload-id: WEB-A01-IDOR-001 -->
<!-- context: HTTP/1.1; Flask 3.x fixture at 127.0.0.1:8000; actor owns synthetic order 1042 only; object-level authorization model [S2] -->
<!-- prerequisites: seed orders 1042-1044 with different owners; authenticate as owner of 1042; limit the test to these three IDs -->
<!-- encoding: ASCII numeric path segments, Host and Authorization headers; raw harness emits CRLF; requests have no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns another owner's synthetic order; fixed fixture returns 403 for 1043/1044 and 200 for 1042 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Attacker changes order_id from their own (1042) to another user's (1043)
GET /api/orders/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>

GET /api/orders/1043 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>

GET /api/orders/1044 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>
```
**Pattern 2: UUID is not always safe**

UUID has multiple versions: v4 uses random/pseudorandom bits, while v1/v6/v7 have a timestamp field and different structure. An UUID can be exposed through responses, logs, or links; the difficulty of guessing it does not prove access rights. Testing IDOR must use two actors/owners in a lab and verify server-side authorization for the object, without unlimited brute-force. [S5]

**Pattern 3: BOLA in a REST API**

<!-- payload-id: WEB-A01-IDOR-003 -->
<!-- context: Bash 5.x and curl 8.x; Flask 3.x fixture at 127.0.0.1:8000; synthetic users 500-503; object-level authorization model [S2] -->
<!-- prerequisites: seed four users with separate owners; use only lab_token_user_500; truncate lab-observations.jsonl before the run -->
<!-- encoding: UTF-8 shell source with ASCII numeric path segments; curl emits HTTP framing and Authorization header bytes -->
<!-- expected-result: vulnerable fixture writes documents for user 501-503 to the local observation file; fixed fixture returns 403 for all three -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Burp Suite Intruder: enumerate user profiles via API
# Original request from authenticated user (user_id=500)
curl -H "Authorization: Bearer <lab_token_user_500>" \
     http://127.0.0.1:8000/v1/users/500/documents

# Keep the authorized fixture bounded to three synthetic users
for uid in 501 502 503; do
  curl -s -H "Authorization: Bearer <lab_token_user_500>" \
       "http://127.0.0.1:8000/v1/users/$uid/documents" >> lab-observations.jsonl
done
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile_vulnerable(user_id):
    # BAD: No ownership check — any authenticated user can access any profile
    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == user_id
    ).first()
    return jsonify(profile.to_dict())


# === SECURE CODE ===
@app.route('/api/users/me/profile', methods=['GET'])
def get_profile_secure():
    # GOOD: Use session-based identity, not client-supplied ID
    current_user = get_authenticated_user(request)

    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()

    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    # Log access for audit trail
    audit_log.info(f"Profile accessed by user_id={current_user.id}")
    return jsonify(profile.to_dict())


# === SECURE CODE (when cross-user access is needed, e.g. admin) ===
@app.route('/api/admin/users/<int:user_id>/profile', methods=['GET'])
@require_role('admin')  # Enforce role-based access control
def admin_get_profile(user_id):
    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == user_id
    ).first()
    if not profile:
        return jsonify({"error": "Not found"}), 404
    audit_log.info(f"Admin accessed profile of user_id={user_id}")
    return jsonify(profile.to_dict())
```

## 10. Detection

- Use two actors and the seeded objects; change the identifier and then confirm the owner of the response/mutation. [S2]

- Review query only filters by ID without restricting owner/tenant or policy. [S2]

- Log actor, object ID, owner/tenant, action, and policy result.

## 11. Defense

### Compulsory control

- Check object-level authorization on the server side for each request before returning or modifying the object. [S2]

- Query scope by actor/tenant or call authorized policy; default is deny. [S2]

### Defense-in-depth

- UUID is hard to predict, only reduces enumeration, does not change authorization.

- Rate limit supports bulk ID detection review.

## 12. Retest

- **Positive:** the actor can read/modify their own object.

- **Negative:** the other actor is rejected and the object remains unchanged.

- **Boundary:** object does not exist, UUID is wrong, bulk and nested object.

- **Telemetry:** the audit log must connect the actor, object owner, and policy result.

## 13. Common Mistakes

- Only change the serial number to UUID.

- Retrieve the object by ID first, then check the owner after the data has been returned.

- Missing bulk endpoint or nested resource.

- Infer vulnerability from the 403/404 difference without seeing unauthorized data.

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

- **BOLA/IDOR:** missing permission check of the actor on the object selected by identifier. [S2]

- **Object identifier:** value of the selected object; knowing the identifier does not imply having access. [S2]

- **Ownership:** the relationship between actor/tenant and object that the policy uses to determine rights. [S2]

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/access-control/idor — version/status: current version; accessed: 2026-07-17. 
- **[S2]** OWASP API Top 10. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ — version/status: current version; accessed: 2026-07-17. 
- **[S5]** RFC 9562 — Universally Unique IDentifiers (UUIDs). https://www.rfc-editor.org/rfc/rfc9562.html — version/date: May 2024; accessed: 2026-07-17.
