---
schema_version: 1
id: WEB-A01-BROKEN-ACCESS-CONTROL
title: "Broken Access Control"
slug: broken-access-control
level: beginner
estimated_minutes: 35
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

# Broken Access Control

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Broken Access Control by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Authentication, authorization, and the subject–resource–action model.

- How the session is mapped to the server-side actor.

- Read the handler, policy, and log of synthetic data changes.

## 3. Background Knowledge

Imagine you are registering for a service at a large hotel. When checking in at the front desk, the staff will check your ID and give you a room key. The process of checking your ID to determine who you are is called **Authentication**. As for the fact that the key only opens the specific room 204 you rented, and cannot open the next room 205 or the presidential suite, that is called **Authorization**. [S4]

The same applies in the web world. When you log in successfully, the server will give your browser an identifier called a **session token** (like a room key). Each time the browser sends a request to fetch data (via cookie or HTTP header), the server only needs to check this token to know whether you are logged in or not. However, a serious vulnerability occurs if the hotel manager 'forgets' to install smart locks, and you just walk down the hallway and turn the doorknob of another room and the door opens automatically. The **Broken Access Control** vulnerability appears when the server receives a request from you, knows you are logged in, but lazily does not check whether you actually own the room or the document you are requesting. They blindly trust the room number (ID resource) you send and swing the door wide open for you. [S4]

```python
# Flask route verifying resource ownership based on authenticated session user ID
from flask import abort, jsonify
from flask_login import login_required, current_user
from models import Document

@app.route('/api/document/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    # Retrieve the document from the database
    document = Document.query.get_or_404(doc_id)

    # Secure: Verify if the authenticated user owns this specific document
    if document.owner_id != current_user.id:
        # Deny access if user is not the owner
        abort(403, description="Access denied: You do not own this resource.")

    # Return the document data if authorized
    return jsonify(document.to_json())
```

## 4. Description and Root Cause

Hard-to-guess identifiers can reduce the risk of enumeration in some threat models, but they do not grant permissions and do not replace server-side authorization checks. If an actor obtains an identifier through logs, referrers, sharing, or another legitimate flow, all resources must still be policy-checked on each request. [S3], [S4]

Broken Access Control occurs when the policy for subject–resource–action is not properly enforced at the authoritative trust boundary. The consequences can include unauthorized reading or modification of resources, but it must be demonstrated according to the correct handler and side effect; hidden interfaces, sequential ID, or a single status code are not sufficient. Checks must be performed on the server side for each request and, by default, deny when there is no rule allowing it. [S4]


## 5. Threat Model and Exploitation Conditions

- **Assets:** Synthetic records of each owner and admin-only functions.

- **Actor:** user 1234 has been verified; user 5678 and admin are control actors.

- **Trust boundary:** Flask 3.x decorator/middleware and querying the Account on the server.

- **Necessary condition:** client replaces object ID or route; policy ownership/role is missing on the actual handler.

- **Environment:** API 127.0.0.1:8000, two separate owners, raw HTTP or proxy; no browser needed.

Must prove the response contains actor data or that the admin function has run; just seeing 200/403 or ID sequentially is not enough to conclude. [S1]

## 6. Attack Mechanism

The handler takes the subject from the session but queries the object or calls the function only according to ID/route provided by the client. When there is no ownership/role policy applied before the query, response or mutation exceeding privileges occurs. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** seed user 1234, user 5678, and admin in Flask 3.x; enable application and policy log.  
2. **Baseline:** each user correctly reads their own profile; admin reads the admin route.  
3. **Action:** keep user 1234 token, sequentially change ID to 5678 and call the admin route.  
4. **Expected result:** bug returns unauthorized synthetic data; fix returns 403 and does not query/serialize forbidden resources.  
5. **Boundary:** check ID does not exist, empty role, expired token, and route alias.  
6. **Cleanup:** delete fixture/token and correlate ID between proxy, application, and datastore.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker noticed that a company's sensitive press releases were posted using a predictable naming convention and checked a potential URL before the official release date. Upon noticing that the server did not enforce authorization, the attacker wrote a script to collect the documents before release in order to gain an unfair advantage on the stock market. [S4]

### Example HTTP request illustrating Access Control violation:<!-- payload-id: WEB-A01-BROKEN-ACCESS-CONTROL-001 -->
<!-- context: HTTP/1.1; Flask 3.x fixture at 127.0.0.1:8000; authenticated synthetic user 1234; server authorization model [S4] -->
<!-- prerequisites: seed users 1234 and 5678 plus an admin-only route; use the token for user 1234; capture policy logs -->
<!-- encoding: ASCII request-target, Host and Authorization headers; raw harness emits CRLF; requests have no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns synthetic user 5678 or admin data; fixed fixture returns 403 while user 1234 can still read own data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Normal user accessing their own profile
GET /api/users/1234/profile HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>

# Horizontal escalation: change ID to access another user
GET /api/users/5678/profile HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>
# If server returns 200 with user 5678's data → IDOR vulnerability

# Vertical escalation: access admin endpoint
GET /api/admin/users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>
# If server returns admin data → BFLA vulnerability
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE (Flask 3.x) ===
from flask import abort, request, jsonify
from flask_login import login_required, current_user
from models import Account

@app.route('/api/account/<int:account_id>', methods=['GET'])
@login_required
def get_account_details_vulnerable(account_id):
    # BAD: Authentication exists, but ownership is never checked
    account = Account.query.get_or_404(account_id)
    return jsonify(account.to_json())


# === SECURE CODE (same framework and use case) ===
from flask import abort, request, jsonify
from flask_login import login_required, current_user
from models import Account

@app.route('/api/account/<int:account_id>', methods=['GET'])
@login_required
def get_account_details_secure(account_id):
    # Retrieve resource
    account = Account.query.get_or_404(account_id)

    # Safety check: Ensure user and owner IDs are valid and not None
    if not current_user or current_user.id is None or account.user_id is None:
        abort(403)

    # Enforce authorization: Check if current logged-in user owns the account
    if account.user_id != current_user.id and not current_user.is_admin:
        # Log access denial
        app.logger.warning(f"User {current_user.id} unauthorized access attempt to Account {account_id}")
        abort(403) # Forbidden

    return jsonify(account.to_json())
```

## 10. Detection

- Compare the same resource under owner, non-owner, and admin; verify both response and mutation. [S4]

- Review the place where the handler gets the subject and the place that queries the object to find the path bypassing the policy. [S4]

- Log actor, resource, action, policy result and correlation ID.

## 11. Defense

### Compulsory control

- Implement server-side authorization for each subject–resource–action before reading or modifying data. [S4]

- Default deny and reuse policy on all equivalent access paths. [S4]

### Defense-in-depth

- ID is hard to predict, only reduces enumeration; does not grant privileges.

- Speed limit and alert support for bulk access detection.

## 12. Retest

- **Positive:** owner and role are allowed and can still complete the operation.

- **Negative:** non-owner or low role is denied, data remains unchanged.

- **Boundary:** check non-existent objects, bulk, nested, and alias routes.

- **Telemetry:** compare policy decision with datastore mutation.

## 13. Common Mistakes

- Only check logged-in users.

- Tin ownership or role sent by the client.

- Use UUID, UI hiding or WAF instead of authorization.

- Edit an endpoint but miss a batch or nested resource.

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

- **Authentication:** establish or verify the identity of the actor; do not self-grant permissions on the resource. [S4]

- **Authorization:** decides which actions an actor can perform on which resources. [S4]

- **Default deny:** deny when there is no clear policy allowing the request. [S4]

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** RFC 9562 — Universally Unique IDentifiers (UUIDs). https://www.rfc-editor.org/rfc/rfc9562.html — version/date: May 2024; accessed: 2026-07-17.
- **[S4]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.