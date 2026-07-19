---
schema_version: 1
id: WEB-A01-PRIVILEGE-ESCALATION
title: "Privilege Escalation"
slug: privilege-escalation
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A06:2025
cwe:
  - CWE-269
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Privilege Escalation

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Privilege Escalation by the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Roles, permissions, and differences between horizontal/vertical escalation.

- Server-side policy for objects and functions.

- How profile update handles the privilege field.

## 3. Background Knowledge

Imagine you walk into a large hospital. If you are an ordinary patient, you can move around the waiting area, examination rooms, or the cafeteria. You cannot casually enter another patient's room to look at their medical records — if you intentionally do so, that is **horizontal privilege escalation**, which means encroaching on the authority of someone else who has the same position as you. On the other hand, the operating room or central medical records storage room is reserved only for head doctors. If you try to sneak in there, take a white coat, perform surgeries, or modify medical records on your own, that is **vertical privilege escalation**, which means seizing privileges higher than your own authority. [S3]

In the app development world, to delineate this power boundary, developers use a model called **RBAC** (Role-Based Access Control - RBAC). This model divides users into clear role groups (such as Admin, Manager, User) and assigns specific permissions to each role. However, trouble arises if the software only worries about "hiding" the 'Admin Dashboard' button on the user's phone screen or browser, while on the server side (backend), it does not check who is actually sending the request. A malicious actor can easily bypass the display interface, send requests directly to the server, and grant themselves top-level privileges. [S3]

```python
# Decorator verifying user role at the backend to enforce RBAC rules
from functools import wraps
from flask import abort, session

def require_role(allowed_roles):
    """
    Decorator to enforce Role-Based Access Control (RBAC) on route handlers.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Retrieve the user's role stored securely in the server-side session
            user_role = session.get('user_role')

            # Enforce authorization: check if the user role is authorized
            if not user_role or user_role not in allowed_roles:
                # Reject unauthorized access with HTTP 403 Forbidden
                abort(403, description="Access Forbidden: Insufficient privileges.")

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/settings', methods=['POST'])
@require_role(['admin']) # Only allow users with 'admin' role
def save_admin_settings():
    # Process settings changes securely
    return "Settings updated."
```

## 4. Description and Root Cause

**Privilege Escalation** vulnerability occurs when the system has gaps in the management and verification of permissions, allowing regular users to perform actions beyond the scope of their allowed privileges. [S3]

This vulnerability is extremely dangerous because it allows an attacker to break all of the application's security rules. By bypassing the loose checkpoints on the server side, the malicious actor can read all the data of other users (horizontal attack) or make themselves a Super Administrator (vertical attack). From there, they have full control over the system, can change configurations, delete data, or even turn the entire application into a tool serving their malicious purposes. Any sensitive actions on the system must be thoroughly checked and authenticated by the server before being executed; the user interface (UI) or client-side parameters should never be fully trusted. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** role, administrative function, and synthetic records with high privileges.

- **Actor:** user has authenticated with the user role; admin is the positive control.

- **Trust boundary:** Flask 3.x authorization decorator and field update in ORM.

- **Necessary condition:** sensitive route lacks role check or client has modified the role/is_admin field.

- **Environment:** API loopback, database snapshot, token synthetic; do not try real credentials or target.

Must observe the actual role or function changes on the server; the client/UI claiming to be admin does not prove privilege escalation. [S1]

## 6. Attack Mechanism

Users often access the privileged handler or mass-updates field role due to missing policy/field allowlist. The server then saves high privileges or executes business actions with incorrect authority. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** seed regular and admin users in Flask 3.x, snapshot DB and enable audit log.
2. **Baseline:** user is blocked on admin route; admin accesses successfully.
3. **Action:** with user token, call admin route and send an update containing the role field on the synthetic account.
4. **Expected result:** bug allows changing permissions/executing function; fix returns 403 or removes protected field and logs deny.
5. **Boundary:** check route alias, different method, null role, and old session after role change.
6. **Cleanup:** restore snapshot, revoke token and verify user role is restored.

## 8. Payloads and Scope of Applicability

The payload below only applies to the input fixture and the described context; it does not prove that every Flask application has a vulnerability. Only send this input to the local fixture with a synthetic account and database. [S3]

<!-- payload-id: WEB-A01-PRIVILEGE-ESCALATION-001 -->
<!-- context: Flask 3.x JSON profile update; synthetic user in a disposable local database; privileged-field authorization model [S3] -->
<!-- prerequisites: authenticated fixture user; vulnerable endpoint mass-assigns the client-controlled role field -->
<!-- encoding: UTF-8 JSON; Content-Type application/json -->
<!-- expected-result: vulnerable fixture persists role admin; secure fixture rejects or ignores role and records the authorization decision -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-17 -->
```json
{"display_name":"Lab User","role":"admin"}
```
The result is only considered positive when the server actually stores a higher role or allows administrative actions after the request. The client displaying the string `admin` by itself is not evidence of privilege escalation. [S3]

## 9. Vulnerable Code and Secure Code

```python
from functools import wraps
from flask import abort, g

# === VULNERABLE CODE (Flask 3.x) ===
@app.get('/admin')
def admin_dashboard_vulnerable():
    # BAD: The route trusts that the UI hid this endpoint from regular users
    return "Welcome to the admin panel!"


# === SECURE CODE (same framework and use case) ===
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'user', None)
            if not user or user.role != role:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.get('/admin')
@require_role('admin')
def admin_dashboard():
    return "Welcome to the admin panel!"
```

## 10. Detection

- Compare regular and admin roles on the same operation; confirm the role is stored in the datastore after the request. [S3]

- Review field binding, policy before mutation, and all paths of role/permission changes. [S3]

- Log actor, old/new role, policy result, and approver if any.

## 11. Defense

### Compulsory control

- Only allow actors with separate permissions to change roles/permissions; check on the server side before mutation. [S3]

- Allowlist the profile fields that users can edit themselves; separate the admin endpoint from self-service. [S3]

### Defense-in-depth

- Requires re-authentication or approval for high-privilege operations.

- Alert when the role changes unusually or permissions increase rapidly.

## 12. Retest

- **Positive:** admin is allowed to change roles according to the policy.

- **Negative:** users usually cannot elevate privileges through the body or a different route.

- **Boundary:** role does not exist, downgrade, concurrent update, and bulk import.

- **Telemetry:** confirm that the audit log contains old/new role and policy decision.

## 13. Common Mistakes

- Information of field `role` or `isAdmin` sent by the client.

- Only hide the admin menu.

- Check the role after the mutation has been committed.

- Protect the main endpoint but overlook import or batch update.

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

- **Horizontal escalation:** actor bypasses policy to access objects/operations of actors with the same level of privilege. [S3]

- **Vertical escalation:** actor achieves a function or permission intended for a higher role. [S3]

- **RBAC:** model for assigning permissions to roles and then assigning actors to roles according to policy. [S3]

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.