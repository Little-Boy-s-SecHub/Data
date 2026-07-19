---
schema_version: 1
id: WEB-A05-SECOND-ORDER-SQLI
title: "Second-Order SQL Injection"
slug: second-order-sqli
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-89
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Second-Order SQL Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Second-Order SQL Injection using the root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of a Second-Order SQL Injection scenario and how to handle input across trust boundaries. 
- Distinguish authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the examples. 
- Have a local lab isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

In traditional first-order SQL Injection attacks, an attacker injects malicious code, and it triggers immediately within the same request sent. To counter this, modern applications have well-protected entry points using parameterized queries. However, attackers still have a more sneaky technique called second-order SQL Injection (Second-Order SQL Injection). With this technique, the attacker submits a seemingly harmless malicious string in the first step so that the application safely stores it in the database. Then, in a second step, when the application reads this data from the database to execute another query, the malicious code actually triggers. The key point here is that the place where the malicious code is entered and the place where the code executes are completely different.

```python
# Step 1: User registration — stores username safely with parameterized query
def register(username, password):
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hash_password(password))
    )
    # Username is stored AS-IS in the database — including special characters

# Step 2: Password change — retrieves username from session
def change_password(session_user, new_password):
    # The username is read from database, assumed "safe"
    cursor.execute(
        "UPDATE users SET password=%s WHERE username=%s",
        (hash_password(new_password), session_user)
    )
```
The above process is safe because **both steps use parameterized queries**. The problem arises when the second step uses string concatenation.

## 4. Description and Root Cause

The Second-Order SQLi vulnerability occurs because developers make a common mistake regarding trust boundaries: they assume that data, once safely stored inside their database, is inherently safe and can be freely used by concatenating it directly. Attackers exploit this by submitting a malicious username (for example: `admin' --`). The account registration proceeds smoothly, and the username is saved in the database. When the victim later performs a password change, the application retrieves this username and directly concatenates it into the SQL password update statement, inadvertently turning the statement into "change the admin user's password." This vulnerability is extremely dangerous because it is well-hidden, bypasses common automated scanning tools, and can quietly cause harm after being stored for several days.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** value of the saved profile and SQL report/job in the next step.
- **Actor, authentication, and role:** user role saves the profile; job or admin view reuses the data.
- **Exploitation conditions:** data is saved in step one but is concatenated into SQL in the second sink.
- **Browser, proxy, framework, and version:** PostgreSQL 16 with Python 3.12/Flask 3.x and two-step logs with correlation ID; must store actual image/package version along with evidence.
- **Mandatory evidence:** with correlation ID must concatenate input, control decision, and impact the correct asset; individual status code is insufficient. [S1]

## 6. Attack Mechanism

For second order SQLi, data is stored in the first step but is concatenated into SQL at the second sink. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when the original control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch PostgreSQL 16 with Python 3.12/Flask 3.x and log two steps with correlation ID; only load aggregated data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the second order SQLi use case; save raw request/response, determine the policy, and asset status before testing.
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider the vulnerable fixture positive when logs demonstrate the mechanism “data saved in step one but appended into SQL at the second sink”; the secure fixture must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete the data, markers, and logs of the second order SQLi; revoke related session/cache, revert snapshot, and confirm no remaining callback/test process.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Classic scenario: Changing the admin password**

<!-- payload-id: WEB-A05-SECOND-ORDER-SQLI-001 -->
<!-- context: PostgreSQL 16 two-step registration/password-change fixture uses a stored username later -->
<!-- prerequisites: synthetic account and transaction only; two requests with one correlation chain; rollback enabled -->
<!-- encoding: registration form UTF-8 percent-encodes quote once; stored value is passed unchanged to the second query -->
<!-- expected-result: vulnerable second statement selects/updates wrong fixture row; parameterized second use affects only caller -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Step 1: Attacker registers with malicious username
# Registration uses parameterized query — payload stored safely
register_username = "admin'--"
register_password = "anything"
# INSERT INTO users (username, password) VALUES ('admin''--', 'hashed')
# The username admin'-- is now stored in the database

# Step 2: Attacker changes their own password
# But the vulnerable code builds SQL via concatenation
def change_password_vulnerable(session_user, new_password):
    hashed = hash_password(new_password)
    # DANGER: Username from DB used in string concatenation
    query = f"UPDATE users SET password='{hashed}' WHERE username='{session_user}'"
    cursor.execute(query)

# When session_user = "admin'--", the query becomes:
# UPDATE users SET password='new_hash' WHERE username='admin'--'
# The -- comments out the rest — admin's password is changed!
```
**Data exfiltration script via profile page**:

<!-- payload-id: WEB-A05-SECOND-ORDER-SQLI-002 -->
<!-- context: PostgreSQL 16 report fixture concatenates a stored company value into a later SELECT -->
<!-- prerequisites: synthetic report rows containing only a public LAB_REPORT_MARKER; one store and one report action; transaction rollback -->
<!-- encoding: company string is UTF-8 form data with quote/spaces encoded once; SQL driver receives stored text unchanged -->
<!-- expected-result: vulnerable report includes only public LAB_REPORT_MARKER from another row; bound query returns caller company rows -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Stored fixture value: ' UNION SELECT 'LAB_REPORT_MARKER'--
company = get_user_company(user_id)
query = f"SELECT display_value FROM reports WHERE company='{company}'"
# The vulnerable report returns only the documented public marker.
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
def change_password_vulnerable(user_id, new_password):
    # Fetch username from database — developer assumes it's safe
    cursor.execute("SELECT username FROM users WHERE id=%s", (user_id,))
    username = cursor.fetchone()[0]

    hashed = hash_password(new_password)
    # DANGER: Username from DB concatenated into SQL
    query = f"UPDATE users SET password='{hashed}' WHERE username='{username}'"
    cursor.execute(query)


# === SECURE CODE ===
def change_password_secure(user_id, new_password):
    hashed = hash_password(new_password)
    # Use parameterized query — even for data retrieved from database
    # Update by user ID instead of username to avoid injection entirely
    cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed, user_id)
    )
    # No string concatenation, no injection possible
    # Using ID (integer) instead of username further reduces attack surface
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Second-Order SQL Injection, the policy result, and ID correlation; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact. 
- Scanner or WAF alert is only an investigation signal; it is not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Bind parameters at every execution, including data read back from storage.
- Apply the same control to all routes, operations, and equivalent processing paths; on failure, it must stop before side effects.

### Defense-in-depth

With Second-Order SQL Injection, the following measures help reduce the blast radius or increase detection capabilities. Rate limiting, unpredictable UUID, WAF, CSP, or general validation should not be used as a substitute for primary control.

- **Summary**: Use parameterized queries everywhere data is used, do not trust data retrieved from the database. 
- **Detailed steps**:
  - Parameterized queries EVERYWHERE: Not only at input points but everywhere data is used in SQL — including data fetched from the database.
  - Zero trust for stored data: Consider data from the database as untrusted input as well, apply the same level of sanitization.
  - Input validation at registration: Validate that usernames only contain valid characters (alphanumeric, underscore).
  - Cross-module code review: Trace data flow from input → storage → retrieval → usage to detect second-order vulnerabilities.
  - ORM framework: Use ORM (SQLAlchemy, Django ORM) to automatically parameterize all queries.

## 12. Retest

- **Positive case:** with Second-Order SQL Injection, valid flows still work correctly for the allowed actor and data.  
- **Negative case:** with the same input/resource, unauthorized actor or context should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, extreme edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** verify policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save a minimal script that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Second-Order SQL Injection without confirming side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for a different root control.  
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

- **Second-Order SQLi**: SQL Injection vulnerability occurs when malicious code is stored in the database first and then executed in a subsequent query.
- **Trust Boundary**: The boundary that distinguishes between sanitized data and unsanitized data.
- **Parameterized Query**: A technique of passing separate parameters that completely eliminates the possibility of unauthorized SQL statement injection.
- **String Concatenation**: The act of joining strings together, often causing injection errors.
- **First-Order SQLi**: Traditional SQL Injection vulnerability that executes immediately in the submitted request.

## 16. Related Lessons and Further Reading

- [SQL Injection](../sql-injection/) — Basic SQL Injection vulnerability using direct user input within the same request lifecycle.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/sql-injection#second-order-sql-injection — version/status: current version; accessed: 2026-07-17.  
- **[S2]** OWASP. https://owasp.org/www-community/attacks/SQL_Injection — version/status: current version; accessed: 2026-07-17.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/89.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.