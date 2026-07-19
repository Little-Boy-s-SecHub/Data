---
schema_version: 1
id: WEB-A06-INFORMATION-LEAKAGE
title: "Information Leakage"
slug: information-leakage
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-200
  - CWE-538
  - CWE-527
content_status: technical-review
payload_status: none
last_verified: null
---

# Information Leakage

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Information Leakage by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited. 
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow for the Information Leakage scenario and how to apply input handling across trust boundaries. 
- Differentiate between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local lab isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you are building a fortress to protect your treasure. You design thick walls, sturdy iron gates, and equip it with advanced weapons. However, your gatekeeper accidentally drops a detailed blueprint of the fortress right in front of the gate, or cheerfully answers anyone asking about the locations of secret passages, troop layouts, and the types of locks being used. This situation is similar to the **Information Leakage** vulnerability in software.

When the application encounters a technical issue, it will respond with a status code HTTP (HTTP status codes). If not configured carefully, the system may generate stack traces — a long list of internal source code lines detailing the error from start to finish.

This error often occurs when developers forget to turn off **debug mode** when deploying the application to the production environment. Debug mode is like opening the fortress's glass doors wide to clearly see all activities inside during construction. But once the fortress is operational, exposing technical parameters, sensitive environment variables, or source code diagrams will nullify previously made security efforts.

#### Illustration of normal operation (Normal Operation)```python
# Secure error handling demonstrating production mode with generic responses
import logging
from flask import Flask, jsonify

app = Flask(__name__)

# Configure internal logger for server-side debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In production, debug mode must be disabled
app.config['DEBUG'] = False

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Log the detailed stack trace internally for developers
    logger.exception("An unhandled exception occurred: %s", str(error))

    # Return a generic HTTP response status code (500) and safe message to client
    # This prevents stack trace leaking to external users
    response = jsonify({
        "error": "Internal Server Error",
        "message": "A generic error occurred. Please try again later."
    })
    return response, 500
```

## 4. Description and Root Cause

An Information Leakage vulnerability occurs when an application accidentally exposes technological secrets or sensitive system data to users who are not authorized to know.

These leaked pieces of information could be detailed error codes, software version information, database table structures, hidden configuration files (such as `.git`), or temporary backup files that developers accidentally left on the server (such as `.bak`, `.old`).

Although the act of information leakage itself does not immediately crash systems or allow for instant control takeover, it provides a large amount of valuable 'intelligence.' Attackers can use this information to paint a complete picture of your technology, thereby searching for known vulnerabilities of that version to carry out more precise and faster destructive attacks.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare against the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** aggregated secrets, config, version, and debug artifact. 
- **Actor, authentication, and role:** anonymous or user role accessing public/error/static route. 
- **Exploitation conditions:** debug header, stack trace, source map, or artifact exposing unnecessary internal data. 
- **Browser, proxy, framework, and version:** Nginx pinned before Flask/Express production fixture; HTTP loopback; must retain actual image/package version along with evidence. 
- **Mandatory evidence:** along with correlation ID must connect input, control decision, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For information leakage, debug headers, stack traces, source maps, or artifacts exposing unnecessary internal data. The positive case must demonstrate that the input reaches the correct sink and produces the described impact; the negative case, when native controls are enabled, must be blocked before any side effect. The conclusion applies only to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start Nginx pinned before the Flask/Express production fixture; HTTP loopback; only load synthetic data, enable application/proxy/datastore logs and attach correlation ID.
2. **Baseline:** send a valid input of the use case information leakage; save raw request/response, decide policy and asset status before the test.
3. **Input and operation:** use exactly one scenario/input variable described in section 8; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs prove a “debug header, stack trace, source map or artifact exposing unnecessary internal data”; the secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete information leakage data, markers and logs; revoke related sessions/cache, revert snapshots and ensure there are no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use the target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Exploiting Stack Trace through error messages:**
Attackers deliberately input invalid data (such as passing special characters into the parameter ID) to trigger a system error. Detailed error pages containing the framework's stack trace (such as Django, Express) will expose the system libraries in use, specific versions, database table structures, and physical file paths on the server.

**2. Exposure of the `.git` directory (Git Directory Exposure):**
If the web server is misconfigured and allows direct access to hidden files, an attacker can access the `https://victim.lab.test/.git/` path. By downloading the files in this directory (such as `.git/index`, `.git/refs/heads/master`, `.git/objects/`), the attacker can recover the entire historical source code commits and find API keys or configuration passwords that were previously committed.

**3. Backup File Disclosure:**
Developers who edit source code directly on the server often leave automatic backup files from the editor or manually renamed files (e.g., `index.php.bak`, `config.php.old`, `.app.py.swp`, `settings.py~`). Attackers use fuzzer tools to scan and download these files, revealing configuration secrets and source code logic.

**4. Leak through robots.txt/sitemap:**
The files `robots.txt` and `sitemap.xml` are used to guide search bots. However, developers often put sensitive paths into `Disallow` (for example: `Disallow: /admin-secret-login/`, `Disallow: /backups/`, `Disallow: /dev/`). Attackers read this file to precisely identify the sensitive directories to target.

**5. Source code leakage due to web server configuration errors:**
Incorrect configurations on Nginx or Apache can cause the server to not forward script file requests (such as `.php`, `.jsp`) to the processing interpreter (such as PHP-FPM, Tomcat) but return them directly as plain text. An attacker accesses the website and the browser will display the entire raw source code of the application.

## 9. Vulnerable Code and Secure Code

```nginx
# === VULNERABLE CONFIGURATION ===
# Vulnerable Nginx configuration leaking hidden directories and backup files
server {
    listen 80;
    server_name victim.lab.test;
    root /var/www/html;

    # DANGER: No restriction on hidden files or folders
    # Anyone can download http://victim.lab.test/.git/config
    # Anyone can access http://victim.lab.test/config.php.bak
    location / {
        try_files $uri $uri/ =404;
    }

    # DANGER: Misconfigured PHP handler that falls back to plaintext if PHP-FPM is down or misconfigured
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

```nginx
# === SECURE CONFIGURATION ===
# Secure Nginx configuration blocking sensitive files and hiding signatures
server {
    listen 80;
server_name secure-app.lab.test;
    root /var/www/html;

    # SECURE: Hide Nginx version signature from error pages and headers
    server_tokens off;

    location / {
        try_files $uri $uri/ =404;
    }

    # SECURE: Block access to all hidden files and directories (starting with a dot)
    location ~ /\.(?!well-known) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Block access to backup, swap, and temporary development files
    location ~* \.(bak|old|save|swp|orig|temp|tmp|~)$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Properly configured PHP handler with strict error trapping
    location ~ \.php$ {
        try_files $uri =404; # Prevent execution of non-existent PHP files (mitigates RCE)
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Information Leakage, policy results, and ID correlation; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to verify that the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Reduce response/artifact data and disable debug/source/config exposure in the production build.
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With Information Leakage, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or common validation cannot be used to replace original controls.

- **Summary**: Mitigate information disclosure by removing debugging interfaces, disabling stack trace output in production, and scrubbing headers and response metadata.
- **Detailed steps**:
  - Disable developer debug modes, diagnostic pages, and stack trace dumps in production environments.
  - Implement global error handling to display generic, non-informative error messages to public users.
  - Remove unnecessary server signatures and software version information from outgoing HTTP response headers.
  - Scrub metadata (e.g., GPS tags, author info) from file attachments, images, and documents before serving them.
  - Ensure system log configuration does not write sensitive information like credentials, passwords, session tokens, or PII.
  - **Block Access to Hidden Files**: Configure Nginx/Apache to completely block access to all hidden files and directories starting with a dot (e.g., `.git`, `.env`) and backup file extensions (`.bak`, `.old`, `.swp`, `~`).
  - **Clean Deployments**: Use a professional CI/CD process to deploy the application, ensuring that the `.git` directory or temporary backup files are not copied to the production environment.

## 12. Retest

- **Positive case:** with Information Leakage, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resources but an unauthorized actor or context, it is denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal scenario reproducing the old error and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Information Leakage without verifying side effects and logs.
- Use payloads with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another root control.
- Only fix one route while the same sink/policy is used on another route.
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

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

- **Information Leakage (Information Leakage)**: An error that occurs when the system discloses sensitive technical information (such as stack traces, system configuration, software versions) to unauthorized users, indirectly making it easier for hackers to attack.  
- **HTTP Response Status Codes**: Standard codes returned by the web server to report the result of an HTTP request (e.g., `200 OK`, `404 Not Found`, `500 Internal Server Error`).  
- **Stack Trace (Stack Trace)**: A detailed record of the path of function calls leading to an error, showing the file names and code line numbers in the program.  
- **Debug Mode (Debug Mode)**: Application running mode that provides detailed technical information for developers to find and fix errors. This mode must be turned off in production environments.  
- **Git Directory (`.git`)**: A hidden directory containing the entire source code management history, branches, commits, and may contain sensitive configuration information if not properly protected.  
- **Fuzzer**: A tool that automates the process of sending a large number of random or pre-prepared data requests to an application to detect hidden files, unprotected paths, or software errors.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE-538. https://cwe.mitre.org/data/definitions/538.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** CWE-527. https://cwe.mitre.org/data/definitions/527.html — version/status: current version; accessed: 2026-07-18.