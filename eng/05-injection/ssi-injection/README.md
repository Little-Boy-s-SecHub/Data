---
schema_version: 1
id: WEB-A05-SSI-INJECTION
title: "Server-Side Include (SSI) Injection"
slug: ssi-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-97
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Include (SSI) Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Server-Side Include (SSI) Injection by root cause instead of only describing the consequences.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose the root control, implement a fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Server-Side Include (SSI) Injection scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local lab isolated, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

In the early days of the internet, when powerful languages like PHP or ASP were not yet widespread, web servers used a simple technology called Server-Side Includes (SSI). Imagine SSI as special instruction stickers in the form of comments HTML (for example: `<!--#echo var="DATE_LOCAL" -->` to display the date and time) embedded in the files of a website (usually with the extension `.shtml`). Before sending a webpage to the user's browser, the server scans the entire webpage, looks for these directive stickers to process them, and then inserts the results there. Because SSI has many different directives, the lesson only uses a composite marker in the lab to demonstrate that user input has been parsed as SSI.

```html
<!-- Normal SSI directives in a .shtml file -->

<!-- Display current date -->
<!--#echo var="DATE_LOCAL" -->

<!-- Include content from another file -->
<!--#include file="header.html" -->

<!-- Include output of a CGI script -->
<!--#include virtual="/cgi-bin/counter.cgi" -->

<!-- Display file size -->
<!--#fsize file="document.pdf" -->

<!-- Echo a lab-only marker variable -->
<!--#echo var="SECHUB_LAB_MARKER" -->
```
When the web server receives a request for the file `.shtml`, it parses the entire content, looks for `<!--#...-->` directives, processes them, and replaces them with the results before returning to the client. The client only receives plain HTML — it does not see the SSI directive.

For example, a website uses SSI to display a dynamic footer:

```html
<!-- page.shtml — using SSI for dynamic footer -->
<html>
<body>
  <h1>Welcome</h1>
  <p>Main content here...</p>
  <footer>
    <!-- SSI directive to include shared footer -->
    <!--#include file="footer.html" -->
    <!-- Display last modified time -->
    <p>Last updated: <!--#echo var="LAST_MODIFIED" --></p>
  </footer>
</body>
</html>
```

## 4. Description and Root Cause

The SSI Injection vulnerability occurs when a web application receives information from users (such as registration names or comments) and directly embeds them into files processed by the SSI tool without passing through a safety filter. Testers in the lab can input a synthetic marker that looks like a directive, such as `<!--#echo var="SECHUB_LAB_MARKER" -->` or `<!--#include virtual="/lab/marker.txt" -->`, to confirm that user content is processed by the SSI parser rather than being rendered as text. The root cause is that user input goes into a region processed by SSI; the actual level of impact depends on the directive configuration, the privileges of the web process, and the data that can be accessed in that environment.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** SSI documents rendered and web process privileges. 
- **Actor, authentication and role:** user role saves rendered content as .shtml.
- **Exploitation conditions:** user content is parsed as SSI directive instead of text.
- **Browser, proxy, framework and version:** Apache HTTP Server 2.4 mod_include in non-root container; pin SSI exec state; must save actual image/package version along with evidence.
- **Mandatory evidence:** together with ID correlation, must link input, control decisions, and impact the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For ssi injection, the user content is parsed as the SSI directive instead of text. The positive case must demonstrate that the input reaches the correct sink and produces the described effect; the negative case, when origin control is enabled, must be blocked before any side effect occurs. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Apache HTTP Server 2.4 mod_include in a non-root container; pin the SSI exec state; only load aggregate data, enable application/proxy/datastore logging, and attach ID correlation. 2. **Baseline:** send a valid input of the SSI injection use case; save raw request/response, decide policy and asset state before testing. 3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap. 4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism that “user content is parsed as SSI directive instead of text”; secure fixture must block before side effects and boundary input must fail closed. 5. **Cleanup:** delete SSI injection data, markers, and logs; revoke related session/cache, revert the snapshot, and confirm there are no remaining test callbacks/processes. 6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing actions must have network/CPU/memory/request caps.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Marker qua echo directive**:

<!-- payload-id: WEB-A05-SSI-INJECTION-001 -->
<!-- context: Apache 2.4 mod_include parses a user-controlled SSI echo directive in .shtml -->
<!-- prerequisites: disposable lab container; environment exposes only the public SECHUB_LAB_MARKER value; one render; no network -->
<!-- encoding: UTF-8 SSI directive in HTML comment syntax; variable name is ASCII -->
<!-- expected-result: vulnerable render returns the public marker value; user-content route with SSI disabled returns the directive literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- The fixture evaluates only a public lab marker variable. -->
<!--#echo var="SECHUB_LAB_MARKER" -->
```
**Include aggregate marker in disposable fixture**:

<!-- payload-id: WEB-A05-SSI-INJECTION-002 -->
<!-- context: Apache httpd 2.4 SSI fixture serves /lab/marker.txt as a synthetic lab file -->
<!-- prerequisites: local synthetic file only; filesystem outside the lab fixture is unavailable; one render -->
<!-- encoding: UTF-8 SSI directive; virtual path is an ASCII absolute URL path, not a host filesystem path -->
<!-- expected-result: response includes the synthetic LAB_MARKER value from /lab/marker.txt -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Include only the synthetic file provided by the lab. -->
<!--#include virtual="/lab/marker.txt" -->
```
**Confirm including only touches the lab marker**:

<!-- payload-id: WEB-A05-SSI-INJECTION-003 -->
<!-- context: Apache httpd 2.4 SSI fixture with /fixtures/lab-marker.txt -->
<!-- prerequisites: local synthetic file only; filesystem outside the fixture is unavailable -->
<!-- encoding: UTF-8 SSI directive; virtual path is an ASCII absolute URL path, not a host filesystem path -->
<!-- expected-result: response includes the synthetic LAB_MARKER value -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Include only the synthetic file provided by the lab. -->
<!--#include virtual="/fixtures/lab-marker.txt" -->
```
**Display sanitized lab environment variables**:

<!-- payload-id: WEB-A05-SSI-INJECTION-004 -->
<!-- context: Apache 2.4 SSI echo directive in a sanitized environment fixture -->
<!-- prerequisites: environment contains only LAB_ENV_MARKER and generic fixture values; no secrets; one render -->
<!-- encoding: UTF-8 SSI comment directives with ASCII variable names -->
<!-- expected-result: vulnerable output exposes only LAB_ENV_MARKER; secure user-content route does not evaluate directives -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Echo only a sanitized fixture variable. -->
<!--#echo var="LAB_ENV_MARKER" -->
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name')
    message = request.form.get('message')

    # DANGER: User input written directly to .shtml file
    with open('/var/www/html/guestbook.shtml', 'a') as f:
        f.write(f"<p><b>{name}</b>: {message}</p>\n")

    return "Message posted!"


# === SECURE CODE ===
import html
from flask import Flask, request

app = Flask(__name__)

def sanitize_ssi(text):
    """Remove SSI directives and HTML-encode the input"""
    # HTML-encode to neutralize < > characters
    safe_text = html.escape(text, quote=True)
    return safe_text

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name', '')
    message = request.form.get('message', '')

    # Validate input length
    if len(name) > 50 or len(message) > 500:
        return "Input too long", 400

    # Sanitize all user input before writing
    safe_name = sanitize_ssi(name)
    safe_message = sanitize_ssi(message)

    # Write to regular .html file instead of .shtml
    # Even if SSI is enabled, .html files are not parsed by default
    with open('/var/www/html/guestbook.html', 'a') as f:
        f.write(f"<p><b>{safe_name}</b>: {safe_message}</p>\n")

    return "Message posted!"
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Server-Side Include (SSI) Injection, policy results, and correlation ID; do not log secrets or full tokens.  
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether a request reached the sink and whether there was any impact.  
- Scanner or WAF alert is only a signal for investigation; it is not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Do not SSI-process user content; disable exec and separate content from paths with Includes enabled.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Server-Side Include (SSI) Injection, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used to replace the original controls.

- **Summary**: Disable the SSI feature if not in use, or disable command execution permission and user data encryption. 
- **Detailed steps**:
  - Disable SSI: If not used, completely turn off `mod_include` in Apache or `ssi off` in Nginx.
  - Disable `exec` directive: In Apache, use `Options +IncludesNOEXEC` to allow SSI but forbid exec.
  - HTML-encode user input: Encode characters `<`, `>`, `!`, `#`, `-` before rendering in `.shtml`.
  - Do not store user input in .shtml files: Separate static SSI templates and dynamic user data.
  - Switch to modern technology: Use template engines (Jinja2, EJS, Blade) instead of SSI.

## 12. Retest

- **Positive case:** with Server-Side Include (SSI) Injection, the valid flow still works correctly for the actor and permitted data. 
- **Negative case:** the same input/resource but the actor or context is not allowed should be denied without leaking sensitive details. 
- **Boundary case:** test empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID. 
- **Recheck:** keep a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Server-Side Include (SSI) Injection without verifying side effects and logs. 
- Use a payload with correct syntax but incorrect DBMS, browser, framework, protocol, or injection context.
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.
- Only fix one route while the same sink/policy is used in other routes.
- Conclude that a vulnerability exists without saving the source, fixture version, and observable proof.

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

- **SSI (Server-Side Includes)**: Technology for embedding server-side dynamic processing directives in HTML files.  
- **SSI Injection**: Injecting SSI directives into user-controlled areas causing the server to process content unexpectedly.  
- **Directive**: A directive located within a special HTML comment structure that SSI scans and executes.  
- **CGI Script**: CGI programming interface that helps create dynamic web content from the server.

## 16. Related Lessons and Further Reading

- [SSTI](../ssti/) — Exploiting the template execution mechanism from the server side.

## 17. References

- **[S1]** Apache HTTP Server 2.4 — Introduction to Server Side Includes. https://httpd.apache.org/docs/2.4/howto/ssi.html — version/date: 2.4; accessed: 2026-07-17.
- **[S2]** OWASP WSTG — Testing for SSI Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection — version/status: latest; accessed: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/97.html — version/status: current; accessed: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current; accessed: 2026-07-17.