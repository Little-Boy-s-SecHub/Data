---
schema_version: 1
id: WEB-A05-XSS-STORED
title: "Cross-Site Scripting (Stored)"
slug: xss-stored
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site Scripting (Stored)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Site Scripting (Stored) by root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish between expected results and false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of a Cross-Site Scripting (Stored) scenario and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the examples.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

In web application design, data is often stored in two ways: temporarily (only existing during a request or a short-term session) and permanently (written deeply into a database or server files for long-term reuse). Permanent data, such as comments under written lessons or your personal information, will always be there, ready to be displayed to anyone who accesses the website later. This is exactly fertile ground for storage attacks if not managed securely.

```python
import nh3

# Mock database representing persistent storage
class CommentDatabase:
    def __init__(self):
        self.storage = []

    def save_comment(self, user_id, raw_content):
        # Store the raw text content in persistent storage.
        # It is a best practice to store data in raw form and handle safety during rendering.
        self.storage.append({"user_id": user_id, "content": raw_content})

    def get_comments(self):
        return self.storage

# Initialize secure database instance
db = CommentDatabase()
db.save_comment(101, "This is a normal comment.")
db.save_comment(102, "Hello world, <b>great post</b>!")

# Render comments securely using nh3 to sanitize HTML at output time
def render_comments_to_html():
    comments = db.get_comments()
    rendered_list = []
    for comment in comments:
        # nh3.clean blocks scripts and allows only secure, white-listed formatting tags
        safe_content = nh3.clean(comment["content"], tags={'b', 'i', 'strong', 'em', 'p'})
        rendered_list.append(f"<div class='comment'>User {comment['user_id']}: {safe_content}</div>")
    return "\n".join(rendered_list)
```

## 4. Description and Root Cause

The Stored XSS vulnerability (XSS stored or XSS permanent) occurs when a web application allows users to enter data containing malicious code, then naively stores this raw data directly into the database without any sanitization. The real danger lies in the fact that: since this malicious code has been permanently stored, every time any user accesses that website, the server will automatically fetch the malicious data from the database and display it on their browser, triggering the code to run immediately. This is the most dangerous type of XSS because the attacker does not need to send a tempting link to each individual; the malicious code will automatically spread and attack multiple website visitors completely silently.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** database content and DOM of the subsequent viewer. 
- **Actor, authentication and role:** user role creates content; other user/moderator views it. 
- **Exploitation conditions:** stored input is rendered into browser sink and can be executed. 
- **Browser, proxy, framework and version:** Chromium, Express/Flask, and PostgreSQL 16 pinned with synthetic data; must store actual image/package version along with evidence. 
- **Mandatory evidence:** same ID correlation must concatenate input, determine control, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For stored, the saved input rendered into the browser sink can be executed. The positive case must demonstrate that the input reaches the correct sink and produces the described effect; the negative case when origin control is enabled must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium, Express/Flask, and PostgreSQL 16 pinned with synthetic data; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID. 
2. **Baseline:** send a valid input of the stored use case; record raw request/response, determine policy and asset state before testing.
3. **Input and actions:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and adhere to the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate that the 'stored input was rendered into a browser-executable sink'; the secure fixture must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete stored data, markers, and logs; revoke related session/cache, restore snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real target, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Advanced Stored XSS attack variants include:

*   **XSS via SVG Upload**: The attacker uploads a vector graphics file (SVG) containing malicious JavaScript code. SVG is actually a XML document, so the browser can execute the script inside it when the file is displayed directly.
    *   *Malicious SVG payload*:<!-- payload-id: WEB-A05-XSS-STORED-001 -->
<!-- context: Chromium 126 opens an uploaded SVG inline from the same-origin Flask/SQLite fixture -->
<!-- prerequisites: synthetic blog and browser profile; SVG route is deliberately inline; no session secret or network callback; one author and one viewer -->
<!-- encoding: SVG is UTF-8 XML uploaded as multipart/form-data; the harness generates the multipart boundary once -->
<!-- expected-result: vulnerable inline viewer sets documentElement.dataset.storedXss to svg; secure route serves attachment from an isolated origin or rejects active SVG -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <?xml version="1.0" standalone="no"?>
        <svg xmlns="http://www.w3.org/2000/svg" onload="document.documentElement.dataset.storedXss='svg'">
          <circle cx="50" cy="50" r="40" fill="blue" />
        </svg>
        ```
*   **Mutation XSS (mXSS)**: Occurs due to inconsistencies in how HTML is handled between the sanitizer library and the web browser. An attacker sends a seemingly harmless payload to the HTML sanitizer library, but when the browser parses it and writes it to DOM (via `innerHTML`), it automatically mutates the structure and triggers JavaScript execution.
    *   *Example mXSS payload*: <!-- payload-id: WEB-A05-XSS-STORED-002 -->
<!-- context: Chromium 126 reparses stored HTML through a deliberately flawed lab sanitizer and then innerHTML; this is not a claim about current DOMPurify/nh3 -->
<!-- prerequisites: synthetic comment only; broken image remains local; one author/viewer; no cookie access; exact sanitizer fixture is pinned with the evidence -->
<!-- encoding: UTF-8 form body; angle brackets/quotes are percent-encoded once by the client and decoded before the single innerHTML assignment -->
<!-- expected-result: vulnerable reparse sets documentElement.dataset.storedXss to mxss once; context-aware escaping or the pinned secure sanitizer prevents creation of the img element -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```html
        <noscript><p title="</noscript><img src=x onerror="document.documentElement.dataset.storedXss='mxss'">"></noscript>
        ```
The HTML filter sees the `noscript` tag as safe and ignores the `title` attribute wrapped in double quotes. But when assigned to `innerHTML`, the browser automatically closes the `noscript` tag early due to syntax transformation, causing the `<img>` tag to be exposed and executed.
*   **Polyglot Payloads**: A payload string that is cleverly designed to successfully execute JavaScript in multiple different HTML contexts (outside tags, inside single-quoted attributes, double-quoted attributes, or within script tags).
    *   *Typical Polyglot Payload*:<!-- payload-id: WEB-A05-XSS-STORED-003 -->
<!-- context: Flask/SQLite comment fixture stores an HTML polyglot fragment opened in Chromium 126 body context -->
<!-- prerequisites: synthetic origin without sensitive cookies; no outbound network; one author/viewer -->
<!-- encoding: UTF-8 SVG/HTML fragment is form-encoded once and parsed in the recorded body context -->
<!-- expected-result: vulnerable SVG branch sets documentElement.dataset.storedXss to polyglot; secure renderer outputs text or removes active SVG content -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```html
        javascript:"/*'/*`/*--></noscript></title></style></textarea></script></xmp><svg/onload="document.documentElement.dataset.storedXss='polyglot'">
        ```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE (Python Flask) ===
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def add_comment():
    content = request.form.get('content')
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    # Stores the raw content including potential SVG payloads or polyglots
    cursor.execute("INSERT INTO comments (content) VALUES (?)", (content,))
    conn.commit()
    return "Comment added!"

@app.route('/view')
def view_comments():
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM comments")
    comments = cursor.fetchall()

    # DANGER: Directly rendering unsanitized HTML from database leads to Stored XSS
    html = "<ul>"
    for c in comments:
        html += f"<li>{c[0]}</li>"
    html += "</ul>"
    return html

# === SECURE CODE (Python Flask using nh3) ===
import nh3

@app.route('/secure-view')
def view_comments_secure():
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM comments")
    comments = cursor.fetchall()

    html = "<ul>"
    for c in comments:
        # SECURE: Sanitize rich text using nh3 before rendering, removing dangerous scripts/tags
        safe_content = nh3.clean(c[0], tags={'b', 'i', 'strong', 'em', 'p', 'br'})
        html += f"<li>{safe_content}</li>"
    html += "</ul>"
    return html
```

```javascript
// === SECURE CLIENT-SIDE RENDERING (JavaScript) ===
// Safe DOM manipulation using textContent to prevent mXSS
function displayCommentSecure(rawCommentText) {
    const commentElement = document.createElement('div');
    commentElement.className = 'comment-box';

    // SECURE: textContent automatically treats input as plaintext, preventing XSS and mXSS
    commentElement.textContent = rawCommentText;

    document.getElementById('comments-container').appendChild(commentElement);
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Cross-Site Scripting (Stored), policy results, and correlation ID; do not log secrets or the entire token.  
- Compare authorization/validation failures against a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not there was an impact.  
- Scanner or WAF alert is just an investigation signal; it is not the sole proof that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Encode at the output; if HTML is needed, sanitize the allowlist right before rendering.
- Apply the same control to all routes, operations, and equivalent handling paths; failure must stop before any side effect.

### Defense-in-depth

With Cross-Site Scripting (Stored), the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used to replace the original control.

- **Summary**: Use specialized filtering libraries HTML (such as DOMPurify on the client, nh3 on the server), encode output according to context, configure CSP, and set HttpOnly cookies.
- **Detailed steps**:
  - Never trust data from the database; perform HTML output encoding before rendering.
  - Use secure library `nh3` (Python) or `DOMPurify` (JavaScript) to sanitize HTML for fields that allow rich text input.
  - For uploaded files (such as SVG): configure the server to return the `Content-Disposition: attachment` header or serve these files from a separate domain (sandboxed domain) to prevent stealing cookies from the main domain.
  - Implement a strong Content Security Policy (CSP) to prevent inline script execution.

## 12. Retest

- **Positive case:** with Cross-Site Scripting (Stored), the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource but the actor or context is not allowed, it should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** keep a minimal scenario that reproduces the old issue and demonstrate that the fix is not dependent on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Cross-Site Scripting (Stored) without confirming side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another root control.  
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

- **Stored XSS**: The XSS stored vulnerability, malware stays permanently in the database and activates when users view the page containing that data.
- **Persistent Storage**: A mechanism for storing data long-term that does not disappear when the application is turned off.
- **Sanitize**: Cleaning input data by filtering out harmful components.
- **Session Hijacking**: The act of stealing session tokens to hijack a legitimate user's session.
- **Malware**: Malicious software used to harm the system or users.

## 16. Related Lessons and Further Reading

- [Session Hijacking](../../../07-authentication-failures/session-hijacking/) — Stealing a user's session is one of the most common objectives for attackers when successfully exploiting the Stored XSS vulnerability.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/cross-site-scripting/stored — version/status: current version; accessed: 2026-07-17.  
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/79.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.