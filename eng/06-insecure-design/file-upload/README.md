---
schema_version: 1
id: WEB-A06-FILE-UPLOAD
title: "File Upload Vulnerabilities"
slug: file-upload
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
  - A06:2025
cwe:
  - CWE-434
  - CWE-22
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# File Upload Vulnerabilities

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain File Upload Vulnerabilities by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the flaw to be exploitable. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in the File Upload Vulnerabilities scenario and how to apply input handling across trust boundaries. 
- Distinguish authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing rights.

## 3. Background Knowledge

Imagine the file upload system of a website as a mail reception counter in an office building. Customers can send packages (files) to the building staff. If the security guard only glances at the label on the outside of the box (like the file extension `.jpg`, `.png`, or attribute `Content-Type` declared by the sender) to decide what is inside, they can easily be deceived. A malicious person could label a box as "family photos" while it actually contains a bomb (malware).

Magic bytes are byte signatures at the beginning of a file that help eliminate some cases of extension forgery. This is just a signal: applications still have to use the appropriate parser, limit size/complexity, and handle files according to the correct use case instead of considering magic bytes as full proof of safety. [S6]

In addition, where the box is stored is also extremely important. If the guard stores the box right in the management office (web root folder - **Web Root**) and allows the sender to activate the box remotely via an URL link, the building will be in great danger. If a malicious source file (like PHP Web Shell) is uploaded and called, the web server will obediently execute those destructive commands. Therefore, uploaded parcels must always be stored in an isolated warehouse outside the building (outside the web root folder or on separate cloud storage services) and completely stripped of the 'run' (execute) permission.

#### Illustration of normal operation (Normal Operation)```python
# Secure file upload validation and storage outside the web root
import os
import uuid
import magic  # Used for checking magic bytes/MIME type accurately

# Define upload directory located outside the web root folder
UPLOAD_DIR = "/var/secure_storage/uploads/"
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "application/pdf"}

def process_uploaded_file(file_stream, client_filename):
    # Read the first 2048 bytes to analyze the magic bytes of the file
    header_data = file_stream.read(2048)
    file_stream.seek(0)  # Reset file pointer after reading header

    # Detect the actual MIME type based on the file content (magic bytes)
    detected_mime = magic.from_buffer(header_data, mime=True)

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError("Security violation: Unsupported file format detected via magic bytes")

    # Map the detected type to a server-controlled extension.
    extension_by_mime = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "application/pdf": ".pdf",
    }

    # A random name avoids trusting the client filename; storage and execution
    # policy remain the controls that prevent traversal and code execution.
    secure_filename = f"{uuid.uuid4().hex}{extension_by_mime[detected_mime]}"

    # Save the file in the non-executable directory outside web root
    save_path = os.path.join(UPLOAD_DIR, secure_filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    with open(save_path, 'wb') as dest_file:
        dest_file.write(file_stream.read())

    return secure_filename
```

## 4. Description and Root Cause

File Upload Vulnerabilities occur when a system allows users to upload files but lacks strict control, similar to receiving parcels without any security check.

This allows attackers to upload malicious files (web shells) to remotely control the server, or send malicious compressed files to overwrite important system files. They can even exploit the application to carry out indirect attacks such as SSRF (tricking the server into connecting to sensitive internal services) or injecting JavaScript malware into image files (such as SVG) to attack other users when they view the images. The danger of this vulnerability is very high, often leading to the server being completely controlled (RCE) or serious data leakage.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** storage, archive/image processor, and origin serving uploads.  
- **Actor, authentication, and roles:** user role for upload/import; other users view aggregated assets.  
- **Exploitation conditions:** server trusts extension, MIME, archive path, remote URL or active-content origin.  
- **Browser, proxy, framework, and version:** Python 3.12, ZIP/ImageMagick fixture and pinned Chromium; object storage loopback; must save actual image/package version along with evidence.  
- **Mandatory evidence:** along with correlation ID must connect input, determine control, and impact the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For file uploads, the server trusts the extension, MIME, archive path, remote URL, or active-content origin. Positive cases must prove that the input reaches the correct sink and produces the described impact; negative cases, when origin control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12, ZIP/ImageMagick fixture, and pinned Chromium; object storage loopback; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID. 2. **Baseline:** send a valid input of the file upload use case; store raw request/response, determine the policy and asset state before the test. 3. **Input and operations:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with the request cap. 4. **Expected result:** treat the vulnerable fixture as positive only when logs demonstrate the mechanism “server trusts extension, MIME, archive path, remote URL or active-content origin”; secure fixture must block before side effect and boundary input must fail closed. 5. **Cleanup:** delete data, markers, and logs of the file upload; revoke related session/cache, revert snapshot, and confirm no callback/test process remains. 6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Basic Web Shell Attack:**
The attacker disables client-side checks and uploads the file PHP (`hack.php`) containing the command execution function. Since the server does not rename the file and stores it directly in the web directory, the attacker can invoke commands directly through URL.

**2. ImageTragick (CVE-2016-3714):**
An attacker exploits a vulnerability in popular image processing libraries (such as ImageMagick). The attacker uploads a file with the extension `.png` or `.jpg`, but it actually contains malicious source code in the MVG format (Magick Vector Graphics) intended to trigger system command execution (RCE) when the library processes/renders the image.
*Example payload MVG:*<!-- payload-id: WEB-A06-FILE-UPLOAD-001 -->
<!-- context: ImageMagick 6.9.3-9/7.0.1-0 vulnerable fixture; MVG delegate processing -->
<!-- prerequisites: disposable container; no outbound network; vulnerable delegate configuration reproduced locally -->
<!-- encoding: UTF-8 MVG; double quotes are balanced and the delegate argument is confined to the disposable fixture -->
<!-- expected-result: fixture creates only /tmp/imagemagick-lab-marker; no shell is downloaded or opened -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(http://127.0.0.1:9001/image.png";printf IMAGEMAGICK_LAB >/tmp/imagemagick-lab-marker")'
pop graphic-context
```
**3. Zip Slip (Path Traversal via extraction):**
When an application extracts an archive without checking the canonical destination path, an entry containing upward directory components can escape the extraction root. The lesson does not provide a specific archive for traversal; the fixture only uses a synthetic entry marker and verifies the fix rejects it before writing the file.

**4. Polyglot Files (GIF + PHP):** A file may pass a shallow signature check but still contain different content after the header. The lesson only uses harmless byte markers to demonstrate that checking a single magic-byte is not enough; the upload volume must be non-executable and the file must be decoded/re-encoded using the appropriate library.

**5. SSRF via Upload URL (Upload file via link):**  
When the application supports "Import from URL," an arbitrary URL can cause the server to access services that the user cannot call directly. In the lab, only use mock read-only `http://127.0.0.1:9002/fixtures/metadata` that returns synthetic data; do not call real cloud metadata or endpoints that change state.

**6. SVG XSS (Stored XSS via SVG):**
An SVG (Scalable Vector Graphics) image is actually an XML document. An attacker can insert an `<script>` tag containing malicious JavaScript code into the SVG file.
*Example SVG payload:*<!-- payload-id: WEB-A06-FILE-UPLOAD-002 -->
<!-- context: SVG served by the upload fixture and opened as a top-level document in pinned Chromium -->
<!-- prerequisites: synthetic origin only; no session cookie or sensitive data; outbound network disabled -->
<!-- encoding: UTF-8 XML/SVG with inline JavaScript -->
<!-- expected-result: direct top-level rendering on the vulnerable fixture shows one alert; attachment or isolated-origin delivery does not execute in the application origin -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```
Whether the script executes and shares the same origin as the application depends on the distribution method, `Content-Type`, `Content-Disposition`, `nosniff`, sandbox, and browser. Only conclude stored XSS when the browser harness proves SVG is rendered in an origin carrying the application session; downloading as an attachment or serving from an isolated origin changes the result.

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
import zipfile
import os
import requests

# 1. Vulnerable to Zip Slip (No validation on path traversal inside zip entries)
def extract_zip_unsafe(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # DANGER: Directly joining target path without checking directory escape (../)
            target_path = os.path.join(extract_dir, member.filename)
            zip_ref.extract(member, extract_dir)

# 2. Vulnerable to SSRF via Upload URL (No check for private IP ranges)
def upload_from_url_unsafe(url):
    # DANGER: Allows user to specify internal URLs like http://127.0.0.1 or metadata servers
    response = requests.get(url, timeout=5)
    file_content = response.content
    save_file(file_content)
```

```python
# === SECURE CODE ===
import zipfile
import os
import requests

# 1. Secure Zip Extraction (Zip Slip Prevention)
def extract_zip_secure(zip_path, extract_dir):
    # Get absolute canonical path of the target directory
    extract_dir = os.path.abspath(extract_dir)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # SECURE: Resolve target path and verify it stays inside target directory
            target_path = os.path.abspath(os.path.join(extract_dir, member.filename))

            # Check if resolved path starts with the extract directory path
            if not target_path.startswith(extract_dir + os.sep):
                raise ValueError("Security violation: Directory traversal attempt detected in ZIP!")

            zip_ref.extract(member, extract_dir)

# 2. Secure remote import: users select an application-owned source ID,
# not an arbitrary URL. The egress proxy independently enforces the same
# origin/IP allowlist after DNS resolution and on every connection.
TRUSTED_IMPORT_URLS = {
    "avatar-template": "http://127.0.0.1:9003/avatar.png",
}
MAX_IMPORT_BYTES = 2 * 1024 * 1024

def upload_from_trusted_source(source_id):
    url = TRUSTED_IMPORT_URLS.get(source_id)
    if url is None:
        raise ValueError("Unknown import source")

    with requests.get(
        url,
        timeout=(2, 5),
        allow_redirects=False,
        stream=True,
    ) as response:
        # Never revalidate only the first hop and then follow a redirect.
        if 300 <= response.status_code < 400:
            raise ValueError("Redirects are not allowed")
        response.raise_for_status()

        content = bytearray()
        for chunk in response.iter_content(64 * 1024):
            content.extend(chunk)
            if len(content) > MAX_IMPORT_BYTES:
                raise ValueError("Remote file is too large")
        save_file(bytes(content))
```
Only check IP once and then call back the hostname with `requests.get()` still leaves a gap DNS rebinding; automatic following of redirect can also switch to internal addresses. Safe pattern of type URL is arbitrary from input, disable redirect, and require egress proxy to verify the destination on the actual connection. [S5]

## 10. Detection

- Log actor/session, route or operation, object/resource related to File Upload Vulnerabilities, policy results, and correlation ID; do not log secrets or entire tokens.
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and if there was any impact.
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Verify the content allowlist, store outside the executable webroot, canonicalize extraction, and isolate the origin. 
- Apply the same controls to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With File Upload Vulnerabilities, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Secure file uploads by validating file extensions and MIME-types, renaming uploads randomly, and storing them outside the web root on non-executable folders.
- **Detailed Steps**:
  - Validate file types using strict lists of allowed extensions and verify file headers/magic bytes to confirm the true file format.
  - Remove the client-provided file name from the storage path; generate a server-side name and map the extension from the verified file type. UUID only supports avoiding collisions/guessable names, not replacing canonical-path checks or non-execution policies.
  - Store uploaded files in a separate directory or third-party storage (like AWS S3) entirely outside the web application root.
  - Disable execution permissions (PHP, ASP, CGI, script engines) on the directories hosting user uploads.
  - Enforce strict file size limits to prevent Denial of Service through disk space exhaustion.
  - **Zip Slip Defense**: When extracting, always normalize the extraction path (canonical path) and check whether it starts with the pre-configured destination directory.
  - **SVG XSS Defense**: Prohibit SVG if the use case does not require it; if needed, use a maintained XML processor to apply an allowlist of elements/attributes and serve from an isolated origin. Do not consider filtering just an element name or an event attribute as sufficient. [S6]
  - Serve untrusted files from an origin that does not carry application cookies; for files intended for download only, set verified `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Content-Type`. These headers support secure distribution but do not replace format checks, storage outside the web root, or non-execution policies.
  - **SSRF Defense**: Only allow loading from URL in the trusted domain whitelist, blocking all IP internal addresses (private/loopback ranges).

## 12. Retest

- **Positive case:** with File Upload Vulnerabilities, the valid flow still works correctly for authorized actors and allowed data.  
- **Negative case:** same input/resource but unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** check empty values, extreme boundaries, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Retest:** keep a minimal scenario to reproduce the old error and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of File Upload Vulnerabilities without verifying side effects and logs. 
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control. 
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

- **Magic Bytes**: Byte signatures usually appear at the beginning of a file, useful for preliminary format identification but not proof that the entire file is valid or safe for the parser to handle. 
- **MIME Type (Multipurpose Internet Mail Extensions)**: Character string defining the type of data in the file (e.g., `image/jpeg`), transmitted in the HTTP header so that the browser knows how to handle the file. 
- **Web Root Folder**: The directory on the server containing all source code and publicly accessible resources of the website, where users from the Internet can directly access using URL. 
- **Web Shell**: A malicious file (written in PHP, ASPX, etc.) uploaded to the web server, allowing the attacker to execute system commands and control the server remotely through a web interface. 
- **RCE (Remote Code Execution)**: A vulnerability that allows an attacker to execute arbitrary commands or code on the target server remotely. 
- **SSRF (Server-Side Request Forgery)**: A vulnerability that occurs when an attacker can force a web server to send network requests generated by that server to internal or external systems. 
- **Stored XSS (Stored Cross-Site Scripting)**: A vulnerability that occurs when malicious JavaScript is stored directly in the server’s database and then automatically executed in the browser of any user who visits the website containing that malicious script.

## 16. Related Lessons and Further Reading

- [LFI/RFI](../../05-injection/lfi-rfi/) — Allows an attacker to execute malicious code or read local files after successfully uploading files to the system.
- [Command Execution](../../05-injection/command-execution/) — Uses uploaded files (e.g., web shells) as a foothold to directly execute system commands on the server.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-434. https://cwe.mitre.org/data/definitions/434.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE-22. https://cwe.mitre.org/data/definitions/22.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** CWE-918. https://cwe.mitre.org/data/definitions/918.html — version/status: current version; accessed: 2026-07-18.
- **[S5]** OWASP Server-Side Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.
- **[S6]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.