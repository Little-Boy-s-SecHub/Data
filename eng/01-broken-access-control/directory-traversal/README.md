---
schema_version: 1
id: WEB-A01-DIRECTORY-TRAVERSAL
title: "Directory Traversal"
slug: directory-traversal
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-22
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Directory Traversal

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Directory Traversal by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Filesystem path resolution, canonical path, and symbolic link.

- URL decoding and decode position in the web stack.

- Filesystem permissions of the process running the fixture.

## 3. Background Knowledge

Imagine the file system on a web server as a huge document storage library. In it, each department has its own filing cabinet, and employees are only allowed to view documents in their department's cabinet. To keep it safe, the library manager has set a rule: "You are only allowed to search for files within the designated public drawer." [S4]

In a path structure, a segment that references the parent directory acts as a resolver to go up one level. If an application concatenates multiple such segments from input into the root directory without normalizing and checking containment, the final path may escape the allowed resource tree. The specific mechanism and test chain are isolated in section 8; the background part only needs to remember that checking the string before resolution does not prove that the final file still resides in the permitted directory. [S2] [S4]

In addition, the URL structure of the application often contains query parameters specifying the resource to download (e.g., `https://victim.lab.test/download?file=report.pdf`). The browser sends this URL as an HTTP request, and the server analyzes the value of the `file` parameter to locate the file on the hard drive. If the developer does not validate this parameter and processes the file directly, an attacker can manipulate the URL structure to perform a directory traversal attack. For effective defense, the server must resolve the input path to a normalized absolute path and explicitly verify whether the resolved path actually resides under the allowed root directory. [S4]

```python
# Safe path resolution check to prevent directory traversal
from pathlib import Path

def get_safe_filepath(user_filename, base_dir="/var/www/safe_uploads"):
    """
    Resolves the target file path and ensures it does not escape the base directory.
    """
    # The lab directory is not writable by the requesting user. Canonicalize
    # only paths that already exist so missing components cannot hide behavior.
    base_path = Path(base_dir).resolve(strict=True)

    # Resolve parent segments and existing symlinks at validation time.
    target_path = Path(base_path, user_filename).resolve(strict=True)

    # Verify that the resolved target path is still located within the base path
    if not target_path.is_relative_to(base_path):
        # Deny access if a path traversal attempt is detected
        raise PermissionError("Access Denied: Requested file escapes the base directory.")

    # If an attacker can mutate this directory, use a descriptor-relative open
    # with no-follow semantics instead of returning a path after this check.
    return target_path
```

## 4. Description and Root Cause

**Directory Traversal** vulnerability (Directory Traversal or Path Traversal) occurs when an application blindly trusts the path or file name provided by the user. [S4]

The root cause is that the application used for input determines the file path and then opens the result without mapping through a server-side identifier or without verifying that the canonical path is within the allowed directory. The consequences depend on the process's privileges: the application may accidentally read data outside its scope or write to locations not intended for that function. [S2] [S4]


## 5. Threat Model and Exploitation Conditions

- **Assets:** files outside the menu directory are allowed; the lab only has the marker /srv/lab/lab-secret.txt.

- **Actor:** client not logged in or already logged in if the download endpoint requires a session.

- **Trust boundary:** file parameter goes into the join/resolve path of Python 3.12.

- **Necessary condition:** the actor controls the file name and the handler does not map an allowlist or does not check the resolved path.

- **Environment:** disposable filesystem container; query can be decoded correctly once; no symlink to host.

Only conclude when the log of open() and the content LAB_ONLY_SECRET prove that a file outside the base directory has been read. [S1]

## 6. Attack Mechanism

Handler appends the filename provided by the client to the base path. Parent segments or equivalent decoding that forms a path have resolved escaping from the base directory if there is no allowlist/containment check. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** create /srv/lab/public/menus with a valid menu file and an external synthetic marker file; enable file-access log.
2. **Baseline:** load breakfast.txt or a valid opaque menu ID.
3. **Operation:** send the correct payload annotated in item 8; then try a percent-encoded variant as a separate boundary case.
4. **Expected result:** buggy version returns LAB_ONLY_SECRET; fix only accepts allowlist and returns 404 without opening files outside the base.
5. **Boundary:** check absolute paths, different separators, double decoding, and symlinks only inside the container.
6. **Cleanup:** delete the container and confirm no system/host files were accessed.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

A lab application loads the menu through the parameter `file=menu1.txt`. If the server directly connects input to the root directory, the string `../` can escape the allowed directory and read `lab-secret.txt` in the fixture. Do not use real system files or data to illustrate. [S4]

### Encoding variants to bypass the filter:
| Payload | Meaning |
|---|---|
| `../` | Basic |
| `%2e%2e%2f` | Fully encode URL |
| `..%2f` | Only encode `/` |
| `%2e%2e/` | Only encode `.` |
| `....//` | Can only bypass the filter that deletes `../` once; not a universal variant |
| `..\` | Windows path separator |
| `%252e%252e%252f` | Double encode URL |
| `..%c0%af` | Legacy: only related to the old UTF-8 decoder that accepts overlong sequence; current decoder must reject [S3] |

### Example HTTP request illustrating Directory Traversal:<!-- payload-id: WEB-A01-DIRECTORY-TRAVERSAL-001 -->
<!-- context: HTTP/1.1; fixture root /srv/lab/public/menus; synthetic file /srv/lab/lab-secret.txt; path-containment model [S4] -->
<!-- prerequisites: local fixture normalizes the query once and joins it to the configured menu directory -->
<!-- encoding: ASCII request-target with literal ../ segments; raw harness emits CRLF; request has no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns the marker LAB_ONLY_SECRET; fixed fixture returns 404 without opening a file outside the allowlist -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Each ../ segment moves up one parent directory
GET /download?file=../../lab-secret.txt HTTP/1.1
Host: files.lab.test
# The vulnerable fixture returns the synthetic marker LAB_ONLY_SECRET
```

## 9. Vulnerable Code and Secure Code

```python
from pathlib import Path

BASE_DIRECTORY = Path("/srv/lab/public/menus")
ALLOWED_MENUS = {
    "breakfast": "breakfast.txt",
    "dinner": "dinner.txt",
}

def read_menu_vulnerable(user_filename):
    # BAD: user input is appended directly to the trusted base directory
    return (BASE_DIRECTORY / user_filename).read_text(encoding="utf-8")

def read_menu_secure(menu_id):
    # GOOD: the client selects an opaque ID whose filename is server-controlled
    filename = ALLOWED_MENUS.get(menu_id)
    if filename is None:
        raise FileNotFoundError("Unknown menu")
    return (BASE_DIRECTORY / filename).read_text(encoding="utf-8")
```

## 10. Detection

- Send a valid file name and escape path from base; confirm which file is actually opened in the syscall/log. [S4]

- Review path joining, number of decodes, and containment check after canonicalization. [S4]

- Log file ID, resolved relative path, decision allow/deny; do not log file content.

## 11. Defense

### Compulsory control

- Prioritize mapping the ID file on the server; if receiving a file name, resolve it and then confirm the destination is within the base directory. [S4]

- Reject absolute paths, paths escaping the base, and symlinks that cross boundaries according to a clear policy. [S4]

### Defense-in-depth

- Run the process with minimal filesystem permissions.

- Isolate the fixture/container to reduce the blast radius.

## 12. Retest

- **Positive:** allowlisted file in the base directory can still be read.

- **Negative:** base path and absolute path are denied before open.

- **Boundary:** check encoded separator, decode multiple times, and symlink.

- **Telemetry:** confirm the resolved path and syscall do not touch files outside the fixture.

## 13. Common Mistakes

- Only delete the string `../` before decoding.

- Compare the string-form path before canonicalization.

- Use a prefix string without a separator boundary.

- Test with real system files instead of synthetic markers.

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

- **Canonical path:** the path after runtime resolves relative components and links according to the filesystem. [S4]

- **Containment check:** verify that the resolved object is still under the allowed base directory. [S4]

- **Traversal:** input as the target path to escape from the intended resource tree. [S4]

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S2]** CWE-22. https://cwe.mitre.org/data/definitions/22.html — version/status: current version; accessed: 2026-07-17.
- **[S3]** RFC 3629 — UTF-8, a transformation format of ISO 10646. https://www.rfc-editor.org/rfc/rfc3629.html — version/date: November 2003; accessed: 2026-07-17.
- **[S4]** OWASP Path Traversal. https://owasp.org/www-community/attacks/Path_Traversal — version/status: current version; accessed: 2026-07-18.