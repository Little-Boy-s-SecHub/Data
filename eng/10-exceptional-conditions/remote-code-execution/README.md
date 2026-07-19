---
schema_version: 1
id: WEB-A10-REMOTE-CODE-EXECUTION
title: "Remote Code Execution"
slug: remote-code-execution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp: []
cwe: []
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Remote Code Execution

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Remote Code Execution by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of a Remote Code Execution scenario and how to handle input across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you hire a baker. Instead of giving them a clear, fixed recipe like 'use 2 eggs and 100g of flour,' you give them a blank piece of paper with the instruction: 'Read aloud whatever I write on the paper and follow it exactly!' The process of reading the paper and executing the written instructions immediately is **Code Evaluation**. 
If the paper says 'mix the flour,' the baker will bake. But if the paper is maliciously swapped to say: 'Open the safe and give me all the money,' that mechanical helper will still carry it out without any suspicion.

In the world of programming, dynamic execution functions (**Dynamic Execution**) like `eval()` or `exec()` operate just like that mechanical helper. They are ready to take any string sent by the user, treat it as valid source code, then compile and execute it directly. The small difference between them is: 
- `eval()`: Like quickly calculating a single arithmetic operation (for example: inputting the string "2 + 3" and getting the result 5).
- `exec()`: Even more formidable, it can execute an entire complex script consisting of multiple lines of code, defining functions, classes, or loops.

Abusing these dynamic execution functions with user-controlled data is no different from handing a master key to an attacker. To avoid this danger, wise programmers often refuse to use `eval`/`exec`; instead, they use parsers with a safe structure (such as the JSON parser or the AST tree structure) to only read raw data without ever executing it.

### Illustration of normal operation (Normal Operation)```python
# Normal operation: Safe evaluation of arithmetic string expressions using AST (no eval/exec)
import ast
import operator

# Map AST operators to standard operators safely
SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg
}

def safe_math_eval(expression_str):
    # Parse the string into an Abstract Syntax Tree safely without executing it
    parsed_tree = ast.parse(expression_str, mode='eval')

    def _evaluate(node):
        # Allow only pure mathematical values and operations
        if isinstance(node, ast.Expression):
            return _evaluate(node.body)
        elif isinstance(node, ast.BinOp):
            operator_type = type(node.op)
            if operator_type in SAFE_OPERATORS:
                return SAFE_OPERATORS[operator_type](_evaluate(node.left), _evaluate(node.right))
        elif isinstance(node, ast.UnaryOp):
            operator_type = type(node.op)
            if operator_type in SAFE_OPERATORS:
                return SAFE_OPERATORS[operator_type](_evaluate(node.operand))
        elif isinstance(node, ast.Constant): # Python 3.8+ constant nodes (numbers)
            if isinstance(node.value, (int, float)):
                return node.value

        # Reject any other node type (e.g. Call, Attribute, Name) to block code execution
        raise ValueError(f"Unsupported syntax tree element detected: {type(node).__name__}")

    return _evaluate(parsed_tree)

# Normal application run: Safely compute user math input
user_input = "20 * 5 + (4 - 2)"
try:
    result = safe_math_eval(user_input)
    print(f"Calculated result safely: {result}")
except ValueError as e:
    print(f"Rejected expression: {e}")
```

## 4. Description and Root Cause

**Remote Code Execution (RCE - Remote code execution)** is an impact, not a single root cause. This impact can arise from code injection, command injection, template injection, deserialization, or the server executing an uploaded file. Therefore, this lesson does not map the entire RCE to a single CWE; CWE-94 only fits the code injection branch. [S2]

Once the vulnerability RCE is exploited, the attacker will gain supreme privileges:
- Run any system command as if sitting directly in front of the server screen.
- Sneak a look at, modify, or completely delete sensitive data files.
- Install malicious software, open secret connection ports (backdoors) to access the system at any time.
- Turn the server into a springboard to further attack the enterprise's internal network.

> **Reference source:** technical claims in the lesson are marked with source markers; when applying in practice, cross-check the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** the execution rights of the application process, environment variables, and filesystem that the service account can access. 
- **Trust boundary:** input entering the template engine, operating system command, upload handler, or deserializer before the execution sink. 
- **Actor:** local client with the correct role of the endpoint fixture; only creates harmless markers, does not create reverse shells or Internet callbacks. 
- **Necessary condition:** a specific root cause such as injection, unsafe deserialization, or upload-to-execution must lead the input to execution API; “RCE” is the impact, not a renaming of the root cause. 
- **Environmental condition:** Python 3.12, Flask/Jinja2 3.1 in a non-root container, fake filesystem, and outbound network disabled.

Only conclude execution when the marker created by the process matches the request/correlation ID; template error, status 500, or successful file upload are not enough to prove RCE. [S1]

## 6. Attack Mechanism

Unsafe template evaluation or passing a string into the shell can turn data into commands; upload only leads to execution if the file is on the executable path and the runtime actually processes it. The fixture uses template calculation/local marker writing to demonstrate the sink without opening a shell or connecting outside. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run Flask/Jinja2 fixture non-root, mount the upload directory `noexec`, only allow writing markers in `/tmp/sechub-lab` and block outbound connections.
2. **Input:** baseline render literal text/upload inert file; then use template calculation or pre-defined local marker writing action.
3. **Operation:** send each vector separately, record raw request, application log, PID/UID and the existence/content of marker.
4. **Expected result:** easy-to-fail version assesses input or creates marker; fix literal render, do not call shell and uploaded files cannot be executed at runtime.
5. **Cleanup:** delete marker/upload, stop container and verify no child processes remain running.
6. **Safety limits:** prohibit reverse shell, downloader, credential access and Internet callback; process has timeout/CPU/memory cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The test step must prove the correct sink. For example, command injection requires confirming that the shell interprets a harmless marker; SSTI requires confirming a specific template engine; file upload only leads to execution when the upload directory is mapped to the runtime handler. Do not use a payload from one branch to conclude another branch. [S3], [S4], [S5]

### Probe SSTI does not execute operating system commands<!-- payload-id: WEB-A10-REMOTE-CODE-EXECUTION-001 -->
<!-- context: Jinja2 expression context; fixture must pin the Jinja2 version and render input as a template -->
<!-- prerequisites: use only the local fixture; outbound network is blocked; do not use gadgets that access os/subprocess -->
<!-- encoding: UTF-8, without URL encoding when entered directly into the template fixture -->
<!-- expected-result: the vulnerable fixture renders 49; the secure fixture displays the input literally or rejects it; result 49 proves only SSTI, not RCE -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```jinja2
{{ 7 * 7 }}
```
### Probe executes uploaded file using harmless marker<!-- payload-id: WEB-A10-REMOTE-CODE-EXECUTION-002 -->
<!-- context: PHP 8.x file executed by a disposable local web fixture; upload directory and handler mapping must be documented -->
<!-- prerequisites: fixture filesystem is disposable; uploaded file cannot invoke a shell and outbound network is disabled -->
<!-- encoding: UTF-8 PHP source; upload request framing is generated by the lab client -->
<!-- expected-result: requesting the uploaded file returns SECHUB_UPLOAD_EXECUTION_PROBE only when the server executes PHP in the upload directory -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
<?php
// Harmless execution marker for a disposable PHP fixture
echo "SECHUB_UPLOAD_EXECUTION_PROBE";
?>
```

## 9. Vulnerable Code and Secure Code

### Python 3.12: same use case `ping`, different way to create processes

```python
import subprocess
import ipaddress

def ping_host_vulnerable(user_ip):
    # Vulnerable: the shell interprets metacharacters from user_ip
    result = subprocess.run(
        f"ping -c 1 {user_ip}",
        capture_output=True,
        text=True,
        shell=True,
        timeout=3,
    )
    return result.stdout

def ping_host_secure(user_ip):
    try:
        ipaddress.ip_address(user_ip)
    except ValueError:
        raise ValueError("Invalid IP address")

    # Safe for this use case: no shell, fixed executable and fixed argument positions
    result = subprocess.run(
        ["ping", "-c", "1", user_ip],
        capture_output=True,
        text=True,
        shell=False,
        timeout=3,
        check=False,
    )
    return result.stdout
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Remote Code Execution, policy results and correlation ID; do not log secrets or the entire token. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Limit resources, fail safely, and handle all potentially reachable exceptional states. 
- Eliminate dynamic evaluation/shell, use API with parameters, separate upload from the executable path, and run the service non-root; fix the root cause correctly instead of relying on WAF.
- Use the same policy for all equivalent routes/operations; do not only fix the endpoint that appears in the PoC.

### Defense-in-depth

With Remote Code Execution, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for original controls.

- **Summary**: Fix the root cause leading to RCE: remove interpreting input as code/command, do not execute uploaded files, and do not deserialize arbitrary object types. Isolating processes only reduces blast radius. 
- **Detailed steps**:
  - Do not pass untrusted input into `eval`, `exec`, template sources, shell, or API deserialize which can instantiate arbitrary types.
  - When creating processes, use a fixed executable and a list of arguments; do not concatenate strings and do not enable the shell.
  - Store uploaded files outside the web root, rename them on the server, and do not map the upload directory to the runtime handler.
  - Run processes with low-privilege accounts, restricted filesystem access, and outbound network blocked by default as defense-in-depth.

## 12. Retest

- **Positive case:** with Remote Code Execution, the valid flow still works correctly for allowed actors and data. 
- **Negative case:** the same input/resource but disallowed actor or context is denied without leaking sensitive details. 
- **Boundary case:** check empty values, edge extremes, different encoding, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Re-test:** save the minimal scenario reproducing the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Remote Code Execution without verifying side effects and logs. 
- Use a payload with the correct syntax but the wrong DBMS, browser, framework, protocol, or injection context. 
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for a different root control. 
- Only fix one route while the same sink/policy is used in another route. 
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Code Evaluation**: The process of parsing and directly executing a string of text as actual programming code at runtime.
- **Dynamic Execution**: The ability of a program to execute commands generated flexibly during runtime, instead of being precompiled.
- **Abstract Syntax Tree (AST)**: A tree-shaped data structure representing the syntactic structure of source code, used for safely parsing without executing the code.
- **Backdoor**: A hidden method that bypasses normal authentication mechanisms to gain unauthorized access to a system.
- **Parser**: A syntax analyzer that converts input data into a data structure that the program can understand.
- **Sanitization**: The process of filtering out dangerous characters or commands from user input data before processing.

## 16. Related Lessons and Further Reading

- [Server-Side Template Injection](../../05-injection/ssti/) — Vulnerability of injecting malicious code into the server-side template engine, one of the most common causes leading to RCE. 
- [Command Execution](../../05-injection/command-execution/) — Direct execution of commands on the operating system, a specific manifestation of RCE through the system shell. 
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Unsafe deserialization allows reconstruction of objects containing malicious payloads causing RCE.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S2]** CWE-94. https://cwe.mitre.org/data/definitions/94.html — version/status: current version; accessed: 2026-07-18. 
- **[S3]** OWASP WSTG: Testing for Command Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection — version/status: current version; accessed: 2026-07-18. 
- **[S4]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18. 
- **[S5]** PortSwigger Web Security Academy — Server-side template injection. https://portswigger.net/web-security/server-side-template-injection — version/status: current version; accessed: 2026-07-18.