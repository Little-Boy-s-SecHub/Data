---
schema_version: 1
id: WEB-A05-REGEX-INJECTION
title: "Regex Injection"
slug: regex-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1333
content_status: technical-review
payload_status: none
last_verified: null
---

# Regex Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Regex Injection by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited. 
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Regex Injection scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Regular expressions (Regex) are like an extremely intelligent text filtering grid that helps search for character strings according to a predetermined pattern. When filtering information, Regex engines often use a "backtracking" mechanism – meaning that if one path does not match, it will return to the previous junction to try another path. However, if this filtering grid is designed too complexly (for example, containing nested loops) and encounters a data string that is nearly matching but fails at the last moment, the Regex engine will have to try millions of millions of other path combinations. This phenomenon is called catastrophic backtracking, similar to a person lost in a labyrinth with no way out, exhausted from trying to find a path.

```javascript
// JavaScript normal operation of regex searching
function escapeRegex(inputString) {
    // Escapes special regex characters to treat them as literal characters
    return inputString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function searchUserContent(userInput, documentText) {
    // Escape the user input to prevent regex injection / catastrophic backtracking
    const safePattern = escapeRegex(userInput);

    // Create a regular expression safely using the escaped literal pattern
    const regex = new RegExp(safePattern, 'i');
    return regex.test(documentText);
}
```

## 4. Description and Root Cause

Regex Injection occurs when an actor controls all or part of a pattern and can alter the matching semantics. With backtracking engines, some patterns/inputs cause processing time to increase very quickly and can lead to ReDoS; the CPU level, time, and blast radius depend on the engine, pattern, input, concurrency, and timeout, and are not by default “infinite backtracking” or always reaching 100% CPU. [S2]

> **Reference:** technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** CPU worker and validation results using regex. 
- **Actor, authentication, and role:** anonymous calls search/validation. 
- **Exploitation conditions:** arbitrary regex or bad backtracking causing nonlinear time increase. 
- **Browser, proxy, framework, and version:** Node.js 20 in a container with 200 ms timeout, CPU/memory cap and input limit; must record actual image/package version along with evidence. 
- **Mandatory evidence:** with correlation ID must append input, decide control, and impact the correct asset; individual status code is insufficient. [S1]

## 6. Attack Mechanism

For regex injection, arbitrary regex or bad backtracking causes time to increase nonlinearly. The positive case must prove that the input reaches the correct sink and creates the described effect; the negative case, when origin control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Node.js 20 in a container with a 200 ms timeout, CPU/memory cap and input limit; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the regex injection use case; save raw request/response, decide policy and asset status before testing.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism “arbitrary regex or bad backtracking causing nonlinear time increase”; secure fixture must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete regex injection data, markers, and logs; reclaim related session/cache, revert snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The attacker finds a data search or filtering feature that uses a regular expression (Regex) dynamically constructed from the user's input search string.
Step 2: The attacker sends a specially crafted input string containing nested repeating groups (e.g., `(a+)+` or `(a|a)+$`) along with a mismatched string at the end (such as `aaaaaaaaaaaaaaaaaaaaaaaa!`).
Step 3: The server's Regex parser performs backtracking through millions of possibilities to find a match.
Step 4: In the fixture with a timeout and CPU cap, time/CPU according to input size; only conclude ReDoS when the observed complexity increases unusually and exhausts the set budget, do not run unlimited input. [S2]

## 9. Vulnerable Code and Secure Code

```python
# ReDoS vulnerable pattern: catastrophic backtracking on (a+)+ type
import re, time

# Vulnerable: exponential backtracking
pattern = r'^(a+)+$'  # catastrophic for input like 'aaaaaaaaaaaaaaaaaX'
test_input = 'a' * 30 + 'X'

start = time.time()
try:
    re.match(pattern, test_input, timeout=5)
except re.error:
    pass
print(f'Time: {time.time() - start:.2f}s')  # can take seconds/minutes

# Secure: use atomic groups or rewrite pattern to avoid ambiguity
# Or use timeout mechanism
def safe_match(pattern, text, timeout=1.0):
    import signal
    def handler(signum, frame): raise TimeoutError
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(int(timeout))
    try:
        return re.match(pattern, text)
    finally:
        signal.alarm(0)
```

```javascript
function escapeRegExp(string) {
  // Escape special characters so they are treated as literal characters
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Secure construction using the escaped user string
const safeRegex = new RegExp(escapeRegExp(userInput), 'i');
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Regex Injection, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use a fixed pattern or linear engine, limit length and timeout.
- Apply the same control to every route, operation, and equivalent processing path; failure must stop before side effects.

### Defense-in-depth

With Regex Injection, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used to replace original controls.

- **Summary**: Regular Expression Denial of Service (ReDoS) occurs when user input is directly used to construct a regex without sanitization, or when the regex itself has infinite backtracking flaws. Mitigation measures include: escaping user input, using a non-backtracking engine, setting a timeout for matching operations, and avoiding creating dynamic regex from user-supplied parameters.
- **Detailed Steps**:
  - Do not create dynamic regular expressions from unescaped user input.
  - If dynamic regex must be created, escape all regex special characters first.
  - Write regular expressions carefully to avoid infinite backtracking (avoid nested quantifiers and overlapping character classes).
  - Implement strict timeout control for regex execution, or use a safe engine (like Google's RE2) that ensures linear complexity.

## 12. Retest

- **Positive case:** with Regex Injection, valid flows still work correctly for allowed actors and data.  
- **Negative case:** with the same input/resource but unauthorized actor or context, requests are denied without leaking sensitive details.  
- **Boundary case:** check empty values, extreme limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** keep a minimal scenario that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Regex Injection without verifying side effects and logs.
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
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

- **Regex / Regular Expression**: A regular expression used to match strings according to a pattern.
- **Backtracking**: A mechanism to return to previous steps in the Regex engine to search for all possible matches.
- **ReDoS**: A denial-of-service attack by overloading the Regex processing engine.
- **Catastrophic Backtracking**: An infinite backtracking phenomenon causing maximum consumption of CPU resources.
- **Escape**: The act of nullifying the meaning of special characters by inserting a backslash `\` in front.

## 16. Related Lessons and Further Reading

- [Command Execution](../command-execution/) — Execute command through unsafe handling.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S2]** CWE-1333. https://cwe.mitre.org/data/definitions/1333.html — version/status: current version; accessed: 2026-07-17.