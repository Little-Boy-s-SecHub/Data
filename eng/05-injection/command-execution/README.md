---
schema_version: 1
id: WEB-A05-COMMAND-EXECUTION
title: "Command Execution"
slug: command-execution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-78
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Command Execution

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Command Execution by root cause instead of only describing the consequences. 
- Identify trust boundary, asset, actor, and conditions required for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the difference between an executable, the array `argv`, and the string interpreted by the POSIX shell. 
- Be able to read `subprocess.run`, `os.system`, `child_process.exec`, and `execFile` in examples. 
- Know how to parse IPv4/IPv6 using data type libraries instead of checking the format with regex. 
- Have a non-root container on loopback, with outbound network disabled, and be able to observe the process tree.

## 3. Background Knowledge

The shell interprets metacharacters, concatenation, and expansion according to the shell's own syntax. When the application only needs to run a fixed executable, API passes the array `argv` directly with `shell=False` to avoid the step of string interpretation by the shell; the application still has to allowlist the values and semantics of each argument. [S2] [S3]

```python
import subprocess

def check_network_connectivity(host_ip):
    # Safe subprocess spawning (normal operation)
    # By passing arguments as a list and setting shell=False (default),
    # the operating system executes the 'ping' binary directly.
    # Any shell metacharacters in host_ip are treated as literal arguments, not command symbols.
    command = ["ping", "-c", "1", host_ip]
    result = subprocess.run(command, capture_output=True, text=True, shell=False)
    return result.stdout
```

## 4. Description and Root Cause

OS Command Injection occurs when untrusted input alters the command structure that the application sends to the shell or command interpreter. The lesson only uses markers on the stdout of a disposable container; it does not write system files, does not open callbacks, and does not propagate results between POSIX shell, `cmd.exe`, and PowerShell. [S1] [S2] [S3]

## 5. Threat Model and Exploitation Conditions

- **Assets:** rights of non-root processes, filesystem, and environment variables.

- **Actor, authentication, and role:** public users or users with the user role call the ping/convert function; no shell account.

- **Exploitation conditions:** input structure modification of the string fed into the shell or command interpreter. [S1] [S2] [S3]

- **Runtime:** Python 3.12 fixture pin and POSIX `sh` in a non-root container; do not extend to PowerShell or `cmd.exe`.

- **Evidence:** host logs decoded, API creates process and stdout; the marker must be the output of the second command.

## 6. Attack Mechanism

In the vulnerable version, the semicolon terminates the argument of `ping` and requires POSIX shell to run `printf`. The patched version parses the host into the IP address, calls the fixed executable through the `argv` array, and does not initialize a shell, so the same string must be rejected before creating the process. [S1] [S2]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12/Flask 3.x in container POSIX as non-root with a pinned shell; HTTP/1.1 loopback; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the command execution use case; record raw request/response, decide policy and asset state before the test.
3. **Input and operation:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** only consider a vulnerable fixture as positive when logs show the mechanism “input was concatenated into a shell string or passed with shell=True”; secure fixtures must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete command execution data, markers, and logs; revoke related session/cache, revert snapshot and verify no test callback/process remains.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The probe below only uses the syntax POSIX `sh` in the recorded context; it does not represent all shells or runtimes. Argument injection can occur even without using a shell if the input is passed as a dangerous option to an executable; environment variable injection occurs when environment variables controlled by the client affect the loader/runtime of a subprocess. [S1] [S2]

Time-based, OOB, wildcard and newline depend on shell/OS; these probes only verify the correct annotated context. [S1] [S2]

<!-- claim-source: [S1] [S2] -->
<!-- payload-id: WEB-A05-COMMAND-EXECUTION-001 -->
<!-- context: POSIX sh fixture concatenates the decoded host value into a shell command -->
<!-- prerequisites: disposable loopback container; outbound network disabled; stdout captured; one request -->
<!-- encoding: UTF-8 form value percent-encoded once; the shell receives one semicolon and an ASCII marker -->
<!-- expected-result: vulnerable fixture prints COMMAND_INJECTION_LAB after its normal output; argv-based secure fixture treats the full value as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```text
127.0.0.1; printf COMMAND_INJECTION_LAB
```
**Argument Injection through executable options**

<!-- payload-id: WEB-A05-COMMAND-EXECUTION-002 -->
<!-- context: POSIX tar fixture passes user-controlled archive argument to a fixed executable without a `--` separator -->
<!-- prerequisites: disposable loopback container; archive path is synthetic; command action is limited to printf ARG_INJECTION_LAB -->
<!-- encoding: UTF-8 argument string; shell metacharacters are not required because the sink is argv option parsing -->
<!-- expected-result: vulnerable fixture treats the value as tar options and prints ARG_INJECTION_LAB; secure fixture prefixes `--` or rejects option-looking input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```text
--checkpoint=1 --checkpoint-action=exec='printf ARG_INJECTION_LAB'
```
**Environment Variable Injection into subprocess**

<!-- payload-id: WEB-A05-COMMAND-EXECUTION-003 -->
<!-- context: Python 3.12 worker fixture copies selected request parameters into subprocess environment before importing a lab module -->
<!-- prerequisites: /tmp/sechub-lab contains only a harmless module that prints ENV_INJECTION_LAB; container is disposable and outbound network is disabled -->
<!-- encoding: UTF-8 key/value pair; no shell parsing is required -->
<!-- expected-result: vulnerable fixture loads the lab module through PYTHONPATH and prints ENV_INJECTION_LAB; secure fixture uses a fixed environment allowlist -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```text
PYTHONPATH=/tmp/sechub-lab
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE (Python) ===
import os

def check_ip_vulnerable(user_input):
    # DANGER: Directly concatenating input into os.system executes it via shell
    # Input like "127.0.0.1; sleep 5" will trigger time-based injection
    command = f"ping -c 1 {user_input}"
    os.system(command)

# === SECURE CODE (Python) ===
import subprocess
import ipaddress

def check_ip_secure(user_input):
    # Parse and canonicalize a real IPv4/IPv6 address
    host = str(ipaddress.ip_address(user_input))

    # Run the fixed executable directly without a shell
    subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
```

```javascript
// === VULNERABLE CODE (Node.js) ===
const { exec } = require('child_process');

function pingVulnerable(ip) {
  // DANGER: exec invokes a shell, allowing metacharacter exploitation
  exec(`ping -c 1 ${ip}`, (err, stdout) => {
    console.log(stdout);
  });
}

// === SECURE CODE (Node.js) ===
const { execFile } = require('child_process');
const { isIP } = require('net');

function pingSecure(ip) {
  if (isIP(ip) === 0) {
    throw new TypeError('Expected an IPv4 or IPv6 address');
  }
  // Run a fixed executable directly without invoking a shell
  execFile('ping', ['-c', '1', ip], (err, stdout) => {
    console.log(stdout);
  });
}
```

## 10. Detection

- Search for `os.system`, `shell=True`, `child_process.exec` and the concatenated command strings from requests or stored data.

- Record the executable, canonical arguments, exit code, and duration; do not record the environment or command line with secrets.

- Tracing process trees with an allowlist; shells spawned under a web worker are a signal for investigation.

- The marker must come from the stdout of `printf`; errors or delays from `ping` do not prove command injection.

## 11. Defense

### Compulsory control

- Do not call the shell when not needed; use a fixed executable and a allowlisted argv.

- Parse IPv4/IPv6 using data type libraries and reject invalid input before creating a process. [S2]

### Defense-in-depth

- Run the worker without privileges, filesystem read-only and no outbound network if only pinging loopback. [S2] [S3]

- Set timeout, limit the number of processes, and fix the executable path. [S2]

- Monitor process trees and unexpected shells. These measures reduce impact but do not make command chains composed from input safe. [S2] [S3]

## 12. Retest

- **Positive case:** `127.0.0.1` and `::1` are accepted by the parser, then `ping` runs with the correct executable and the expected argument array.  
- **Negative case:** `127.0.0.1; printf COMMAND_INJECTION_LAB` is rejected and the process tree does not show a shell or `printf`.  
- **Boundary case:** test leading/trailing spaces, IPv4 with wrong octet, compressed IPv6, newline character decoded, and the operating system fixture's shell character.  
- **Telemetry:** confirm logs record canonical host, exit code, and executable but do not record secrets; the number of processes matches exactly one call.  
- **Regression:** check both endpoint HTTP and the helper that creates processes to detect which routes still use `shell=True` or `exec`.

## 13. Common Mistakes

- Block some characters like `;` and `&` but still pass the string into the shell; quoting and expansion are different depending on the shell.

- Using an IPv4 regex only checks the format, so it still accepts octets out of range or unwanted representations.

- Switch from `exec` to `spawn` but keep the shell option enabled or allow the user to control the executable name.

- Run the POSIX payload on PowerShell or `cmd.exe` and then conclude the application is safe if the marker does not appear.

- Use timeouts or low-privilege accounts as a main fix; they only limit the impact after the injection has occurred.

## 14. Summary and Checklist

- [ ] Specific shell identified, API creates the process and web worker privileges.  
- [ ] Probe only prints marker to stdout, does not write files, call callbacks, or create long delays.  
- [ ] Patch uses a fixed executable, `shell=False`/`execFile`, and parsed arguments.  
- [ ] Test confirms no shell or second process exists in the process tree.  
- [ ] IPv4, IPv6, and invalid input all have clear expected results.  
- [ ] Process limits, timeout, and low privileges are only documented as defense-in-depth.

## 15. Glossary

- **Command Execution**: Unauthorized operating system command execution vulnerability due to user injection.  
- **OS Shell**: Command-line interface that allows interaction and control of the operating system.  
- **Metacharacters**: Special characters (such as `;`, `&`, `|`) used to control the command flow in the shell.  
- **Subprocess**: A child process created to perform a separate task.  
- **RCE**: The ability to execute code from a network location; OS command injection only achieves this impact when the sink can be controlled through a remote flow and the process permissions allow it. [S3]

## 16. Related Lessons and Further Reading

- [Code Injection](../code-injection/) — Directly injecting code into the runtime of a programming language (such as eval) instead of calling the operating system command.
- [File Upload](../../06-insecure-design/file-upload/) — Uploading a malicious file (web shell) to achieve remote command execution on the server.
- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — The concept of executing code remotely on the target server through various attack vectors.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/os-command-injection — version/status: current version; accessed: 2026-07-17. 
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/78.html — version/status: current version; accessed: 2026-07-17.