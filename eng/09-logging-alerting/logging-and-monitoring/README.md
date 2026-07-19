---
schema_version: 1
id: WEB-A09-LOGGING-AND-MONITORING
title: "Logging and Monitoring"
slug: logging-and-monitoring
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A09:2025
cwe:
  - CWE-778
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Logging and Monitoring

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Logging and Monitoring by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for a flaw to be exploitable.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Logging and Monitoring scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine a bank operating completely without surveillance cameras and guards recording entry and exit logs. When a thief breaks in and steals the safe, the manager can only stand and watch the wreckage with no clues to trace. In the software world, **security logging (Logging)** plays the role of that 24/7 operating security camera system. Its task is to record every important event: from successful or failed logins, intentional attempts to access restricted areas, to system configuration changes. This is precisely the trace left behind (audit trail) that helps administrators reconstruct the scene of the attack and fix vulnerabilities in time.

However, the surveillance camera must record sharp and orderly images to have value. Application logs need to be recorded in a standard structured format (such as JSON format) so that computers can easily read and understand them. Each photo (log line) must clearly show: the timestamp, who performed the action (user ID), from where (ip_address), what the specific action is, and the transaction identifier (trace ID). Nevertheless, the camera must not record overly sensitive private information such as passwords, account numbers, or PIN (PII data) to prevent the camera itself from becoming a source of information leakage.

Finally, all data from different cameras will be transmitted directly to a central security monitoring room (SIEM). Here, the system not only stores the recordings in a secure place (tamper-resistant) but also automatically correlates the data together. For example, if a detection of a guest knocking on the door 100 consecutive times fails at different branches within 1 minute, the system will immediately trigger an alarm (alerting) for the incident response team to prevent the brute-force behavior.

## 4. Description and Root Cause

The vulnerability **Logging and Monitoring Failures** is like having the security cameras turned off or malfunctioning. In that case, an attacker can freely move around and sabotage the system without anyone knowing.

The danger lies in the fact that:
- When an attack is happening (such as someone scanning for passwords), administrators are completely blind because no warning signals are issued.
- After the attack is complete, the server is damaged or data is lost, and the business suffers without any way to know how the intruder got in or what was taken, because there are no audit logs recording that journey.
- Conversely, if logging is configured carelessly, accidentally storing plaintext passwords or users' credit card information (PII), it becomes a "treasure" handed directly to the attacker if they gain access to the log file.

> **Reference source:** technical claims in the lesson are marked with source markers; when applying in practice, cross-check the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** login records, permission changes, administrative actions; integrity/retention of logs; and alert paths to on-duty personnel. 
- **Trust boundary:** events from the application passing through the structured logger, collector, and log repository/SIEM.
- **Actor:** lab user creating successful/failed logins; administrator simulating permission changes; operator only modifying temporary log copies.
- **Necessary conditions:** sensitive events not logged, missing actor/action/outcome/correlation ID, input containing CR/LF recorded verbatim, or logs can be modified/deleted without detection.
- **Environmental conditions:** Python 3.12 fixture and local collector; synchronized clock; log/alert written to temporary folder, no data sent outside.

Only conclude a failure when a security event is lost/fabricated, a log loses integrity, or an alert is not generated/delivered to the correct path in the fixture. [S1]

## 6. Attack Mechanism

Input containing CR/LF can generate fake log lines if the logger concatenates strings directly; a permission change operation may not leave an audit event if the code path bypasses the logger; and overly broad write permission may allow evidence tampering. Testing must concatenate with the same correlation ID from request to application log, collector, and alert to distinguish recording errors from dashboard query errors. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run Python 3.12 application and local collector; load fake accounts, enable structured log, and write logs to a temporary directory.
2. **Input:** create a baseline consisting of one correct login, one incorrect login, and one privilege change, each request having its own correlation ID.
3. **Actions:** repeat with usernames containing CR/LF; separately disable the fixture's audit hook; modify a copy of the log using a non-privileged account.
4. **Expected result:** the vulnerable copy has fake lines or missing events/alerts; the fix must encode CR/LF, preserve actor/action/outcome, refuse log modification, and issue a test alert.
5. **Cleanup:** stop the collector, delete temporary accounts/data/logs, and confirm no background processes remain.
6. **Safety limits:** do not manipulate real system logs, do not send events to SIEM outside the lab, and only simulate tampering on a disposable copy.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The attacker performs a brute-force attack on the system administrator’s account password by sending thousands of continuous login requests. 
Step 2: Because the application does not record logs of failed login attempts and there is no monitoring system alerting abnormal traffic, this action occurs silently without being detected. 
Step 3: The attacker discovers the correct password, successfully logs in, and makes sensitive configuration changes without leaving investigative traces due to the lack of an Audit Log mechanism.

### Simulating log copy editing in fixture:<!-- payload-id: WEB-A09-LOGGING-AND-MONITORING-001 -->
<!-- context: POSIX shell; operate only on a log copy in the local fixture temporary directory -->
<!-- prerequisites: mktemp, grep, and diff; do not use real system logs -->
<!-- encoding: UTF-8; each record ends with LF -->
<!-- expected-result: altered.log no longer contains the line with 192.0.2.10, original.log remains intact, and diff records the change -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Create a disposable log fixture; never edit a system log for this exercise
lab_dir="$(mktemp -d)"
printf '%s\n' \
  '2026-07-17T03:42:17Z ip=192.0.2.10 action=upload result=success' \
  '2026-07-17T03:43:10Z ip=192.0.2.20 action=login result=failure' \
  > "$lab_dir/original.log"

# Simulate tampering by writing a filtered copy, preserving the original evidence
grep -v 'ip=192.0.2.10' "$lab_dir/original.log" > "$lab_dir/altered.log"
diff -u "$lab_dir/original.log" "$lab_dir/altered.log" || true

# Cleanup after collecting the expected diff in the lab report
rm -r "$lab_dir"
```
### Example of distinguishing good logs and bad logs:<!-- payload-id: WEB-A09-LOGGING-AND-MONITORING-002 -->
<!-- context: log text; illustrates the minimum fields for an authentication event in the fixture -->
<!-- prerequisites: identity data must be synthetic; do not log passwords, tokens, or session IDs -->
<!-- encoding: UTF-8; RFC 3339 timestamp in UTC -->
<!-- expected-result: a good record has timestamp, actor, source, action, result, reason, and correlation ID for investigation -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# POOR: the event lacks the context needed for an investigation
[INFO] Login failed

# BETTER: structured fields support correlation without recording secrets
timestamp=2026-07-17T03:42:17Z level=WARN actor_id=user-42
source_ip=192.0.2.10 action=login result=failure reason=invalid_credential
correlation_id=req-7f12
```

## 9. Vulnerable Code and Secure Code

The following two functions use Python 3.12 for the same authentication event. The error-prone version skips failures and appends untrusted data into free text; the safe version writes the same schema for both outcomes, so the JSON encoder handles control characters and uses correlation ID. Do not write passwords, tokens, or sessions ID. [S2] [S3]

### Not safe (vulnerable): lacking failure event and schema

```python
def record_auth_event_vulnerable(username, is_successful):
    if is_successful:
        # Vulnerable: failures disappear and untrusted data is concatenated
        print("Login succeeded for " + username)
```
### Secure: fixed schema for every outcome

```python
import json
from datetime import datetime, timezone

def record_auth_event_secure(actor_id, source_ip, is_successful, trace_id):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication",
        "outcome": "success" if is_successful else "failure",
        "actor_id": str(actor_id),
        "source_ip": str(source_ip),
        "trace_id": str(trace_id),
    }
    # Secure: JSON encoding preserves event boundaries and escapes controls
    print(json.dumps(event, ensure_ascii=True, separators=(',', ':')))
```

## 10. Detection

- Log the actor/session, route or operation, related object/resource for Logging and Monitoring, policy results and correlation ID; do not log secrets or the entire token.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chain, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to verify whether the request reached the sink and whether it had any impact.  
- Scanner or WAF alerts are just investigation signals; they are not sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Record events with context, protect logs, and generate alerts with a responsible party assigned for handling. 
- Log events according to the allowlist schema, encode CR/LF, send logs to an append-only repository with minimal permissions, and periodically test both the rules and the alert receiving paths.
- Use the same policy for all equivalent routes/operations; do not just fix the endpoint that appears in the PoC.

### Defense-in-depth

With Logging and Monitoring, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for native controls.

- **Summary**: Ensure full security visibility by logging critical events including diagnostic information, and use the SIEM dashboard for detection. 
- **Detailed Steps**:
  - Record all security-related events, including authentication attempts, access control failures, data validation errors, and actions with significant impact.
  - Ensure each event has a timestamp, ID correlation, actor, and source consistent with the threat model; minimize or mask personal data and never log passwords, keys, or session tokens.
  - Forward log streams in real-time to the SIEM system or a secure centralized log aggregator.
  - Set alert thresholds for suspicious activities, such as a high rate of failed authentications or unusual increases in API usage.
  - Store logs in tamper-resistant storage and restrict read/write access to authorized systems only.

## 12. Retest

- **Positive case:** with Logging and Monitoring, the valid flow still works correctly for allowed actors and data. 
- **Negative case:** with the same input/resources but disallowed actor or context, requests are denied without leaking sensitive details. 
- **Boundary case:** test empty values, extreme boundaries, different encodings, repeated requests, expired session state, and equivalent paths/operations. 
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Re-test:** keep a minimal scenario that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string from Logging and Monitoring without verifying side effects and logs. 
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
- Consider UUID, rate limit, WAF, CSP, or common input validation as a fix for a different primary control.
- Only fix one route while the same sink/policy is used in other routes.
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **Audit Trail**: A series of log records that document the system's activity history, helping track behavior and reconstruct security incidents when needed.
- **Log**: An automatic record of events occurring within a software system.
- **Personally Identifiable Information (PII)**: Any information that can be used to directly or indirectly identify an individual (such as name, phone number, password, credit card).
- **Masking**: A technique that replaces part or all of sensitive characters with a generic character (such as an asterisk) to protect information.
- **Security Information and Event Management (SIEM)**: A system that manages security events and information, collecting and analyzing logs from multiple sources to detect threats early.
- **Tamper-resistant**: The ability to prevent or record any unauthorized modification or deletion of data.
- **Correlation**: The process of linking discrete log events from different sources to find the logical connection of an attack.
- **Brute-force**: A technique that tries all possible options (such as passwords) to find the correct result.
- **Trace**: A unique code assigned to a request to track its journey across multiple service systems.

## 16. Related Lessons and Further Reading

- [Broken Function Level Authorization (BFLA)](../../01-broken-access-control/bfla/) — See more lessons about Broken Function Level Authorization (BFLA).

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-778. https://cwe.mitre.org/data/definitions/778.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** OWASP Logging Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.