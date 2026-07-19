---
schema_version: 1
id: WEB-A03-TOXIC-DEPENDENCIES
title: "Toxic Dependencies"
slug: toxic-dependencies
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A03:2025
cwe:
  - CWE-1395
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Toxic Dependencies

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Toxic Dependencies by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and conditions required for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Direct/transitive dependency and package registry.

- Version range, lockfile, reachability, and lifecycle script.

- The Node.js sandbox fixture has no outbound network.

## 3. Background Knowledge

Imagine you are opening a hot pot restaurant. Instead of planting rice yourself, raising cows, or growing vegetables, you import vegetables from a farm, meat from a slaughterhouse, and bottled sauce from a spice company. This allows your restaurant to operate quickly and serve a variety of dishes. However, if the bottle of sauce you import is contaminated with harmful bacteria and you do not check it before pouring it into the hot pot for customers, all of your diners will be poisoned. [S3]

It's the same in programming; those bottles of sauce are the **dependencies** developed by third parties. To manage them, programmers use online repositories (registries) and package managers to download the source code. When you download a library, that library in turn downloads smaller libraries, forming a tangled **dependency tree**. If even a small branch deep in this dependency tree contains buggy code or is injected with malicious code (called **Toxic Dependencies**), your entire large application can also become infected. To monitor these software "epidemics," the world uses a vulnerability identification system **CVE** to provide timely warnings to the community. [S3]

### Illustration of normal operation (Normal Operation)

For example, `package.json` is valid, below it pins direct dependencies and provides the audit command; JSON standard does not support comments. This file has not fully locked all transitive dependencies or artifact digests: the repository still requires commit/review. `package-lock.json` and CI use `npm ci`. [S3]

```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    "audit": "npm audit --audit-level=high"
  },
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21"
  }
}
```

## 4. Description and Root Cause

**Toxic Library** vulnerability (Toxic Dependencies or Vulnerable Components) occurs when an application integrates third-party libraries that are outdated, no longer maintained, or contain serious security flaws that have been publicly disclosed but not yet updated. [S3]

The danger of this vulnerability is extremely high because developers often focus only on writing their own source code and very rarely review the thousands of lines of code in external libraries they download. Attackers can easily scan your system to find these outdated libraries through publicly available error codes (CVE). Then, they only need to send specially crafted requests designed to trigger existing flaws in that library (such as the famous Heartbleed or Log4Shell vulnerabilities) to steal sensitive data in memory RAM, snoop on system configurations, or directly take full control of your server remotely. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** runtime Node.js disposable and the application's dependency graph.

- **Actor:** input synthetic goes into API easily causing errors in lodash 4.17.4; do not fetch Internet payload.

- **Trust boundary:** JSON.parse and defaultsDeep modify objects/prototypes within the same process.

- **Necessary conditions:** the correct version/path prone to errors is called; the process has not been isolated/removed after the test.

- **Environment:** Node.js 12.x container, local registry, outbound disabled.

Only advisory/CVE match is not enough: need to confirm reachable version and marker LAB_POLLUTED in disposable process. [S3], [S4]

## 6. Attack Mechanism

The application calls API reachable of the correct dependency/version easily prone to errors. Synthetic input activates behavior in the process, such as prototype pollution; advisory not reachable does not create the same mechanism. [S3], [S4]

## 7. Testing in an Authorized Lab

1. **Setup:** build Node 12.x container with lodash 4.17.4 from lab registry; snapshot and then block outbound.  
2. **Baseline:** new object does not have the labPolluted property.  
3. **Action:** run the correct JSON constructor path once in a limited process.  
4. **Expected result:** faulty version prints LAB_POLLUTED=true; fixed version does not pollute and regression test passes.  
5. **Boundary:** check API/other paths only when source confirms; do not generalize to all lodash versions.  
6. **Cleanup:** terminate/discard the entire process and container.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

An attacker can trigger a specific vulnerability when the application actually has the affected version installed and data controlled by the actor reaches API in an unsafe way. For example, the lab below pins lodash 4.17.4 and uses `defaultsDeep`; CVE-2019-10744 affects lodash before 4.17.12 via constructor payload. One should not infer from the package name or CVE to an exploitability without version and call path. [S3], [S4]

### Example of 3 steps to exploit CVE from Toxic Dependency:<!-- payload-id: WEB-A03-TOXIC-DEPENDENCIES-001 -->
<!-- context: Node.js 12.x disposable process; lodash 4.17.4; defaultsDeep constructor path; documented vulnerable-version behavior [S3] -->
<!-- prerequisites: install only from the lab registry with outbound network disabled -->
<!-- encoding: UTF-8 JavaScript source; the JSON string is parsed once with no URL or transport decoding -->
<!-- expected-result: the isolated process prints LAB_POLLUTED=true, then exits and the container is discarded -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3,S4 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// CVE-2019-10744 affects lodash versions below 4.17.12 via defaultsDeep
const defaultsDeep = require('lodash').defaultsDeep;
const payload = '{"constructor":{"prototype":{"labPolluted":true}}}';

defaultsDeep({}, JSON.parse(payload));
console.log(`LAB_POLLUTED=${({}).labPolluted === true}`);

// End the disposable process; never reuse a polluted runtime
delete Object.prototype.labPolluted;
```

## 9. Vulnerable Code and Secure Code

```json
{
  "name": "vulnerable-fixture",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4"
  }
}
```

```json
{
  "name": "secure-app",
  "version": "1.0.0",
  "scripts": {
    "audit": "npm audit --audit-level=high"
  },
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21"
  },
  "overrides": {
    "lodash": "4.17.21"
  }
}
```
Manifest pin direct version without locking bridging dependency. Repository must commit/review `package-lock.json`; CI uses `npm ci` to reject when the manifest and lockfile differ and does not automatically fix the lockfile. Version upgrades only handle CVE when advisory and regression tests confirm that the affected call path has been removed. [S3], [S5]

## 10. Detection

- Confirm the exact artifact/version and call the correct code path in the fixture; CVE a simple match is not enough for reachability. [S3]

- Review transitive graph, install script, publisher/provenance, and runtime behavior. [S3]

- Capture process/file/network event in disposable container; do not provide secret.

## 11. Defense

### Compulsory control

- Pin/review artifact and provenance; type or upgrade dependencies that have unacceptable behavior/risks. [S3]

- Run untrusted dependencies in an isolated build environment, without default credentials/outbound. [S3]

### Defense-in-depth

- SCA and reachability analysis support prioritizing remediation.

- Runtime sandbox reduces the blast radius but does not make the package trustworthy.

## 12. Retest

- **Positive:** the approved version has been installed and runs the necessary code path correctly.

- **Negative:** artifact/digest outside the policy is blocked before execution.

- **Boundary:** transitive version, optional dependency, platform and lockfile drift.

- **Telemetry:** confirms package graph, process spawn, file write, and egress.

## 13. Common Mistakes

- Call all dependencies with CVE exploitable in the application.

- The lockfile automatically verifies the publisher or harmlessness.

- Test the suspicious package on the host with credentials.

- Only upgrade the direct dependency without confirming that the transitive version has changed.

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

- **Dependency graph:** set of direct/transitive packages selected by the resolver for the build. [S5]

- **Known-vulnerable component:** component/version with publicly recorded vulnerabilities such as CVE. [S3]

- **Lockfile:** a record of dependency resolution that `npm ci` uses and checks against the manifest. [S5]

## 16. Related Lessons and Further Reading

- [Malvertising](../malvertising/) — See more lessons about Malvertising.

## 17. References

- **[S3]** NIST NVD — CVE-2019-10744. https://nvd.nist.gov/vuln/detail/CVE-2019-10744 — version/status: current record; access: 2026-07-17.
- **[S4]** Snyk Advisory — Prototype Pollution in lodash. https://security.snyk.io/vuln/SNYK-JS-LODASH-450202 — version/status: current version; access: 2026-07-17.
- **[S5]** npm CLI documentation — `npm ci`. https://docs.npmjs.com/cli/commands/npm-ci/ — version/status: current documentation; access: 2026-07-18.