---
schema_version: 1
id: WEB-A08-PROTOTYPE-POLLUTION
title: "Prototype Pollution"
slug: prototype-pollution
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1321
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Prototype Pollution

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Prototype Pollution by the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Prototype Pollution scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

JavaScript has a prototype inheritance mechanism: when a property does not exist directly on an object, the runtime can continue to look up along the prototype chain. A historical accessor allows observing or changing this linkage, but application code should not use that accessor to API data. [S1]

When code reads a property, the runtime checks the own property first and then goes through the parent prototypes until the chain ends. Therefore, checking permissions or configuration using an inherited property may receive a value that does not belong to the actual business object. [S1]

Because `Object.prototype` is the supreme ancestor, anything that the ancestor owns (such as the basic functions `toString` or `hasOwnProperty`), all descendants born later automatically inherit.

Prototype Pollution exploits merge functions or recursive setters that allow input to select prototype-controlling keys. If the sink modifies a shared prototype, other objects may inherit properties unintentionally. The non-automatic impact is XSS, bypass or RCE: a separate gadget is needed to read the polluted property into a security decision or dangerous sink. The payload and verification marker are kept in section 8. [S1] [S3]

## 4. Description and Root Cause

The **Prototype Pollution** vulnerability occurs when untrusted input is used in assignments or merges that can reach a shared prototype. The root cause is the lack of key control at all depths and then trusting inherited properties; the list of keys and specific test inputs are only in sections 8–9. [S1] [S3]

When the root ancestor is infected, the behavior of the entire JavaScript system will be altered. An attacker can exploit this to:
- Bypass permission checkpoints (for example, automatically assign administrator roles to all user objects).
- Inject malicious script snippets to directly attack users on the browser (Client-side XSS).
- Take control of the server and execute system commands remotely (RCE) if the application is running on Node.js.

> **References:** Technical claims in the lesson are marked with a source; when applying in practice, compare against the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** JavaScript prototype and inherited authorization/config flag.
- **Actor, authentication and role:** user role sends JSON merge/config; target is still user role.
- **Exploitation conditions:** recursive merge receives prototype control keys at any depth and a gadget then reads the inherited property.
- **Browser, proxy, framework and version:** Node.js 20 with pinned merge library and a new process for each case; must record actual image/package version along with evidence.
- **Mandatory evidence:** with correlation ID must append input, decision control, and impact the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For prototype pollution, input goes through a recursive merge to modify an inherited property, then a gadget consumes that property. A positive case must demonstrate both steps; a negative case, when root control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Node.js 20 with the pinned merge library and a new process for each case; only load aggregate data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the prototype pollution use case; save raw request/response, decide policy and asset state before the test.
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider the vulnerable fixture positive only when logs prove merge has fixed the inherited property and the gadget reads the correct marker; secure fixture must block before side effect, and boundary input must fail closed.
5. **Cleanup:** delete data, marker, and logs of prototype pollution; revoke related sessions/cache, revert snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use targets, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Vulnerabilities often appear in three main forms:

### 1. Server-side Prototype Pollution leading to RCE
When a Node.js application uses functions like `child_process.fork()`, `child_process.spawn()`, or `child_process.execSync()` without fully configuring the parameters (or passing an empty options object), Node.js will check `Object.prototype` to get default configurations if they are not explicitly defined. An attacker can exploit this to pollute system configuration properties:
- **`execArgv`**: An array of parameters passed to the Node.js binary. Polluting this property to `["--eval", "payload"]` allows direct code execution when Node.js spawns a child process via `fork()`.
- **`NODE_OPTIONS` (via `env`)**: If a child process is spawned with a custom `options.env` object (e.g., `spawn('node', [], {env: {}})`), this object will inherit properties from `Object.prototype`. If an attacker pollutes `Object.prototype.NODE_OPTIONS = "--require=/tmp/payload.js"`, Node.js will load and execute malicious code at the time the child process is initialized.

### 2. Client-side Prototype Pollution leading to XSS (XSS Chains via innerHTML)  
In the browser environment, if an attacker can pollute `Object.prototype`, they can target the application's JavaScript code (DOM Gadgets) that assigns properties to DOM without validating them.  
A typical example is code that initializes an HTML element by taking the configuration value:<!-- payload-id: WEB-A08-PROTOTYPE-POLLUTION-001 -->
<!-- context: Node.js 20 with lodash.merge 4.17.11 in a disposable jsdom/Chromium fixture; config.html is inherited after a vulnerable deep merge -->
<!-- prerequisites: fresh process/browser context; synthetic span marker; no cookie, process creation or network access; delete polluted property during cleanup -->
<!-- encoding: UTF-8 JavaScript; JSON __proto__ key and marker HTML are represented in exact string bytes -->
<!-- expected-result: vulnerable div creates the marker element from inherited html; own-property safe config uses Default Content -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
const lodash = require("lodash"); // Fixture pins vulnerable 4.17.11.
const input = JSON.parse(
  '{"__proto__":{"html":"<span id=\\"prototype-lab-marker\\">LAB</span>"}}'
);
const config = {};
lodash.merge(config, input);

const div = document.createElement("div");
div.innerHTML = config.html || "Default Content";
document.body.appendChild(div);

if (!document.getElementById("prototype-lab-marker")) {
  throw new Error("fixture did not reproduce the inherited marker");
}
delete Object.prototype.html;
```
If `config.html` is not own property, JavaScript continues to look up on the prototype chain. The block above only creates a harmless marker element and cleans up the property immediately after the case; it does not read cookies or execute any process.

### 3. Specific Errors in Libraries (Library-specific)
Many older versions of popular utility libraries such as `lodash` (functions `lodash.merge`, `lodash.defaultsDeep`) or `jQuery` (function `jQuery.extend` performs deep copy) encounter errors when handling recursive keys.
- **`lodash.merge` (versions < 4.17.12)**: Allows attackers to pass an JSON object containing the key `__proto__` to overwrite global properties.
- **`jQuery.extend` (versions < 3.4.0)**: When performing a deep merge with the first parameter being `true`, this function does not check the `__proto__` key, allowing overwriting of methods/properties on `Object.prototype`.

## 9. Vulnerable Code and Secure Code

### Vulnerable Code Example (Server-side RCE & Client XSS Gadget)
```javascript
const child_process = require('child_process');
const lodash = require('lodash'); // Vulnerable version, e.g., 4.17.11

// 1. Vulnerable Server-side Merge causing RCE
function handleUserPreferences(userJson) {
  let preferences = {};
  // Vulnerable merge operation using outdated lodash version
  lodash.merge(preferences, JSON.parse(userJson));

  // Later in the application, a child process is forked
  // If Object.prototype.execArgv was polluted, it will be executed here
  child_process.fork('./worker.js');
}

// 2. Vulnerable Client-side Gadget (Simulated)
function renderWidget(widgetConfigJson) {
  let config = {};
  // Vulnerable merge
  lodash.merge(config, JSON.parse(widgetConfigJson));

  const container = document.createElement('div');
  // Vulnerable DOM gadget: fallback to prototype property if 'html' is undefined
  const contentHtml = config.html || "<span>Default widget content</span>";
  container.innerHTML = contentHtml; // XSS trigger
}

```

### Secure Code Example
```javascript
const child_process = require('child_process');

// Prevent any changes to the global Object prototype at the entrypoint
Object.freeze(Object.prototype);

// Safe merge function with explicit key sanitization
function safeMerge(target, source) {
  for (let key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // Reject dangerous keys to prevent prototype pollution
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }

      if (target[key] !== null && typeof target[key] === 'object' &&
          source[key] !== null && typeof source[key] === 'object') {
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// Safe usage of child process execution by freezing prototype and isolating env
function runSafeWorker() {
  const options = {
    // Explicitly define execArgv to override any potential polluted property
    execArgv: [],
    // Provide a fresh environment object or filter env properties
    env: Object.assign(Object.create(null), process.env)
  };
  child_process.fork('./worker.js', [], options);
}

// Safe client-side rendering using sanitization and clean objects
function renderSafeWidget(widgetConfigJson) {
  // Use a clean map without prototype
  const config = Object.create(null);
  const parsed = JSON.parse(widgetConfigJson);

  // Sanitized merge
  safeMerge(config, parsed);

  const container = document.createElement('div');
  // Safe default lookup (doesn't inherit from Object.prototype)
  const contentHtml = config.html || "<span>Default widget content</span>";

  // In real applications, sanitization (e.g. DOMPurify) should be used before innerHTML
  container.textContent = contentHtml; // Safer alternative to innerHTML
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Prototype Pollution, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to verify that the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Refuse all prototype control locks at any depth, use safe merge and authorize via own server field. [S1]
- Apply the same control to every route, operation, and corresponding processing path; failure must stop before side effects.

### Defense-in-depth

With Prototype Pollution, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used as a substitute for original controls.

- **Summary**: Prevent Prototype Pollution by freezing the Object.prototype, using objects without a prototype, and updating libraries safely. 
- **Detailed steps**:
  - **Prototype Freezing**: Call `Object.freeze(Object.prototype)` at the start of the application to prevent any modification of base object properties.
  - **Using Prototype-less Objects**: Initialize key-value data storage objects using `Object.create(null)` to completely remove prototype linkage, preventing prototype chain lookup mechanisms.
  - **Using Safe Libraries and Version Pinning**: Upgrade patched dependencies following the advisory from the dependency itself, pin the lockfile while still checking the lock at the trust boundary; a version floor does not replace gadget review. [S1]
  - **Filtering Input Data Keys**: When building merge or parse functions with JSON, always check and remove sensitive keys before merging objects.

## 12. Retest

- **Positive case:** with Prototype Pollution, valid flows still work correctly for allowed actors and data.  
- **Negative case:** with the same input/resources but unauthorized actors or contexts are denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-check:** save the minimal scenario that reproduces the old bug and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Prototype Pollution without verifying side effects and logs.
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
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Prototype Inheritance**: A mechanism in JavaScript that allows objects to inherit properties and methods from another prototype object to reuse code. 
- **Prototype Chain**: The chain of objects that JavaScript looks through when a property does not exist directly on the current object. 
- **Prototype accessor**: A historical accessor that can read or modify an object's prototype; it should not be considered a business data lock. 
- **`Object.prototype`**: The highest base object, acting as the "ancestor" of almost all objects in JavaScript. 
- **Merge (Merging Objects)**: The action of combining properties from multiple different objects into a single object. 
- **XSS (Cross-Site Scripting)**: A vulnerability that injects malicious JavaScript code into a webpage to execute on the victim's browser. 
- **Client-side**: Refers to activities and code running directly on the user's device (browser). 
- **DOM (Document Object Model)**: A tree-structured API used to represent and interact with HTML/XML document structures of a webpage. 
- **DOM Gadget**: Valid JavaScript code present on the webpage but can be exploited to trigger a security vulnerability (like XSS) when combined with controlled input. 
- **Deep Copy**: Copying an object by creating new physical copies of all nested objects inside it, rather than just copying references.

## 16. Related Lessons and Further Reading

- [Insecure Deserialization](../insecure-deserialization/) — The insecure deserialization vulnerability often combines with Prototype Pollution to exploit objects in the runtime environment.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/prototype-pollution — version/status: current version; accessed: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-pdf-archive/OWASP_Top_10_2021_Draft_v1.1.pdf — version/status: archived draft, not the current version; accessed: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1321.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.