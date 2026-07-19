---
schema_version: 1
id: WEB-A05-XSS-DOM-BASED
title: "DOM-based XSS"
slug: xss-dom-based
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

# DOM-based XSS

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain DOM-based XSS using the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in the local lab and distinguish expected results from false positives.
- Choose the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the DOM-based XSS scenario and how to apply input handling across trust boundaries.  
- Distinguish authentication, authorization, and validation.  
- Be able to read code/configuration in the language or framework that appears in the example.  
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

When a browser loads a web page, it translates the source code HTML into a tree structure diagram called DOM (Document Object Model) for management. Then, JavaScript runs to dynamically change the nodes on this DOM tree (such as changing colors, adding text). During this process, JavaScript often reads data from sources available in the browser (called sources - for example the URL part after the `#` mark) and inserts them into data reception points on the page (called sinks - for example the `innerHTML` attribute). The key point here is the way JavaScript inserts data: if it uses `innerHTML`, the browser will try to translate that data into executable code; whereas if it uses `textContent`, the browser will just treat it as harmless plain text and never run any code hidden inside.

### Example code working normally (Secure DOM Manipulation)```javascript
// Secure JavaScript implementation for handling user input in DOM
window.addEventListener('DOMContentLoaded', () => {
    // Extract user profile name from URL query parameter safely
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get('username') || 'Guest';

    // Get DOM elements
    const welcomeTextNode = document.getElementById('welcome-message');
    const customContainer = document.getElementById('custom-content');

    // Safe Method 1: Using textContent to prevent DOM XSS
    // Browser treats the content strictly as text, not HTML/JS
    welcomeTextNode.textContent = `Welcome back, ${username}!`;

    // Safe Method 2: Creating elements programmatically to render structured markup
    const paragraphElement = document.createElement('p');
    paragraphElement.textContent = 'Your profile is loaded successfully.';
    customContainer.appendChild(paragraphElement);
});
```

## 4. Description and Root Cause

The DOM-based XSS vulnerability occurs entirely within the user's browser (client-side) without direct server intervention. It arises when a website's JavaScript code retrieves data from an untrusted source and then pushes it directly into a sensitive sink (such as innerHTML or eval) without checking or sanitizing it. An attacker can trick the victim into clicking a link with an URL suffix containing malicious code. When the website loads, the client-side JavaScript automatically takes this malicious code from URL and writes it into the webpage via `innerHTML`, causing the browser to immediately execute the malicious code. This vulnerability is extremely common in modern applications (Single Page Applications) that heavily rely on JavaScript to manipulate dynamic interfaces.

> **Reference:** technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** DOM and client data from URL, storage, or message.  
- **Actor, authentication, and role:** actor controls the source; victim role is user opening the fixture.  
- **Exploitation conditions:** client source goes into innerHTML, eval, or document.write.  
- **Browser, proxy, framework, and version:** Chromium pinned with static JavaScript fixture on .lab.test; must record actual image/package version along with evidence.  
- **Mandatory evidence:** along with ID correlation, must link input, decide control, and impact the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For DOM-based, client source goes into innerHTML, eval, or document.write. The positive case must prove that the input reaches the correct sink and causes the described effect; the negative case must be blocked before side effects when origin control is enabled. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium pinned with a static JavaScript fixture on .lab.test; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input of the DOM-based use case; save raw request/response, decide policy and asset state before the test.
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and follow the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs prove that the “client source goes into innerHTML, eval, or document.write”; secure fixture must block before side effect, and boundary input must fail closed.
5. **Cleanup:** delete DOM-based data, markers, and logs; reclaim related session/cache, restore snapshot, and confirm no test callback/process remains.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use targets, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The fixture reads the fragment that has been decoded and directly assigns it to `innerHTML`. The probe only sets a marker DOM, does not read cookies, and does not transmit data externally. The results only apply to the correct source/sink and the browser policy of the fixture; a fragment appearing in URL does not by itself prove DOM XSS. [S3]

<!-- payload-id: WEB-A05-DOM-XSS-001 -->
<!-- context: pinned Chromium; decoded location.hash is assigned to element.innerHTML on a synthetic origin -->
<!-- prerequisites: local browser fixture; fresh context; no cookies or sensitive data; outbound network disabled -->
<!-- encoding: UTF-8 HTML fragment percent-encoded once in the URL and decoded once before the sink -->
<!-- expected-result: vulnerable fixture sets document.body.dataset.labExecuted to true; textContent-based fixture displays literal markup -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```html
<img src="x" onerror="document.body.dataset.labExecuted='true'">
```

## 9. Vulnerable Code and Secure Code

```javascript
// Unsafe sink example:
// element.innerHTML = location.hash; // Vulnerable to DOM XSS

// Secure approach 1: Use textContent for text data
const userInput = location.hash.substring(1);
const textElement = document.getElementById("user-display");
textElement.textContent = userInput; // Safe: content is not parsed as HTML/JS

// Secure approach 2: Sanitize HTML using DOMPurify when markup is needed
import DOMPurify from 'dompurify';

const handleHashChange = () => {
    const dirtyHtml = window.location.hash.substring(1);
    const cleanHtml = DOMPurify.sanitize(dirtyHtml);
    document.getElementById("html-display").innerHTML = cleanHtml;
};
window.addEventListener('hashchange', handleHashChange);
handleHashChange();
```

## 10. Detection

- Log actor/session, route or operation, object/resource related to DOM-based XSS, policy results, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use textContent/DOM construction and validate URL scheme before navigation.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With DOM-based XSS, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Prevent DOM-based XSS by limiting the use of innerHTML, favor using textContent, sanitize HTML with robust libraries like DOMPurify when rendering markup, and apply Trusted Types.  
- **Detailed steps**:  
  - Avoid using sinks that interpret character strings as executable code or HTML (such as `element.innerHTML`, `document.write`, `eval`, `setTimeout(string)`).  
  - Use safer API that only handle raw text (text content) instead of parsing HTML, such as `element.textContent` or `element.innerText`.  
  - When it is necessary to display HTML from external data, use a reputable sanitizing library like `DOMPurify` to remove all malicious scripts.  
  - Establish a strict content security policy (CSP) (e.g., disallow the use of `unsafe-inline`).  
  - Configure Trusted Types in the browser to enforce validation and sanitization of data before inserting it into sinks.

## 12. Retest

- **Positive case:** with DOM-based XSS, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but the actor or context is not allowed should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match ID correlation.  
- **Recheck:** keep a minimal scenario to reproduce the old error and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of DOM-based XSS without verifying side effects and logs.  
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for another original control.  
- Only fix one route while the same sink/policy is used in another route.  
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

- **DOM-based XSS**: The XSS vulnerability occurs entirely on the user's browser due to a data handling error in JavaScript.  
- **DOM (Document Object Model)**: A hierarchical document object model representing the content of a web page.  
- **Source**: Input data sources that JavaScript can read in the browser (such as location.hash, document.referrer).  
- **Sink**: JavaScript functions or properties that are sensitive and capable of executing code (such as innerHTML, eval).  
- **DOMPurify**: A library that filters and sanitizes client-side HTML code to prevent XSS.

## 16. Related Lessons and Further Reading

- [DOM Clobbering](../../dom-clobbering/) — Manipulation vulnerability DOM.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17. 
- **[S2]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — version/status: current version; accessed: 2026-07-17. 
- **[S3]** OWASP DOM based XSS Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.