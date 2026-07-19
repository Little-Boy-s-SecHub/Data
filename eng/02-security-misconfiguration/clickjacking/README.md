---
schema_version: 1
id: WEB-A02-CLICKJACKING
title: "Clickjacking"
slug: clickjacking
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-1021
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Clickjacking

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Clickjacking by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Same-origin iframe behavior, user activation and CSS stacking.

- CSP `frame-ancestors` and `X-Frame-Options`.

- Playwright/Chromium fixture with two loopback origins.

## 3. Background Knowledge

Imagine you are browsing a game app on your phone and see a big red button that says: "Click here to receive 1,000,000 VND for free!" You excitedly tap that button. But you have no idea that a malicious person has cleverly placed an invisible transparent glass over your phone screen. On that glass, exactly in the position of the "Receive gift" button, there is actually another real button that says: "Confirm transfer of 1,000,000 VND from your bank account." When your finger touches down, the real click goes through the invisible glass and triggers the money transfer transaction, not receiving the gift. [S3]

This sophisticated phishing technique in the web world is called **Clickjacking** (Click theft) or **UI Redressing** (Interface redecoration). To perform this trick, the attacker relies on three basic tools of HTML and CSS:
- **Iframe tag (`<iframe>`)**: Like a glass window frame, this tag allows embedding an entire web page inside another web page. The attacker will embed the target website (such as a banking or social media site) into their trap page.
- **CSS z-index**: This property decides which object lies over which. The attacker places this iframe window at the top layer, covering the fake interface.
- **CSS opacity**: This attribute adjusts transparency. By setting `opacity: 0`, the attacker makes the iframe window containing the real website completely invisible to the naked eye, while it still remains there, waiting for the user to click on it. [S3]

```html
<!-- A legitimate HTML page showing a modal dialog with z-index and opacity, embedding a safe widget inside an iframe -->
<div class="page-container">
    <h1>Welcome to Our Service</h1>
    <p>Click below to preview our location map.</p>
    <button id="openMapBtn">View Map</button>

    <!-- Legitimate overlay using opacity for backdrop and z-index for proper layering -->
    <div id="modalBackdrop" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: none;"></div>

    <!-- Modal box placed above backdrop with higher z-index -->
    <div id="mapModal" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 600px; background: #fff; border-radius: 8px; z-index: 1001; display: none; padding: 20px;">
        <h2>Our Location</h2>
        <!-- Safe, visible iframe embedding a map with opacity set to 1 (visible) -->
        <iframe
            src="https://maps.lab.test/embed?place=fixture-city"
            width="100%"
            height="350"
            style="border: 0; opacity: 1.0;"
            title="Location Map"
            sandbox="allow-scripts allow-same-origin">
        </iframe>
        <button id="closeMapBtn" style="margin-top: 10px;">Close</button>
    </div>
</div>
```

## 4. Description and Root Cause

Clickjacking vulnerabilities occur when a legitimate website allows itself to be embedded into other websites (via iframe tags) without any defensive measures. [S3]

This vulnerability is extremely dangerous because it turns users' trust and voluntary actions into tools that harm themselves. Users think they are clicking to play a game, view photos, or close an ad on an ordinary entertainment website. However, in reality, they are inadvertently performing extremely sensitive actions on a hidden embedded site such as: clicking the "Follow" button on a strange account, clicking "Delete Account," or worse, pressing "Confirm Financial Transaction." Since these actions are carried out by a legitimately logged-in user, the real website server will process the request as a completely normal action, causing harm to the user without being able to blame a system error. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** operate synthetic theme-toggle; do not use for transfer/delete data.

- **Actor:** the user uses pinned Chromium and has a lab session if the route requires it.

- **Trust boundary:** policy frame-ancestors/X-Frame-Options of ui-target.lab.test when embedded by attacker.lab.test.

- **Necessary condition:** the target allows framing, correctly position the control, and actually click into the iframe.

- **Environment:** two loopback origins, fixed viewport, no extensions and no real credentials.

A screenshot of the iframe is not enough evidence; an event/server log is needed to confirm the click triggered the action on the target. [S1]

## 6. Attack Mechanism

The origin attacker places the target in a transparent iframe and aligns the real control over the decoy. When the target does not forbid framing, the user's pointer event goes to the target and triggers the action under UI, causing confusion. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** map two origins to loopback, pin Chromium/viewport and reset theme marker.
2. **Baseline:** direct action works; attacker page only shows decoy when not embedded.
3. **Operation:** open overlay and click fixed coordinates; record frame tree, console, and server events.
4. **Expected result:** bug changes marker once; fixed with frame-ancestors 'none' blocking iframe and not changing marker.
5. **Boundary:** check SAMEORIGIN, nested frame, and browsers supporting CSP/XFO.
6. **Cleanup:** delete browser profile and stop the two origins.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker places the target application's iframe transparently **on top** of a visible decoy and aligns the real control with the click position. If a link/div of the attacker is on top of the iframe and receives pointer events, the click does not reach the target, so that is not evidence of clickjacking of the target. [S3]

### Example HTML iframe overlay illustrating Clickjacking:<!-- payload-id: WEB-A02-CLICKJACKING-001 -->
<!-- context: UTF-8 HTML; pinned Chromium; attacker.lab.test embeds ui-target.lab.test, both mapped to loopback; frame-restriction model [S3] -->
<!-- prerequisites: target exposes only the harmless theme-toggle action; no authentication secret or real account is used -->
<!-- encoding: UTF-8 HTML served as text/html; the iframe URL is ASCII and requires no secondary decoding -->
<!-- expected-result: vulnerable fixture records one synthetic theme toggle; frame-ancestors 'none' blocks framing in the fixed fixture -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker-controlled lab page -->
<div style="position: relative;">
  <!-- Visible decoy aligned with the real control -->
  <button style="position: absolute; z-index: 1;">Claim reward now!</button>

  <!-- Transparent iframe overlays a harmless action in the local fixture -->
  <iframe src="https://ui-target.lab.test/lab/toggle-theme"
    style="position: absolute;
           z-index: 2;        /* Keep the target above the decoy */
           opacity: 0;        /* Hide the target while preserving pointer input */
           width: 200px;
           height: 50px;">
  </iframe>
</div>
<!-- A click lands on the aligned control inside the transparent iframe -->
```

## 9. Vulnerable Code and Secure Code

```configuration
# VULNERABLE Nginx server: framing policy is absent
server {
    listen 443 ssl;
    server_name ui-target.lab.test;
    location / { proxy_pass http://ui_backend; }
}

# SECURE Nginx server for the same UI
server {
    listen 443 ssl;
    server_name ui-target.lab.test;
    location / { proxy_pass http://ui_backend; }

    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
}
```

## 10. Detection

- Embed the target from a different origin, align the overlay, and confirm that the synthetic action actually occurs. [S3]

- Check `frame-ancestors`/`X-Frame-Options` on every response that has sensitive UI. [S3], [S4]

- Collect the browser console, frame tree, and server log of the operation; do not use a real account.

## 11. Defense

### Compulsory control

- Send CSP `frame-ancestors` suitable to limit the origin allowed to embed the page. [S4]

- Use `X-Frame-Options` for legacy clients when needed, with semantics verified. [S3]

### Defense-in-depth

- Requires confirmation/re-authentication for sensitive operations.

- SameSite cookies do not replace frame restrictions.

## 12. Retest

- **Positive:** page is embedded by an allowlisted origin if the use case requires.

- **Negative:** attacker origin cannot create a frame and has no side effect.

- **Boundary:** nested frame, redirect, error response, and supported browser.

- **Telemetry:** cross-reference the frame tree with the request and action log.

## 13. Common Mistakes

- Only use JavaScript frame-busting.

- Sends headers on the main page but misses sensitive routes/actions.

- Confused `frame-src` with `frame-ancestors`.

- Conclusion from the iframe displays without proving that the action was triggered.

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

- **Clickjacking:** UI redressing causes users to interact with embedded content without correctly recognizing the target. [S3]

- **`frame-ancestors`:** CSP directive limits the origins allowed to embed the document. [S4]

- **Overlay:** the interface layer placed on/under the target to distract the user's actions. [S3]

## 16. Related Lessons and Further Reading

- [Cross-Origin Resource Sharing](../cors/) — See more lessons about Cross-Origin Resource Sharing.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** OWASP Clickjacking Defense Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17.
- **[S4]** W3C Content Security Policy Level 3 — `frame-ancestors`. https://www.w3.org/TR/CSP/#directive-frame-ancestors — version/status: current Working Draft; accessed: 2026-07-18.