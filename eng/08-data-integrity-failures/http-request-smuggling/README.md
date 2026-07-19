---
schema_version: 1
id: WEB-A08-HTTP-REQUEST-SMUGGLING
title: "HTTP Request Smuggling"
slug: http-request-smuggling
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-444
content_status: technical-review
payload_status: lab-verified
last_verified: null
---

# HTTP Request Smuggling

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain HTTP Request Smuggling using the root cause instead of just describing the consequences.
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the HTTP Request Smuggling scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clearly defined testing permissions.

## 3. Background Knowledge

Imagine a modern web system like a fast food restaurant operating at full capacity. When you send a request, it does not go straight to the chef (Back-end Server) immediately. Instead, it has to go through a cashier at the counter (Front-end Proxy/Load Balancer/CDN). To save time and speed up service, the cashier often gathers multiple requests from different customers together and sends them through a single channel (a technique called connection reuse).

For the chef and the cashier to understand each other, they must use a common protocol (HTTP/1.1) with two ways to measure the length of an order:
- **Content-Length (CL)**: Like labeling clearly "This package weighs exactly 13 grams (bytes)."
- **Transfer-Encoding (TE)**: Like sending the dish in parts (chunked) and signaling the end of the order with a part of size 0.

According to RFC 9112, a message containing both `Transfer-Encoding` and `Content-Length` is a dangerous case: the server may reject or process it according to `Transfer-Encoding`, but must close the connection after the response; the proxy must not forward ambiguous framing without normalization. Request smuggling occurs when recipients parse message boundaries differently, not because the standard allows arbitrary choice of CL or TE. [S6]

```
# Normal HTTP/1.1 request flow through proxy chain
Client ──→ [Front-end Proxy] ──TCP connection──→ [Back-end Server]
           │                                      │
           │  Request 1: POST /api                 │  Parses request boundaries
           │  Request 2: GET /home                 │  using CL or TE headers
           │  (multiplexed on same connection)     │
```

```http
# Normal request with Content-Length
POST /api/submit HTTP/1.1
Host: victim.lab.test
Content-Length: 13

{"key":"val"}
```

```http
# Normal request with Transfer-Encoding: chunked
POST /api/submit HTTP/1.1
Host: victim.lab.test
Transfer-Encoding: chunked

d\r\n
{"key":"val"}\r\n
0\r\n
\r\n
```

## 4. Description and Root Cause

The **HTTP Request Smuggling (HTTP request smuggling)** vulnerability arises mainly from the aforementioned lack of synchronization. Imagine the attacker as a clever customer. He prepares a 'super special' order combining both CL and TE labels to trick the system. The cashier at the front reads the CL label, sees a reasonable length, and lets it pass. But when it reaches the chef at the back, who prioritizes reading the TE label, he stops halfway, thinking the order is finished. The leftover part of that order still lingers on the conveyor belt.

When you – the next innocent user – go to the counter to submit your request, the attacker's previously 'smuggled' tail will automatically stick to the head of your request. As a result, the system processes your request but executes the action that the attacker had planted beforehand.

This vulnerability is extremely dangerous because it can allow attackers to:
- Bypass security control systems (WAF).
- Hijack sessions or personal information of other users when they accidentally access it afterward.
- Poison the cache, causing all other users to receive malicious content.
- Sneak into internal administrative interfaces that they normally cannot access.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4], [S5], [S6].

## 5. Threat Model and Exploitation Conditions

- **Assets:** request boundary between frontend/backend and queue/cache state. 
- **Actor, authentication and role:** anonymous raw client only reaches disposable proxy namespace. 
- **Exploitation conditions:** two hops preferably CL/TE or different parse chunks causing boundary mismatch. 
- **Browser, proxy, framework and version:** pinned frontend/backend pair, raw HTTP/1.1 socket and isolated network namespace; must record actual image/package version along with evidence. 
- **Mandatory evidence:** same correlation ID must link input, decision control and impact on correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For HTTP request smuggling, two hops prioritize CL/TE or different chunk parsing causing boundary mismatch. The positive case must demonstrate that the input reaches the correct sink and creates the described impact; the negative case, when original controls are enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the pinned frontend/backend pair, raw HTTP/1.1 socket, and isolated network namespace; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.  
2. **Baseline:** send a valid input for the http request smuggling use case; record raw request/response, determine policy, and asset state before the test.  
3. **Input and operations:** use exactly one core payload listed in item 8 within the annotated context; change one variable at a time and adhere to request cap.  
4. **Expected result:** consider the vulnerable fixture positive only when logs demonstrate the "two-hop priority CL/TE mechanism or differing chunk parsing causing boundary mismatch"; secure fixture must block before any side effect, and boundary input must fail closed.  
5. **Cleanup:** delete http request smuggling data, markers, and logs; reclaim related sessions/caches, revert snapshot, and confirm no remaining callback/test processes.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing actions must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Variants HTTP/1.1 Basic Desync:**

- **Fixture framing CL/TE does not open socket**:<!-- payload-id: WEB-A08-HTTP-REQUEST-SMUGGLING-001 -->
<!-- context: Python 3.12; HTTP/1.1 byte model according to RFC 9112; no network I/O -->
<!-- prerequisites: run the local byte-only fixture; do not open sockets or send requests to the network -->
<!-- encoding: ASCII bytes with explicit CRLF; Content-Length is calculated on body bytes -->
<!-- expected-result: the body is exactly 6 bytes long and the fixture policy returns REJECT_AMBIGUOUS_FRAMING -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
  ```python
  # Safe framing fixture: construct bytes only; never send them to a socket
  BODY = b"0\r\n\r\nG"
  AMBIGUOUS_REQUEST = (
      b"POST /fixture HTTP/1.1\r\n"
      b"Host: lab.example.test\r\n"
      b"Content-Length: 6\r\n"
      b"Transfer-Encoding: chunked\r\n"
      b"\r\n" + BODY
  )

  assert len(BODY) == 6
  assert b"Content-Length: 6\r\n" in AMBIGUOUS_REQUEST
  assert b"Transfer-Encoding: chunked\r\n" in AMBIGUOUS_REQUEST
  ```
*Explanation*: regression test only confirms byte length/CRLF and that the policy must reject ambiguous framing. It does not send a request and does not prove that a real proxy is desynced. [S6]

- **TE.CL Attack (Front-end uses TE, back-end uses CL)**: only keep the conceptual description. The old payload had inconsistent chunk size/byte length, so it was removed from the lesson; it can only be reintroduced after having a proxy pair pin version and regression evidence.

- **TE.TE/header obfuscation**: behavior depends on the parser and specific version. There is no common canonical payload; the fixture must record the exact header string and how each hop parses it before drawing a conclusion.

**2. Request capture:** the state-changing variant can affect requests of other sessions. Lesson does not release this payload; it is only simulated using two synthetic clients on a disposable proxy fixture, without using real cookies/tokens.

**3. HTTP/2 Downgrade Smuggling (H2.CL and H2.TE):**
  - **Mechanism**: Multiple front-end proxies receive HTTP/2 requests from clients but downgrade them to HTTP/1.1 before forwarding to the back-end. Since HTTP/2 is a binary protocol and determines request length through data frames, it does not require headers to define boundaries. However, attackers can manually insert `content-length` or `transfer-encoding` headers into HTTP/2 requests. Front-end proxies usually ignore these headers because there are binary frames, but when downgrading to HTTP/1.1, the proxy attaches these headers to the request sent to the back-end, causing desynchronization at the back-end.
  - **H2.CL Attack**: An attacker sends an HTTP/2 request containing a forged `content-length` header. After downgrading, the HTTP/1.1 back-end processes the request based on this `content-length` header, leaving part of the request body in the buffer to be appended to the next request.
  - **H2.TE Attack**: An attacker sends an HTTP/2 request containing an `transfer-encoding: chunked` header. When converted to HTTP/1.1, the back-end server prioritizes processing it in chunked form, causing a desync with the data stream already sent by the front-end.

**4. CL.0 Attacks (Content-Length 0):**
  - **Mechanism**: Occurs when the front-end proxy forwards the request body and uses the `Content-Length` header normally, but the back-end server is configured to ignore the body of certain requests (for example, specific API, GET, or POST) and by default considers the body length to be `0`.
  - **Attack**: The attacker sends an POST request containing additional data in the body and specifies the exact `Content-Length`. The front-end forwards the entire request. The back-end receives the request, but because it considers the body length to be `0`, it processes immediately and treats the actual body of the request as the beginning of the next request sent over the same TCP connection.

**5. Request Tunneling (Request Tunneling via Proxy):**
  - **Mechanism**: An attacker exploits the desynchronization between the proxy and the back-end to package another complete request inside the body of the first request (smuggled request).
  - This request is "tunneled" through the proxy without being checked by security policies, IP filters, authentication, or WAF set on the front-end proxy. The back-end server, when reading the data stream from the socket, separates this injected request and executes it as a valid internal request, allowing the attacker to access sensitive endpoints (such as `/admin`, `/internal-api`) or impersonate internal users.

## 9. Vulnerable Code and Secure Code

The example below only classifies the metadata framing that has already been separated by the parser fixture; it does not open a socket and does not use timeout as evidence of vulnerability.

```python
def framing_policy_vulnerable(headers):
    """Vulnerable: silently prefers Transfer-Encoding when CL and TE coexist."""
    content_length = headers.get("content-length", [])
    transfer_encoding = headers.get("transfer-encoding", [])
    if transfer_encoding:
        return "chunked"
    if content_length:
        return "content-length"
    return "no-body"


def framing_policy_secure(headers):
    """Reject ambiguous HTTP/1.1 framing before forwarding a request."""
    content_length = headers.get("content-length", [])
    transfer_encoding = headers.get("transfer-encoding", [])

    if content_length and transfer_encoding:
        raise ValueError("ambiguous Content-Length/Transfer-Encoding")
    if len(set(content_length)) > 1:
        raise ValueError("conflicting Content-Length values")
    if transfer_encoding and transfer_encoding != ["chunked"]:
        raise ValueError("unsupported Transfer-Encoding chain")
    return "chunked" if transfer_encoding else "content-length" if content_length else "no-body"


fixture_headers = {
    "content-length": ["6"],
    "transfer-encoding": ["chunked"],
}
assert framing_policy_vulnerable(fixture_headers) == "chunked"
try:
    framing_policy_secure(fixture_headers)
except ValueError as exc:
    assert str(exc) == "ambiguous Content-Length/Transfer-Encoding"
else:
    raise AssertionError("ambiguous framing was not rejected")
```
This is an illustration of policy at one hop, not a complete HTTP parser. Actual retesting still needs to use the pinned frontend/backend pair, comparing how both hops determine message boundaries and not inferring from a single timeout. [S1], [S6]

## 10. Detection

- Log the actor/session, route or operation, related object/resource regarding HTTP Request Smuggling, the policy results, and correlation ID; do not log secrets or full tokens. 
- Compare authorization/validation failure with a valid baseline and alert according to the behavior chain, not just a single payload chain. 
- Combine application, reverse proxy, and datastore telemetry to confirm that the request has reached the sink and whether or not there is an impact. 
- Scanner or WAF alert is only a signal for investigation; it is not the sole evidence that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Apply a framing policy and reject any vague CL/TE requests at the edge. 
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With HTTP Request Smuggling, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation cannot be used as a substitute for original controls.

```nginx
# Nginx — reject ambiguous requests
if ($http_transfer_encoding ~* "chunked" ) {
    # If both CL and TE are present, return 400
    set $ambiguous "TE";
}
if ($content_length != "") {
    set $ambiguous "${ambiguous}CL";
}
if ($ambiguous = "TECL") {
    return 400;  # Reject ambiguous requests
}
```
- **Summary**: Prevent HTTP Request Smuggling by using HTTP/2 end-to-end, configuring proxies to reject ambiguous requests, and normalizing HTTP headers. 
- **Detailed steps**:
  - **Use HTTP/2 end-to-end** — HTTP/2 uses binary framing, completely eliminating ambiguity in request boundaries. Ensure there is no downgrade to HTTP/1.1 at the back-end.
  - **Configure proxy to reject ambiguous requests** — reject requests containing both `Content-Length` and `Transfer-Encoding`.
  - **Normalize headers** before forwarding — strip duplicate `Transfer-Encoding`, remove obfuscation.
  - **One TCP connection per request** — disable connection reuse between front-end and back-end (reduces performance but is safer).
  - **Use testing tools** — Burp Suite's HTTP Request Smuggler extension to detect vulnerabilities.

## 12. Retest

- **Positive case:** with HTTP Request Smuggling, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource but the actor or context is not allowed, it should be rejected without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old bug and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of HTTP Request Smuggling without confirming side effects and logs. 
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for a different root control. 
- Only fix one route while the same sink/policy is used in other routes. 
- Conclude that a vulnerability exists without saving the source, fixture version, and observed evidence.

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

- **CDN (Content Delivery Network)**: A content delivery network helps speed up page loading by storing copies in multiple locations around the world closer to users.  
- **Load Balancer**: A load balancer distributes traffic evenly across backend servers to prevent overload.  
- **Reverse Proxy**: An intermediary server positioned in front of application servers to receive, process, or filter client requests before sending them into the internal system.  
- **Application Server**: An application server handles the main business logic of a website (such as database processing, login, purchasing…).  
- **Connection Reuse**: A technique of reusing a network connection (TCP) to send multiple consecutive requests to save the time of establishing new connections.  
- **TCP Connection**: A reliable network connection that ensures stable and accurate data transmission between two computers.  
- **RFC**: A set of technical standard documents specifying the operational rules of protocols on the Internet.  
- **Desync (Loss of synchronization)**: The inconsistency in understanding or data state between two or more different systems.  
- **WAF (Web Application Firewall)**: A firewall that protects web applications from attacks by filtering and monitoring HTTP traffic.  
- **Cache Poisoning**: A technique of poisoning cache, causing the system to store and return malicious content to all subsequent users accessing it.  
- **Endpoint**: The end point (specific URL address) of a service or API to which an application can send requests.  
- **Obfuscation (Making obscure)**: A technique to blur, transform, or hide information/data to avoid detection by security scanning systems while remaining functional.  
- **Downgrade**: The process of reducing a protocol or technology version to a lower level (e.g., from HTTP/2 to HTTP/1.1) for backward compatibility or vulnerability exploitation.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/request-smuggling — version/status: current version; accessed: 2026-07-18.  
- **[S2]** OWASP WSTG — Testing for HTTP Request Smuggling. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling — version/status: latest; accessed: 2026-07-18.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/444.html — version/status: current version; accessed: 2026-07-18.  
- **[S4]** James Kettle. https://portswigger.net/research/http-desync-attacks — version/status: current version; accessed: 2026-07-18.  
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.  
- **[S6]** RFC 9112 — HTTP/1.1, sections 6.3 and 11.2. https://www.rfc-editor.org/rfc/rfc9112.html — version/date: June 2022; accessed: 2026-07-18.