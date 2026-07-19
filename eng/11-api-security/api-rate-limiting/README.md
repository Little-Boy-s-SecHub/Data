---
schema_version: 1
id: WEB-A11-API-RATE-LIMITING
title: "API Rate Limiting & Resource Abuse"
slug: api-rate-limiting
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - API4:2023
cwe:
  - CWE-770
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Rate Limiting & Resource Abuse

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain API Rate Limiting & Resource Abuse by the root cause instead of just describing the consequence. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the API Rate Limiting & Resource Abuse scenario and how to apply input handling across trust boundaries.
- Differentiate authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you open a free gift booth for people. You notice that some greedy individuals line up to receive gifts and then run to the back of the line to take more dozens of times, causing those who come later to have no gifts. To solve this, you decide to appoint a security guard at the door to control: "Each person is allowed to receive a maximum of 1 gift within 1 hour."  
This frequency control mechanism in the online world is called **Rate Limiting**. It is the shield that protects your API portals from greedy individuals who deliberately send millions of continuous requests to brute force passwords, crash the server (DoS), or drain the system's resources.

To implement this, the protector can apply several methods:
- **Fixed Window**: Divide time into fixed intervals (for example, from 8:00 to 8:01 PM maximum 100 requests can be received).
- **Sliding Window**: More flexible, counting back exactly 60 seconds from the current moment to count the number of requests sent.
- **Token Bucket**: Give each user a bucket that automatically fills over time. Each time they send a request, they must submit 1 token from the bucket; if the bucket is empty, they must wait for a token to be generated automatically.
- **Leaky Bucket**: Like a bucket with a hole at the bottom. Requests poured into the bucket can come in bursts, but the water only flows out at a steady rate; if poured in too quickly and the bucket overflows, the excess requests will be dropped.

This guardian can be stationed at various checkpoints: right at the entry gate to the system (API Gateway), the protective firewall (WAF), or directly within the application (Middleware).

```python
# Simple token bucket rate limiter — normal operation
import time

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity          # Maximum tokens in bucket
        self.tokens = capacity            # Current available tokens
        self.refill_rate = refill_rate    # Tokens added per second
        self.last_refill = time.time()

    def allow_request(self):
        """Check if a request should be allowed"""
        self._refill()
        if self.tokens >= 1:
            self.tokens -= 1              # Consume one token
            return True                   # Request allowed
        return False                      # Rate limited — reject request

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

# Usage: 10 requests per second
limiter = TokenBucket(capacity=10, refill_rate=10)
```

## 4. Description and Root Cause

The vulnerability **Unrestricted Resource Consumption** occurs when your system is overly generous and lacks vigilance, allowing clients to request the execution of extremely costly tasks without any limitations.

Imagine a guest entering a restaurant and requesting: "Serve me 1 million dishes at once" (Pagination abuse) or sending a request that is pages long just to record a small line of text (Large payload DoS). If the restaurant tries to fulfill it, the kitchen would immediately be paralyzed due to overload.  
This vulnerability opens up countless dangers:  
- Attackers can freely send millions of requests to probe codes like OTP or passwords without ever being blocked.  
- Requests for the server to output millions of lines of data at once, causing RAM the server to overload and crash (OOM).  
- Sending huge files or data packets to overflow the server's memory.  
- Cloud server operating costs skyrocket due to the reckless abuse of resources, creating a shock billing situation for businesses.

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** OTP/reset/login budget, quota according to principal and capacity of handler/backend.  
- **Trust boundary:** request passes through trusted proxy/gateway and distributed counter before reaching authentication logic or resource-intensive operation.  
- **Actor:** local client using account/IP/API aggregated key; do not send traffic outside the fixture.  
- **Necessary conditions:** limiter missing, placed after handler, using wrong key/scope, not atomic between workers, or `X-Forwarded-For` data from untrusted source.  
- **Environmental conditions:** Flask 3.x, Redis 7 local, and a trusted reverse proxy; must record policy/key/window/quota and number of workers before testing.

Just changing IP/header or receiving a 200 status is not enough to prove a bypass; it is necessary to verify the counter, side effect, and the same principal/operation in the application log. [S1]

## 6. Attack Mechanism

The limiter can be exceeded when the same principal splits requests across multiple workers/IP instances, when a batch contains multiple operations but counts as only one request, or when side effects occur before `INCR`. Testing must prove the counter is atomic, has the correct dimension, and fixes returning 429 before the handler once the quota is exhausted. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run Flask 3.x, Redis 7, and local proxy; seed fake user/OTP, set quota 5 times/15 minutes, and enable counter/handler logs.
2. **Input:** send 4 valid requests as baseline, then up to 3 requests with the same principal; test separately with another user and header IP through trusted/untrusted hop.
3. **Actions:** record status, rate-limit headers, Redis key/TTL, and number of times handler/side effect is called; iterate once with limited concurrency.
4. **Expected result:** the 6th request returns 429/`Retry-After`, handler is not called; another user does not share quota and client cannot spoof trusted IP.
5. **Cleanup:** delete Redis namespace, fake OTP/user, stop proxy/app, and confirm no timers/processes remain.
6. **Safety limits:** limit total requests/concurrency, do not test on real API and do not use OTP or real user accounts.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Probe OTP has limits — check quota by actor and operation:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-001 -->
<!-- context: Python 3.12 + requests; local OTP fixture at 127.0.0.1:18080 -->
<!-- prerequisites: fixture uses fake account user-42, the trial quota is 5, and there is no outbound network -->
<!-- encoding: JSON UTF-8; OTP is always a six-digit string -->
<!-- expected-result: at most five attempts are processed; the sixth attempt returns 429 and Retry-After, without trying the full OTP space -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Bounded regression probe; never enumerate the full OTP space
import requests

TARGET = "http://127.0.0.1:18080/verify-otp"
HEADERS = {"Authorization": "Bearer lab-user-42"}

for otp in ("000000", "000001", "000002", "000003", "000004", "000005"):
    response = requests.post(
        TARGET,
        json={"otp": otp},
        headers=HEADERS,
        timeout=2,
    )
    print(otp, response.status_code, response.headers.get("Retry-After"))
```

**2. Pagination abuse — Dump entire database:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-002 -->
<!-- context: HTTP/1.1 GET; pagination parameter is an integer -->
<!-- prerequisites: local fixture contains exactly 150 fake records and documents page_size maximum 100 -->
<!-- encoding: ASCII request target; no request body -->
<!-- expected-result: server rejects page_size=101 with 400 or caps it to 100 and records the policy decision -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/users?page=1&page_size=101 HTTP/1.1
Host: api.victim.lab.test
Accept: application/json
```
**3. Boundary probe for request body limit:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-003 -->
<!-- context: Python 3.12 + requests; local import fixture at 127.0.0.1:18080 -->
<!-- prerequisites: fixture sets a 512-byte body limit; the container has a memory cap and outbound network is blocked -->
<!-- encoding: JSON UTF-8 with Content-Length generated by requests -->
<!-- expected-result: an approximately 1 KiB payload is rejected with 413 before JSON/business processing runs -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Send a small over-limit payload to a disposable local fixture
import requests

over_limit_payload = {"data": "A" * 1024}

response = requests.post(
    "http://127.0.0.1:18080/import",
    json=over_limit_payload,
    timeout=2,
)
assert response.status_code == 413
```
**4. Check for `X-Forwarded-For` untrusted from the client directly:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-004 -->
<!-- context: HTTP/1.1 GET through a local trusted-proxy fixture -->
<!-- prerequisites: direct client connection is not in the trusted proxy allowlist; no request reaches Internet -->
<!-- encoding: ASCII headers; X-Forwarded-For contains documentation address 192.0.2.10 -->
<!-- expected-result: limiter ignores the client-supplied forwarding header and uses the verified peer identity for the quota key -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/quota-probe HTTP/1.1
Host: api.victim.lab.test
X-Forwarded-For: 192.0.2.10
```
**5. IP/Header rotation cannot be separated from principal quota:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-005 -->
<!-- context: Python 3.12 + requests; local OTP fixture at 127.0.0.1:18080 behind a trusted-proxy simulator; case: WEB-A11-API-RATE-LIMITING-005 -->
<!-- prerequisites: fixture uses synthetic user-42, quota is 5 per account and per verified peer; direct client cannot assert trusted proxy headers -->
<!-- encoding: JSON UTF-8 and ASCII headers; documentation IPs are used only inside the local fixture -->
<!-- expected-result: vulnerable fixture counts each rotated header as a new bucket; fixed fixture still returns 429 after the account quota is exhausted -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-18 -->
```python
import requests

target = "http://127.0.0.1:18080/verify-otp"
for i, ip in enumerate(("192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15")):
    response = requests.post(
        target,
        json={"account": "user-42", "otp": f"{i:06d}"},
        headers={"Authorization": "Bearer lab-user-42", "X-Forwarded-For": ip},
        timeout=2,
    )
    print(ip, response.status_code)
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE: No rate limit, no pagination cap, no body limit ===
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()  # No body size limit!
    user = db.users.find_one({"email": data['email']})
    if user and check_password(data['password'], user['password']):
        return jsonify({"token": generate_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401
    # No rate limit — attacker can try millions of passwords

# === SECURE: body limit before parsing plus operation-specific throttling ===
app.config['MAX_CONTENT_LENGTH'] = 1024

@app.route('/api/login', methods=['POST'])
def login_secure():
    if request.content_length is not None and request.content_length > 1024:
        return jsonify({"error": "Request body too large"}), 413
    data = request.get_json(force=False, silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    email = data.get('email', '')

    # Account and peer quotas use normalized/server-derived identifiers.
    if not consume_login_quotas(
        server_side_identifier(normalize_account(email)),
        verified_peer_id(request),
    ):
        return jsonify({"error": "Rate limit exceeded"}), 429

    user = db.users.find_one({"email": email})
    if user and check_password(data['password'], user['password']):
        return jsonify({"token": generate_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to API Rate Limiting & Resource Abuse, the result of the policy, and ID correlation; do not log secrets or full tokens. 
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had an impact or not. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Apply control at the level of objects, attributes, functions, and resource consumption of API. 
- Use atomic/shared counters, keyed by principal and operation, executed before resource-intensive/state-changing handlers; for sensitive routes, there must be a clear policy when Redis fails. 
- Use the same policy for all equivalent routes/operations; do not just modify the endpoint appearing in the PoC.

### Defense-in-depth

With API Rate Limiting & Resource Abuse, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a replacement for original controls.

```python
# Redis Lua keeps INCR and first-window expiry atomic.
WINDOW_COUNTER = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return current
"""

def consume_quota(key, limit, window_seconds):
    current = redis_client.eval(WINDOW_COUNTER, 1, key, window_seconds)
    return int(current) <= limit

def verified_peer_id(request):
    # Use proxy-derived identity only when the direct peer is trusted.
    return trusted_proxy_client_ip(request) or request.remote_addr

@app.post('/verify-otp')
def verify_otp():
    body = request.get_json(silent=True) or {}
    account = normalize_account(body.get('account', ''))
    keys = (
        f"otp:account:{server_side_identifier(account)}",
        f"otp:peer:{verified_peer_id(request)}",
    )
    if not account or not all(consume_quota(key, 5, 900) for key in keys):
        return jsonify({"error": "Rate limit exceeded"}), 429, {"Retry-After": "900"}
    return check_synthetic_otp(account, body.get('code', ''))
```
```python
# Enforce maximum page size and request body limits
@app.route('/api/users')
def list_users():
    page = max(1, request.args.get('page', 1, type=int))
    page_size = request.args.get('page_size', 20, type=int)
    page_size = max(1, min(page_size, 100))
    users = db.users.find().skip((page - 1) * page_size).limit(page_size)
    return jsonify(users)
# Limit request body size at framework level
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max body size
```
```http
HTTP/1.1 429 Too Many Requests
RateLimit-Policy: "login";q=100;w=60
RateLimit: "login";r=0;t=30
Retry-After: 30
```
- **Summary**: Protect API from resource abuse using atomic counters across multiple dimensions determined by the server, while also limiting payload size and pagination. 
- **Detailed steps**:
  - **Rate limit across multiple dimensions**: apply quotas based on authenticated actor, verified IP/peer, API key, route/operation, and sensitive actions such as login/OTP; keys must be normalized by the server and use atomic/shared counters.
  - **Limit pagination and payload size**: set maximum `page_size`, safe defaults, restrict offset/cursor, and block bodies/files exceeding limits at the gateway or framework before parsing or business logic handling.
  - **Return rate limit headers**: return `RateLimit-Policy`, `RateLimit`, and `Retry-After` consistently for 429 responses so the client knows the remaining quota and retry timing.
  - **Normalize URL/method** before applying rate limits — prevent bypass via case variation.
  - **Do not trust `X-Forwarded-For`** from the client — only use IP from trusted proxies.

## 12. Retest

- **Positive case:** with API Rate Limiting & Resource Abuse, valid flows still work correctly for allowed actors and data.  
- **Negative case:** the same input/resource but if the actor or context is not allowed, it is rejected without leaking sensitive details.  
- **Boundary case:** test empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Rechecking:** retain minimal scenarios reproducing old bugs and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of API Rate Limiting & Resource Abuse without confirming side effects and logs.  
- Use a payload with correct syntax but incorrect DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for a different original control.  
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
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Rate Limiting**: A mechanism to control and limit the number of requests a user can send to the system within a certain period of time.
- **API Gateway**: An intermediary server that acts as the first gateway receiving and routing API requests from the outside into the system.
- **Middleware**: Code segments situated between the request reception flow and the main application logic, primarily used to check access rights or apply rate limits.
- **Token**: An identification card or authorization token used to make requests in the Token Bucket algorithm.
- **Credential Stuffing**: An attack method using lists of accounts/passwords leaked from other sources to attempt automated logins on a large scale.
- **Pagination**: A technique to divide the results returned from a database into multiple small pages to improve display performance.
- **Bill Shock**: A sudden and uncontrollable increase in cloud service bills due to overconsumption of system resources.
- **Account Lockout**: A mechanism to temporarily lock an account after a number of consecutive failed login attempts to prevent brute force attacks.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ — version/status: current version; accessed: 2026-07-18. 
- **[S2]** PortSwigger. https://portswigger.net/web-security/authentication/password-based — version/status: current version; accessed: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/770.html — version/status: current version; accessed: 2026-07-18. 
- **[S4]** IETF HTTPAPI. https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/ — version/status: draft-ietf-httpapi-ratelimit-headers-11, work in progress, 2026-05-23; accessed: 2026-07-18. 
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.