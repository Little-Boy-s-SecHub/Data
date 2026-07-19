---
schema_version: 1
id: WEB-A10-DENIAL-OF-SERVICE
title: "Denial of Service Attacks"
slug: denial-of-service
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp: []
cwe:
  - CWE-400
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Denial of Service Attacks

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Denial of Service Attacks by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and differentiate between expected results and false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of the Denial of Service Attacks scenario and how to apply input handling across trust boundaries.  
- Distinguish between authentication, authorization, and validation.  
- Be able to read code/configuration in the language or framework appearing in the example.  
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine a customer service call center with only 10 operators. Normally, when you call for assistance, a reliable connection process takes place called the **3-step Handshake (TCP 3-way handshake)**:
- Step 1: You pick up the phone and say: "Hello, I want to connect!" (SYN).
- Step 2: The operator picks up and answers: "Yes, I’m listening, can you hear me?" (SYN-ACK) and temporarily holds the line waiting for your response.
- Step 3: You say: "I can hear clearly, let’s start talking!" (ACK). The connection is officially established.

The danger arises when a harasser intentionally sabotages the system. He uses thousands of phones to automatically call the switchboard repeatedly (sending SYN packets), causing all 10 operators to pick up and ask, "I'm listening..." (SYN-ACK). However, the harasser deliberately remains silent, refusing to respond to step 3 (ACK). All 10 operators have to wait for these half-open calls in vain. 
Because the switchboard resources are limited (connection pool limits), all 10 lines are fully occupied. At this point, if a real person in distress tries to call, the system will signal busy or fail to accept the call. This is the essence of a Denial of Service (DoS - DoS) attack: crippling the system by exhausting all connection resources, preventing legitimate users from getting through.

### Illustration of normal operation (Normal Operation)```python
# Normal operation: Safe socket handler enforcing short timeouts and connection management
import socket
import select

def run_safe_server(host="127.0.0.1", port=8080):
    # Initialize a secure IPv4 TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse to avoid port binding delays
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to address and start listening with backlog limit
    server_socket.bind((host, port))
    server_socket.listen(10) # Restrict queue size for pending connections
    server_socket.setblocking(False) # Enable non-blocking mode for I/O multiplexing

    print(f"TCP server is running on {host}:{port}...")

    try:
        while True:
            # Use select to wait for incoming connections without blocking indefinitely
            readable, _, _ = select.select([server_socket], [], [], 5.0)

            for s in readable:
                if s is server_socket:
                    client_socket, addr = server_socket.accept()
                    # Enforce strict timeouts to disconnect idle or slow clients (mitigates Slowloris)
                    client_socket.settimeout(3.0)

                    try:
                        data = client_socket.recv(1024)
                        if data:
                            # Send standard HTTP response
                            client_socket.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nResponse OK")
                    except socket.timeout:
                        print(f"Connection from {addr} closed due to inactivity timeout.")
                    except Exception as e:
                        print(f"Error handling connection: {e}")
                    finally:
                        # Explicitly close client socket to free connection slots immediately
                        client_socket.close()
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        server_socket.close()
```

## 4. Description and Root Cause

The **Denial of Service (DoS - Service Denial)** vulnerability is a weakness in the way a system allocates and protects resources. When an application or network system is too naive, allowing an individual or a group of computers to request unlimited resources, an attacker will find a way to overload that system.

He can:
- Send millions of meaningless packets to clog your network bandwidth (like SYN flood).
- Open thousands of connections but send data extremely slowly so the server has to struggle waiting (like Slowloris or R.U.D.Y. with HTTP POST slow body).
- Mobilize an entire army of zombie computers (botnet) to simultaneously launch attacks from multiple directions (DDoS).
The consequence is that your website or service freezes, completely paralyzed, turning an online service into a "dead city" inaccessible to real customers.

> **Reference source:** technical claims in the lesson are marked with source markers; when applying in practice, cross-check the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** readiness, p95 latency, worker/queue, CPU and lab service memory.  
- **Trust boundary:** request body, regex parameters, or burst requests entering parser, regex engine, and worker queue.  
- **Actor:** non-privileged local client, limited in number of requests, input size, and execution time.  
- **Necessary condition:** input that causes cost amplification or consumes unlimited resources; lack of cap on size/depth/time/concurrency/queue at the exact sink.  
- **Environmental conditions:** local container without outbound access, with timeout and CPU/memory/PID cap; collect baseline latency and resource metrics before testing.

A single slow response is not enough to conclude DoS; it is necessary to prove abnormal cost increase or resources exceeding the threshold under repeatable fixture conditions. [S1]

## 6. Attack Mechanism

Regex with super-linear backtracking, too large body, or non-blocking concurrency can drain CPU, memory, or workers. Measurements must compare the same endpoint/valid input, increase in limited steps, and confirm the fix rejects early before resource-intensive tasks. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run the fixture in a container with `--cpus`, `--memory`, `--pids-limit` and timeout; enable metrics for latency, queue, CPU and memory.
2. **Input:** measure baseline with small requests, then increase regex/body length or maximum burst according to the test table.
3. **Actions:** change only one dimension at a time; record number of requests, size, elapsed time, peak resource, and status code.
4. **Expected result:** the error-prone version exceeds the lab threshold; fix returns a limit error early, keeps the worker available, and recovers to baseline after the test run.
5. **Cleanup:** stop the client/fixture, delete queue/temporary data, and confirm resources return to baseline.
6. **Safety limits:** do not run payloads on the Internet or shared environments; stop immediately when reaching the defined CPU/memory/latency threshold.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

<!-- payload-id: WEB-A10-DENIAL-OF-SERVICE-001 -->
<!-- context: Python 3.12 backtracking regex fixture in a CPU/memory-capped disposable container; pattern is fixed by the lab -->
<!-- prerequisites: limit input to at most 25 characters, use a two-second timeout and stop before the resource threshold -->
<!-- encoding: ASCII input consumed directly by the Python regex engine -->
<!-- expected-result: the vulnerable pattern shows increasing bounded elapsed time; the fixed linear pattern remains within the baseline envelope -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S4 -->
<!-- last-verified: 2026-07-17 -->
```text
aaaaaaaaaaaaaaaaaaaaaaaa!
```
Denial of Service (DoS) attacks (DoS) can target network infrastructure or directly target an application's processing logic to exhaust resources:

1. **TCP SYN Flood, Slowloris and R.U.D.Y. (Basic)**:
   - **SYN Flood**: Send a large number of TCP SYN packets but ignore the SYN-ACK response to occupy half-open connection slots.
   - **Slowloris**: Open multiple HTTP connections and send/receive data extremely slowly to keep connections busy, exhausting the connection pool.
   - **R.U.D.Y. (R-U-Dead-Yet)**: Send HTTP POST with large `Content-Length` then slowly drip the body, causing the worker to hold the request body parser longer than the baseline. Testing only uses a single local connection with a short timeout, not wide-scale deployment.

2. **Hash Collision DoS (Algorithmic Complexity DoS)**:
   - **Mechanism**: If many keys fall into the same bucket, the cost of a single operation can reach $O(N)$ and the cost of inserting a whole set of $N$ keys can reach $O(N^2)$. The structure of the bucket and the collision-handling mechanism depend on the runtime; not every hash table uses a linked list. Python enables hash randomization by default for `str` and `bytes`, but it's still necessary to limit the number of fields and request size. [S3]

3. **Algorithmic Complexity DoS - ReDoS (Regular Expression Denial of Service)**:
   - **Mechanism**: A backtracking engine can try many different ways of partitioning when an ambiguous pattern contains nested quantifiers, for example `(a+)+`. With certain patterns/inputs, the time increases exponentially; this is very slow processing and not an infinite loop. A linear engine or different pattern may not exhibit this behavior. [S4]

4. **Amplification Attacks (DNS, NTP, Memcached)**:
   - **Mechanism**: This is a network-layer DDoS attack based on the UDP protocol (does not require a handshake). The attacker spoofs the IP source address in outgoing request packets as the IP address of the victim, then sends these requests to open intermediary servers on the internet (such as Open DNS, NTP servers, or Memcached).
   - **Amplification Factor**: The response is larger than the request and is sent to the spoofed source address. The actual factor depends on the protocol, configuration, and data size; a fixed number is not used as a current attribute. `monlist` is a historically significant example (NTP) and is often disabled in updated deployments.
   All of this massive response traffic is directed to the IP of the victim, congesting their bandwidth.

5. **HTTP/2 Rapid Reset (CVE-2023-44487)**:
   - **Mechanism**: HTTP/2 allows multiplexing on a single TCP connection, where the client can simultaneously open multiple streams by sending `HEADERS` frames. HTTP/2 also defines `RST_STREAM` frames that allow the client to cancel any stream at any time if no response is needed.
   - **Attack**: The attacker continuously sends a series of `HEADERS` frames to request the opening of streams, and immediately sends `RST_STREAM` frames to cancel those streams on the same TCP connection. Since the streams are immediately canceled, the server does not need to send responses (saving bandwidth for the attacker), but the server still has to expend CPU and RAM resources to set up the stream, process the initial request, and cancel the stream. Repeating this action at a high rate causes the CPU of the web server to overload and quickly deplete stream processing resources without congesting the network bandwidth of either side.

## 9. Vulnerable Code and Secure Code

### 1. Nginx 1.25+: connection and request limits```nginx
# Resource limits complement, but do not replace, vendor security updates
http {
    # Limit requests to 10 per second per IP with a burst capacity of 20
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

    # Bound concurrent streams and requests per connection
    http2_max_concurrent_streams 100;
    keepalive_requests 1000;

    server {
        listen 443 ssl;
        http2 on;
        server_name victim.lab.test;

        # Mitigate Slowloris by setting short timeouts
        client_body_timeout 10s;
        client_header_timeout 10s;
        keepalive_timeout 5s 5s;
        send_timeout 10s;

        location / {
            limit_req zone=mylimit burst=20 nodelay;
            proxy_pass http://app_servers;
        }
    }
}
```

### 2. Regular Expression DoS (ReDoS)
```python
# === VULNERABLE: Regex with nesting qualifiers causing catastrophic backtracking ===
import re
import time

# Vulnerable regex: (a+)+$ matches groups of 'a's, but ends with a different character
# When evaluated against "aaaa...aaaX", it performs exponential backtracking
VULN_REGEX = re.compile(r"^(a+)+$")

def check_string_vuln(input_data):
    start_time = time.time()
    # Evaluating matching logic
    VULN_REGEX.match(input_data)
    duration = time.time() - start_time
    print(f"Match evaluated in {duration:.5f} seconds")

# Attack payload: 25 characters of 'a' followed by 'X'
# Will cause severe CPU spikes and take significant time to evaluate
# check_string_vuln("aaaaaaaaaaaaaaaaaaaaaaaaX")


# === SECURE FOR THIS LANGUAGE: remove the ambiguous nested quantifier ===
SAFE_REGEX = re.compile(r"^a+$")

def check_string_secure(input_data, max_length=256):
    # Length caps bound work and memory even when the pattern changes later
    if len(input_data) > max_length:
        raise ValueError("Input exceeds the documented limit")
    return SAFE_REGEX.fullmatch(input_data) is not None
```

### 3. Hash Collision DoS (Python Implementation)
```python
# === VULNERABLE: Custom hash table without collision protection ===
class SimpleHashTable:
    def __init__(self, size=1024):
        self.size = size
        # Array of buckets storing key-value pairs
        self.table = [[] for _ in range(self.size)]

    def _hash(self, key):
        # A simple modulo hash function is highly vulnerable to intentional collisions
        return sum(ord(c) for c in key) % self.size

    def insert(self, key, value):
        h = self._hash(key)
        # Append to bucket. If collision occurs, it builds a linked list
        self.table[h].append((key, value))

    def get(self, key):
        h = self._hash(key)
        # Searching the bucket in O(N) linear time if there are collisions
        for k, v in self.table[h]:
            if k == key:
                return v
        return None

# === SAFER: randomized string hashes plus explicit request limits ===
def process_request_parameters(user_params, max_fields=100):
    if len(user_params) > max_fields:
        raise ValueError("Too many request fields")
    safe_storage = {}
    for key, value in user_params.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("Invalid key")
        safe_storage[key] = value
    return safe_storage
```

## 10. Detection

- Log actor/session, route or operation, object/resource related to Denial of Service Attacks, policy results, and correlation ID; do not log secrets or entire tokens.  
- Compare authorization/validation failure with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request has reached the sink and whether it had an impact.  
- Scanner or WAF alerts are just investigation signals; they are not sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Limit resources, fail safely, and handle all possible exceptional states.
- Apply a hard cap for size/depth/time/concurrency/queue before expensive processing and use algorithms with controlled cost; rate limiting is just an additional layer.
- Use the same policy for all equivalent routes/operations; do not just fix the endpoint that appears in the PoC.

### Defense-in-depth

With Denial of Service Attacks, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used to replace original controls.

- **Summary**: Protect the system from availability depletion by implementing multiple layers of protection including rate limiting, connection timeouts, and WAF. 
- **Detailed Steps**:
  - Configure rate limiting on web servers (e.g., limit_req_zone in Nginx) to limit the request rate per IP.
  - Set short connection and body timeouts in web server configuration to automatically close idle or slow connections.
  - Enable TCP SYN cookies on the operating system to prevent connection pool depletion from SYN flood attacks.
  - Deploy dedicated DDoS mitigation services or Web Application Firewalls (WAF) to absorb and filter distributed attack traffic.

## 12. Retest

- **Positive case:** with Denial of Service Attacks, legitimate flows still work correctly for the actor and allowed data. 
- **Negative case:** the same input/resource but non-permitted actor or context is denied without leaking sensitive details. 
- **Boundary case:** check empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Recheck:** save a minimal scenario that reproduces the old bug and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Denial of Service Attacks without verifying side effects and logs.  
- Use a syntactically correct payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.  
- Only fix one route while the same sink/policy is used in another route.  
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

- **SYN (Synchronize)**: Packet that initializes a request to establish a network connection in the TCP protocol.  
- **SYN-ACK**: Server response packet to acknowledge the connection request from the client and indicate readiness to connect.  
- **ACK (Acknowledgment)**: Packet sent by the client to confirm the completion of the connection to the server.  
- **Half-open Connection**: Connection state when the client has only sent SYN, the server responds with SYN-ACK, but the client has not yet sent the final ACK to complete the connection.  
- **Connection Pool**: Group of pre-established network connections that are continuously maintained for the system to quickly reuse.  
- **Slowloris**: DoS attack technique by opening many HTTP connections to the server and keeping these connections busy by transmitting data extremely slowly.  
- **Hash Table**: Data structure that stores key-value pairs, enabling extremely fast data retrieval.  
- **Hash Collision**: Situation where two or more different keys produce the same hash value in a hash table.  
- **Backtracking**: Algorithm that searches for solutions by trying each possibility and returning to the previous step if it hits a dead end.  
- **Catastrophic Backtracking**: Phenomenon where a Regex tool hangs due to the number of possibilities to try and backtrack increasing exponentially when the input string does not match.  
- **Amplification Factor**: Index measuring the degree of increase in the size of a response packet compared to the original request packet.  
- **Botnet**: Network of devices or computers infected with malware and controlled remotely by an attacker to conduct large-scale attacks (DDoS).  
- **Stream**: Independent data flow that allows multiple requests/responses to run simultaneously over a single HTTP/2 connection.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** Python data model — hash randomization. https://docs.python.org/3/reference/datamodel.html — version/status: Python 3.14; accessed: 2026-07-18.
- **[S4]** CWE-1333. https://cwe.mitre.org/data/definitions/1333.html — version/status: current version; accessed: 2026-07-18.