---
schema_version: 1
id: WEB-A04-DNS-POISONING
title: "DNS Poisoning"
slug: dns-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-345
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# DNS Poisoning

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain DNS Poisoning by root cause instead of just describing the consequence.
- Identify trust boundary, asset, actor, and necessary conditions for the flaw to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Recursive DNS, transaction ID, source port and cache.

- Authoritative data, TTL and DNSSEC validation state.

- Read packet transcript in an isolated network namespace.

## 3. Background Knowledge

Imagine the internet as a huge city, where each website is a house with a numeric address (called IP address). Since we humans cannot remember these complex numbers, we use domain names (like `wikipedia.org`). To find the way, our devices have to ask a "navigator" called the **DNS resolver** (usually provided by the network provider). [S3]

When you request access to a website, this navigator will go on your behalf to inquire through a series of different domain servers (called the recursive resolution mechanism - **recursive resolution**), until it encounters the server that holds the original address book (called the authoritative name server - **authoritative name server**). After receiving the exact address IP, the navigator will record it in a temporary notebook (called a cache - **DNS cache**) for a certain period (**TTL**). Next time, if you or someone in the area asks for that domain again, the navigator only needs to flip open the notebook to reply immediately without having to ask from the beginning, making web browsing much faster. [S3]

### Illustration of normal operation (Normal Operation)```python
# Normal lookup against an OS resolver configured to use the local lab resolver
import socket

def resolve_domain_normally(domain_name):
    # gethostbyname uses the OS resolver configuration; it does not itself
    # request or prove DNSSEC validation.
    try:
        ip_address = socket.gethostbyname(domain_name)
        print(f"Resolved '{domain_name}' to IP: {ip_address}")
        return ip_address
    except socket.gaierror as error:
        print(f"Failed to resolve domain {domain_name}: {error}")
        return None

# The fixture maps this reserved lab name and has no route to public DNS.
target_domain = "service.lab.test"
ip = resolve_domain_normally(target_domain)
```

## 4. Description and Root Cause

The "DNS Poisoning" vulnerability (**DNS Poisoning** or **DNS Cache Poisoning**) is like a malicious person sneaking in and swapping the addresses written in the navigator's notebook (cache). [S3]

When the navigator is sending a query to find the address of a popular website, the attacker quickly sends a bunch of fake responses containing the address IP of a 'fake house' they have set up. If the attacker is faster than the real authoritative server, the navigator will trust this fake response and store the malicious address in the cache. [S3]

As a result, from that point on, any user requesting access to that legitimate website would be redirected by the guide to the attacker's fraudulent website. This vulnerability is extremely dangerous because the victim types the correct website address in the browser, there is no clear warning at all, yet their sensitive data or login information goes directly into the hands of the malicious party. [S3]

> **📌 Distinguishing the mechanisms:**
> - **DNS cache poisoning** (this lesson): fake DNS data is accepted and stored in the resolver's cache. The scope of impact depends on whether that resolver serves a single machine or multiple clients.
> - **DNS hijacking**: a broad term for unauthorized changes to the resolution path, such as taking over a registrar/authoritative DNS account or modifying resolver configuration on a router/client. It can affect a single endpoint, an entire network, or a whole domain.
> - **Hosts-file tampering**: modifying local name mappings on a host; this is not poisoning the DNS protocol cache, although the resulting redirection effects may be similar. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** cache of the recursive resolver fixture and the authenticity of DNS answer.

- **Actor:** fake response source in the model; lesson does not create or send packets.

- **Trust boundary:** BIND 9.18 receives responses for outstanding queries and performs DNSSEC validation.

- **Necessary condition:** reply matches question/ID/addresses/port, comes before authentic reply, and data is not authenticated by DNSSEC.

- **Environment:** resolver/authoritative mock in container, synthetic zone, not public DNS.

Transcript only explains the conditions; the conclusion of poisoning requires the cache/log fixture to be changed to a fake answer, not based on a strange response. [S3]

## 6. Attack Mechanism

The resolver has outstanding queries and receives fake responses before real responses. Only responses that match the transaction tuple/question and pass validation can replace the cache; DNSSEC valid as synthetic data is rejected. [S3]

## 7. Testing in an Authorized Lab

1. **Setup:** run BIND/authoritative mock with zone .lab.test, CPU/network cap and no Internet.  
2. **Baseline:** valid query caches answer from authoritative fixture and DNSSEC valid case passes.  
3. **Operation:** use harness to simulate response matching/mismatching; lesson payload does not spontaneously generate packets.  
4. **Expected result:** legacy fixture only accepts condition-matching record; DNSSEC-validating fixture rejects synthetic data.  
5. **Boundary:** check ID, source port, question, timing and unsigned delegation separately.  
6. **Cleanup:** flush cache, delete zone/log and stop network namespace.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Within the scope of this lesson, the actor targets the outstanding query of the recursive resolver so that synthetic data enters the cache. Modifying the hosts file, changing the nameserver on the router, or taking over the authoritative DNS must be classified and tested like other mechanisms, not used as evidence of cache poisoning. [S3]

The resolver should only accept responses that match the question, query ID, the address and port of the pending query; query ID and the source port are hard to predict, increasing the space that must be guessed. [S3] With BIND 9.18, `dnssec-validation auto` uses a managed root trust anchor; unlike `yes`, which requires a configured trust anchor. [S4]

### Illustration of DNS Cache Poisoning (Kaminsky Attack 2008):<!-- payload-id: WEB-A04-DNS-POISONING-001 -->
<!-- context: conceptual transcript for an isolated legacy recursive-resolver fixture; no packet generator; forged-answer matching model [S3] -->
<!-- prerequisites: resolver accepts unsigned forged replies and has weak or predictable query-ID/source-port selection -->
<!-- encoding: UTF-8 explanatory transcript only; no DNS wire-format message, compression pointer, or packet length is emitted -->
<!-- expected-result: the transcript explains every field that must match; no traffic is emitted -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```
# Conceptual DNS cache-poisoning transcript
1. The resolver sends an outstanding query after a cache miss.
2. A forged reply must match the question, query ID, source address,
   destination address, and destination port used by that query.
3. The matching forged reply must arrive before the authentic reply.
4. A modern resolver expands the guess space with unpredictable query IDs
   and source ports; DNSSEC validation rejects forged signed data.
```

## 9. Vulnerable Code and Secure Code

```configuration
// VULNERABLE BIND 9.18 legacy fixture
options {
    recursion yes;
    allow-recursion { any; };
    dnssec-validation no;
};
```

```configuration
// SECURE BIND 9.18 recursive-resolver fixture
acl trusted_clients {
    192.0.2.0/24;
    localhost;
};

options {
    directory "/var/named";
    recursion yes;
    allow-recursion { trusted_clients; };

    // Use BIND's managed root trust anchor for DNSSEC validation
    dnssec-validation auto;
};
```

## 10. Detection

- Compare the query with the response regarding ID, question, source, and timing; only cache entries that have changed are side effects. [S3]

- Review resolver recursion, randomization, bailiwick, and DNSSEC validation configuration. [S3]

- Collect query/response/cache log locally; do not send spoofed packets to the real network.

## 11. Defense

### Compulsory control

- Use the current resolver with source-port/transaction randomization and proper validation. [S3]

- Enable DNSSEC validation when the zone/trust model supports it and handle failures according to the policy. [S3]

### Defense-in-depth

- Recursion limit allowed for the client.

- Monitoring cache anomaly supports detection, does not authenticate data.

## 12. Retest

- **Positive:** authoritative valid response cached according to TTL.

- **Negative:** incorrect response to transaction/question/source or DNSSEC fail is discarded.

- **Boundary:** retry, fragment, CNAME chain, TTL zero and clock skew.

- **Telemetry:** cross-check packet transcript, validation state, and cache entry.

## 13. Common Mistakes

- Only saw DNS returning IP abnormally and concluded cache poisoning.

- Ignore the source port, question, and timing of the response.

- Call the HTTPS certificate warning evidence that DNS has been poisoned.

- Send spoof packets out to a real interface for demonstration.

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

- **Recursive resolver:** the server that the client queries the string DNS and caches the result. [S3]

- **Forged answer:** the fake response must match the fields/timing that the resolver uses to identify the query. [S3]

- **DNSSEC validation:** check the signature/trust string before considering the data secure. [S4]

## 16. Related Lessons and Further Reading

- [Downgrade Attacks](../downgrade-attacks/) — See more lessons about Downgrade Attacks.

## 17. References

- **[S3]** RFC 5452 — Measures for Making DNS More Resilient against Forged Answers. https://www.rfc-editor.org/rfc/rfc5452.html — version/date: January 2009; accessed: 2026-07-17.
- **[S4]** ISC BIND 9.18 DNSSEC Guide. https://bind9.readthedocs.io/en/v9.18.38/dnssec-guide.html — version: BIND 9.18.38; accessed: 2026-07-17.