---
schema_version: 1
id: WEB-A06-RACE-CONDITIONS
title: "Race Conditions (TOCTOU)"
slug: race-conditions
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-362
  - CWE-367
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Race Conditions (TOCTOU)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Race Conditions (TOCTOU) by root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of Race Conditions (TOCTOU) scenarios and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you and a friend share a bank account with only 1,000,000 VND. At the same second, both of you are at two different ATM ATMs and both press the command to withdraw 1,000,000 VND. The first ATM ATM asks the server: "Does this account have enough money?" - The server replies: "Yes, it has 1,000,000 VND." However, just before the server can deduct the money at the first ATM ATM, the second ATM ATM also sends the same question, and the server still replies: "Yes, it has 1,000,000 VND" (because the balance has not been deducted yet). As a result, both ATM ATMs dispense money, and you have withdrawn 2,000,000 VND from an account that only had 1,000,000 VND. This resource contention phenomenon is called a **Race Condition**.

In modern computer systems, to serve thousands of users simultaneously, servers must handle multiple requests in parallel (multithreading). When these requests read and write to a common database at the same time, if not carefully ordered, they can overwrite each other.

The most common case is the **TOCTOU (Time-of-Check to Time-of-Use)** error. This is a two-step process: first, the system checks the condition (Check), and then performs the action based on that result (Use). The extremely short gap between these two steps is the **race window**. An attacker will try to insert themselves into this gap to perform an action before the system can register the change.

Example of a normal money transfer process:

```python
# A single-threaded demonstration; this is not sufficient for concurrent production use.
def transfer(sender_id, receiver_id, amount):
    sender = get_account(sender_id)

    # CHECK: verify sufficient balance
    if sender.balance >= amount:
        # USE: deduct and credit
        sender.balance -= amount
        receiver = get_account(receiver_id)
        receiver.balance += amount
        save(sender)
        save(receiver)
        return "Transfer successful"

    return "Insufficient funds"
```
In the illustration without concurrency, the code can produce the expected result. In a real system, correctness also depends on transactions, partial failures, and data writing rules. When two requests simultaneously read the same balance before updating, the invariant can be broken and create double spending.

## 4. Description and Root Cause

A Race Condition occurs when the correctness of a program depends on the timing or order of execution of parallel processes.

Attackers exploit this vulnerability by using tools to send a large number of identical requests to the server within the same millisecond. By flooding the server in this way, they intentionally create a contention situation to bypass the system's logic checks.

The danger of this vulnerability is that an attacker can carry out illegal actions such as withdrawing money beyond the limit (double spending), applying a discount code multiple times to get free goods, voting repeatedly, or registering multiple accounts with the same username. This flaw is extremely difficult to detect if testing is done only in the usual step-by-step manner.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare against the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** balance, coupon, and invariant one-time. 
- **Actor, authentication, and role:** role user sends exactly two simultaneous requests on the account fixture. 
- **Exploitation conditions:** check-then-write is not atomic for the two requests, seeing the same old state. 
- **Browser, proxy, framework, and version:** Python 3.12 aiohttp and PostgreSQL 16 at 127.0.0.1 with two-request cap; must record actual image/package version along with evidence. 
- **Mandatory evidence:** the same correlation ID must link input, control decision, and impact on the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

For race conditions, check-then-write is not atomic for two requests seeing the same old state. The positive case must prove that the input reaches the correct sink and produces the described effect; the negative case, when original control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12 aiohttp and PostgreSQL 16 at 127.0.0.1 with a two-request cap; only load aggregated data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the race conditions use case; save raw request/response, determine policy and asset state before the test.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and adhere to the request cap.
4. **Expected result:** consider the vulnerable fixture as positive only when logs prove the “check-then-write not atomic for two requests seeing the same old state” mechanism; secure fixture must block side effects beforehand and boundary input must fail closed.
5. **Cleanup:** delete race conditions data, markers, and logs; reclaim related session/cache, revert snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker uses a tool to send multiple simultaneous requests to exploit the race window:

<!-- payload-id: WEB-A06-RACE-CONDITIONS-001 -->
<!-- context: Python 3.12 and aiohttp fixture calling a disposable ledger at 127.0.0.1:9002 -->
<!-- prerequisites: synthetic accounts and single-use coupon; database snapshot; exactly two concurrent requests; no outbound network -->
<!-- encoding: application/json encoded by aiohttp from the Python dictionary -->
<!-- expected-result: vulnerable fixture may record two credits while the fixed fixture records exactly one credit and one conflict -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Attack: sending concurrent requests to exploit race window
import asyncio
import aiohttp

async def exploit_double_spend(session, url, headers, payload):
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "http://127.0.0.1:9002/api/redeem-coupon"
    headers = {"Authorization": "Bearer SYNTHETIC_LAB_TOKEN"}
    payload = {"coupon": "LAB-ONCE", "account": "fixture-user"}

    async with aiohttp.ClientSession() as session:
        # Keep the race test bounded to exactly two identical requests
        tasks = [exploit_double_spend(session, url, headers, payload) for _ in range(2)]
        results = await asyncio.gather(*tasks)

        # Count successful transfers (should be 1, but may be more)
        success = sum(1 for r in results if r.get("status") == "success")
        print(f"Successful transfers: {success}")

asyncio.run(main())
```
With Burp Suite, an attacker can use the **"Send group in parallel (last-byte sync)"** feature in Repeater to synchronize the exact timing of request sending, maximizing the chance of hitting the race window.

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: read-then-write without locking
def redeem_coupon(user_id, coupon_code):
    coupon = db.query("SELECT * FROM coupons WHERE code = %s", coupon_code)
    if coupon and not coupon.used:
        # Race window: another request can pass the check here
        db.execute("UPDATE coupons SET used = TRUE WHERE code = %s", coupon_code)
        db.execute("UPDATE users SET balance = balance + %s WHERE id = %s", coupon.value, user_id)
        return {"status": "success", "credited": coupon.value}
    return {"status": "error", "message": "Invalid or used coupon"}
```

```python
# SECURE: atomic operation with database-level protection
def redeem_coupon_safe(user_id, coupon_code):
    # Atomic update: only succeeds if coupon is not yet used
    result = db.execute(
        "UPDATE coupons SET used = TRUE, used_by = %s "
        "WHERE code = %s AND used = FALSE "
        "RETURNING value",
        user_id, coupon_code
    )

    if result.rowcount == 1:
        coupon_value = result.fetchone().value
        # Credit user within same transaction
        db.execute(
            "UPDATE users SET balance = balance + %s WHERE id = %s",
            coupon_value, user_id
        )
        db.commit()
        return {"status": "success", "credited": coupon_value}

    db.rollback()
    return {"status": "error", "message": "Invalid or already used coupon"}
```

## 10. Detection

- Log the actor/session, route or operation, related object/resource for Race Conditions (TOCTOU), policy results, and correlation ID; do not log secrets or full tokens.  
- Compare authorization/validation failure with a valid baseline and alert according to the behavior chain, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact.  
- Scanner or WAF alerts are only investigation signals; they are not sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Enforce invariants using atomic conditional updates, transactions, or unique constraints.
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before any side effects.

### Defense-in-depth

With Race Conditions (TOCTOU), the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Prevent Race Condition by using atomic database operations, locking mechanisms at the DB level, or distributed locks (Redis). 
- **Detailed steps**:
  - **Database-level locking**: Use `SELECT ... FOR UPDATE` or optimistic locking with a version column to serialize operations on the same record.
  - **Atomic operations**: Use atomic SQL statements instead of separate read-then-write operations.
  - **Distributed locks**: Use Redis locks or database advisory locks for distributed systems.
  - **Idempotency keys**: Require clients to send a unique key with each operation; the server rejects duplicate keys.

## 12. Retest

- **Positive case:** with Race Conditions (TOCTOU), the valid flow still works correctly for the actor and the allowed data.  
- **Negative case:** with the same input/resources, if the actor or context is not allowed, it should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, extreme values, different encoding, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old bug and prove the fix is not dependent on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Race Conditions (TOCTOU) without confirming side effects and logs.  
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for a different original control.  
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

- **Multithreading**: Technology that allows a computer program to simultaneously execute multiple threads of work to optimize performance and processing speed.
- **Concurrency**: The ability of a system to handle multiple tasks or requests overlapping in time, giving the impression that they are running in parallel simultaneously.
- **Shared Resource**: Any data variable, file, or memory area that multiple processes or threads can access and modify.
- **Time-of-Check to Time-of-Use (TOCTOU)**: A class of time-related security vulnerabilities that occurs when there is a delay between the moment a resource's validity is checked and the moment the resource is actually used.
- **Race Window**: The small time interval between when a condition is checked and when an action is performed, providing an opportunity for an attacker to intervene and modify data.
- **Atomic Operations**: Operations whose effects are observed as an indivisible unit according to a defined scope and consistency model; it does not mean that all code inside cannot be interrupted by the scheduler.

## 16. Related Lessons and Further Reading

- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/) — Business logic vulnerabilities, where Race Conditions are often used to break assumptions and business processes such as purchasing or payment.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/race-conditions — version/status: current version; access: 2026-07-18.
- **[S2]** CWE-367 — Time-of-check Time-of-use Race Condition. https://cwe.mitre.org/data/definitions/367.html — version/status: CWE 4.20; access: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/362.html — version/status: current version; access: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; access: 2026-07-18.