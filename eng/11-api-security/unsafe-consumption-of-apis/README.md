---
schema_version: 1
id: WEB-A11-UNSAFE-CONSUMPTION-OF-APIS
title: "Unsafe Consumption of APIs"
slug: unsafe-consumption-of-apis
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - api-integration-basics
owasp:
  - API10:2023
cwe:
  - CWE-20
  - CWE-345
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Unsafe Consumption of APIs

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- Identify risks when excessively applying response data from the third-party API.
- Test schema validation, signature, timeout, retry, and fail-closed behavior.
- Design a clear boundary between the API provider and consumer.

## 2. Prerequisites

- JSON schema, webhook signature, and mTLS/TLS validation.
- Retry/backoff and timeout.
- Data validation before writing into the domain model.

## 3. Background Knowledge

Unsafe Consumption of APIs happens when the consumer considers the third-party API to be absolutely trusted: not validating the schema, not verifying the signature, trusting URL callback, unlimited retries, or writing data outside the contract into the internal system. [S1]

## 4. Description and Root Cause

The root cause is the lack of control at the outbound/inbound trust boundary. Responses or webhooks from the provider may be erroneous, compromised, replayed, or have a changed schema. Consumers still need to validate and limit impact. [S1]

## 5. Threat Model and Exploitation Conditions

- **Assets:** internal data, payment status, orders, webhook handler. 
- **Actor:** mock provider with errors or attacker impersonating webhook. 
- **Trust boundary:** data from external API entering the domain model. 
- **Precondition:** consumer does not verify authenticity/schema or fail-open. 
- **Environment:** local mock provider and local webhook receiver.

## 6. Attack Mechanism

The actor sent a webhook missing a signature, with an incorrect schema, or a replayed event. If the consumer processes it as a valid event, the internal state may be altered against the contract.

## 7. Testing in an Authorized Lab

1. Seed order `pending`. 
2. Send a valid webhook for baseline. 
3. Send a webhook missing signature, wrong schema, or replay `event_id`. 
4. Expect rejection fix before updating the order. 
5. Cleanup order/event store.

## 8. Payloads and Scope of Applicability

**Webhook missing signature**

<!-- payload-id: WEB-A11-UNSAFE-CONSUMPTION-OF-APIS-001 -->
<!-- context: HTTP/1.1 POST against local webhook fixture at 127.0.0.1:18080; case: WEB-A11-UNSAFE-CONSUMPTION-OF-APIS-001 -->
<!-- prerequisites: order-123 is pending and provider signing secret is configured only in fixture -->
<!-- encoding: JSON UTF-8; no real provider secret is used -->
<!-- expected-result: vulnerable fixture marks order paid; fixed fixture rejects missing signature and leaves order unchanged -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/webhooks/payment HTTP/1.1
Host: api.victim.lab.test
Content-Type: application/json

{"event_id":"evt-123","type":"payment.succeeded","order_id":"order-123","amount":1000}
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: trusts webhook body directly.
def payment_webhook(body):
    mark_paid(body["order_id"])

# SECURE: verifies authenticity, schema and idempotency first.
def payment_webhook_secure(body, signature):
    verify_signature(body, signature)
    event = validate_schema(body)
    if seen_event(event["event_id"]):
        return "duplicate"
    mark_paid_if_amount_matches(event["order_id"], event["amount"])
```

## 10. Detection

- Log provider identity, signature result, schema result and idempotency decision.
- Alert on repeated invalid signatures or schema drift.
- Track downstream side effects for every external event.

## 11. Defense

### Compulsory control

- Verify webhook signatures or mTLS where applicable.
- Validate schema and business invariants before side effects.
- Use timeout, retry budget and circuit breaker for outbound calls.

### Defense-in-depth

- Quarantine unknown event types.
- Pin provider endpoints and TLS settings.
- Monitor schema/version drift.

## 12. Retest

- **Positive:** valid signed event updates expected state.
- **Negative:** missing signature, wrong schema and replay are rejected.
- **Boundary:** timeout, partial provider outage, duplicated event.
- **Telemetry:** no side effect for rejected event.

## 13. Common Mistakes

- Trust provider response because network path is private.
- Retry state-changing requests without idempotency.
- Store third-party fields directly without allowlist.

## 14. Summary and Checklist

- [ ] External API data crosses an explicit validation boundary.
- [ ] Authenticity and schema are verified.
- [ ] Retry/idempotency/circuit breaker are defined.
- [ ] Rejected events do not change business state.

## 15. Glossary

- **Consumer:** a system that calls or receives data from another API. 
- **Webhook:** HTTP callback from provider to consumer. 
- **Idempotency:** repeated processing does not create repeated side effects.

## 16. Related Lessons and Further Reading

- [Supply Chain Attacks](../../03-supply-chain/supply-chain-attacks/)
- [Error Handling](../../06-insecure-design/error-handling/)
- [Logging and Monitoring](../../09-logging-alerting/logging-and-monitoring/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API10 Unsafe Consumption of APIs. https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/ — current version; accessed: 2026-07-18.
- **[S2]** CWE-20 — Improper Input Validation. https://cwe.mitre.org/data/definitions/20.html — current version; accessed: 2026-07-18.
- **[S3]** CWE-345 — Insufficient Verification of Data Authenticity. https://cwe.mitre.org/data/definitions/345.html — current version; accessed: 2026-07-18.