---
schema_version: 1
id: WEB-A11-UNRESTRICTED-BUSINESS-FLOWS
title: "Unrestricted Access to Sensitive Business Flows"
slug: unrestricted-business-flows
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - business-logic-basics
owasp:
  - API6:2023
cwe:
  - CWE-841
  - CWE-770
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Unrestricted Access to Sensitive Business Flows

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- Identify sensitive business flows without being limited by their intended use.
- Distinguish general resource consumption from abuse flows in business operations such as ticket purchasing, coupon redemption, or scheduling.
- Design guardrails according to actor, inventory, velocity, and state transition.

## 2. Prerequisites

- Business logic, state machine, and anti-automation.
- Rate limit per user/operation.
- Telemetry for multi-step behavior.

## 3. Background Knowledge

API6:2023 talks about flows that are technically valid but are automated or abused on a scale beyond business purposes. For example: collecting promotional goods, bulk booking, repeated coupon redemption, or creating accounts to receive rewards. [S1]

## 4. Description and Root Cause

The root cause is that the system only checks individual requests without controlling the workflow, business quota, inventory, and intent. The general rate limit HTTP is not sufficient if an attacker distributes the flow across multiple accounts or multiple valid steps.

## 5. Threat Model and Exploitation Conditions

- **Assets:** inventory, promotion budget, booking slot, signup reward.
- **Actor:** user or bot with multiple synthetic accounts.
- **Trust boundary:** valid request chain passing through the business state machine.
- **Preconditions:** lacking quota/velocity/state guardrail according to the flow.
- **Environment:** local fixture with fake coupon, cart, and inventory.

## 6. Attack Mechanism

The actor performs many valid steps but exceeds business limits: reserving multiple items, redeeming multiple coupons, or creating multiple bookings before checkout. Evidence needs to connect multiple requests into one flow.

## 7. Testing in an Authorized Lab

1. Seed inventory/coupon synthetic and operational quota.  
2. Run a baseline with a valid flow.  
3. Repeat the flow exceeding the quota using the same actor or synthetic actor group.  
4. Expected fix to block at the policy before deducting budget/inventory.  
5. Cleanup booking/coupon/cart state.

## 8. Payloads and Scope of Applicability

**Redeem coupon over quota**

<!-- payload-id: WEB-A11-UNRESTRICTED-BUSINESS-FLOWS-001 -->
<!-- context: HTTP/1.1 POST against local coupon fixture at 127.0.0.1:18080; case: WEB-A11-UNRESTRICTED-BUSINESS-FLOWS-001 -->
<!-- prerequisites: coupon LAB10 allows one redemption per user and test user has zero redemptions -->
<!-- encoding: JSON UTF-8 -->
<!-- expected-result: vulnerable fixture accepts repeated redemptions; fixed fixture accepts first request and rejects subsequent requests without reducing budget -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/coupons/LAB10/redeem HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{"cart_id":"cart-123"}
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: validates coupon existence only.
def redeem(coupon, user, cart):
    cart.discount += coupon.value
    coupon.remaining_budget -= coupon.value

# SECURE: enforces the business invariant before side effects.
def redeem_secure(coupon, user, cart):
    if already_redeemed(user.id, coupon.id):
        raise Conflict("coupon already redeemed")
    with transaction():
        mark_redeemed(user.id, coupon.id)
        apply_discount(cart, coupon)
```

## 10. Detection

- Correlate multiple steps with flow ID, actor, device and business entity.
- Alert on excessive reserve/redeem/cancel loops.
- Track business side effects, not just HTTP status.

## 11. Defense

### Compulsory control

- Encode business invariants as server-side policy.
- Enforce quota/velocity by flow, not only by raw request count.
- Use idempotency keys and transactional checks for state-changing steps.

### Defense-in-depth

- Bot friction for high-risk flow.
- Abuse monitoring tied to inventory/budget.
- Manual review thresholds for suspicious flow clusters.

## 12. Retest

- **Positive:** a valid flow completes.  
- **Negative:** flow exceeding quota is blocked.  
- **Boundary:** retry/idempotency, concurrent redeem, multi-account cluster.  
- **Telemetry:** budget/inventory unchanged after negative case.

## 13. Common Mistakes

- Only add captcha without enforcing invariant. 
- Use rate limit IP for flows that can be split across multiple accounts. 
- Do not test concurrency on budget/inventory.

## 14. Summary and Checklist

- [ ] Sensitive flow has clear invariants. 
- [ ] Quota is attached to actor/entity/business state. 
- [ ] Side effects are checked within the transaction. 
- [ ] Retest includes retry and concurrency.

## 15. Glossary

- **Business flow:** a chain of business steps with a clear purpose.
- **Invariant:** a condition that must always hold true for the business process.
- **Idempotency key:** a key that helps retries not create repeated side effects.

## 16. Related Lessons and Further Reading

- [Business Logic Vulnerabilities](../../06-insecure-design/business-logic-vulnerabilities/)
- [Race Conditions](../../06-insecure-design/race-conditions/)
- [API Rate Limiting](../api-rate-limiting/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API6 Unrestricted Access to Sensitive Business Flows. https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ — current version; access: 2026-07-18.
- **[S2]** CWE-841 — Improper Enforcement of Behavioral Workflow. https://cwe.mitre.org/data/definitions/841.html — current version; access: 2026-07-18.
- **[S3]** CWE-770 — Allocation of Resources Without Limits or Throttling. https://cwe.mitre.org/data/definitions/770.html — current version; access: 2026-07-18.