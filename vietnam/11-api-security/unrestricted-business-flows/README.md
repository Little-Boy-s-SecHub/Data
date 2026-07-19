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
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Nhận diện business flow nhạy cảm không được giới hạn theo mục đích sử dụng.
- Phân biệt resource consumption chung với abuse flow nghiệp vụ như mua vé, redeem coupon, đặt lịch.
- Thiết kế guardrail theo actor, inventory, velocity và state transition.

## 2. Kiến thức cần có

- Business logic, state machine và anti-automation.
- Rate limit theo user/operation.
- Telemetry cho hành vi nhiều bước.

## 3. Kiến thức nền tảng

API6:2023 nói về flow hợp lệ về mặt kỹ thuật nhưng bị tự động hóa hoặc lạm dụng ở quy mô ngoài mục đích kinh doanh. Ví dụ: gom hàng khuyến mãi, giữ chỗ hàng loạt, redeem coupon lặp hoặc tạo tài khoản để nhận thưởng. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause là hệ thống chỉ kiểm tra request đơn lẻ mà không kiểm soát workflow, quota nghiệp vụ, inventory và intent. Rate limit HTTP chung không đủ nếu attacker chia flow qua nhiều tài khoản hoặc nhiều bước hợp lệ.

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** inventory, promotion budget, booking slot, signup reward.
- **Actor:** user hoặc bot có nhiều tài khoản synthetic.
- **Trust boundary:** chuỗi request hợp lệ đi qua business state machine.
- **Điều kiện cần:** thiếu quota/velocity/state guardrail theo flow.
- **Môi trường:** fixture local có coupon, cart và inventory giả.

## 6. Cơ chế tấn công

Actor thực hiện nhiều bước hợp lệ nhưng vượt giới hạn nghiệp vụ: reserve nhiều item, redeem nhiều coupon hoặc tạo nhiều booking trước khi checkout. Evidence cần nối nhiều request thành một flow.

## 7. Kiểm thử trong lab được ủy quyền

1. Seed inventory/coupon synthetic và quota nghiệp vụ.
2. Chạy baseline một flow hợp lệ.
3. Lặp flow vượt quota bằng cùng actor hoặc nhóm actor synthetic.
4. Kỳ vọng bản sửa chặn tại policy trước khi trừ budget/inventory.
5. Cleanup booking/coupon/cart state.

## 8. Payload và phạm vi áp dụng

**Redeem coupon vượt quota**

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

## 9. Code dễ bị lỗi và code an toàn

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

## 10. Phát hiện

- Correlate multiple steps with flow ID, actor, device and business entity.
- Alert on excessive reserve/redeem/cancel loops.
- Track business side effects, not just HTTP status.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Encode business invariants as server-side policy.
- Enforce quota/velocity by flow, not only by raw request count.
- Use idempotency keys and transactional checks for state-changing steps.

### Defense-in-depth

- Bot friction for high-risk flow.
- Abuse monitoring tied to inventory/budget.
- Manual review thresholds for suspicious flow clusters.

## 12. Retest

- **Positive:** một flow hợp lệ hoàn tất.
- **Negative:** flow vượt quota bị chặn.
- **Boundary:** retry/idempotency, concurrent redeem, multi-account cluster.
- **Telemetry:** budget/inventory không đổi sau negative case.

## 13. Sai lầm thường gặp

- Chỉ thêm captcha mà không enforce invariant.
- Dùng rate limit IP cho flow có thể chia nhiều tài khoản.
- Không test concurrency trên budget/inventory.

## 14. Tóm tắt và checklist

- [ ] Flow nhạy cảm có invariant rõ.
- [ ] Quota gắn actor/entity/business state.
- [ ] Side effect được kiểm tra trong transaction.
- [ ] Retest gồm retry và concurrency.

## 15. Giải thích thuật ngữ

- **Business flow:** chuỗi bước nghiệp vụ có mục đích rõ.
- **Invariant:** điều kiện luôn phải đúng của nghiệp vụ.
- **Idempotency key:** khóa giúp retry không tạo side effect lặp.

## 16. Bài liên quan và đọc thêm

- [Business Logic Vulnerabilities](../../06-insecure-design/business-logic-vulnerabilities/)
- [Race Conditions](../../06-insecure-design/race-conditions/)
- [API Rate Limiting](../api-rate-limiting/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API6 Unrestricted Access to Sensitive Business Flows. https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-841 — Improper Enforcement of Behavioral Workflow. https://cwe.mitre.org/data/definitions/841.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-770 — Allocation of Resources Without Limits or Throttling. https://cwe.mitre.org/data/definitions/770.html — bản hiện hành; truy cập: 2026-07-18.
