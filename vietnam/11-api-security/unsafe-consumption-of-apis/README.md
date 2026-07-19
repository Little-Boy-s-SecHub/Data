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
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Nhận diện rủi ro khi ứng dụng tin response từ API bên thứ ba quá mức.
- Kiểm thử schema validation, signature, timeout, retry và fail-closed behavior.
- Thiết kế boundary rõ giữa API provider và consumer.

## 2. Kiến thức cần có

- JSON schema, webhook signature và mTLS/TLS validation.
- Retry/backoff và timeout.
- Data validation trước khi ghi vào domain model.

## 3. Kiến thức nền tảng

Unsafe Consumption of APIs xảy ra khi consumer coi API bên thứ ba là trusted tuyệt đối: không validate schema, không verify signature, tin URL callback, retry vô hạn hoặc ghi dữ liệu ngoài contract vào hệ thống nội bộ. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause là thiếu kiểm soát tại trust boundary outbound/inbound. Response hoặc webhook từ provider có thể bị lỗi, bị compromise, bị replay hoặc thay đổi schema. Consumer vẫn phải validate và giới hạn tác động. [S1]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** dữ liệu nội bộ, trạng thái thanh toán, đơn hàng, webhook handler.
- **Actor:** provider mock lỗi hoặc attacker giả mạo webhook.
- **Trust boundary:** dữ liệu từ API bên ngoài đi vào domain model.
- **Điều kiện cần:** consumer không verify authenticity/schema hoặc fail-open.
- **Môi trường:** mock provider local và webhook receiver local.

## 6. Cơ chế tấn công

Actor gửi webhook thiếu chữ ký, sai schema hoặc replay event. Nếu consumer xử lý như event hợp lệ, trạng thái nội bộ có thể bị thay đổi trái contract.

## 7. Kiểm thử trong lab được ủy quyền

1. Seed order `pending`.
2. Gửi webhook hợp lệ để baseline.
3. Gửi webhook thiếu signature, sai schema hoặc replay `event_id`.
4. Kỳ vọng bản sửa từ chối trước khi cập nhật order.
5. Cleanup order/event store.

## 8. Payload và phạm vi áp dụng

**Webhook thiếu signature**

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

## 9. Code dễ bị lỗi và code an toàn

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

## 10. Phát hiện

- Log provider identity, signature result, schema result and idempotency decision.
- Alert on repeated invalid signatures or schema drift.
- Track downstream side effects for every external event.

## 11. Phòng thủ

### Kiểm soát bắt buộc

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

## 13. Sai lầm thường gặp

- Trust provider response because network path is private.
- Retry state-changing requests without idempotency.
- Store third-party fields directly without allowlist.

## 14. Tóm tắt và checklist

- [ ] External API data crosses an explicit validation boundary.
- [ ] Authenticity and schema are verified.
- [ ] Retry/idempotency/circuit breaker are defined.
- [ ] Rejected events do not change business state.

## 15. Giải thích thuật ngữ

- **Consumer:** hệ thống gọi hoặc nhận dữ liệu từ API khác.
- **Webhook:** HTTP callback từ provider tới consumer.
- **Idempotency:** xử lý lặp không tạo side effect lặp.

## 16. Bài liên quan và đọc thêm

- [Supply Chain Attacks](../../03-supply-chain/supply-chain-attacks/)
- [Error Handling](../../06-insecure-design/error-handling/)
- [Logging and Monitoring](../../09-logging-alerting/logging-and-monitoring/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API10 Unsafe Consumption of APIs. https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-20 — Improper Input Validation. https://cwe.mitre.org/data/definitions/20.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-345 — Insufficient Verification of Data Authenticity. https://cwe.mitre.org/data/definitions/345.html — bản hiện hành; truy cập: 2026-07-18.
