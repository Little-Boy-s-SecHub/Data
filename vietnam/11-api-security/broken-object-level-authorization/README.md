---
schema_version: 1
id: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION
title: "Broken Object Level Authorization (BOLA)"
slug: broken-object-level-authorization
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API1:2023
cwe:
  - CWE-639
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Broken Object Level Authorization (BOLA)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Phân biệt BOLA với IDOR nói chung: trọng tâm là authorization theo từng object API.
- Kiểm thử request đổi object ID mà vẫn giữ cùng actor, token và operation.
- Thiết kế retest chứng minh policy kiểm tra owner/scope trước khi đọc hoặc ghi dữ liệu.

## 2. Kiến thức cần có

- HTTP method, path parameter, query parameter và JSON body.
- Authentication vs authorization.
- Cách API biểu diễn object ID bằng integer, UUID hoặc opaque key.

## 3. Kiến thức nền tảng

BOLA xảy ra khi API tin rằng một user đã đăng nhập thì được phép truy cập mọi object có ID hợp lệ. Object ID có thể nằm trong URL, query string, header hoặc body. ID khó đoán chỉ giảm xác suất dò, không thay thế kiểm tra quyền trên server. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause là handler lấy object theo ID client gửi nhưng không ràng buộc object đó với actor hiện tại, tenant hiện tại hoặc scope được cấp. Lỗi thường xuất hiện ở endpoint đọc chi tiết, cập nhật profile, tải invoice, xem order hoặc mutation GraphQL. [S1]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** object thuộc user/tenant khác, như order, invoice, ticket hoặc profile.
- **Actor:** user thường có token hợp lệ cho chính mình.
- **Trust boundary:** object ID từ client đi vào service/data layer.
- **Điều kiện cần:** API trả hoặc sửa object không thuộc actor nhưng chỉ dựa vào ID.
- **Môi trường:** fixture local có user A, user B và object riêng cho từng user.

## 6. Cơ chế tấn công

Actor gửi request hợp lệ cho object của mình để lấy baseline, sau đó thay object ID sang object của user khác. Evidence phải chứng minh response hoặc side effect thuộc object khác owner, không chỉ dựa vào status code.

## 7. Kiểm thử trong lab được ủy quyền

1. Seed `user-a` với `order-a` và `user-b` với `order-b`.
2. Gửi request baseline bằng token `user-a` tới `order-a`.
3. Gửi cùng method/headers nhưng đổi ID sang `order-b`.
4. Kỳ vọng bản lỗi trả dữ liệu `order-b`; bản sửa trả 403 hoặc 404 không phân biệt tồn tại.
5. Ghi log actor, object ID, owner trong datastore và policy decision.
6. Cleanup token, object và log fixture.

## 8. Payload và phạm vi áp dụng

Payload chỉ dùng object ID synthetic trong fixture local.

**BOLA read probe**

<!-- payload-id: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION-001 -->
<!-- context: HTTP/1.1 GET against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-OBJECT-LEVEL-AUTHORIZATION-001 -->
<!-- prerequisites: seed user-a, user-b, order-a and order-b; token belongs only to user-a -->
<!-- encoding: ASCII request target and bearer token placeholder -->
<!-- expected-result: vulnerable fixture returns order-b to user-a; fixed fixture returns 403 or ownership-neutral 404 before data access -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
GET /api/orders/order-b HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer USER_A_TOKEN
Accept: application/json
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: fetches by user-controlled object ID only.
def get_order_vulnerable(order_id, current_user):
    return db.orders.find_one({"id": order_id})

# SECURE: binds object access to the authenticated principal.
def get_order_secure(order_id, current_user):
    order = db.orders.find_one({"id": order_id, "owner_id": current_user.id})
    if order is None:
        raise NotFound()
    return order
```

## 10. Phát hiện

- Log actor, object ID, owner ID, tenant ID và policy decision.
- So sánh baseline allowed object với cross-owner object.
- Không kết luận chỉ vì ID tuần tự; phải có dữ liệu hoặc side effect trái quyền.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Kiểm tra object authorization trong mọi function đọc/ghi object.
- Query datastore bằng cả object ID và owner/tenant/scope.
- Áp policy nhất quán ở REST, GraphQL, batch và background action.

### Defense-in-depth

- Dùng ID khó đoán, audit log và anomaly detection, nhưng không thay thế object-level authorization.
- Ẩn khác biệt 403/404 nếu threat model cần giảm object enumeration.

## 12. Retest

- **Positive:** user đọc/sửa object của chính mình thành công.
- **Negative:** user không đọc/sửa object của user khác.
- **Boundary:** ID không tồn tại, ID thuộc tenant khác, batch nhiều ID.
- **Telemetry:** policy decision khớp datastore owner.

## 13. Sai lầm thường gặp

- Coi JWT hợp lệ là đủ quyền với mọi object.
- Chỉ kiểm tra UI mà bỏ qua API trực tiếp.
- Dựa vào UUID/random ID thay cho authorization.

## 14. Tóm tắt và checklist

- [ ] Mọi object access có kiểm tra owner/tenant/scope.
- [ ] Test có ít nhất hai actor và hai object khác owner.
- [ ] Response và side effect đều được xác minh.
- [ ] Bản sửa không chỉ chặn một endpoint trong PoC.

## 15. Giải thích thuật ngữ

- **BOLA:** Broken Object Level Authorization, lỗi thiếu kiểm tra quyền trên từng object.
- **Object ID:** định danh tài nguyên do API nhận từ client.
- **Tenant:** ranh giới dữ liệu giữa tổ chức/khách hàng.

## 16. Bài liên quan và đọc thêm

- [IDOR](../../01-broken-access-control/idor/)
- [Broken Access Control](../../01-broken-access-control/broken-access-control/)
- [GraphQL Vulnerabilities](../graphql-vulnerabilities/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API1 Broken Object Level Authorization. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-639 — Authorization Bypass Through User-Controlled Key. https://cwe.mitre.org/data/definitions/639.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — bản hiện hành; truy cập: 2026-07-18.
