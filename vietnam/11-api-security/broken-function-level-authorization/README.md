---
schema_version: 1
id: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION
title: "API Broken Function Level Authorization (BFLA)"
slug: broken-function-level-authorization
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API5:2023
cwe:
  - CWE-285
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Broken Function Level Authorization (BFLA)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Nhận diện API function chỉ dành cho admin/operator nhưng user thường vẫn gọi được.
- Kiểm thử method/path/role matrix thay vì chỉ một request đơn.
- Thiết kế policy ở gateway/service layer không phụ thuộc UI.

## 2. Kiến thức cần có

- HTTP method, route, role và permission.
- RBAC/ABAC cơ bản.
- Khác biệt giữa object-level và function-level authorization.

## 3. Kiến thức nền tảng

BFLA tập trung vào quyền gọi chức năng. Một user có thể không truy cập được object của người khác nhưng vẫn gọi được function admin như export, approve, delete hoặc config update nếu route thiếu kiểm tra role. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause là API route được expose nhưng policy không kiểm tra role/scope tương ứng với function. Lỗi thường nằm ở endpoint admin, method ít dùng, route legacy hoặc route chỉ bị ẩn khỏi UI. [S1]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** chức năng quản trị, bulk export, status transition, config change.
- **Actor:** user thường có token hợp lệ.
- **Trust boundary:** route/method đi qua gateway và service controller.
- **Điều kiện cần:** function nhạy cảm thiếu role/scope check.
- **Môi trường:** fixture local có token user và token admin.

## 6. Cơ chế tấn công

Actor lấy endpoint từ OpenAPI, mobile app hoặc traffic; sau đó gọi function nhạy cảm bằng token user thường. Evidence phải ghi function được thực thi hoặc bị policy chặn.

## 7. Kiểm thử trong lab được ủy quyền

1. Liệt kê route/method nhạy cảm trong fixture.
2. Gọi baseline bằng token admin.
3. Gọi cùng request bằng token user thường.
4. Kỳ vọng bản sửa trả 403 trước side effect.
5. Cleanup state thay đổi bởi test.

## 8. Payload và phạm vi áp dụng

**Admin export bằng user token**

<!-- payload-id: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION-001 -->
<!-- context: HTTP/1.1 POST against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-FUNCTION-LEVEL-AUTHORIZATION-001 -->
<!-- prerequisites: USER_TOKEN has role user only; endpoint requires admin:export scope in the fixed fixture -->
<!-- encoding: ASCII request target and JSON body -->
<!-- expected-result: vulnerable fixture starts an export job; fixed fixture returns 403 and no job is created -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/admin/export-users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{"format":"csv"}
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: authenticated users can call the admin function.
@app.post("/api/admin/export-users")
def export_users():
    return start_export_job()

# SECURE: function-level policy runs before the handler.
@app.post("/api/admin/export-users")
@require_scope("admin:export-users")
def export_users_secure():
    return start_export_job()
```

## 10. Phát hiện

- Log route, method, required scope, actor role và policy decision.
- Alert khi user role thấp gọi admin/operator endpoint.
- Scanner chỉ hỗ trợ route discovery; finding cần side effect/policy evidence.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Tạo policy matrix theo route, method, role và scope.
- Enforce ở server/gateway, không dựa vào UI.
- Test mọi method tương đương như `GET/POST/PUT/DELETE/PATCH`.

### Defense-in-depth

- Tách admin API namespace và network policy.
- Audit log mọi function nhạy cảm.
- Dùng deny-by-default cho route chưa khai báo policy.

## 12. Retest

- **Positive:** admin gọi function thành công.
- **Negative:** user thường bị 403 và không tạo side effect.
- **Boundary:** method override, legacy route, batch function.
- **Telemetry:** job/audit log không xuất hiện trong negative case.

## 13. Sai lầm thường gặp

- Ẩn button admin ở frontend rồi coi là đã bảo vệ.
- Kiểm tra role ở một route nhưng bỏ route alias.
- Không test method khác trên cùng path.

## 14. Tóm tắt và checklist

- [ ] Mọi function nhạy cảm có scope/role bắt buộc.
- [ ] Policy deny-by-default cho route mới.
- [ ] Test có cả token admin và user thường.
- [ ] Side effect được xác minh sau negative case.

## 15. Giải thích thuật ngữ

- **BFLA:** Broken Function Level Authorization.
- **Scope:** quyền cụ thể gắn với credential.
- **Policy matrix:** bảng route/method/role/scope được phép.

## 16. Bài liên quan và đọc thêm

- [BFLA](../../01-broken-access-control/bfla/)
- [Privilege Escalation](../../01-broken-access-control/privilege-escalation/)
- [Shadow APIs](../shadow-apis/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API5 Broken Function Level Authorization. https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-285 — Improper Authorization. https://cwe.mitre.org/data/definitions/285.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — bản hiện hành; truy cập: 2026-07-18.
