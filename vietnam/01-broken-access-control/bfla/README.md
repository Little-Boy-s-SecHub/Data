---
schema_version: 1
id: WEB-A01-BFLA
title: "Broken Function Level Authorization (BFLA)"
slug: bfla
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-285
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Broken Function Level Authorization (BFLA)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Broken Function Level Authorization (BFLA) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- HTTP method, route mapping và middleware của Express.js 4.x.

- Khác biệt giữa authentication, role và quyền gọi function.

- Đọc audit log và kiểm tra side effect trên dữ liệu synthetic.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn bước vào một tòa nhà văn phòng hiện đại. Để đi qua cửa chính hay vào phòng làm việc của mình, bạn chỉ cần quẹt chiếc thẻ nhân viên thông thường. Tuy nhiên, để bước vào phòng máy chủ hay phòng nhân sự — nơi chứa những thông tin vô cùng nhạy cảm — bạn cần một chiếc thẻ có đặc quyền cao hơn. Trong thế giới phần mềm, việc kiểm soát xem ai được phép thực hiện hành động nào (như xóa tài khoản, nâng cấp quyền hạn hay xem báo cáo doanh thu) được gọi là **Function Level Authorization** (Kiểm soát quyền truy cập cấp chức năng). [S5]

Khác với việc kiểm tra xem bạn có quyền sở hữu hay xem một hồ sơ cụ thể hay không (Object Level Authorization), cơ chế này tập trung vào câu hỏi: "Bạn có quyền thực hiện hành động này hay không?". [S5]

Một hệ thống API điển hình phân tách endpoint theo role:

```python
# Typical API structure with role-based endpoints
# Public endpoints — accessible to all authenticated users
# GET  /api/users/me              → view own profile
# PUT  /api/users/me              → update own profile

# Admin endpoints — restricted to admin role
# GET  /api/admin/users           → list all users
# DELETE /api/admin/users/:id     → delete a user
# PUT  /api/admin/users/:id/role  → change user role

# Middleware enforces role check BEFORE handler executes
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_authenticated_user(request)
        if user.role != 'admin':
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated
```

Kiến trúc phổ biến sử dụng **middleware** hoặc **decorator** để kiểm tra role trước khi thực thi logic nghiệp vụ. Tuy nhiên, một sai lầm vô cùng phổ biến là lập trình viên chỉ lo "giấu" chiếc nút bấm Admin trên giao diện màn hình của người dùng thông thường (client-side), mà quên mất việc đặt chốt chặn thực sự ở phía máy chủ (server-side), hoặc chỉ bảo vệ một số endpoint admin mà bỏ sót những endpoint khác. [S5]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **BFLA** (Broken Function Level Authorization) xuất hiện khi máy chủ không kiểm tra quyền của actor trên một chức năng cụ thể. Việc đoán được route, đổi HTTP method hoặc nhìn thấy nút quản trị chỉ giúp tiếp cận bề mặt kiểm thử; chỉ khi request quyền thấp thực sự đi qua policy và thực thi chức năng quyền cao mới xác nhận BFLA. [S1], [S2]

- **Thử đoán đường đi mới**: Thay đổi địa chỉ trên trình duyệt từ `/api/users/` thành `/api/admin/users/` xem chuyện gì xảy ra.
- **Thay đổi cách hành động**: Thay vì chỉ yêu cầu xem thông tin (`GET`), họ thử đổi sang lệnh xóa (`DELETE`) hay chỉnh sửa (`PUT`).
- **Gửi thêm trường đặc quyền**: trường như `{"role": "admin"}` là một đường kiểm thử mass assignment/field-level authorization riêng; chỉ xếp vào BFLA khi handler update cho actor quyền thấp thực sự cho phép thực hiện chức năng đổi role. [S1]

Hậu quả phụ thuộc chức năng bị bỏ kiểm soát: actor có thể đọc, sửa hoặc xóa dữ liệu ngoài quyền, hoặc gọi thao tác quản trị. Kiến trúc microservice không tự tạo BFLA; rủi ro xuất hiện khi policy không được thực thi nhất quán tại từng service hoặc gateway có thẩm quyền. [S1], [S2]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** chức năng quản trị, dữ liệu người dùng giả và audit trail của API.

- **Actor:** người dùng đã đăng nhập với role regular; token admin chỉ dùng làm positive baseline.

- **Trust boundary:** middleware phân quyền của Express.js 4.x trước các route GET, PUT và DELETE.

- **Điều kiện cần:** actor biết route hoặc đổi HTTP method; server xác thực token nhưng không kiểm tra quyền trên đúng chức năng. [S5]

- **Môi trường:** fixture 127.0.0.1:9080, dữ liệu synthetic, proxy/raw HTTP tùy payload; không cần browser.

Chỉ kết luận BFLA khi cùng token regular gọi được chức năng admin và log/datastore xác nhận tác động; route đoán được hoặc nút UI bị ẩn không tự chứng minh lỗ hổng. [S1]

## 6. Cơ chế tấn công

Router chọn đúng handler từ path và method, nhưng middleware chỉ xác thực danh tính hoặc bỏ sót policy của chức năng. Token regular vì thế đi tới business logic admin; bằng chứng phải nối policy decision với side effect của đúng request. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khôi phục snapshot Express.js 4.x, seed hai user synthetic cùng token regular/admin và bật policy/audit log.
2. **Baseline:** token regular đọc tài nguyên của chính nó; token admin thực hiện chức năng admin hợp lệ.
3. **Thao tác:** dùng token regular thử GET admin và PUT role; DELETE chỉ chạy với user lab-user-1042 trên snapshot disposable.
4. **Expected result:** bản lỗi cho phép thao tác trái role; bản sửa trả 403, giữ nguyên dữ liệu và ghi quyết định deny.
5. **Boundary:** lặp lại trên route tương đương, method khác và token hết hạn; không brute-force route.
6. **Cleanup:** khôi phục snapshot, thu hồi token fixture và xác nhận không có outbound network.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Pattern 1: URL Path Manipulation**

<!-- payload-id: WEB-A01-BFLA-001 -->
<!-- context: HTTP/1.1; Express.js 4.x fixture at 127.0.0.1:9080; regular role; synthetic users only; function-authorization model [S5] -->
<!-- prerequisites: seed regular_user_token and two synthetic users; capture application authorization log; no Internet route -->
<!-- encoding: ASCII request-target and headers; raw harness emits CRLF and recalculates Content-Length when a body is added -->
<!-- expected-result: vulnerable route returns the synthetic user list; fixed route returns 403 and records an authorization denial -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Regular user discovers admin endpoint pattern
GET /api/v1/users/me HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>

# Attacker guesses admin endpoint by modifying URL path
GET /api/v1/admin/users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>
```

**Pattern 2: HTTP Method Tampering**

<!-- payload-id: WEB-A01-BFLA-002 -->
<!-- context: HTTP/1.1; Express.js 4.x disposable fixture at 127.0.0.1:9080; regular role; synthetic user lab-user-1042; function-authorization model [S5] -->
<!-- prerequisites: restore a database snapshot before each run; seed lab-user-1042 and regular_user_token; never use production data -->
<!-- encoding: ASCII method, request-target and headers; raw harness emits CRLF; request has no body or Content-Length -->
<!-- expected-result: vulnerable fixture deletes only lab-user-1042 and returns 204; fixed fixture returns 403 and leaves the seeded record intact -->
<!-- risk: destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Regular user can view their own data
GET /api/v1/users/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>

# Attacker changes method to DELETE — server lacks method-level auth
DELETE /api/v1/users/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <regular_user_token>
```

**Pattern 3: Privilege Escalation via PUT**

<!-- payload-id: WEB-A01-BFLA-003 -->
<!-- context: curl 8.x against Express.js 4.x fixture at 127.0.0.1:9080; regular role; own synthetic account; function-authorization model [S5] -->
<!-- prerequisites: seed regular_user_token and reset the synthetic account to role=user before each run; no Internet route -->
<!-- encoding: UTF-8 JSON with Content-Type application/json; curl calculates Content-Length -->
<!-- expected-result: vulnerable fixture changes the synthetic role; fixed fixture ignores protected fields and keeps role=user -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Attacker sends role update request using their own token
curl -X PUT http://127.0.0.1:9080/api/v1/users/me \
  -H "Authorization: Bearer <regular_user_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "is_superuser": true}'
# If server doesn't filter writable fields → privilege escalation
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// === VULNERABLE CODE (Express.js) ===
const express = require('express');
const router = express.Router();

// BAD: No role check — any authenticated user can delete users
router.delete('/api/v1/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

// BAD: No field filtering — user can set their own role
router.put('/api/v1/users/me', authenticate, async (req, res) => {
    // Directly spreading user input into update query
    await User.findByIdAndUpdate(req.user.id, req.body);
    res.json({ message: 'Updated' });
});


// === SECURE CODE (Express.js) ===
// GOOD: The same route and method enforce admin authorization before the handler
router.delete('/api/v1/users/:id', authenticate, authorize('admin'),
    async (req, res) => {
        await User.findByIdAndDelete(req.params.id);
        audit.log(`User ${req.params.id} deleted by admin ${req.user.id}`);
        res.status(204).send();
    }
);

// GOOD: Whitelist allowed fields to prevent mass assignment
const ALLOWED_UPDATE_FIELDS = ['name', 'email', 'avatar'];

router.put('/api/v1/users/me', authenticate, async (req, res) => {
    // Only pick allowed fields from request body
    const updates = {};
    for (const field of ALLOWED_UPDATE_FIELDS) {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    }
    await User.findByIdAndUpdate(req.user.id, updates);
    res.json({ message: 'Updated' });
});

// Centralized RBAC middleware
function authorize(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}
```

## 10. Phát hiện

- Gửi cùng operation bằng token admin và token regular; so sánh policy decision với side effect, không chỉ status code. [S5]

- Review middleware trên mọi method/alias của function đặc quyền, kể cả bulk route. [S5]

- Log actor, function, policy result và correlation ID; không ghi token đầy đủ.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Kiểm tra quyền gọi function phía server trước business logic và mặc định từ chối khi không có rule cho phép. [S5]

- Áp dụng cùng policy cho mọi HTTP method, alias và route quản trị tương đương. [S5]

### Defense-in-depth

- Ẩn nút quản trị chỉ cải thiện UX; không phải kiểm soát quyền.

- Alert khi role thường gọi dồn dập function đặc quyền.

## 12. Retest

- **Positive:** token admin gọi được function và audit log ghi allow.

- **Negative:** token regular bị từ chối trước mọi side effect.

- **Boundary:** lặp lại trên GET/PUT/DELETE, alias và bulk route.

- **Telemetry:** nối correlation ID giữa middleware, handler và datastore.

## 13. Sai lầm thường gặp

- Chỉ ẩn route hoặc nút admin trên client.

- Bảo vệ GET nhưng bỏ sót PUT, DELETE hoặc alias.

- Đồng nhất BFLA với mass assignment khi function đổi role vốn không được phép.

- Kết luận từ status code mà không kiểm tra side effect.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Function authorization:** quyết định actor có được gọi một thao tác nghiệp vụ cụ thể hay không. [S5]

- **Middleware:** lớp chạy trước handler để thực thi authentication, authorization hoặc logging nhất quán. [S5]

- **Policy decision:** kết quả allow/deny cho actor, function và context của request. [S5]

## 16. Bài liên quan và đọc thêm

- [Broken Access Control](../broken-access-control/) — Xem thêm bài học về Broken Access Control.

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Top 10. https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP Access Control Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
