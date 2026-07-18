---
schema_version: 1
id: WEB-A01-PRIVILEGE-ESCALATION
title: "Privilege Escalation"
slug: privilege-escalation
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A06:2025
cwe:
  - CWE-269
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Privilege Escalation

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Privilege Escalation bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Role, permission và khác biệt horizontal/vertical escalation.

- Server-side policy cho object và function.

- Cách profile update xử lý trường đặc quyền.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn bước vào một bệnh viện lớn. Nếu bạn là một bệnh nhân bình thường, bạn có thể đi lại ở khu vực sảnh chờ, phòng khám hoặc căng tin. Bạn không thể tự tiện bước vào phòng bệnh của một bệnh nhân khác để xem bệnh án của họ — nếu bạn cố tình làm vậy, đó chính là **leo thang đặc quyền chiều ngang (horizontal escalation)**, tức là lấn sân sang quyền hạn của người khác có cùng vị trí giống bạn. Mặt khác, phòng phẫu thuật hay phòng lưu trữ hồ sơ bệnh án trung tâm chỉ dành riêng cho các bác sĩ trưởng khoa. Nếu bạn tìm cách lẻn vào đó, tự ý lấy áo blouse trắng mặc vào để thực hiện các ca mổ hoặc chỉnh sửa bệnh án, đó chính là **leo thang đặc quyền chiều dọc (vertical escalation)**, tức là chiếm đoạt đặc quyền cao hơn quyền hạn của bản thân. [S3]

Trong thế giới phát triển ứng dụng, để phân chia ranh giới quyền lực này, các lập trình viên sử dụng một mô hình gọi là **RBAC** (Role-Based Access Control - Kiểm soát truy cập dựa trên vai trò). Mô hình này chia người dùng thành các nhóm vai trò rõ ràng (như Admin, Manager, User) và gán cho mỗi vai trò những quyền hạn cụ thể. Tuy nhiên, rắc rối sẽ xảy ra nếu phần mềm chỉ lo "ẩn" chiếc nút bấm "Bảng điều khiển Admin" trên màn hình điện thoại hay trình duyệt của người dùng thông thường, mà ở phía máy chủ (backend) lại không hề kiểm tra xem người gửi yêu cầu thực sự là ai. Kẻ xấu có thể dễ dàng bỏ qua giao diện hiển thị, gửi trực tiếp yêu cầu lên máy chủ để tự phong cho mình các đặc quyền tối cao. [S3]

```python
# Decorator verifying user role at the backend to enforce RBAC rules
from functools import wraps
from flask import abort, session

def require_role(allowed_roles):
    """
    Decorator to enforce Role-Based Access Control (RBAC) on route handlers.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Retrieve the user's role stored securely in the server-side session
            user_role = session.get('user_role')

            # Enforce authorization: check if the user role is authorized
            if not user_role or user_role not in allowed_roles:
                # Reject unauthorized access with HTTP 403 Forbidden
                abort(403, description="Access Forbidden: Insufficient privileges.")

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/settings', methods=['POST'])
@require_role(['admin']) # Only allow users with 'admin' role
def save_admin_settings():
    # Process settings changes securely
    return "Settings updated."
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Leo thang đặc quyền** (Privilege Escalation) xuất hiện khi hệ thống có những kẽ hở trong khâu quản lý và kiểm tra quyền hạn, cho phép người dùng bình thường làm được những việc vượt quá phạm vi được phép của họ. [S3]

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó giúp kẻ tấn công phá vỡ mọi quy tắc bảo mật của ứng dụng. Bằng cách lách qua các chốt chặn lỏng lẻo ở phía máy chủ, kẻ xấu có thể đọc trộm toàn bộ dữ liệu của người dùng khác (chiều ngang) hoặc biến mình thành Quản trị viên tối cao (chiều dọc). Từ đó, họ có toàn quyền kiểm soát hệ thống, thay đổi cấu hình, xóa dữ liệu, hoặc thậm chí là biến toàn bộ ứng dụng thành công cụ phục vụ cho mục đích xấu của mình. Mọi hành động nhạy cảm trên hệ thống bắt buộc phải được máy chủ kiểm tra và xác thực quyền hạn kỹ lưỡng trước khi thực thi, không bao giờ được tin tưởng hoàn toàn vào giao diện người dùng (UI) hay các tham số từ client. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** role, chức năng quản trị và bản ghi synthetic có quyền cao.

- **Actor:** user đã xác thực với role user; admin là positive control.

- **Trust boundary:** decorator phân quyền Flask 3.x và field update trong ORM.

- **Điều kiện cần:** route nhạy cảm thiếu role check hoặc client được sửa field role/is_admin.

- **Môi trường:** API loopback, database snapshot, token synthetic; không thử credential hay target thật.

Phải quan sát role hoặc chức năng thực tế thay đổi ở server; nội dung client/UI tự xưng admin không chứng minh privilege escalation. [S1]

## 6. Cơ chế tấn công

User thường tới được privileged handler hoặc mass-updates field role do thiếu policy/field allowlist. Server sau đó lưu quyền cao hoặc chạy business action với authority sai. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** seed user thường và admin trong Flask 3.x, snapshot DB và bật audit log.
2. **Baseline:** user bị chặn ở route admin; admin truy cập thành công.
3. **Thao tác:** với token user, gọi route admin và gửi update chứa field role trên tài khoản synthetic.
4. **Expected result:** bản lỗi thay đổi quyền/chạy chức năng; bản sửa trả 403 hoặc bỏ field protected và ghi deny.
5. **Boundary:** kiểm tra route alias, method khác, role null và session cũ sau khi đổi quyền.
6. **Cleanup:** restore snapshot, revoke token và xác nhận role user được phục hồi.

## 8. Payload và phạm vi áp dụng

`static-verified` chỉ xác nhận cấu trúc và ngữ cảnh của input đã qua gate tĩnh; nó không chứng minh mọi ứng dụng Flask đều có lỗi. Chỉ gửi input này tới fixture local có tài khoản và database synthetic. [S3]

<!-- payload-id: WEB-A01-PRIVILEGE-ESCALATION-001 -->
<!-- context: Flask 3.x JSON profile update; synthetic user in a disposable local database; privileged-field authorization model [S3] -->
<!-- prerequisites: authenticated fixture user; vulnerable endpoint mass-assigns the client-controlled role field -->
<!-- encoding: UTF-8 JSON; Content-Type application/json -->
<!-- expected-result: vulnerable fixture persists role admin; secure fixture rejects or ignores role and records the authorization decision -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-17 -->
```json
{"display_name":"Lab User","role":"admin"}
```

Kết quả chỉ được coi là dương tính khi server thực sự lưu role cao hơn hoặc cho phép hành động quản trị sau request. Việc client tự hiển thị chuỗi `admin` không phải bằng chứng leo thang đặc quyền. [S3]

## 9. Code dễ bị lỗi và code an toàn

```python
from functools import wraps
from flask import abort, g

# === VULNERABLE CODE (Flask 3.x) ===
@app.get('/admin')
def admin_dashboard_vulnerable():
    # BAD: The route trusts that the UI hid this endpoint from regular users
    return "Welcome to the admin panel!"


# === SECURE CODE (same framework and use case) ===
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'user', None)
            if not user or user.role != role:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.get('/admin')
@require_role('admin')
def admin_dashboard():
    return "Welcome to the admin panel!"
```

## 10. Phát hiện

- So sánh role thường và admin trên cùng operation; xác nhận role lưu trong datastore sau request. [S3]

- Review field binding, policy trước mutation và mọi đường thay đổi role/permission. [S3]

- Log actor, old/new role, policy result và người phê duyệt nếu có.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Chỉ cho phép actor có quyền riêng biệt thay đổi role/permission; kiểm tra phía server trước mutation. [S3]

- Allowlist trường profile mà user tự sửa; tách endpoint quản trị khỏi self-service. [S3]

### Defense-in-depth

- Yêu cầu re-auth hoặc approval cho thao tác đặc quyền cao.

- Alert khi role thay đổi bất thường hoặc quyền tăng nhanh.

## 12. Retest

- **Positive:** admin được phép thay đổi role theo policy.

- **Negative:** user thường không thể tự tăng quyền qua body hoặc route khác.

- **Boundary:** role không tồn tại, downgrade, concurrent update và bulk import.

- **Telemetry:** xác nhận audit log chứa old/new role và policy decision.

## 13. Sai lầm thường gặp

- Tin trường `role` hoặc `isAdmin` do client gửi.

- Chỉ ẩn menu quản trị.

- Kiểm tra role sau khi mutation đã commit.

- Bảo vệ endpoint chính nhưng bỏ sót import hoặc batch update.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Horizontal escalation:** actor vượt policy để truy cập object/thao tác của actor ngang quyền. [S3]

- **Vertical escalation:** actor đạt function hoặc permission dành cho role cao hơn. [S3]

- **RBAC:** mô hình gán permission cho role rồi gán actor vào role theo policy. [S3]

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
