---
schema_version: 1
id: WEB-A01-BROKEN-ACCESS-CONTROL
title: "Broken Access Control"
slug: broken-access-control
level: beginner
estimated_minutes: 35
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

# Broken Access Control

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Broken Access Control bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Authentication, authorization và mô hình subject–resource–action.

- Cách session được ánh xạ thành actor phía server.

- Đọc handler, policy và log thay đổi dữ liệu synthetic.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đăng ký dịch vụ tại một khách sạn lớn. Khi làm thủ tục tại quầy lễ tân, nhân viên sẽ kiểm tra chứng minh thư của bạn và đưa cho bạn một chiếc chìa khóa phòng. Quá trình kiểm tra chứng minh thư để xác định bạn là ai chính là **Authentication** (Xác thực). Còn việc chiếc chìa khóa đó chỉ mở được đúng căn phòng 204 bạn đã thuê, chứ không thể mở được phòng 205 bên cạnh hay phòng tổng thống, chính là **Authorization** (Phân quyền). [S4]

Trong thế giới web cũng vậy. Khi bạn đăng nhập thành công, máy chủ (server) sẽ cấp cho trình duyệt của bạn một mã định danh gọi là **session token** (giống như chiếc chìa khóa phòng). Mỗi khi trình duyệt gửi yêu cầu lấy dữ liệu (qua cookie hoặc HTTP header), máy chủ chỉ cần kiểm tra mã này để biết bạn đã đăng nhập hay chưa. Tuy nhiên, một lỗ hổng nghiêm trọng sẽ xảy ra nếu người quản lý khách sạn "quên" cài đặt ổ khóa thông minh, chỉ cần bạn đi bộ hành lang và vặn tay nắm cửa phòng khác là cửa tự mở. Lỗ hổng **Kiểm soát truy cập bị lỗi** (Broken Access Control) xuất hiện khi máy chủ nhận được yêu cầu từ bạn, biết bạn đã đăng nhập, nhưng lại lười biếng không kiểm tra xem bạn có thực sự sở hữu căn phòng hay tài liệu mà bạn đang yêu cầu hay không. Họ chỉ tin tưởng mù quáng vào số phòng (ID tài nguyên) bạn gửi lên và mở toang cửa cho bạn vào. [S4]

```python
# Flask route verifying resource ownership based on authenticated session user ID
from flask import abort, jsonify
from flask_login import login_required, current_user
from models import Document

@app.route('/api/document/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    # Retrieve the document from the database
    document = Document.query.get_or_404(doc_id)

    # Secure: Verify if the authenticated user owns this specific document
    if document.owner_id != current_user.id:
        # Deny access if user is not the owner
        abort(403, description="Access denied: You do not own this resource.")

    # Return the document data if authorized
    return jsonify(document.to_json())
```

## 4. Mô tả và nguyên nhân gốc

Định danh khó đoán có thể giảm khả năng enumeration trong một số threat model, nhưng không cấp quyền và không thay thế kiểm tra authorization phía máy chủ. Nếu actor lấy được định danh qua log, referrer, chia sẻ hoặc một luồng hợp lệ khác, mọi tài nguyên vẫn phải được policy kiểm tra trên từng request. [S3], [S4]

Broken Access Control xảy ra khi policy cho subject–resource–action không được thực thi đúng tại trust boundary có thẩm quyền. Hậu quả có thể là đọc hoặc thay đổi tài nguyên trái quyền, nhưng phải được chứng minh theo đúng handler và side effect; giao diện ẩn, ID tuần tự hoặc status code đơn lẻ chưa đủ. Kiểm tra phải thực hiện phía máy chủ trên từng request và mặc định từ chối khi không có rule cho phép. [S4]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** hồ sơ synthetic của từng chủ sở hữu và chức năng chỉ dành cho admin.

- **Actor:** user 1234 đã xác thực; user 5678 và admin là actor đối chứng.

- **Trust boundary:** decorator/middleware Flask 3.x và truy vấn Account phía server.

- **Điều kiện cần:** client thay object ID hoặc route; policy ownership/role bị thiếu trên handler thực tế.

- **Môi trường:** API 127.0.0.1:8000, hai owner riêng biệt, raw HTTP hoặc proxy; không cần browser.

Phải chứng minh response chứa dữ liệu actor khác hoặc chức năng admin đã chạy; chỉ thấy 200/403 hay ID tuần tự chưa đủ kết luận. [S1]

## 6. Cơ chế tấn công

Handler lấy subject từ session nhưng truy vấn object hoặc gọi chức năng chỉ theo ID/route do client cung cấp. Khi không có policy ownership/role trước truy vấn, response hoặc mutation vượt quyền xảy ra. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** seed user 1234, user 5678 và admin trong Flask 3.x; bật application và policy log.
2. **Baseline:** mỗi user đọc đúng hồ sơ của mình; admin đọc route quản trị.
3. **Thao tác:** giữ token user 1234, lần lượt đổi ID sang 5678 và gọi route admin.
4. **Expected result:** bản lỗi trả dữ liệu synthetic trái quyền; bản sửa trả 403 và không truy vấn/serialize tài nguyên cấm.
5. **Boundary:** kiểm tra ID không tồn tại, role rỗng, token hết hạn và route alias.
6. **Cleanup:** xóa fixture/token và đối chiếu correlation ID giữa proxy, ứng dụng và datastore.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công nhận thấy rằng các thông cáo báo chí nhạy cảm của một công ty được đăng bằng cách sử dụng một quy ước đặt tên có thể đoán trước được và kiểm tra một URL tiềm năng trước ngày công bố chính thức. Khi nhận thấy máy chủ không thực thi quyền ủy quyền, kẻ tấn công viết một kịch bản để thu thập các tài liệu trước khi phát hành nhằm giành được lợi thế không công bằng trên thị trường chứng khoán. [S4]

### Ví dụ HTTP request minh họa vi phạm Access Control:
<!-- payload-id: WEB-A01-BROKEN-ACCESS-CONTROL-001 -->
<!-- context: HTTP/1.1; Flask 3.x fixture at 127.0.0.1:8000; authenticated synthetic user 1234; server authorization model [S4] -->
<!-- prerequisites: seed users 1234 and 5678 plus an admin-only route; use the token for user 1234; capture policy logs -->
<!-- encoding: ASCII request-target, Host and Authorization headers; raw harness emits CRLF; requests have no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns synthetic user 5678 or admin data; fixed fixture returns 403 while user 1234 can still read own data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Normal user accessing their own profile
GET /api/users/1234/profile HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>

# Horizontal escalation: change ID to access another user
GET /api/users/5678/profile HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>
# If server returns 200 with user 5678's data → IDOR vulnerability

# Vertical escalation: access admin endpoint
GET /api/admin/users HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <user_token_1234>
# If server returns admin data → BFLA vulnerability
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE (Flask 3.x) ===
from flask import abort, request, jsonify
from flask_login import login_required, current_user
from models import Account

@app.route('/api/account/<int:account_id>', methods=['GET'])
@login_required
def get_account_details_vulnerable(account_id):
    # BAD: Authentication exists, but ownership is never checked
    account = Account.query.get_or_404(account_id)
    return jsonify(account.to_json())


# === SECURE CODE (same framework and use case) ===
from flask import abort, request, jsonify
from flask_login import login_required, current_user
from models import Account

@app.route('/api/account/<int:account_id>', methods=['GET'])
@login_required
def get_account_details_secure(account_id):
    # Retrieve resource
    account = Account.query.get_or_404(account_id)

    # Safety check: Ensure user and owner IDs are valid and not None
    if not current_user or current_user.id is None or account.user_id is None:
        abort(403)

    # Enforce authorization: Check if current logged-in user owns the account
    if account.user_id != current_user.id and not current_user.is_admin:
        # Log access denial
        app.logger.warning(f"User {current_user.id} unauthorized access attempt to Account {account_id}")
        abort(403) # Forbidden

    return jsonify(account.to_json())
```

## 10. Phát hiện

- So sánh cùng tài nguyên dưới owner, non-owner và admin; xác nhận cả response lẫn mutation. [S4]

- Review nơi handler lấy subject và nơi truy vấn object để tìm đường đi bỏ qua policy. [S4]

- Log actor, resource, action, policy result và correlation ID.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Thực thi authorization phía server cho từng subject–resource–action trước đọc hoặc sửa dữ liệu. [S4]

- Mặc định từ chối và tái sử dụng policy trên mọi đường truy cập tương đương. [S4]

### Defense-in-depth

- ID khó đoán chỉ giảm enumeration; không cấp quyền.

- Giới hạn tốc độ và alert hỗ trợ phát hiện truy cập hàng loạt.

## 12. Retest

- **Positive:** owner và role được phép vẫn hoàn thành thao tác.

- **Negative:** non-owner hoặc role thấp bị từ chối, dữ liệu giữ nguyên.

- **Boundary:** kiểm tra object không tồn tại, bulk, nested và alias route.

- **Telemetry:** đối chiếu policy decision với datastore mutation.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra người dùng đã đăng nhập.

- Tin ownership hoặc role do client gửi.

- Dùng UUID, UI hiding hoặc WAF thay authorization.

- Sửa một endpoint nhưng bỏ sót batch hoặc nested resource.

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

- **Authentication:** thiết lập hoặc xác minh danh tính actor; không tự cấp quyền trên tài nguyên. [S4]

- **Authorization:** quyết định actor được thực hiện action nào trên resource nào. [S4]

- **Default deny:** từ chối khi không có policy rõ ràng cho phép request. [S4]

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** RFC 9562 — Universally Unique IDentifiers (UUIDs). https://www.rfc-editor.org/rfc/rfc9562.html — phiên bản/ngày: May 2024; truy cập: 2026-07-17.
- **[S4]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
