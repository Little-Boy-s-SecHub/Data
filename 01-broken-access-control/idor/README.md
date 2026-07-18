---
schema_version: 1
id: WEB-A01-IDOR
title: "Insecure Direct Object Reference (IDOR)"
slug: idor
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-639
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Direct Object Reference (IDOR)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Insecure Direct Object Reference (IDOR) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Authentication, object-level authorization và ownership.

- REST route có object identifier, kể cả UUID.

- Đọc truy vấn ORM và audit log của fixture.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn gửi xe ở một bãi đỗ xe thông minh. Sau khi gửi, nhân viên đưa cho bạn một chiếc vé ghi số `1042` — đây chính là **Object Identifier** (Mã định danh đối tượng) giúp nhận diện chiếc xe của bạn. Khi bạn muốn lấy xe, bạn đưa chiếc vé này cho nhân viên, họ đối chiếu số vé với chiếc xe tương ứng trong bãi và trả xe cho bạn. [S2]

Trong thế giới web cũng vậy. Mọi thông tin như hồ sơ cá nhân, đơn hàng, hóa đơn hay hình ảnh của bạn đều được gán một mã số định danh duy nhất (ví dụ: `id=1042` hoặc một chuỗi ký tự dài như UUID). Khi bạn muốn xem đơn hàng của mình, trình duyệt sẽ gửi một yêu cầu (request) lên máy chủ kèm theo ID đó. Để hệ thống hoạt động an toàn, máy chủ phải thực hiện một bước kiểm tra tối quan trọng: "Người đưa chiếc vé số `1042` này có thực sự là chủ nhân của chiếc xe số `1042` hay không?". Quá trình này được gọi là **Authorization** (Phân quyền). Nếu người giữ xe chỉ nhìn số vé mà giao xe ngay, không thèm kiểm tra xem người lấy xe là ai, thì bất kỳ ai nhặt được hoặc tự vẽ ra một chiếc vé số `1043` đều có thể lấy mất xe của người khác. Trong bảo mật API hiện đại, việc thiếu bước kiểm tra này được gọi là **BOLA** (Broken Object Level Authorization). [S2]

Quy trình bình thường của một API endpoint trả về thông tin đơn hàng:

```python
# Normal flow: server retrieves order by ID from authenticated user
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    user = get_authenticated_user(request)
    # Query filters by BOTH order_id AND user_id — correct behavior
    order = db.session.query(Order).filter(
        Order.id == order_id,
        Order.user_id == user.id
    ).first()
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order.to_dict())
```

Cơ chế **authorization** (phân quyền) đảm bảo rằng người dùng A không thể truy cập tài nguyên thuộc về người dùng B, ngay cả khi họ biết ID của tài nguyên đó. Đây là lớp kiểm soát quan trọng nhất trong bất kỳ ứng dụng nào xử lý dữ liệu đa người dùng. OWASP API Security gọi pattern này là **Broken Object Level Authorization (BOLA)** — lỗ hổng phổ biến nhất trong API hiện đại. [S2]

## 4. Mô tả và nguyên nhân gốc

IDOR xảy ra khi máy chủ hoạt động giống như người giữ xe cẩu thả nói trên: họ **chỉ dựa vào ID tài nguyên** do người dùng gửi lên để lấy dữ liệu từ cơ sở dữ liệu mà hoàn toàn **không xác thực quyền sở hữu**. Kẻ tấn công chỉ cần thay đổi giá trị ID trong URL, request body hoặc query parameter để truy cập dữ liệu của người dùng khác. [S2]

Lỗ hổng này đặc biệt nguy hiểm vì:
- **Dễ khai thác**: không cần kỹ năng cao, chỉ cần thay đổi một con số
- **Khó phát hiện bằng scanner**: logic authorization là business-specific
- **Phạm vi ảnh hưởng rộng**: leak PII, tài liệu nội bộ, giao dịch tài chính [S2]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** order, document và profile synthetic thuộc từng user.

- **Actor:** user 500/owner 1042 đã xác thực; owner khác và admin là đối chứng.

- **Trust boundary:** Flask 3.x lấy object ID từ path trước truy vấn SQLAlchemy và serialize response.

- **Điều kiện cần:** actor biết một ID khác từ fixture và server thiếu kiểm tra ownership/permission sau truy vấn.

- **Môi trường:** API loopback, bốn user synthetic, tối đa ba ID thử nghiệm; không brute-force.

ID dễ đoán hay UUID bị lộ chỉ là điều kiện hỗ trợ; bằng chứng IDOR là actor A đọc/sửa object của actor B vì thiếu authorization. [S1], [S5]

## 6. Cơ chế tấn công

API dùng object ID làm khóa truy vấn nhưng không ràng buộc kết quả với subject hiện tại. Thay ID giữ nguyên token có thể làm server serialize object của owner khác. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** seed owner A/B, order 1042-1044 và document 500-503; bật policy/query log.
2. **Baseline:** token A đọc object A; token B đọc object B.
3. **Thao tác:** giữ token A và thay đúng ba ID synthetic đã định nghĩa trong payload.
4. **Expected result:** bản lỗi trả object B; bản sửa trả 403/404 thống nhất và không serialize dữ liệu B.
5. **Boundary:** kiểm tra object không tồn tại, token hết hạn, route admin và UUID được lộ hợp lệ.
6. **Cleanup:** xóa observation file, thu hồi token và dừng fixture.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**Pattern 1: Numeric ID Enumeration**

<!-- payload-id: WEB-A01-IDOR-001 -->
<!-- context: HTTP/1.1; Flask 3.x fixture at 127.0.0.1:8000; actor owns synthetic order 1042 only; object-level authorization model [S2] -->
<!-- prerequisites: seed orders 1042-1044 with different owners; authenticate as owner of 1042; limit the test to these three IDs -->
<!-- encoding: ASCII numeric path segments, Host and Authorization headers; raw harness emits CRLF; requests have no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns another owner's synthetic order; fixed fixture returns 403 for 1043/1044 and 200 for 1042 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Attacker changes order_id from their own (1042) to another user's (1043)
GET /api/orders/1042 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>

GET /api/orders/1043 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>

GET /api/orders/1044 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer <lab_token_order_owner_1042>
```

**Pattern 2: UUID không phải lúc nào cũng an toàn**

UUID có nhiều phiên bản: v4 dùng bit random/pseudorandom, trong khi v1/v6/v7 có trường thời gian và cấu trúc khác. Một UUID có thể bị lộ qua response, log hoặc liên kết; độ khó đoán không chứng minh quyền truy cập. Kiểm thử IDOR phải dùng hai actor/owner trong lab và xác nhận server-side authorization cho object, không brute-force không giới hạn. [S5]

**Pattern 3: BOLA trong REST API**

<!-- payload-id: WEB-A01-IDOR-003 -->
<!-- context: Bash 5.x and curl 8.x; Flask 3.x fixture at 127.0.0.1:8000; synthetic users 500-503; object-level authorization model [S2] -->
<!-- prerequisites: seed four users with separate owners; use only lab_token_user_500; truncate lab-observations.jsonl before the run -->
<!-- encoding: UTF-8 shell source with ASCII numeric path segments; curl emits HTTP framing and Authorization header bytes -->
<!-- expected-result: vulnerable fixture writes documents for user 501-503 to the local observation file; fixed fixture returns 403 for all three -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Burp Suite Intruder: enumerate user profiles via API
# Original request from authenticated user (user_id=500)
curl -H "Authorization: Bearer <lab_token_user_500>" \
     http://127.0.0.1:8000/v1/users/500/documents

# Keep the authorized fixture bounded to three synthetic users
for uid in 501 502 503; do
  curl -s -H "Authorization: Bearer <lab_token_user_500>" \
       "http://127.0.0.1:8000/v1/users/$uid/documents" >> lab-observations.jsonl
done
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile_vulnerable(user_id):
    # BAD: No ownership check — any authenticated user can access any profile
    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == user_id
    ).first()
    return jsonify(profile.to_dict())


# === SECURE CODE ===
@app.route('/api/users/me/profile', methods=['GET'])
def get_profile_secure():
    # GOOD: Use session-based identity, not client-supplied ID
    current_user = get_authenticated_user(request)

    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()

    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    # Log access for audit trail
    audit_log.info(f"Profile accessed by user_id={current_user.id}")
    return jsonify(profile.to_dict())


# === SECURE CODE (when cross-user access is needed, e.g. admin) ===
@app.route('/api/admin/users/<int:user_id>/profile', methods=['GET'])
@require_role('admin')  # Enforce role-based access control
def admin_get_profile(user_id):
    profile = db.session.query(UserProfile).filter(
        UserProfile.user_id == user_id
    ).first()
    if not profile:
        return jsonify({"error": "Not found"}), 404
    audit_log.info(f"Admin accessed profile of user_id={user_id}")
    return jsonify(profile.to_dict())
```

## 10. Phát hiện

- Dùng hai actor và các object đã seed; đổi identifier rồi xác nhận owner của response/mutation. [S2]

- Review query chỉ lọc theo ID mà không ràng buộc owner/tenant hoặc policy. [S2]

- Log actor, object ID, owner/tenant, action và policy result.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Kiểm tra object-level authorization phía server trên mỗi request trước khi trả hoặc sửa object. [S2]

- Scope truy vấn theo actor/tenant hoặc gọi policy có thẩm quyền; mặc định từ chối. [S2]

### Defense-in-depth

- UUID khó đoán chỉ giảm enumeration, không thay authorization.

- Rate limit hỗ trợ phát hiện duyệt ID hàng loạt.

## 12. Retest

- **Positive:** actor đọc/sửa được object của chính mình.

- **Negative:** actor khác bị từ chối và object không đổi.

- **Boundary:** object không tồn tại, UUID sai, bulk và nested object.

- **Telemetry:** audit log phải nối actor, object owner và policy result.

## 13. Sai lầm thường gặp

- Chỉ đổi số tuần tự sang UUID.

- Lấy object theo ID rồi mới kiểm tra owner sau khi đã trả dữ liệu.

- Bỏ sót bulk endpoint hoặc nested resource.

- Suy ra lỗ hổng từ khác biệt 403/404 mà không thấy dữ liệu trái quyền.

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

- **BOLA/IDOR:** thiếu kiểm tra quyền của actor trên object được chọn bằng identifier. [S2]

- **Object identifier:** giá trị chọn object; biết identifier không đồng nghĩa có quyền truy cập. [S2]

- **Ownership:** quan hệ giữa actor/tenant và object mà policy dùng để quyết định quyền. [S2]

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/access-control/idor — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP API Top 10. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** RFC 9562 — Universally Unique IDentifiers (UUIDs). https://www.rfc-editor.org/rfc/rfc9562.html — phiên bản/ngày: May 2024; truy cập: 2026-07-17.
