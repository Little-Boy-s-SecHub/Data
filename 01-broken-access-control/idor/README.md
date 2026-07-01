# Insecure Direct Object Reference (IDOR)

> **CWE**: CWE-639 | **Phân loại**: Access Control

## Kiến thức Nền tảng
Hãy tưởng tượng bạn gửi xe ở một bãi đỗ xe thông minh. Sau khi gửi, nhân viên đưa cho bạn một chiếc vé ghi số `1042` — đây chính là **Object Identifier** (Mã định danh đối tượng) giúp nhận diện chiếc xe của bạn. Khi bạn muốn lấy xe, bạn đưa chiếc vé này cho nhân viên, họ đối chiếu số vé với chiếc xe tương ứng trong bãi và trả xe cho bạn. 

Trong thế giới web cũng vậy. Mọi thông tin như hồ sơ cá nhân, đơn hàng, hóa đơn hay hình ảnh của bạn đều được gán một mã số định danh duy nhất (ví dụ: `id=1042` hoặc một chuỗi ký tự dài như UUID). Khi bạn muốn xem đơn hàng của mình, trình duyệt sẽ gửi một yêu cầu (request) lên máy chủ kèm theo ID đó. Để hệ thống hoạt động an toàn, máy chủ phải thực hiện một bước kiểm tra tối quan trọng: "Người đưa chiếc vé số `1042` này có thực sự là chủ nhân của chiếc xe số `1042` hay không?". Quá trình này được gọi là **Authorization** (Phân quyền). Nếu người giữ xe chỉ nhìn số vé mà giao xe ngay, không thèm kiểm tra xem người lấy xe là ai, thì bất kỳ ai nhặt được hoặc tự vẽ ra một chiếc vé số `1043` đều có thể lấy mất xe của người khác. Trong bảo mật API hiện đại, việc thiếu bước kiểm tra này được gọi là **BOLA** (Broken Object Level Authorization).

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

Cơ chế **authorization** (phân quyền) đảm bảo rằng người dùng A không thể truy cập tài nguyên thuộc về người dùng B, ngay cả khi họ biết ID của tài nguyên đó. Đây là lớp kiểm soát quan trọng nhất trong bất kỳ ứng dụng nào xử lý dữ liệu đa người dùng. OWASP API Security gọi pattern này là **Broken Object Level Authorization (BOLA)** — lỗ hổng phổ biến nhất trong API hiện đại.

## Mô tả lỗ hổng
IDOR xảy ra khi máy chủ hoạt động giống như người giữ xe cẩu thả nói trên: họ **chỉ dựa vào ID tài nguyên** do người dùng gửi lên để lấy dữ liệu từ cơ sở dữ liệu mà hoàn toàn **không xác thực quyền sở hữu**. Kẻ tấn công chỉ cần thay đổi giá trị ID trong URL, request body hoặc query parameter để truy cập dữ liệu của người dùng khác.

Lỗ hổng này đặc biệt nguy hiểm vì:
- **Dễ khai thác**: không cần kỹ năng cao, chỉ cần thay đổi một con số
- **Khó phát hiện bằng scanner**: logic authorization là business-specific
- **Phạm vi ảnh hưởng rộng**: leak PII, tài liệu nội bộ, giao dịch tài chính

## Cơ chế tấn công
**Pattern 1: Numeric ID Enumeration**

```http
# Attacker changes order_id from their own (1042) to another user's (1043)
GET /api/orders/1042 HTTP/1.1        → 200 OK (own order)
GET /api/orders/1043 HTTP/1.1        → 200 OK (another user's order — IDOR!)
GET /api/orders/1044 HTTP/1.1        → 200 OK (keeps enumerating)
```

**Pattern 2: UUID không phải lúc nào cũng an toàn**

```python
# Attacker discovers UUID via API response, logs, or predictable generation
# UUIDv1 contains timestamp + MAC address — partially guessable
import uuid
guessed = uuid.uuid1()  # Output: 6fa459ea-ee8a-11e8-9e36-0242ac120002
# Attacker brute-forces the timestamp portion
```

**Pattern 3: BOLA trong REST API**

```bash
# Burp Suite Intruder: enumerate user profiles via API
# Original request from authenticated user (user_id=500)
curl -H "Authorization: Bearer <token_of_user_500>" \
     https://api.target.com/v1/users/500/documents

# Attacker replaces 500 with 501..9999
for uid in $(seq 501 9999); do
  curl -s -H "Authorization: Bearer <token_of_user_500>" \
       "https://api.target.com/v1/users/$uid/documents" >> loot.json
done
```

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống tham chiếu đối tượng trực tiếp không an toàn (IDOR) bằng cách kiểm tra quyền sở hữu đối với mọi truy vấn, sử dụng bản đồ tham chiếu gián tiếp, giới hạn tần suất yêu cầu, sử dụng UUIDv4 và ghi nhật ký kiểm toán.
- **Các bước chi tiết**:
  - **Luôn kiểm tra quyền sở hữu (Always check ownership)**: mọi query phải filter theo `user_id` từ session/token, không tin ID từ client.
  - **Sử dụng bản đồ tham chiếu gián tiếp (Use indirect reference map)**: ánh xạ ID nội bộ sang token ngẫu nhiên cho mỗi session.
  - **Giới hạn tần suất (Rate limiting)**: giới hạn số request đến endpoint nhạy cảm để chặn enumeration.
  - **Sử dụng UUIDv4**: sử dụng UUID ngẫu nhiên thay vì sequential ID, nhưng không dùng UUID thay thế cho authorization.
  - **Ghi nhật ký kiểm toán (Audit logging)**: ghi log mọi truy cập tài nguyên để phát hiện các mẫu hành vi bất thường.

## Code Example
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


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/access-control/idor
- OWASP API Top 10: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- CWE-639: https://cwe.mitre.org/data/definitions/639.html

## Giải thích thuật ngữ
- **Object Identifier (ID đối tượng)**: Mã số hoặc chuỗi ký tự duy nhất dùng để phân biệt và định vị một tài nguyên cụ thể (như người dùng, sản phẩm, đơn hàng) trong cơ sở dữ liệu.
- **UUID (Universally Unique Identifier)**: Định danh duy nhất toàn cầu, là chuỗi 36 ký tự ngẫu nhiên giúp định danh tài nguyên mà không lo bị trùng lặp hoặc bị đoán trước dễ dàng như số tự tăng.
- **BOLA (Broken Object Level Authorization)**: Tên gọi khác của lỗ hổng IDOR trong bảo mật API, nhấn mạnh việc lỗi phân quyền xảy ra ở cấp độ từng đối tượng dữ liệu cụ thể.
- **Scanner (Công cụ quét bảo mật)**: Các phần mềm tự động rà quét trang web để phát hiện các lỗ hổng bảo mật phổ biến.
- **PII (Personally Identifiable Information)**: Thông tin định danh cá nhân nhạy cảm (như họ tên, số điện thoại, số CCCD, địa chỉ, email).
- **Enumeration (Dò quét/Liệt kê)**: Kỹ thuật thử nghiệm liên tục các giá trị theo thứ tự (như ID tăng dần từ 1, 2, 3...) để tìm kiếm và thu thập dữ liệu có quy luật.
- **REST API**: Một chuẩn thiết kế API phổ biến dựa trên các phương thức HTTP chuẩn để quản lý tài nguyên.
- **Rate Limiting (Giới hạn tần suất)**: Biện pháp kiểm soát giới hạn số lượng yêu cầu mà một người dùng hoặc IP có thể gửi lên máy chủ trong một khoảng thời gian nhất định để ngăn chặn tấn công dò quét hoặc spam.
