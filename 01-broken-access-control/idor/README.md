# Insecure Direct Object Reference (IDOR)

> **OWASP Top 10:2025**: A01 – Broken Access Control | **CWE**: CWE-639 | **Nguồn**: OWASP API Top 10 (API1:2023 - BOLA), PortSwigger

## 🧱 Kiến thức Nền tảng

Trong kiến trúc web hiện đại, mỗi tài nguyên (user profile, đơn hàng, file) đều được định danh bằng một **Object Identifier** — có thể là số nguyên tự tăng (`id=1042`), UUID (`550e8400-e29b-41d4-a716-446655440000`), hoặc slug (`invoice-2024-0731`). Khi client gửi request, server sử dụng ID này để truy vấn database và trả về dữ liệu tương ứng.

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

## 🔍 Mô tả lỗ hổng

IDOR xảy ra khi server **chỉ dựa vào Object ID** do client cung cấp để truy xuất dữ liệu mà **không kiểm tra quyền sở hữu**. Kẻ tấn công chỉ cần thay đổi giá trị ID trong URL, request body hoặc query parameter để truy cập dữ liệu của người dùng khác.

Lỗ hổng này đặc biệt nguy hiểm vì:
- **Dễ khai thác**: không cần kỹ năng cao, chỉ cần thay đổi một con số
- **Khó phát hiện bằng scanner**: logic authorization là business-specific
- **Phạm vi ảnh hưởng rộng**: leak PII, tài liệu nội bộ, giao dịch tài chính

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Luôn kiểm tra ownership**: mọi query phải filter theo `user_id` từ session/token, không tin ID từ client
2. **Sử dụng indirect reference map**: ánh xạ ID nội bộ sang token ngẫu nhiên cho mỗi session
3. **Rate limiting**: giới hạn số request đến endpoint nhạy cảm để chặn enumeration
4. **UUIDv4**: sử dụng UUID ngẫu nhiên thay vì sequential ID, nhưng **không dùng UUID thay thế cho authorization**
5. **Audit logging**: ghi log mọi truy cập tài nguyên để phát hiện pattern bất thường

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/access-control/idor
- OWASP API Top 10: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
