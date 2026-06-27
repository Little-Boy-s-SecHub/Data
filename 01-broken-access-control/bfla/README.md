# Broken Function Level Authorization (BFLA)

> **OWASP Top 10:2025**: A01 – Broken Access Control | **CWE**: CWE-285 | **Nguồn**: OWASP API Top 10 (API5:2023)

## 🧱 Kiến thức Nền tảng

Trong hệ thống phần mềm, **Function Level Authorization** là cơ chế kiểm soát quyền truy cập ở cấp độ chức năng (function/endpoint). Khác với Object Level Authorization (kiểm tra "user có quyền truy cập object này không?"), Function Level Authorization kiểm tra "user có quyền **thực hiện hành động** này không?" — ví dụ: xóa user, thay đổi role, duyệt giao dịch.

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

Kiến trúc phổ biến sử dụng **middleware** hoặc **decorator** để kiểm tra role trước khi thực thi logic nghiệp vụ. Tuy nhiên, sai lầm thường gặp là developer chỉ ẩn nút/link trên giao diện (client-side) mà quên enforce ở server-side, hoặc chỉ bảo vệ một số endpoint admin mà bỏ sót những endpoint khác.

## 🔍 Mô tả lỗ hổng

BFLA xảy ra khi một user có quyền thấp (regular user) có thể gọi thành công các **function/endpoint dành cho role cao hơn** (admin, manager). Kẻ tấn công không cần khai thác bug phức tạp — họ chỉ cần:

- **Đoán URL pattern**: thay `/api/users/` thành `/api/admin/users/`
- **Đổi HTTP method**: chuyển `GET` thành `DELETE` hoặc `PUT`
- **Thêm parameter**: gửi `{"role": "admin"}` trong request body

Lỗ hổng này phổ biến trong kiến trúc microservice, nơi mỗi service có thể có cơ chế authorization riêng biệt và không đồng nhất.

## ⚔️ Cơ chế tấn công

**Pattern 1: URL Path Manipulation**

```http
# Regular user discovers admin endpoint pattern
GET /api/v1/users/me HTTP/1.1
Authorization: Bearer <regular_user_token>
→ 200 OK

# Attacker guesses admin endpoint by modifying URL path
GET /api/v1/admin/users HTTP/1.1
Authorization: Bearer <regular_user_token>
→ 200 OK — full user list returned (BFLA!)
```

**Pattern 2: HTTP Method Tampering**

```http
# Regular user can view their own data
GET /api/v1/users/1042 HTTP/1.1
Authorization: Bearer <regular_user_token>
→ 200 OK

# Attacker changes method to DELETE — server lacks method-level auth
DELETE /api/v1/users/1042 HTTP/1.1
Authorization: Bearer <regular_user_token>
→ 204 No Content — user deleted! (BFLA!)
```

**Pattern 3: Privilege Escalation via PUT**

```bash
# Attacker sends role update request using their own token
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <regular_user_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "is_superuser": true}'
# If server doesn't filter writable fields → privilege escalation
```

## 🛡️ Biện pháp phòng thủ

1. **Default deny**: mặc định từ chối mọi truy cập, chỉ cho phép khi có rule rõ ràng
2. **Centralized authorization middleware**: không để mỗi endpoint tự kiểm tra riêng lẻ
3. **Tách biệt controller theo role**: admin controller và user controller riêng biệt
4. **Whitelist writable fields**: chỉ cho phép update các field được phép, filter `role`, `is_admin` khỏi input
5. **API Gateway enforcement**: áp dụng policy tại gateway level trước khi request đến service

## 💻 Code Example

```javascript
// === VULNERABLE CODE (Express.js) ===
const express = require('express');
const router = express.Router();

// BAD: No role check — any authenticated user can delete users
router.delete('/api/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

// BAD: No field filtering — user can set their own role
router.put('/api/users/me', authenticate, async (req, res) => {
    // Directly spreading user input into update query
    await User.findByIdAndUpdate(req.user.id, req.body);
    res.json({ message: 'Updated' });
});


// === SECURE CODE (Express.js) ===
const { authorize } = require('./middleware/rbac');

// GOOD: Role-based middleware enforces admin-only access
router.delete('/api/admin/users/:id', authenticate, authorize('admin'),
    async (req, res) => {
        await User.findByIdAndDelete(req.params.id);
        audit.log(`User ${req.params.id} deleted by admin ${req.user.id}`);
        res.status(204).send();
    }
);

// GOOD: Whitelist allowed fields to prevent mass assignment
const ALLOWED_UPDATE_FIELDS = ['name', 'email', 'avatar'];

router.put('/api/users/me', authenticate, async (req, res) => {
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

## 📚 Nguồn tham khảo
- OWASP API Top 10: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP Access Control Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
