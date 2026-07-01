# Broken Function Level Authorization (BFLA)

> **CWE**: CWE-285 | **Phân loại**: Access Control

## Kiến thức Nền tảng
Hãy tưởng tượng bạn bước vào một tòa nhà văn phòng hiện đại. Để đi qua cửa chính hay vào phòng làm việc của mình, bạn chỉ cần quẹt chiếc thẻ nhân viên thông thường. Tuy nhiên, để bước vào phòng máy chủ hay phòng nhân sự — nơi chứa những thông tin vô cùng nhạy cảm — bạn cần một chiếc thẻ có đặc quyền cao hơn. Trong thế giới phần mềm, việc kiểm soát xem ai được phép thực hiện hành động nào (như xóa tài khoản, nâng cấp quyền hạn hay xem báo cáo doanh thu) được gọi là **Function Level Authorization** (Kiểm soát quyền truy cập cấp chức năng).

Khác với việc kiểm tra xem bạn có quyền sở hữu hay xem một hồ sơ cụ thể hay không (Object Level Authorization), cơ chế này tập trung vào câu hỏi: "Bạn có quyền thực hiện hành động này hay không?". 

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

Kiến trúc phổ biến sử dụng **middleware** hoặc **decorator** để kiểm tra role trước khi thực thi logic nghiệp vụ. Tuy nhiên, một sai lầm vô cùng phổ biến là lập trình viên chỉ lo "giấu" chiếc nút bấm Admin trên giao diện màn hình của người dùng thông thường (client-side), mà quên mất việc đặt chốt chặn thực sự ở phía máy chủ (server-side), hoặc chỉ bảo vệ một số endpoint admin mà bỏ sót những endpoint khác.

## Mô tả lỗ hổng
Lỗ hổng **BFLA** (Broken Function Level Authorization) xuất hiện chính từ sơ hở đó. Nó giống như việc một tòa nhà chỉ khóa cửa trước nhưng lại để ngỏ cửa sau, hoặc chỉ cần người dùng thông thường tò mò đi vòng ra lối đi riêng là có thể tự do ra vào. Lỗ hổng này cực kỳ nguy hiểm bởi vì kẻ tấn công không cần phải có kỹ năng siêu việt hay công cụ hack phức tạp. Họ chỉ cần đóng vai một vị khách tò mò:

- **Thử đoán đường đi mới**: Thay đổi địa chỉ trên trình duyệt từ `/api/users/` thành `/api/admin/users/` xem chuyện gì xảy ra.
- **Thay đổi cách hành động**: Thay vì chỉ yêu cầu xem thông tin (`GET`), họ thử đổi sang lệnh xóa (`DELETE`) hay chỉnh sửa (`PUT`).
- **Lén lút gửi thêm thông tin**: Tự ý điền thêm quyền hạn mong muốn như `{"role": "admin"}` vào gói dữ liệu gửi đi.

Nếu máy chủ không kiểm tra quyền hạn một cách nghiêm ngặt cho từng hành động này, kẻ tấn công hoàn toàn có thể tự nâng cấp bản thân thành Quản trị viên tối cao, xóa sạch dữ liệu của hệ thống, hoặc thao túng toàn bộ ứng dụng. Điều này đặc biệt dễ xảy ra trong các hệ thống lớn được ghép lại từ nhiều dịch vụ nhỏ (microservices), nơi mà mỗi dịch vụ lại do một nhóm lập trình viên khác nhau phát triển và thiếu đi một quy chuẩn bảo mật thống nhất.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
- **Tóm tắt**: Thiết lập kiểm soát quyền truy cập cấp chức năng bằng cách mặc định từ chối mọi truy cập, sử dụng phần mềm trung gia tập trung, tách biệt controller theo vai trò, lọc dữ liệu đầu vào và áp dụng chính sách tại API Gateway.
- **Các bước chi tiết**:
  - **Mặc định từ chối (Default deny)**: mặc định từ chối mọi truy cập, chỉ cho phép khi có rule rõ ràng.
  - **Middleware ủy quyền tập trung (Centralized authorization middleware)**: không để mỗi endpoint tự kiểm tra riêng lẻ.
  - **Tách biệt controller theo vai trò (Role segregation)**: admin controller và user controller riêng biệt.
  - **Danh sách trắng các trường ghi (Whitelist writable fields)**: chỉ cho phép update các field được phép, filter `role`, `is_admin` khỏi input.
  - **Áp dụng tại API Gateway (API Gateway enforcement)**: áp dụng policy tại gateway level trước khi request đến service.

## Code Example
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


## Xem thêm
- [Broken Access Control](../broken-access-control/) — Xem thêm bài học về Broken Access Control.

## Nguồn tham khảo
- OWASP API Top 10: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP Access Control Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
- CWE-285: https://cwe.mitre.org/data/definitions/285.html

## Giải thích thuật ngữ
- **Function/Endpoint**: Điểm đầu cuối trong giao diện lập trình ứng dụng (API), là nơi hệ thống tiếp nhận và xử lý các yêu cầu từ phía người dùng gửi lên.
- **Middleware**: Phần mềm trung gian đóng vai trò như chốt kiểm soát nằm giữa yêu cầu của người dùng và logic xử lý của hệ thống, thường được dùng để xác thực, phân quyền hoặc ghi nhật ký.
- **Decorator**: Một cú pháp đặc biệt trong lập trình dùng để bao bọc và bổ sung tính năng (như kiểm tra quyền truy cập) cho một hàm mà không cần sửa đổi mã nguồn bên trong hàm đó.
- **Client-side (Phía máy khách)**: Tất cả những gì hiển thị và chạy trực tiếp trên thiết bị của người dùng, chẳng hạn như trình duyệt web (HTML/CSS/JS) hoặc ứng dụng di động.
- **Server-side (Phía máy chủ)**: Nơi tiếp nhận yêu cầu từ client, xử lý các logic nghiệp vụ phức tạp, truy vấn cơ sở dữ liệu và gửi kết quả phản hồi lại cho client.
- **HTTP Method (Phương thức HTTP)**: Các lệnh chuẩn hóa (như GET để lấy dữ liệu, POST để tạo mới, PUT để cập nhật, DELETE để xóa) dùng để chỉ định hành động muốn thực hiện trên tài nguyên web.
- **Parameter (Tham số)**: Các giá trị dữ liệu được gửi kèm theo yêu cầu (trong URL hoặc thân yêu cầu) để cung cấp thông tin chi tiết cho máy chủ xử lý.
- **Microservices**: Kiến trúc phần mềm chia nhỏ một ứng dụng lớn thành nhiều dịch vụ độc lập, mỗi dịch vụ đảm nhận một chức năng riêng biệt và giao tiếp với nhau qua mạng.
