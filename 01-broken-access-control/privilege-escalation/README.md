# Privilege Escalation

> **OWASP Top 10:2025**: A01:2025 – Broken Access Control | **CWE**: CWE-269 (Improper Privilege Management) | **Phân loại**: Access Control

## 🧱 Kiến thức Nền tảng
Leo thang đặc quyền (Privilege Escalation) là dạng lỗ hổng bảo mật kiểm soát truy cập, xảy ra khi kẻ tấn công lợi dụng các khiếm khuyết trong ứng dụng để giành được quyền hạn hoặc quyền truy cập cao hơn so với tài khoản ban đầu được cấp. Lỗ hổng này được chia thành hai hình thức chính: **horizontal/vertical escalation**. Trong đó, *horizontal escalation* (leo thang chiều ngang) xảy ra khi kẻ tấn công truy cập trái phép vào dữ liệu hoặc thực hiện hành động nhân danh một người dùng khác có cùng cấp bậc đặc quyền (ví dụ: người dùng thường xem báo cáo tài chính của người dùng thường khác). Ngược lại, *vertical escalation* (leo thang chiều dọc) xảy ra khi kẻ tấn công có mức đặc quyền thấp đạt được quyền truy cập vào các chức năng có mức đặc quyền cao hơn (ví dụ: tài khoản thường truy cập trang quản trị admin).

Để ngăn chặn và kiểm soát nguy cơ leo thang đặc quyền, hệ thống cần áp dụng cơ chế **RBAC** (Role-Based Access Control - Kiểm soát truy cập dựa trên vai trò). Mô hình RBAC quản lý quyền hạn của người dùng bằng cách gán các hành động cụ thể cho các vai trò như Admin, Manager, User, và liên kết người dùng với vai trò tương ứng. Tuy nhiên, RBAC chỉ an toàn nếu các kiểm tra vai trò được thực thi nghiêm ngặt ở phía máy chủ đối với mọi yêu cầu API. Nếu ứng dụng chỉ ẩn các nút chức năng trên giao diện người dùng mà không kiểm tra quyền ở backend, kẻ tấn công có thể dễ dàng sửa đổi tham số yêu cầu để thực hiện hành vi leo thang đặc quyền.

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

## 🔍 Mô tả lỗ hổng
Leo thang đặc quyền (Privilege Escalation) xảy ra khi kẻ tấn công khai thác lỗ hổng để đạt được quyền hạn cao hơn so với tài khoản ban đầu của họ. Leo thang theo chiều ngang xảy ra khi kẻ tấn công truy cập tài nguyên của người dùng khác cùng cấp; leo thang theo chiều dọc xảy ra khi họ chiếm quyền của quản trị viên. Nguyên nhân chủ yếu do ứng dụng thiếu các bước kiểm tra phân quyền (authorization check) ở phía máy chủ đối với các hành động nhạy cảm.

## ⚔️ Cơ chế tấn công
Bước 1: Người dùng thông thường (Mal) đăng nhập vào hệ thống và nhận được session cookie chứa ID người dùng (`user_id=123`) hoặc thuộc tính vai trò (`role=user`).
Bước 2: Mal phát hiện ứng dụng dựa vào cookie hoặc tham số ẩn phía client để quyết định quyền hạn truy cập API.
Bước 3: Mal chỉnh sửa cookie thành `role=admin` hoặc thay đổi tham số trong HTTP request gửi đến chức năng tạo người dùng mới.
Bước 4: Do máy chủ không kiểm tra lại quyền hạn của phiên làm việc thực sự trong DB/Session mà tin tưởng trực tiếp vào tham số do client gửi lên, Mal thực hiện thành công quyền quản trị.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Privilege escalation occurs when an attacker obtains access to resources or functionality they are not authorized to use (horizontal or vertical). Mitigation relies on robust Access Control Lists (ACLs), Role-Based Access Control (RBAC), verifying authorization on every request, and implementing the principle of least privilege.
- **Các bước chi tiết**:
  - Perform server-side authentication and authorization checks on every single request and API endpoint; never rely on UI hiding alone.
  - Use standard authorization frameworks rather than rolling custom access check logic.
  - Implement both vertical (role-based) and horizontal (owner-based) authorization checks to ensure users can only access their own resources.
  - Run application processes, services, and database connections with the minimum privileges required (Least Privilege Principle).

## 💻 Code Example
```python
from functools import wraps
from flask import abort, g

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

@require_role('admin')
def admin_dashboard():
    return "Welcome to the admin panel!"
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Khẳng định cơ chế phân quyền phải được xác thực hoàn toàn ở phía máy chủ đối với mỗi yêu cầu thao tác dữ liệu, không tin tưởng vào các thông số do client gửi lên như cookie vai trò hoặc trường ẩn.
- **Nguồn tham khảo**: OWASP A01:2021, CWE-269
