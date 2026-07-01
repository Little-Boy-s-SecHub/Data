# Privilege Escalation

> **CWE**: CWE-269 (Improper Privilege Management) | **Phân loại**: Access Control

## Kiến thức Nền tảng
Hãy tưởng tượng bạn bước vào một bệnh viện lớn. Nếu bạn là một bệnh nhân bình thường, bạn có thể đi lại ở khu vực sảnh chờ, phòng khám hoặc căng tin. Bạn không thể tự tiện bước vào phòng bệnh của một bệnh nhân khác để xem bệnh án của họ — nếu bạn cố tình làm vậy, đó chính là **leo thang đặc quyền chiều ngang (horizontal escalation)**, tức là lấn sân sang quyền hạn của người khác có cùng vị trí giống bạn. Mặt khác, phòng phẫu thuật hay phòng lưu trữ hồ sơ bệnh án trung tâm chỉ dành riêng cho các bác sĩ trưởng khoa. Nếu bạn tìm cách lẻn vào đó, tự ý lấy áo blouse trắng mặc vào để thực hiện các ca mổ hoặc chỉnh sửa bệnh án, đó chính là **leo thang đặc quyền chiều dọc (vertical escalation)**, tức là chiếm đoạt đặc quyền cao hơn quyền hạn của bản thân.

Trong thế giới phát triển ứng dụng, để phân chia ranh giới quyền lực này, các lập trình viên sử dụng một mô hình gọi là **RBAC** (Role-Based Access Control - Kiểm soát truy cập dựa trên vai trò). Mô hình này chia người dùng thành các nhóm vai trò rõ ràng (như Admin, Manager, User) và gán cho mỗi vai trò những quyền hạn cụ thể. Tuy nhiên, rắc rối sẽ xảy ra nếu phần mềm chỉ lo "ẩn" chiếc nút bấm "Bảng điều khiển Admin" trên màn hình điện thoại hay trình duyệt của người dùng thông thường, mà ở phía máy chủ (backend) lại không hề kiểm tra xem người gửi yêu cầu thực sự là ai. Kẻ xấu có thể dễ dàng bỏ qua giao diện hiển thị, gửi trực tiếp yêu cầu lên máy chủ để tự phong cho mình các đặc quyền tối cao.

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

## Mô tả lỗ hổng
Lỗ hổng **Leo thang đặc quyền** (Privilege Escalation) xuất hiện khi hệ thống có những kẽ hở trong khâu quản lý và kiểm tra quyền hạn, cho phép người dùng bình thường làm được những việc vượt quá phạm vi được phép của họ. 

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó giúp kẻ tấn công phá vỡ mọi quy tắc bảo mật của ứng dụng. Bằng cách lách qua các chốt chặn lỏng lẻo ở phía máy chủ, kẻ xấu có thể đọc trộm toàn bộ dữ liệu của người dùng khác (chiều ngang) hoặc biến mình thành Quản trị viên tối cao (chiều dọc). Từ đó, họ có toàn quyền kiểm soát hệ thống, thay đổi cấu hình, xóa dữ liệu, hoặc thậm chí là biến toàn bộ ứng dụng thành công cụ phục vụ cho mục đích xấu của mình. Mọi hành động nhạy cảm trên hệ thống bắt buộc phải được máy chủ kiểm tra và xác thực quyền hạn kỹ lưỡng trước khi thực thi, không bao giờ được tin tưởng hoàn toàn vào giao diện người dùng (UI) hay các tham số từ client.

## Cơ chế tấn công
Bước 1: Người dùng thông thường (Mal) đăng nhập vào hệ thống và nhận được session cookie chứa ID người dùng (`user_id=123`) hoặc thuộc tính vai trò (`role=user`).
Bước 2: Mal phát hiện ứng dụng dựa vào cookie hoặc tham số ẩn phía client để quyết định quyền hạn truy cập API.
Bước 3: Mal chỉnh sửa cookie thành `role=admin` hoặc thay đổi tham số trong HTTP request gửi đến chức năng tạo người dùng mới.
Bước 4: Do máy chủ không kiểm tra lại quyền hạn của phiên làm việc thực sự trong DB/Session mà tin tưởng trực tiếp vào tham số do client gửi lên, Mal thực hiện thành công quyền quản trị.

## Biện pháp phòng thủ
- **Tóm tắt**: Privilege escalation occurs when an attacker obtains access to resources or functionality they are not authorized to use (horizontal or vertical). Mitigation relies on robust Access Control Lists (ACLs), Role-Based Access Control (RBAC), verifying authorization on every request, and implementing the principle of least privilege.
- **Các bước chi tiết**:
  - Perform server-side authentication and authorization checks on every single request and API endpoint; never rely on UI hiding alone.
  - Use standard authorization frameworks rather than rolling custom access check logic.
  - Implement both vertical (role-based) and horizontal (owner-based) authorization checks to ensure users can only access their own resources.
  - Run application processes, services, and database connections with the minimum privileges required (Least Privilege Principle).

## Code Example
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


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A01:2021, CWE-269

## Giải thích thuật ngữ
- **Horizontal Escalation (Leo thang chiều ngang)**: Hành vi truy cập trái phép vào dữ liệu hoặc chức năng của một người dùng khác có cùng mức phân quyền trong hệ thống.
- **Vertical Escalation (Leo thang chiều dọc)**: Hành vi chiếm đoạt quyền truy cập vào các chức năng hoặc tài nguyên dành riêng cho người dùng có cấp bậc đặc quyền cao hơn (ví dụ như Admin).
- **RBAC (Role-Based Access Control)**: Mô hình kiểm soát truy cập dựa trên vai trò, phân chia người dùng vào các nhóm chức danh và quyết định quyền hạn dựa trên nhóm đó.
- **Backend (Phía máy chủ)**: Phần chạy ẩn bên dưới của ứng dụng, chịu trách nhiệm lưu trữ cơ sở dữ liệu, xử lý logic nghiệp vụ và bảo mật thông tin.
- **UI (User Interface)**: Giao diện người dùng, nơi hiển thị các hình ảnh, nút bấm và thông tin để người dùng tương tác trực tiếp trên màn hình.
- **ACL (Access Control List)**: Danh sách kiểm soát truy cập, quy định chi tiết người dùng hoặc tiến trình nào được phép thực hiện hành động gì trên một tài nguyên cụ thể.
- **Least Privilege Principle (Nguyên tắc đặc quyền tối thiểu)**: Nguyên tắc bảo mật yêu cầu chỉ cấp cho người dùng hoặc tiến trình đúng những quyền hạn tối thiểu cần thiết để hoàn thành công việc, không cấp dư thừa.
