# Insecure Design

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-73 (External Control of File Name or Path), CWE-918 (SSRF) | **Phân loại**: Design & Process

## 🧱 Kiến thức Nền tảng
Thiết kế không an toàn (Insecure Design) là nhóm lỗ hổng phát sinh từ các quyết định sai lầm ngay trong giai đoạn hoạch định kiến trúc của vòng đời phát triển phần mềm (SDLC - Software Development Life Cycle). Để xây dựng ứng dụng an toàn, quy trình phát triển cần chuyển dịch sang Secure SDLC, tích hợp bảo mật vào từng bước từ khâu lên ý tưởng, thiết kế cho đến lập trình và vận hành.

Trụ cột cốt lõi của Secure SDLC trong giai đoạn thiết kế là Threat Modeling (Mô hình hóa mối đe dọa). Thông qua việc xây dựng sơ đồ luồng dữ liệu (DFD), nhà phát triển có thể chủ động nhận diện, phân loại các nguy cơ bảo mật tiềm ẩn và xếp hạng mức độ ưu tiên của các biện pháp giảm thiểu.

Trong quá trình mô hình hóa, việc phân định rõ các Trust Boundaries (Ranh giới tin cậy) là cực kỳ quan trọng. Ranh giới tin cậy là đường phân tách giữa các vùng có mức độ kiểm soát khác nhau, ví dụ như giữa trình duyệt của người dùng (vùng không tin cậy) và máy chủ dịch vụ (vùng tin cậy). Một thiết kế an toàn đòi hỏi mọi luồng dữ liệu hoặc yêu cầu từ vùng không tin cậy đi qua ranh giới này đều phải chịu sự kiểm tra nghiêm ngặt về tính hợp lệ và quyền hạn ở phía máy chủ. Việc phụ thuộc vào kiểm tra bảo mật ở phía client hoặc giả định rằng dữ liệu từ client luôn an toàn là biểu hiện điển hình của việc thiết lập ranh giới tin cậy sai lầm, dẫn đến nguy cơ hệ thống bị xâm nhập dễ dàng.

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Decorator to enforce trust boundary checks at the backend API layer
from functools import wraps
from flask import session, abort, request

def enforce_trust_boundary(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if the user is authenticated and has the correct role
            # This validation occurs right at the entry point of the trusted zone
            user_role = session.get('user_role')
            if not user_role or user_role != required_role:
                # Reject unauthorized traffic from untrusted client zone
                abort(403, "Access Denied: Insufficient privileges at trust boundary")
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

## 🔍 Mô tả lỗ hổng
Thiết kế không an toàn (Insecure Design) đại diện cho các lỗi bảo mật phát sinh ngay từ giai đoạn thiết kế kiến trúc hệ thống, trước khi viết code. Lỗ hổng này không thể được khắc phục bằng cách sửa mã nguồn cục bộ vì bản thân logic hoặc luồng xử lý của hệ thống đã bị sai sót hoặc thiếu các cơ chế kiểm soát cần thiết. Ví dụ điển hình bao gồm việc thiếu mô hình hóa mối đe dọa (threat modeling), thiếu phân định ranh giới tin cậy (trust boundaries), hoặc phụ thuộc vào kiểm tra bảo mật ở phía client.

## ⚔️ Cơ chế tấn công
Bước 1: Trong giai đoạn thiết kế, các nhà phát triển không thực hiện mô hình hóa mối đe dọa (threat modeling) và không xác định đúng ranh giới tin cậy (trust boundaries).
Bước 2: Ứng dụng phụ thuộc hoàn toàn vào việc ẩn các chức năng hành động (như nút 'Xóa người dùng') ở giao diện HTML phía client đối với người dùng không có quyền quản trị.
Bước 3: Kẻ tấn công là người dùng thông thường phân tích mã nguồn HTML/JS, tìm ra URL API của chức năng xóa (`/admin/delete-user`), và gửi trực tiếp HTTP POST request đến API đó.
Bước 4: Do backend không thực hiện kiểm tra quyền hạn của phiên làm việc hiện tại mà chỉ dựa vào việc ẩn nút bấm ở frontend, hành động xóa được thực thi thành công.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Avoid insecure design by embedding threat modeling, secure design patterns, and rigorous access control checks throughout the SDLC.
- **Các bước chi tiết**:
  - Incorporate security analysis, such as threat modeling (e.g., STRIDE), into the initial design phase of any project.
  - Implement the principle of least privilege, ensuring default configurations restrict access until explicitly authorized.
  - Verify authorization checks at all backend logical layers, rather than relying on frontend client-side UI visibility settings.
  - Leverage verified security libraries and patterns rather than building custom, unproven security schemes.
  - Review and enforce business logic workflows to ensure users cannot bypass critical validation steps.

## 💻 Code Example
```python
from functools import wraps
from flask import session, abort

# Secure design enforces access controls on the backend API,
# not just hiding buttons or links on the frontend templates.
def require_privilege(needed_privilege):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_permissions = session.get('permissions', [])
            if needed_privilege not in user_permissions:
                # Terminate with unauthorized error status
                abort(403, "Access Forbidden: Insufficient Permissions")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin/delete-user', methods=['POST'])
@require_privilege('admin_manage')
def delete_user():
    # Execute deletion logic
    pass
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này đã được chỉnh sửa (FIXED). Đã sửa lỗi thiếu dấu ngoặc đóng/mở trên hàm psycopg2.connect và lỗi logic vòng lặp fetch dữ liệu ở Slide 10. Sửa lỗi kiểm tra SSRF yếu kém ở Slide 11, thay thế bằng cơ chế kiểm tra địa chỉ IP đã phân giải có thuộc dải IP nội bộ/không an toàn (RFC 1918, RFC 1122, RFC 3927) hay không. Bổ sung mã hóa UTF-8 cho mật khẩu bcrypt ở Slide 12.
- **Nguồn tham khảo**: OWASP A04:2021, CWE-73, CWE-918
