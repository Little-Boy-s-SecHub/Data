# Insecure Design

> **CWE**: CWE-73 (External Control of File Name or Path), CWE-918 (SSRF) | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng bạn muốn xây dựng một ngôi nhà. Bản thiết kế ban đầu của kiến trúc sư hoàn toàn quên vẽ cửa sổ phòng tắm, hoặc đặt két sắt ngay cạnh cửa sổ tầng trệt mà không có song sắt bảo vệ. Dù sau đó thợ xây có sử dụng loại gạch tốt nhất, xi măng đắt nhất và xây dựng cực kỳ tỉ mỉ (code chuẩn không lỗi cú pháp), ngôi nhà vẫn rất dễ bị đột nhập. Lỗi thiết kế gốc này tương tự như **Thiết kế không an toàn (Insecure Design)**.

Để tránh những sai lầm chết người ngay từ đầu, quy trình phát triển phần mềm cần áp dụng mô hình **Secure SDLC** — tức là đưa các tiêu chuẩn bảo mật vào từng bước, ngay từ khâu lên ý tưởng. 

Một công cụ quan trọng trong Secure SDLC là **Threat Modeling (Mô hình hóa mối đe dọa)**, giúp lập trình viên vẽ ra bản đồ các mối nguy để chủ động phòng tránh trước khi đặt những viên gạch code đầu tiên. 
Trong bản đồ này, việc vẽ ra các **Trust Boundaries (Ranh giới tin cậy)** là tối quan trọng. Hãy tưởng tượng ranh giới tin cậy giống như lớp cửa kính an ninh tại sân bay: khu vực sảnh ngoài là nơi bất kỳ ai cũng có thể vào (vùng không tin cậy - trình duyệt người dùng), còn khu vực phòng chờ lên máy bay là nơi cực kỳ bảo mật (vùng tin cậy - máy chủ dịch vụ). Một thiết kế an toàn bắt buộc phải kiểm tra kỹ càng mọi hành lý, giấy tờ của hành khách ngay tại cửa an ninh. Nếu bạn chỉ tin tưởng vào các tấm biển báo "cấm vào" ở sảnh ngoài mà không có nhân viên soát vé thật sự ở cửa an ninh, kẻ xấu sẽ dễ dàng lẻn vào khu vực cấm.

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

## Mô tả lỗ hổng
Lỗ hổng Thiết kế không an toàn (Insecure Design) là những sai lầm nghiêm trọng nằm ngay ở kiến trúc và tư duy logic của hệ thống trước khi mã nguồn được viết ra. 

Nó nguy hiểm ở chỗ, bạn không thể vá lỗ hổng này bằng cách sửa một vài dòng code đơn lẻ. Lỗi nằm ở cách thức vận hành của quy trình. 

Ví dụ điển hình là việc bạn thiết kế hệ thống chỉ ẩn nút "Xóa người dùng" trên giao diện web của người dùng thường, nhưng lại quên cấu hình kiểm tra quyền hạn thực sự ở máy chủ backend. Kẻ tấn công chỉ cần tìm ra đường dẫn API ẩn và gửi yêu cầu trực tiếp là có thể xóa bất kỳ ai. Dù code của tính năng xóa được viết hoàn hảo, không có lỗi kỹ thuật nào, hệ thống của bạn vẫn bị sụp đổ từ bên trong do lỗi thiết kế quy trình lỏng lẻo.

## Cơ chế tấn công
Bước 1: Trong giai đoạn thiết kế, các nhà phát triển không thực hiện mô hình hóa mối đe dọa (threat modeling) và không xác định đúng ranh giới tin cậy (trust boundaries).
Bước 2: Ứng dụng phụ thuộc hoàn toàn vào việc ẩn các chức năng hành động (như nút 'Xóa người dùng') ở giao diện HTML phía client đối với người dùng không có quyền quản trị.
Bước 3: Kẻ tấn công là người dùng thông thường phân tích mã nguồn HTML/JS, tìm ra URL API của chức năng xóa (`/admin/delete-user`), và gửi trực tiếp HTTP POST request đến API đó.
Bước 4: Do backend không thực hiện kiểm tra quyền hạn của phiên làm việc hiện tại mà chỉ dựa vào việc ẩn nút bấm ở frontend, hành động xóa được thực thi thành công.

### Ví dụ HTTP request bypass frontend validation:
```http
# Frontend chỉ hiển thị nút "Mua" nếu tài khoản đủ tiền
# Nhưng kẻ tấn công bypass hoàn toàn frontend bằng cách gửi request trực tiếp:

POST /api/purchase HTTP/1.1
Content-Type: application/json

{"item_id": 999, "quantity": 100, "price": 0}

# Server không kiểm tra lại balance phía backend
# → Đơn hàng được xử lý với giá 0 đồng
```

## Biện pháp phòng thủ
- **Tóm tắt**: Tránh thiết kế không an toàn bằng cách nhúng mô hình hóa mối đe dọa, các mẫu thiết kế bảo mật và kiểm tra kiểm soát truy cập nghiêm ngặt xuyên suốt vòng đời phát triển phần mềm (SDLC).
- **Các bước chi tiết**:
  - Tích hợp phân tích bảo mật — như mô hình hóa mối đe dọa (ví dụ: STRIDE) — vào giai đoạn thiết kế ban đầu của mọi dự án.
  - Áp dụng nguyên tắc đặc quyền tối thiểu, đảm bảo cấu hình mặc định hạn chế quyền truy cập cho đến khi được cấp phép rõ ràng.
  - Xác minh kiểm tra phân quyền tại tất cả các lớp logic backend, thay vì chỉ dựa vào cài đặt hiển thị giao diện phía client (frontend UI).
  - Sử dụng các thư viện và mẫu bảo mật đã được kiểm chứng thay vì tự xây dựng các cơ chế bảo mật tùy chỉnh chưa được kiểm tra.
  - Rà soát và thực thi quy trình logic nghiệp vụ để đảm bảo người dùng không thể bỏ qua các bước xác thực quan trọng.

## Code Example
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A04:2021, CWE-73, CWE-918

## Giải thích thuật ngữ
- **Insecure Design (Thiết kế không an toàn)**: Nhóm lỗ hổng phát sinh do sai sót hoặc thiếu sót trong quá trình lập kế hoạch và thiết kế kiến trúc hệ thống, khiến hệ thống không có các cơ chế kiểm soát bảo mật cần thiết ngay từ đầu.
- **Secure SDLC (Vòng đời phát triển phần mềm bảo mật)**: Quy trình phát triển phần mềm tích hợp các hoạt động kiểm tra và thực hành bảo mật vào mọi giai đoạn từ yêu cầu, thiết kế, triển khai cho đến kiểm thử và bảo trì.
- **Threat Modeling (Mô hình hóa mối đe dọa)**: Phương pháp phân tích hệ thống để xác định các nguy cơ bảo mật tiềm ẩn, các tác nhân đe dọa và đề xuất các biện pháp giảm thiểu tương ứng trong giai đoạn thiết kế.
- **Trust Boundaries (Ranh giới tin cậy)**: Điểm phân cách trong kiến trúc hệ thống nơi dữ liệu chuyển tiếp từ vùng có mức độ tin cậy thấp (ví dụ: dữ liệu do người dùng gửi lên) sang vùng có mức độ tin cậy cao (ví dụ: cơ sở dữ liệu nội bộ).
- **STRIDE**: Khung phân loại mối đe dọa do Microsoft phát triển, đại diện cho: Giả mạo (Spoofing), Can thiệp (Tampering), Chối bỏ (Repudiation), Tiết lộ thông tin (Information Disclosure), Từ chối dịch vụ (Denial of Service), và Leo thang đặc quyền (Elevation of Privilege).
- **Least Privilege (Đặc quyền tối thiểu)**: Nguyên tắc bảo mật yêu cầu chỉ cấp cho người dùng hoặc tiến trình các quyền hạn tối thiểu cần thiết để hoàn thành công việc của họ, nhằm hạn chế thiệt hại nếu tài khoản bị xâm nhập.
