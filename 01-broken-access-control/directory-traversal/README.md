# Directory Traversal

> **OWASP Top 10:2025**: A01:2025 – Broken Access Control | **CWE**: CWE-22 | **Phân loại**: File & Data

## 🧱 Kiến thức Nền tảng
Lỗ hổng duyệt thư mục (Directory Traversal) cho phép kẻ tấn công đọc các tệp tin tùy ý trên máy chủ chạy ứng dụng web bằng cách thoát khỏi thư mục cơ sở được ứng dụng chỉ định. Lỗ hổng này liên quan trực tiếp đến cơ chế **path resolution** (phân giải đường dẫn) của hệ điều hành. Hệ thống tệp tin sử dụng chuỗi ký tự tương đối `../` làm tham chiếu để di chuyển ngược lên một cấp trong cấu trúc thư mục dạng cây. Khi một ứng dụng chấp nhận đầu vào của người dùng và ghép nối trực tiếp vào đường dẫn tệp tin mà không có biện pháp lọc, kẻ tấn công có thể chèn các chuỗi `../` liên tục (ví dụ: `../../../../etc/passwd`) để thoát khỏi ranh giới thư mục chỉ định và truy cập các tệp hệ thống nhạy cảm.

Ngoài ra, **URL structure** (cấu trúc URL) của ứng dụng thường chứa các tham số truy vấn chỉ định tài nguyên tải xuống (ví dụ: `https://example.com/download?file=report.pdf`). Trình duyệt gửi URL này dưới dạng HTTP request, và máy chủ sẽ phân tích giá trị của tham số `file` để định vị tệp trên đĩa cứng. Nếu lập trình viên không xác thực tham số này mà xử lý tệp trực tiếp, kẻ tấn công sẽ thao túng cấu trúc URL để thực hiện cuộc tấn công duyệt thư mục. Để phòng thủ hiệu quả, máy chủ bắt buộc phải phân giải đường dẫn đầu vào thành một đường dẫn tuyệt đối chuẩn hóa (canonical path) và xác thực rõ ràng xem đường dẫn đã được giải quyết có thực sự nằm bên dưới thư mục gốc được phép truy cập hay không.

```python
# Safe path resolution check to prevent directory traversal
from pathlib import Path

def get_safe_filepath(user_filename, base_dir="/var/www/safe_uploads"):
    """
    Resolves the target file path and ensures it does not escape the base directory.
    """
    # Convert base directory to an absolute canonical path
    base_path = Path(base_dir).resolve()
    
    # Combine the base path with the user-provided filename and resolve it
    # This automatically eliminates dynamic path segments like '..' or symlinks
    target_path = Path(base_path, user_filename).resolve()
    
    # Verify that the resolved target path is still located within the base path
    if not target_path.is_relative_to(base_path):
        # Deny access if a path traversal attempt is detected
        raise PermissionError("Access Denied: Requested file escapes the base directory.")
        
    return target_path
```

## 🔍 Mô tả lỗ hổng
Duyệt thư mục (directory traversal) xảy ra khi một ứng dụng chấp nhận các đường dẫn do người dùng cung cấp để đọc các tệp mà không có sự xác thực phù hợp. Kẻ tấn công có thể tận dụng các chuỗi duyệt đường dẫn tương đối (như '../') để thoát khỏi thư mục cơ sở được chỉ định và đọc các tệp nhạy cảm từ hệ thống tệp cục bộ của máy chủ.

## ⚔️ Cơ chế tấn công
Một ứng dụng tải xuống thực đơn nhà hàng thông qua một tham số (ví dụ: menu=menu1.pdf). Trix thao túng tham số này, yêu cầu menu=../../../../ssl/private.key. Máy chủ nối đường dẫn này một cách ngây thơ và đọc tệp, làm lộ khóa SSL riêng tư của máy chủ cho kẻ tấn công.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Giải quyết các đường dẫn thành các vị trí tuyệt đối, kiểm tra xem chúng có nằm trong thư mục cơ sở hay không, và hạn chế các đặc quyền truy cập tệp.
- **Các bước chi tiết**:
  - Tránh truyền tên tệp trực tiếp trong các tham số người dùng; thay vào đó, hãy sử dụng ánh xạ gián tiếp (như ID số hoặc các khóa tra cứu).
  - Nếu tên tệp phải do người dùng nhập, hãy xác thực chúng dựa trên danh sách trắng nghiêm ngặt chỉ chứa các ký tự chữ và số được phép.
  - Giải quyết các đường dẫn đầu vào thành các đường dẫn tuyệt đối bằng cách sử dụng các hàm chuẩn hóa (ví dụ: Path.resolve() của Python) và xác minh rõ ràng rằng đường dẫn đích đã được giải quyết nằm bên trong thư mục cơ sở dự kiến.
  - Đảm bảo tiến trình máy chủ web chạy dưới một tài khoản người dùng bị hạn chế với các đặc quyền đọc chỉ giới hạn nghiêm ngặt trong các tài sản công cộng và cách ly ứng dụng bằng containerization hoặc chroot jails.

## 💻 Code Example
```python
import os
from pathlib import Path

def safe_read_file(user_filename, base_directory="/var/www/uploads"):
    # Convert base directory to absolute path
    base_path = Path(base_directory).resolve()
    
    # Combine and resolve the target path to eliminate '..' and symlinks
    target_path = Path(base_path, user_filename).resolve()
    
    # Explicitly check that the resolved path stays inside the base directory
    if not target_path.is_relative_to(base_path):
        raise PermissionError("Access Denied: Path traversal attempt detected.")
        
    with open(target_path, 'r') as file:
        return file.read()
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã loại bỏ các mô tả trình đơn điều hướng bị trùng lặp vốn được thêm sai vào các phần mô tả của từ slide 5 đến slide 10.
- **Nguồn tham khảo**: OWASP A01:2021-Broken Access Control, CWE-22 (Path Traversal)
