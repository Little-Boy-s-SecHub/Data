# Directory Traversal

> **CWE**: CWE-22 | **Phân loại**: Access Control

## Kiến thức Nền tảng
Hãy tưởng tượng hệ thống tệp tin trên máy chủ web giống như một thư viện lưu trữ tài liệu khổng lồ. Trong đó, mỗi phòng ban có một tủ hồ sơ riêng và nhân viên chỉ được phép xem các tài liệu trong tủ hồ sơ của phòng mình. Để giữ an toàn, người quản lý thư viện đã đặt quy định: "Bạn chỉ được phép tìm kiếm hồ sơ trong phạm vi ngăn tủ công cộng được chỉ định". 

Tuy nhiên, trong cấu trúc đường dẫn của máy tính, có một "phép thuật" dịch chuyển ngược dòng, đó là ký hiệu `../` (đại diện cho việc lùi lại một thư mục cha). Nếu hệ thống quản lý thư viện quá ngây thơ, nhận yêu cầu tìm kiếm từ bạn và đi thẳng vào kho mà không kiểm tra xem bạn có đang lén lút dùng ký hiệu "lùi lại" này hay không, một điều nguy hại sẽ xảy ra. Kẻ tấn công chỉ cần viết yêu cầu dưới dạng `../` nhiều lần liên tiếp để đi ngược ra khỏi tủ hồ sơ công cộng, lách qua cửa bảo vệ, và đi thẳng vào ngăn kéo lưu trữ thông tin tuyệt mật của hệ điều hành (như tệp lưu mật khẩu hệ thống hay mã khóa bảo mật). Cơ chế phân giải đường dẫn (path resolution) của máy chủ nếu không được lập trình để chặn đứng hành vi "leo tường" này sẽ tạo điều kiện cho kẻ xấu tự do lục lọi.

Ngoài ra, cấu trúc URL (URL structure) của ứng dụng thường chứa các tham số truy vấn chỉ định tài nguyên tải xuống (ví dụ: `https://example.com/download?file=report.pdf`). Trình duyệt gửi URL này dưới dạng HTTP request, và máy chủ sẽ phân tích giá trị của tham số `file` để định vị tệp trên đĩa cứng. Nếu lập trình viên không xác thực tham số này mà xử lý tệp trực tiếp, kẻ tấn công sẽ thao túng cấu trúc URL để thực hiện cuộc tấn công duyệt thư mục. Để phòng thủ hiệu quả, máy chủ bắt buộc phải phân giải đường dẫn đầu vào thành một đường dẫn tuyệt đối chuẩn hóa (canonical path) và xác thực rõ ràng xem đường dẫn đã được giải quyết có thực sự nằm bên dưới thư mục gốc được phép truy cập hay không.

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

## Mô tả lỗ hổng
Lỗ hổng **Duyệt thư mục** (Directory Traversal hoặc Path Traversal) xuất hiện khi ứng dụng tin tưởng mù quáng vào đường dẫn hoặc tên tệp tin do người dùng nhập vào. 

Nó cực kỳ nguy hiểm vì nó giống như việc bạn đưa cho thủ thư một mảnh giấy ghi: "Cho tôi xem tài liệu nằm ở: `phòng_công_cộng/../../../thư_mục_hệ_thống/mật_khẩu.txt`", và người thủ thư cứ thế đi lấy mà không mảy may suy nghĩ. Bằng cách lách qua các thư mục giới hạn thông qua các ký tự tương đối, kẻ tấn công có thể đọc trộm các tệp cấu hình chứa mật khẩu cơ sở dữ liệu, mã nguồn của ứng dụng, hay thậm chí là các tệp hệ thống nhạy cảm nhất. Điều này biến một ứng dụng tưởng chừng an toàn thành một "lỗ hổng mở" khiến toàn bộ bí mật của máy chủ bị phơi bày ra ngoài.

## Cơ chế tấn công
Một ứng dụng tải xuống thực đơn nhà hàng thông qua một tham số (ví dụ: menu=menu1.pdf). Trix thao túng tham số này, yêu cầu menu=../../../../ssl/private.key. Máy chủ nối đường dẫn này một cách ngây thơ và đọc tệp, làm lộ khóa SSL riêng tư của máy chủ cho kẻ tấn công.

### Các biến thể encoding để bypass filter:
| Payload | Ý nghĩa |
|---|---|
| `../` | Cơ bản |
| `%2e%2e%2f` | URL encode toàn phần |
| `..%2f` | Chỉ encode `/` |
| `%2e%2e/` | Chỉ encode `.` |
| `....//` | Double slash bypass |
| `..\` | Windows path separator |
| `%252e%252e%252f` | Double URL encode |
| `..%c0%af` | Unicode overlong encoding |

### Ví dụ HTTP request minh họa Directory Traversal:
```http
# Mỗi ../ đi lên 1 thư mục cha
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: vulnerable-app.com
# ../ lần 1: ra khỏi /var/www/html/uploads
# ../ lần 2: ra khỏi /var/www/html
# ../ lần 3: ra khỏi /var/www
# ../ lần 4: về root /
# → đọc /etc/passwd (file chứa tên người dùng hệ thống)
```

## Biện pháp phòng thủ
- **Tóm tắt**: Giải quyết các đường dẫn thành các vị trí tuyệt đối, kiểm tra xem chúng có nằm trong thư mục cơ sở hay không, và hạn chế các đặc quyền truy cập tệp.
- **Các bước chi tiết**:
  - Tránh truyền tên tệp trực tiếp trong các tham số người dùng; thay vào đó, hãy sử dụng ánh xạ gián tiếp (như ID số hoặc các khóa tra cứu).
  - Nếu tên tệp phải do người dùng nhập, hãy xác thực chúng dựa trên danh sách trắng nghiêm ngặt chỉ chứa các ký tự chữ và số được phép.
  - Giải quyết các đường dẫn đầu vào thành các đường dẫn tuyệt đối bằng cách sử dụng các hàm chuẩn hóa (ví dụ: Path.resolve() của Python) và xác minh rõ ràng rằng đường dẫn đích đã được giải quyết nằm bên trong thư mục cơ sở dự kiến.
  - Đảm bảo tiến trình máy chủ web chạy dưới một tài khoản người dùng bị hạn chế với các đặc quyền đọc chỉ giới hạn nghiêm ngặt trong các tài sản công cộng và cách ly ứng dụng bằng containerization hoặc chroot jails.

## Code Example
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


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A01:2021-Broken Access Control, CWE-22 (Path Traversal)

## Giải thích thuật ngữ
- **Path Resolution (Phân giải đường dẫn)**: Quá trình hệ điều hành chuyển đổi một đường dẫn (tương đối hoặc tuyệt đối) thành vị trí thực tế của tệp tin hoặc thư mục trên ổ cứng.
- **Canonical Path (Đường dẫn chuẩn hóa)**: Đường dẫn tuyệt đối duy nhất và đầy đủ của một tệp tin hoặc thư mục, sau khi đã loại bỏ tất cả các ký tự di chuyển tương đối như `.` hoặc `..` và các liên kết tượng trưng (symlinks).
- **URL Structure (Cấu trúc URL)**: Cách sắp xếp các thành phần trong một địa chỉ web (gồm giao thức, tên miền, đường dẫn và các tham số truy vấn) để định vị tài nguyên trên internet.
- **Encoding (Mã hóa)**: Quá trình chuyển đổi dữ liệu từ định dạng này sang định dạng khác (ví dụ: URL encode chuyển đổi các ký tự đặc biệt thành dạng `%xx`) để truyền tải an toàn qua môi trường web hoặc để vượt qua các bộ lọc bảo mật.
- **Bypass (Vượt qua)**: Kỹ thuật lách qua hoặc vô hiệu hóa các biện pháp kiểm soát bảo mật để thực hiện hành vi trái phép.
- **Containerization (Container hóa)**: Công nghệ đóng gói ứng dụng cùng toàn bộ thư viện và cấu hình cần thiết để chạy độc lập và cách ly với hệ điều hành máy chủ (ví dụ như Docker).
- **Chroot Jail**: Một cơ chế trên hệ điều hành Unix/Linux giúp cô lập một tiến trình bằng cách thay đổi thư mục gốc ảo của nó, ngăn không cho tiến trình đó truy cập các tệp tin bên ngoài thư mục được chỉ định.
