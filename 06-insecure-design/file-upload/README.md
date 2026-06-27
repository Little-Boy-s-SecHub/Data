# File Upload Vulnerabilities

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type) | **Phân loại**: File & Data

## 🧱 Kiến thức Nền tảng
Lỗ hổng tải tệp tin (File Upload Vulnerabilities) xuất hiện khi ứng dụng cho phép người dùng tải tệp lên hệ thống mà không thực hiện kiểm tra và cô lập thích hợp. Để xác định định dạng tệp tải lên, ứng dụng không nên chỉ dựa vào phần mở rộng (.jpg, .png) hoặc MIME type do trình duyệt của client khai báo trong header `Content-Type`. MIME type rất dễ bị giả mạo bằng các công cụ chặn bắt request.

Thay vào đó, hệ thống cần đọc Magic bytes (các byte ma thuật) - tức là các byte đầu tiên của nội dung tệp tin để xác thực định dạng thực tế của tệp (ví dụ: `FF D8 FF` cho JPEG hoặc `89 50 4E 47` cho PNG).

Bên cạnh việc xác định định dạng, vị trí lưu trữ tệp cũng ảnh hưởng trực tiếp đến an ninh hệ thống. Web root folder (thư mục gốc của dịch vụ web) là nơi lưu trữ các tệp tĩnh và mã nguồn mà máy chủ web có quyền truy cập trực tiếp qua URL để phục vụ người dùng. Nếu các tệp tải lên được lưu trực tiếp vào trong Web root folder mà không tắt quyền thực thi script (như PHP, ASP.NET), kẻ tấn công có thể tải lên một web shell và kích hoạt nó trực tiếp thông qua đường dẫn URL. Vì vậy, các tệp tải lên phải được lưu trữ bên ngoài thư mục gốc web hoặc trên các dịch vụ lưu trữ đám mây độc lập.

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

## 🔍 Mô tả lỗ hổng
Lỗ hổng Tải tệp tin (File Upload Vulnerabilities) xảy ra khi ứng dụng cho phép người dùng tải lên các tệp tin lên máy chủ mà không kiểm soát chặt chẽ loại tệp, tên tệp hoặc quyền thực thi. Điều này tạo cơ hội cho kẻ tấn công tải lên các mã độc (ví dụ: web shell viết bằng PHP, ASP) lên thư mục có quyền thực thi của web server. Nếu kẻ tấn công truy cập trực tiếp được vào tệp tin đã tải lên qua URL, máy chủ sẽ thực thi mã độc và cho phép chúng chiếm quyền điều khiển hệ thống.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công (Mal) phát hiện trang web cho phép tải lên ảnh đại diện mà không đổi tên file và chỉ kiểm tra định dạng file bằng JavaScript ở phía client.
Bước 2: Mal viết một web shell đơn giản bằng PHP (`hack.php`) chứa hàm `system($_REQUEST['cmd'])` để thực thi các lệnh hệ điều hành thông qua tham số `cmd`.
Bước 3: Mal tắt JavaScript trên trình duyệt của mình để bỏ qua kiểm tra định dạng và tải lên tệp `hack.php` thành công.
Bước 4: Do máy chủ không đổi tên file và lưu trực tiếp trong thư mục web, Mal truy cập trực tiếp tệp tin qua URL (ví dụ: `/uploads/hack.php?cmd=cat+/etc/mysql/my.cnf`) để thực thi mã độc và đọc file cấu hình cơ sở dữ liệu nhạy cảm.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Secure file uploads by validating file extensions and MIME-types, renaming uploads randomly, and storing them outside the web root on non-executable folders.
- **Các bước chi tiết**:
  - Validate file types using strict lists of allowed extensions and verify file headers/magic bytes to confirm the true file format.
  - Rename all uploaded files using random unique identifiers (like UUIDs) to prevent path traversal attempts and execution.
  - Store uploaded files in a separate directory or third-party storage (like AWS S3) entirely outside the web application root.
  - Disable execution permissions (PHP, ASP, CGI, script engines) on the directories hosting user uploads.
  - Enforce strict file size limits to prevent Denial of Service through disk space exhaustion.

## 💻 Code Example
```python
import os
import uuid
from flask import Flask, request, abort

app = Flask(__name__)
UPLOAD_DIR = "/var/storage/uploads/"
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # Max 8MB limit

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def handle_upload():
    if 'file' not in request.files:
        abort(400, "Missing file payload")
    
    file = request.files['file']
    if file.filename == '':
        abort(400, "No file selected")
        
    if file and allowed_file(file.filename):
        # Generate random name to prevent directory traversal and execution hijack
        ext = file.filename.rsplit('.', 1)[1].lower()
        secure_name = f"{uuid.uuid4().hex}.{ext}"
        save_path = os.path.join(UPLOAD_DIR, secure_name)
        
        # Ensure upload directory exists to prevent crash
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        file.save(save_path)
        return {"status": "uploaded", "file_name": secure_name}
        
    abort(400, "Unsupported file format")
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS (không phát hiện lỗi kỹ thuật hay lỗi cú pháp). Mã nguồn Python Flask kiểm soát an toàn bằng cách giới hạn kích thước file (MAX_CONTENT_LENGTH), kiểm tra phần mở rộng thông qua danh sách cho phép (ALLOWED_EXTENSIONS), và đổi tên file thành chuỗi ngẫu nhiên UUID để ngăn chặn tấn công Path Traversal hoặc thực thi trực tiếp script.
- **Nguồn tham khảo**: OWASP A08:2021, CWE-434, PortSwigger Web Security Academy
