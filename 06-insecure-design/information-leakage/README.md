# Information Leakage

> **CWE**: CWE-200, CWE-538, CWE-527 | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang xây dựng một pháo đài để bảo vệ kho báu. Bạn thiết kế các bức tường dày, các cổng sắt kiên cố và trang bị vũ khí tối tân. Thế nhưng, người gác cổng của bạn lại vô tình làm rơi một tấm bản đồ thiết kế chi tiết của pháo đài ngay trước cổng, hoặc vui vẻ trả lời bất kỳ ai hỏi về vị trí của các lối đi bí mật, sơ đồ bố trí quân lính và loại khóa đang dùng. Tình huống này tương tự như lỗi **Rò rỉ thông tin (Information Leakage)** trong phần mềm.

Khi ứng dụng gặp sự cố kỹ thuật, nó sẽ phản hồi bằng một mã trạng thái HTTP (HTTP status codes). Nếu không được cấu hình cẩn thận, hệ thống có thể tạo ra các vết ngăn xếp (**stack trace**) — một danh sách dài các dòng mã nguồn nội bộ mô tả lỗi chi tiết từ đầu đến cuối.

Lỗi này thường xảy ra khi lập trình viên quên tắt **chế độ gỡ lỗi (debug mode)** khi đưa ứng dụng lên môi trường thực tế (production). Chế độ gỡ lỗi giống như việc mở toang cửa kính pháo đài để nhìn rõ mọi hoạt động bên trong trong lúc xây dựng. Nhưng khi pháo đài đã đi vào hoạt động, việc để lộ các thông số kỹ thuật, biến môi trường nhạy cảm hay sơ đồ mã nguồn sẽ biến những nỗ lực bảo mật trước đó thành công cốc.

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Secure error handling demonstrating production mode with generic responses
import logging
from flask import Flask, jsonify

app = Flask(__name__)

# Configure internal logger for server-side debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In production, debug mode must be disabled
app.config['DEBUG'] = False

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Log the detailed stack trace internally for developers
    logger.exception("An unhandled exception occurred: %s", str(error))
    
    # Return a generic HTTP response status code (500) and safe message to client
    # This prevents stack trace leaking to external users
    response = jsonify({
        "error": "Internal Server Error",
        "message": "A generic error occurred. Please try again later."
    })
    return response, 500
```

## Mô tả lỗ hổng
Lỗ hổng Rò rỉ thông tin (Information Leakage) xảy ra khi ứng dụng vô tình phơi bày các bí mật công nghệ hoặc dữ liệu nhạy cảm của hệ thống cho những người dùng không có quyền biết. 

Các thông tin rò rỉ này có thể là mã lỗi chi tiết, thông tin phiên bản phần mềm, cấu trúc bảng cơ sở dữ liệu, các tệp cấu hình ẩn (như `.git`), hoặc những tệp sao lưu tạm thời mà lập trình viên vô tình bỏ quên trên máy chủ (như `.bak`, `.old`). 

Mặc dù bản thân việc rò rỉ thông tin không lập tức làm sập hệ thống hoặc cho phép chiếm quyền điều khiển ngay, nhưng nó lại cung cấp một lượng lớn "tình báo" quý giá. Kẻ tấn công có thể sử dụng thông tin này để vẽ nên bức tranh toàn cảnh về công nghệ của bạn, từ đó tìm kiếm các lỗ hổng đã biết của phiên bản đó để thực hiện các cuộc tấn công phá hoại chính xác và nhanh chóng hơn.

## Cơ chế tấn công
**1. Khai thác Stack Trace qua thông báo lỗi:**
Kẻ tấn công cố tình nhập các dữ liệu đầu vào không hợp lệ (như truyền ký tự đặc biệt vào tham số ID) để kích hoạt lỗi hệ thống. Trang lỗi chi tiết chứa stack trace của framework (như Django, Express) sẽ phơi bày các thư viện hệ thống đang dùng, phiên bản cụ thể, cấu trúc bảng dữ liệu, và đường dẫn file vật lý trên server.

**2. Lộ lọt thư mục `.git` (Git Directory Exposure):**
Nếu máy chủ web được cấu hình sai và cho phép truy cập trực tiếp vào các tệp ẩn, kẻ tấn công có thể truy cập đường dẫn `https://target.com/.git/`. Bằng cách tải xuống các tệp tin trong thư mục này (như `.git/index`, `.git/refs/heads/master`, `.git/objects/`), kẻ tấn công có thể khôi phục lại toàn bộ mã nguồn lịch sử commit và tìm thấy các API key hoặc mật khẩu cấu hình từng được commit trước đó.

**3. Rò rỉ tệp sao lưu (Backup File Disclosure):**
Lập trình viên khi chỉnh sửa trực tiếp mã nguồn trên máy chủ thường để lại các tệp sao lưu tự động của editor hoặc tệp đổi tên thủ công (ví dụ: `index.php.bak`, `config.php.old`, `.app.py.swp`, `settings.py~`). Kẻ tấn công sử dụng công cụ fuzzer để quét và tải các file này về, đọc được các bí mật cấu hình và mã nguồn kiểm tra logic.

**4. Rò rỉ qua robots.txt/sitemap:**
File `robots.txt` và `sitemap.xml` được dùng để điều hướng bot tìm kiếm. Tuy nhiên, lập trình viên thường điền các đường dẫn nhạy cảm vào mục `Disallow` (ví dụ: `Disallow: /admin-secret-login/`, `Disallow: /backups/`, `Disallow: /dev/`). Kẻ tấn công đọc tệp này để xác định chính xác các thư mục nhạy cảm cần nhắm tới.

**5. Rò rỉ mã nguồn do lỗi cấu hình máy chủ web:**
Cấu hình sai trên Nginx hoặc Apache có thể khiến máy chủ không chuyển tiếp các yêu cầu tệp script (như `.php`, `.jsp`) đến trình thông dịch xử lý (như PHP-FPM, Tomcat) mà trả về trực tiếp dưới dạng văn bản thuần túy. Kẻ tấn công truy cập trang web và trình duyệt sẽ hiển thị toàn bộ mã nguồn thô của ứng dụng.

## Biện pháp phòng thủ
- **Tóm tắt**: Mitigate information disclosure by removing debugging interfaces, disabling stack trace output in production, and scrubbing headers and response metadata.
- **Các bước chi tiết**:
  - Disable developer debug modes, diagnostic pages, and stack trace dumps in production environments.
  - Implement global error handling to display generic, non-informative error messages to public users.
  - Remove unnecessary server signatures and software version information from outgoing HTTP response headers.
  - Scrub metadata (e.g. GPS tags, author info) from file attachments, images, and documents before serving them.
  - Ensure system log configuration does not write sensitive information like credentials, passwords, session tokens, or PII.
  - **Block Access to Hidden Files**: Cấu hình Nginx/Apache để chặn hoàn toàn quyền truy cập vào tất cả các tệp và thư mục ẩn bắt đầu bằng dấu chấm (ví dụ: `.git`, `.env`) và các phần mở rộng tệp sao lưu (`.bak`, `.old`, `.swp`, `~`).
  - **Clean Deployments**: Sử dụng quy trình CI/CD chuyên nghiệp để triển khai ứng dụng, đảm bảo không sao chép thư mục `.git` hoặc các tệp sao lưu tạm thời lên môi trường production.

## Code Example
```nginx
# === VULNERABLE CONFIGURATION ===
# Vulnerable Nginx configuration leaking hidden directories and backup files
server {
    listen 80;
    server_name vulnerable-app.com;
    root /var/www/html;

    # DANGER: No restriction on hidden files or folders
    # Anyone can download http://vulnerable-app.com/.git/config
    # Anyone can access http://vulnerable-app.com/config.php.bak
    location / {
        try_files $uri $uri/ =404;
    }
    
    # DANGER: Misconfigured PHP handler that falls back to plaintext if PHP-FPM is down or misconfigured
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

```nginx
# === SECURE CONFIGURATION ===
# Secure Nginx configuration blocking sensitive files and hiding signatures
server {
    listen 80;
    server_name secure-app.com;
    root /var/www/html;

    # SECURE: Hide Nginx version signature from error pages and headers
    server_tokens off;

    location / {
        try_files $uri $uri/ =404;
    }

    # SECURE: Block access to all hidden files and directories (starting with a dot)
    location ~ /\.(?!well-known) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Block access to backup, swap, and temporary development files
    location ~* \.(bak|old|save|swp|orig|temp|tmp|~)$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Properly configured PHP handler with strict error trapping
    location ~ \.php$ {
        try_files $uri =404; # Prevent execution of non-existent PHP files (mitigates RCE)
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A05:2021, CWE-200, PortSwigger Web Security Academy

## Giải thích thuật ngữ
- **Information Leakage (Rò rỉ thông tin)**: Lỗi xảy ra khi hệ thống tiết lộ các thông tin kỹ thuật nhạy cảm (như stack trace, cấu hình hệ thống, phiên bản phần mềm) cho người dùng không có quyền truy cập, gián tiếp giúp tin tặc dễ dàng tấn công hơn.
- **HTTP Response Status Codes**: Mã số tiêu chuẩn do máy chủ web trả về để thông báo kết quả của một yêu cầu HTTP (ví dụ: `200 OK`, `404 Not Found`, `500 Internal Server Error`).
- **Stack Trace (Vết ngăn xếp)**: Bản ghi chi tiết về đường đi của các lệnh gọi hàm dẫn đến lỗi, hiển thị tên tệp và số dòng code trong chương trình.
- **Debug Mode (Chế độ gỡ lỗi)**: Chế độ chạy ứng dụng cung cấp nhiều thông tin kỹ thuật chi tiết để lập trình viên tìm và sửa lỗi. Chế độ này bắt buộc phải tắt trên môi trường sản xuất (production).
- **Git Directory (`.git`)**: Thư mục ẩn chứa toàn bộ lịch sử quản lý mã nguồn, các nhánh, các cam kết (commit) và có thể chứa cả thông tin cấu hình nhạy cảm nếu không được bảo vệ.
- **Fuzzer**: Công cụ tự động hóa quá trình gửi số lượng lớn các yêu cầu dữ liệu ngẫu nhiên hoặc được chuẩn bị trước đến ứng dụng để phát hiện các tệp tin ẩn, đường dẫn chưa được bảo vệ hoặc các lỗi phần mềm.
