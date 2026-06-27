# Information Leakage

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) | **Phân loại**: Design & Process

## 🧱 Kiến thức Nền tảng
Rò rỉ thông tin (Information Leakage) xảy ra khi ứng dụng vô tình tiết lộ dữ liệu nhạy cảm của hệ thống cho các đối tượng không được ủy quyền. Yếu tố đầu tiên cần lưu ý là các HTTP response status codes (mã trạng thái phản hồi HTTP). Việc trả về các mã lỗi cụ thể (như 500 Internal Server Error) đi kèm thông tin chi tiết có thể giúp kẻ tấn công đoán biết tình trạng lỗi bên trong máy chủ.

Nguyên nhân phổ biến dẫn đến rò rỉ là Stack trace generation (quá trình sinh vết ngăn xếp). Khi xảy ra ngoại lệ (exception) mà không được xử lý an toàn, runtime environment sẽ tạo ra một danh sách chi tiết các hàm đã gọi kèm theo đường dẫn file, dòng code cụ thể. Nếu stack trace này được gửi thẳng về phía máy khách, kẻ tấn công sẽ nắm giữ sơ đồ cấu trúc mã nguồn và tên các thư viện.

Tình trạng này thường xảy ra khi hệ thống vẫn bật Server debug mode (chế độ gỡ lỗi của máy chủ) trên môi trường production. Chế độ debug rất hữu ích cho lập trình viên khi phát triển ứng dụng nhưng cực kỳ nguy hiểm nếu hoạt động công khai, bởi nó tự động phơi bày toàn bộ stack trace và các biến môi trường nhạy cảm. Do đó, cấu hình an toàn đòi hỏi phải tắt chế độ debug, xử lý lỗi tập trung và chỉ phản hồi các thông điệp lỗi chung chung kèm mã trạng thái HTTP thích hợp để bảo vệ thông tin hệ thống.

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

## 🔍 Mô tả lỗ hổng
Rò rỉ thông tin (Information Leakage) xảy ra khi ứng dụng vô tình hiển thị các thông tin hệ thống nhạy cảm cho người dùng thông thường. Các thông tin này có thể là stack trace chi tiết của lỗi, phiên bản phần mềm, cấu trúc cơ sở dữ liệu hoặc thông tin cấu hình máy chủ. Mặc dù không trực tiếp gây ra sự cố, những thông tin này giúp kẻ tấn công hiểu rõ sơ đồ công nghệ của hệ thống để xây dựng các kịch bản tấn công chính xác hơn.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công cố tình nhập các dữ liệu đầu vào không hợp lệ hoặc gây lỗi (như truyền ký tự đặc biệt vào tham số ID) để kích hoạt lỗi hệ thống.
Bước 2: Ứng dụng không bắt lỗi (exception) hoặc để chế độ debug bật, trả về trang lỗi chi tiết chứa stack trace của framework (như Django, Express) hoặc thông tin truy vấn SQL bị lỗi.
Bước 3: Kẻ tấn công đọc trang lỗi và xác định được chính xác các thư viện hệ thống đang dùng, phiên bản cụ thể, cấu trúc bảng dữ liệu, thậm chí cả đường dẫn file vật lý trên server để tìm kiếm mã khai thác phù hợp.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Mitigate information disclosure by removing debugging interfaces, disabling stack trace output in production, and scrubbing headers and response metadata.
- **Các bước chi tiết**:
  - Disable developer debug modes, diagnostic pages, and stack trace dumps in production environments.
  - Implement global error handling to display generic, non-informative error messages to public users.
  - Remove unnecessary server signatures and software version information from outgoing HTTP response headers.
  - Scrub metadata (e.g. GPS tags, author info) from file attachments, images, and documents before serving them.
  - Ensure system log configuration does not write sensitive information like credentials, passwords, session tokens, or PII.

## 💻 Code Example
```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// Use Helmet middleware to hide X-Powered-By and configure secure headers
app.use(helmet());
app.disable('x-powered-by');

// Centralized generic error handler for production
app.use((err, req, res, next) => {
    // Log complete error stack internally for monitoring
    console.error(err.stack);
    
    // If headers are already sent, delegate to default handler
    if (res.headersSent) {
        return next(err);
    }
    
    // Hide details from client and output a generic message
    res.status(500).json({
        error: "An unexpected error occurred. Please contact administrator if the issue persists."
    });
});
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Biện pháp bảo mật chính bao gồm tắt chế độ debug trong môi trường sản phẩm, xử lý biệt lệ một cách tổng quát không trả về stack trace cho client, và ẩn thông tin phiên bản trong header phản hồi của web server.
- **Nguồn tham khảo**: OWASP A05:2021, CWE-200, PortSwigger Web Security Academy
