# Error Handling & Exception Mismanagement

> **CWE**: CWE-755 | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang lái một chiếc xe hơi hiện đại. Khi động cơ gặp sự cố, hệ thống điều khiển thông minh trên xe sẽ sáng đèn báo lỗi "Check Engine" màu vàng trên táp-lô để bạn biết đường mang xe đi sửa. Chiếc xe hoàn toàn ẩn đi các thông số kỹ thuật phức tạp như áp suất buồng đốt hay lỗi dòng điện cụ thể để tránh làm bạn bối rối. Cơ chế xử lý sự cố này tương tự như **xử lý lỗi (error handling)** trong lập trình. Khi ứng dụng gặp tình huống bất ngờ (như cơ sở dữ liệu bị ngắt kết nối, người dùng nhập chữ vào ô nhập số), nó cần phải phản hồi một cách khéo léo để hệ thống không bị sập hoàn toàn.

Trong bảo mật phần mềm, khi xảy ra lỗi, hệ thống phải tuân theo hai triết lý thiết kế đối nghịch:
- **Fail-Close (Thất bại thì Đóng/Bảo mật)**: Giống như một chiếc két sắt thông minh, khi hệ thống quét vân tay bị mất điện hoặc gặp lỗi, két sắt sẽ tự động khóa chặt lại để bảo vệ tài sản bên trong. Đây là cách xử lý an toàn và đúng đắn nhất.
- **Fail-Open (Thất bại thì Mở)**: Ngược lại, nếu khóa cửa từ của một tòa nhà bị lỗi mất điện mà lại tự động mở toang cửa cho bất kỳ ai đi vào mà không cần quẹt thẻ, đó chính là Fail-Open. Thiết kế này cực kỳ nguy hiểm trong bảo mật vì nó tạo ra sơ hở cho kẻ xấu lợi dụng.

```python
# Normal error handling in a web application
from flask import Flask, jsonify
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # Log full details server-side for debugging
    logger.error(f"Unhandled exception: {error}", exc_info=True)
    
    # Return generic message to client (no internal details)
    return jsonify({
        "error": "An unexpected error occurred",
        "reference": "ERR-2025-06-27-001"
    }), 500
```

Đoạn code trên minh họa cách xử lý đúng: log chi tiết ở server, trả về thông báo chung cho client kèm mã tham chiếu để đội support có thể tra cứu.

## Mô tả lỗ hổng
Lỗ hổng xử lý lỗi (Improper Error Handling) xảy ra khi ứng dụng trở nên lúng túng khi gặp sự cố và vô tình "nói quá nhiều" hoặc "mở toang cửa".

Cụ thể, khi có lỗi xảy ra, thay vì hiển thị một lời xin lỗi chung chung, ứng dụng lại ném ra toàn bộ nhật ký lỗi kỹ thuật chi tiết (stack trace), bao gồm đường dẫn thư mục, tên bảng trong cơ sở dữ liệu, phiên bản thư viện đang dùng, hay thậm chí là hệ điều hành của máy chủ. 

Tệ hơn nữa, nếu hệ thống được thiết kế theo kiểu "Fail-Open", khi quá trình kiểm tra đăng nhập gặp lỗi kỹ thuật, nó lại mặc định cho phép người dùng đi qua. 

Mối nguy hiểm của lỗ hổng này là nó cung cấp cho kẻ tấn công một "bản đồ kho báu" chi tiết về cấu trúc bên trong của hệ thống để chúng lên kế hoạch tấn công chính xác, hoặc giúp chúng dễ dàng vượt qua các bước xác thực bằng cách cố tình tạo ra các lỗi hệ thống.

## Cơ chế tấn công
**1. Stack Trace Information Disclosure — kích hoạt lỗi để thu thập thông tin:**

```http
GET /api/users/abc HTTP/1.1
Host: target.com

// Response with verbose error (DANGEROUS):
HTTP/1.1 500 Internal Server Error
{
    "error": "Traceback (most recent call last):\n  File \"/app/views/user.py\", line 42\n    user = User.objects.get(id=int(user_id))\nValueError: invalid literal for int() with base 10: 'abc'\n\nDjango Version: 4.2.1\nDatabase: PostgreSQL 15.3 at db-prod.internal:5432\nOS: Ubuntu 22.04"
}
// Attacker now knows: framework, DB type, internal hostname, OS version
```

**2. Fail-Open Authentication Bypass — lợi dụng lỗi để vượt qua xác thực:**

```python
# VULNERABLE: fail-open design
def check_authentication(token):
    try:
        user = verify_jwt(token)
        return user
    except Exception:
        # On ANY error (expired, invalid, malformed), grant access anyway!
        return {"role": "guest", "authenticated": True}  # DANGEROUS
```

Attacker có thể gửi token sai định dạng cố ý để trigger exception và được cấp quyền truy cập.

## Biện pháp phòng thủ
- **Tóm tắt**: Xử lý lỗi an toàn bằng cách ẩn stack trace chi tiết trên môi trường production, thiết kế theo nguyên lý Fail-Close, và ghi log cấu trúc phía máy chủ.
- **Các bước chi tiết**:
  - **Custom error pages**: Cấu hình error page riêng cho production, ẩn toàn bộ stack trace và thông tin debug.
  - **Fail-close by default**: Khi xảy ra lỗi, luôn từ chối truy cập và yêu cầu xác thực lại.
  - **Structured logging**: Ghi log chi tiết ở server (ELK Stack, Splunk) nhưng chỉ trả về error code/reference cho client.
  - **Disable debug mode**: Tắt `DEBUG=True` (Django), `app.debug` (Flask), `SHOW_ERRORS` (Laravel) trong production.

## Code Example
```python
# VULNERABLE: exposes internal details and fails open
@app.route('/api/admin/dashboard')
def admin_dashboard():
    try:
        token = request.headers.get('Authorization')
        user = verify_admin_token(token)
        return get_admin_data(user)
    except Exception as e:
        # Leaks full error details to attacker
        return jsonify({
            "error": str(e),
            "stack": traceback.format_exc(),
            "db_host": app.config['DB_HOST']
        }), 500
```

```python
# SECURE: fail-close with generic error response
@app.route('/api/admin/dashboard')
def admin_dashboard():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        
        user = verify_admin_token(token)
        if not user or user.get('role') != 'admin':
            return jsonify({"error": "Forbidden"}), 403
        
        return get_admin_data(user)
    
    except jwt.ExpiredSignatureError:
        # Specific exception: deny access (fail-close)
        return jsonify({"error": "Session expired, please re-login"}), 401
    
    except Exception:
        # Generic exception: deny access and log internally
        logger.exception("Admin dashboard error")
        return jsonify({
            "error": "Internal server error",
            "ref": generate_error_reference()
        }), 500
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/information-disclosure
- OWASP: https://owasp.org/www-community/Improper_Error_Handling
- CWE: https://cwe.mitre.org/data/definitions/755.html

## Giải thích thuật ngữ
- **Stack Trace (Vết ngăn xếp)**: Danh sách chi tiết các hàm đang chạy tại thời điểm xảy ra lỗi, chỉ ra chính xác tệp tin và số dòng code gặp sự cố. Đây là thông tin cực kỳ hữu ích cho lập trình viên nhưng rất nguy hiểm nếu để lộ ra ngoài.
- **Fail-Close (Thất bại - Đóng)**: Nguyên tắc thiết kế bảo mật mà khi một chức năng hoặc hệ thống gặp lỗi, nó sẽ mặc định chuyển sang trạng thái an toàn nhất bằng cách từ chối mọi yêu cầu truy cập.
- **Fail-Open (Thất bại - Mở)**: Thiết kế lỗi mà khi hệ thống gặp sự cố, nó lại tự động bỏ qua các bước kiểm tra bảo mật và cho phép người dùng truy cập vào tài nguyên.
- **Exception (Ngoại lệ)**: Một sự kiện đặc biệt xảy ra trong quá trình thực thi chương trình làm gián đoạn luồng hướng dẫn bình thường (như lỗi chia cho 0, lỗi mất kết nối mạng).
- **Graceful Error Handling (Xử lý lỗi khéo léo)**: Việc bắt và xử lý các lỗi phát sinh sao cho ứng dụng không bị sập đột ngột, đồng thời chỉ hiển thị những thông báo thân thiện và an toàn cho người dùng cuối.
