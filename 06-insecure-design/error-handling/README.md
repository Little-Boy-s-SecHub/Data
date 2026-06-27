# Error Handling & Exception Mismanagement

> **OWASP Top 10:2025**: A10:2025 – Server-Side Request Forgery & Insufficient Logging (NEW) | **CWE**: CWE-755 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Error handling (xử lý lỗi) là cơ chế giúp ứng dụng phản hồi đúng cách khi gặp tình huống bất thường — input không hợp lệ, kết nối database thất bại, file không tồn tại, hoặc lỗi logic. Mọi ngôn ngữ lập trình hiện đại đều hỗ trợ cơ chế exception: `try/catch` (Java, JavaScript, C#), `try/except` (Python), `begin/rescue` (Ruby).

Trong production, ứng dụng phải xử lý lỗi một cách **graceful** — thông báo cho user biết có lỗi xảy ra mà không tiết lộ chi tiết kỹ thuật nội bộ. Hai triết lý xử lý lỗi quan trọng trong bảo mật:

- **Fail-Close (Fail-Secure)**: Khi có lỗi, hệ thống từ chối truy cập. Đây là cách an toàn.
- **Fail-Open**: Khi có lỗi, hệ thống cho phép truy cập. Đây là cách nguy hiểm.

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

## 🔍 Mô tả lỗ hổng

Lỗ hổng error handling xảy ra khi ứng dụng: (1) để lộ stack trace, đường dẫn file, tên database, hoặc phiên bản framework cho user; (2) xử lý lỗi theo kiểu fail-open, cho phép bypass authentication/authorization khi hệ thống gặp sự cố; (3) không xử lý exception, dẫn đến crash hoặc trạng thái không xác định. Attacker thu thập thông tin từ error message để lên kế hoạch tấn công chính xác hơn.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Custom error pages**: Cấu hình error page riêng cho production, ẩn toàn bộ stack trace và thông tin debug.
2. **Fail-close by default**: Khi xảy ra lỗi, luôn từ chối truy cập và yêu cầu xác thực lại.
3. **Structured logging**: Ghi log chi tiết ở server (ELK Stack, Splunk) nhưng chỉ trả về error code/reference cho client.
4. **Disable debug mode**: Tắt `DEBUG=True` (Django), `app.debug` (Flask), `SHOW_ERRORS` (Laravel) trong production.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/information-disclosure
- OWASP: https://owasp.org/www-community/Improper_Error_Handling
- CWE: https://cwe.mitre.org/data/definitions/755.html
