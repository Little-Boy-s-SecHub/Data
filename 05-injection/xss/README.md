# Cross-Site Scripting (XSS)

> **CWE**: CWE-79 | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

Hãy tưởng tượng trình duyệt web của bạn giống như một người chấp hành mệnh lệnh trung thành: nó hiển thị hình ảnh, chữ viết (HTML) và chạy các đoạn mã lập trình (JavaScript) do máy chủ gửi về. Tuy nhiên, người chấp hành này lại rất "ngây thơ": nếu thấy một đoạn mã JavaScript được nhúng trong trang web, nó sẽ tự động chạy đoạn mã đó mà không hề nghi ngờ. Lỗ hổng Cross-Site Scripting (XSS) phát sinh khi kẻ tấn công tìm cách chèn mã JavaScript độc hại của riêng họ vào trang web để trình duyệt của người dùng khác chạy nó. Sự nguy hiểm của XSS bắt nguồn từ việc trình duyệt tin tưởng hoàn toàn vào mọi đoạn mã chạy trên trang web đó (Browser trust model) – cho phép mã độc truy cập cookie phiên làm việc, bộ nhớ cục bộ, hoặc tự ý thực hiện các hành động nhân danh nạn nhân.

```python
# Normal operation: HTML template with proper auto-escaping
from flask import Flask, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    # SAFE: Jinja2 auto-escaping converts < > " & to HTML entities
    # User input '<script>' becomes '&lt;script&gt;' — displayed as text, not executed
    name = escape("Alice <script>alert(1)</script>")
    return render_template_string('<h1>Hello, {{ name }}!</h1>', name=name)
```

## Mô tả lỗ hổng

Lỗ hổng XSS xảy ra khi ứng dụng web nhận thông tin từ người dùng rồi đưa trực tiếp thông tin đó lên trang hiển thị mà không tiến hành làm sạch hoặc mã hóa đúng cách. Việc này giống như bạn cho phép người lạ viết bất kỳ điều gì lên bảng tin công cộng của ứng dụng, kể cả những dòng lệnh nguy hiểm. Khi một người dùng khác đến đọc bảng tin, trình duyệt của họ sẽ chạy đoạn mã độc đó. Kẻ tấn công có thể lợi dụng XSS để âm thầm lấy cắp mã token đăng nhập (session cookie) để chiếm đoạt tài khoản, ghi lại từng phím bấm của bạn (keylogging), làm giả giao diện để lừa đảo (defacement), hoặc phát tán mã độc đến những người dùng khác.

## Cơ chế tấn công

Có 3 loại chính:

1. **Stored XSS** — payload lưu vĩnh viễn trong database, tấn công nhiều nạn nhân
2. **Reflected XSS** — payload trong URL/request, chỉ tấn công nạn nhân click link
3. **DOM-based XSS** — khai thác trong client-side JS, không qua server

Payload kiển điển:

```
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
"><script>alert(1)</script>
```

Tham khảo chi tiết từng loại:
- Stored XSS → [stored/README.md](stored/README.md)
- Reflected XSS → [reflected/README.md](reflected/README.md)
- DOM-based XSS → [dom-based/README.md](dom-based/README.md)
- XSSI → [xssi/README.md](xssi/README.md)

## Biện pháp phòng thủ

- **Tóm tắt**: Mã hóa đầu ra theo ngữ cảnh hiển thị, thiết lập chính sách Content Security Policy (CSP), và bảo vệ cookie với cờ HttpOnly.
- **Các bước chi tiết**:
  - Output encoding: HTML entity encoding khi render user data vào HTML.
  - Content Security Policy (CSP): cấm script inline, chỉ cho phép source tin cậy.
  - HttpOnly cookie: ngăn XSS đánh cắp session cookie qua `document.cookie`.
  - Input validation: whitelist characters, reject dangerous tags.
  - DOMPurify: sanitize HTML trước khi set `innerHTML`.

## Code Example

```python
# Vulnerable: reflecting user input without encoding
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # DANGEROUS: directly embedding user input into HTML response
    return f'<h1>Kết quả tìm kiếm: {query}</h1>'

# Secure: use template engine auto-escaping
from markupsafe import escape

@app.route('/search-safe')
def search_safe():
    query = request.args.get('q', '')
    # SAFE: markupsafe escapes HTML special characters automatically
    return f'<h1>Kết quả tìm kiếm: {escape(query)}</h1>'
```

```html
<!-- Secure CSP header to block inline scripts -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none';">
```

```javascript
// Safe DOM manipulation using textContent instead of innerHTML
// DANGEROUS: element.innerHTML = userInput; (executes scripts)
// SAFE: element.textContent = userInput; (treats as plain text)
document.getElementById('output').textContent = userInput;

// When HTML is needed, use DOMPurify to sanitize first
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

## Xem thêm

- [Stored XSS](stored/) — Tấn công lưu trữ vĩnh viễn trong database
- [Reflected XSS](reflected/) — Tấn công qua URL/form submit
- [DOM-based XSS](dom-based/) — Tấn công trong client-side JavaScript
- [XSSI](xssi/) — Cross-Site Script Inclusion qua JSONP

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/cross-site-scripting
- OWASP: https://owasp.org/www-community/attacks/xss/

## Giải thích thuật ngữ

- **XSS (Cross-Site Scripting)**: Lỗ hổng chèn mã kịch bản độc hại (thường là JavaScript) chạy trên trình duyệt người dùng.
- **Execution Context**: Ngữ cảnh mà trình duyệt dùng để biên dịch và chạy các dòng lệnh.
- **Browser Trust Model**: Mô hình tin tưởng mặc định của trình duyệt dành cho các đoạn mã chạy trên cùng một nguồn gốc.
- **HTML Entity Encoding**: Chuyển đổi các ký tự HTML đặc biệt thành dạng hiển thị an toàn (như `<` thành `&lt;`).
- **Session Cookie**: File cookie lưu mã xác thực giúp duy trì trạng thái đăng nhập của người dùng.
