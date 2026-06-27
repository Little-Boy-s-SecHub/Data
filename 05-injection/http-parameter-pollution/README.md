# HTTP Parameter Pollution (HPP)

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-235 | **Nguồn**: OWASP, Luca Carettoni & Stefano di Paola

## 🧱 Kiến thức Nền tảng

Khi trình duyệt gửi HTTP request, tham số (parameter) được truyền qua URL query string hoặc request body. Theo chuẩn HTTP, **không có quy định rõ ràng** về cách xử lý khi cùng một tham số xuất hiện nhiều lần. Mỗi web server và framework xử lý tình huống này **khác nhau hoàn toàn**.

Ví dụ request với tham số trùng lặp:

```http
GET /search?category=electronics&category=books HTTP/1.1
Host: shop.example.com
```

```python
# How different server technologies handle duplicate parameters:

# PHP (Apache/Nginx)
# $_GET["category"] = "books"          → Takes LAST occurrence

# ASP.NET / IIS
# Request.QueryString["category"] = "electronics,books"  → Concatenates ALL

# Python Flask
# request.args.get("category") = "electronics"           → Takes FIRST occurrence
# request.args.getlist("category") = ["electronics", "books"]  → Returns list

# Java Servlet (Tomcat)
# request.getParameter("category") = "electronics"       → Takes FIRST occurrence
# request.getParameterValues("category") = ["electronics", "books"]

# Node.js Express
# req.query.category = ["electronics", "books"]           → Returns array

# Ruby on Rails
# params[:category] = "books"          → Takes LAST occurrence
```

Sự khác biệt này tạo ra mâu thuẫn khi ứng dụng sử dụng **nhiều lớp xử lý** (ví dụ: WAF viết bằng Java đứng trước backend PHP). WAF kiểm tra tham số đầu tiên (Java lấy first), nhưng backend PHP lại dùng tham số cuối cùng — kẻ tấn công lợi dụng để bypass.

## 🔍 Mô tả lỗ hổng

HTTP Parameter Pollution (HPP) là kỹ thuật tấn công bằng cách **gửi nhiều tham số cùng tên** trong một HTTP request. Có hai dạng chính:

**Server-Side HPP:** Kẻ tấn công inject tham số bổ sung để thay đổi logic phía server — bypass validation, thay đổi giá trị giao dịch, hoặc truy cập trái phép.

**Client-Side HPP:** Kẻ tấn công thao túng URL để inject tham số vào link/form được server render — ảnh hưởng hành vi phía client.

Lỗ hổng này đặc biệt nguy hiểm trong hệ thống có **proxy, WAF, hoặc middleware** đứng trước application server, vì mỗi lớp có thể hiểu tham số khác nhau.

## ⚔️ Cơ chế tấn công

**Tấn công 1 — Bypass WAF:**

```http
# WAF (Java-based) checks first "id" parameter → safe
# Backend (PHP) uses last "id" parameter → SQLi payload executes
GET /user?id=1&id=1'+OR+1=1--+- HTTP/1.1
Host: vulnerable-app.com
```

```
WAF sees:      id = "1"              → PASS (safe value)
PHP backend:   id = "1' OR 1=1-- -"  → SQL Injection executed!
```

**Tấn công 2 — Thay đổi logic thanh toán:**

```http
# Original payment request
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

to=alice&amount=100&currency=USD
```

```http
# HPP attack: inject duplicate "amount" parameter
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

to=alice&amount=100&amount=1
# If server uses LAST value → only transfers 1 USD
# If validation checks FIRST (100) but execution uses LAST (1) → logic mismatch
```

**Tấn công 3 — Server-side HPP qua URL building:**

```python
# Vulnerable code that builds URL from user input
# User controls "callback" parameter
@app.route("/oauth")
def oauth():
    callback = request.args.get("callback")  # Takes first occurrence
    # Attacker sends: /oauth?callback=legit.com%26client_id%3Dattacker
    # After URL decode: callback = "legit.com&client_id=attacker"
    
    redirect_url = f"https://auth.provider.com/authorize?callback={callback}&client_id=myapp"
    # Result: https://auth.provider.com/authorize?callback=legit.com&client_id=attacker&client_id=myapp
    # OAuth provider uses first client_id → attacker's client_id wins!
    return redirect(redirect_url)
```

**Tấn công 4 — Client-Side HPP:**

```html
<!-- Server renders share link using user-controlled parameter -->
<!-- URL: /page?lang=en&lang="><script>alert(1)</script> -->
<a href="/share?utm_source=social&lang="><script>alert(1)</script>">Share</a>
```

## 🛡️ Biện pháp phòng thủ

1. **Chọn rõ ràng cách xử lý tham số trùng** — reject hoặc chỉ lấy giá trị đầu tiên:
   ```python
   # SECURE: Explicitly handle duplicate parameters
   from werkzeug.exceptions import BadRequest
   
   def get_single_param(request, name):
       """Reject requests with duplicate parameters"""
       values = request.args.getlist(name)
       if len(values) > 1:
           raise BadRequest(f"Duplicate parameter: {name}")
       return values[0] if values else None
   ```

2. **URL-encode khi xây dựng URL** — không nối chuỗi trực tiếp:
   ```python
   # SECURE: Use proper URL encoding library
   from urllib.parse import urlencode, quote
   
   def build_redirect_url(callback):
       params = {
           "callback": callback,  # Properly encoded, & becomes %26
           "client_id": "myapp"
       }
       return "https://auth.provider.com/authorize?" + urlencode(params)
   ```

3. **Đồng nhất parser** giữa WAF và backend — đảm bảo cả hai lớp hiểu tham số giống nhau.

4. **Input validation** — whitelist giá trị hợp lệ cho mỗi tham số.

## 💻 Code Example

```python
# ❌ VULNERABLE: String concatenation allows HPP
@app.route("/redirect")
def redirect_handler():
    next_url = request.args.get("next")
    # Attacker: /redirect?next=evil.com%26admin%3Dtrue
    return redirect(f"/dashboard?next={next_url}&role=user")

# ✅ SECURE: Proper parameter handling with validation
from urllib.parse import urlencode, urlparse

ALLOWED_REDIRECTS = ["dashboard", "profile", "settings"]

@app.route("/redirect")
def redirect_handler():
    next_url = request.args.get("next", "dashboard")
    
    # Validate against whitelist
    if next_url not in ALLOWED_REDIRECTS:
        next_url = "dashboard"
    
    # Use urlencode to properly escape values
    params = urlencode({"next": next_url, "role": "user"})
    return redirect(f"/dashboard?{params}")
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/request-smuggling
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
- CWE: https://cwe.mitre.org/data/definitions/235.html
- Original Paper: https://owasp.org/www-pdf-archive/AppsecEU09_CarssoniDiPaola_v0.8.pdf
