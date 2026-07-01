# HTTP Parameter Pollution (HPP)

> **CWE**: CWE-235 | **Phân loại**: Injection

## Kiến thức Nền tảng

Khi bạn gửi một yêu cầu lên trang web (như tìm kiếm sản phẩm), thông tin thường được gửi kèm dưới dạng các tham số trên đường dẫn (ví dụ: `?category=electronics`). Nhưng điều kỳ lạ là trong thế giới công nghệ, các ngôn ngữ và máy chủ khác nhau lại có cách xử lý rất khác nhau khi gặp hai tham số trùng tên trong cùng một yêu cầu (ví dụ: `?category=electronics&category=books`). PHP sẽ chỉ lấy giá trị cuối cùng, ASP.NET lại nối chúng lại bằng dấu phẩy, còn Python Flask hay Java Servlet thì chỉ lấy giá trị đầu tiên. Sự bất đồng ngôn ngữ này giống như việc mỗi phòng ban trong một công ty hiểu một mệnh lệnh theo cách riêng của mình.

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

## Mô tả lỗ hổng

Lỗ hổng HTTP Parameter Pollution (HPP) xảy ra khi kẻ tấn công lợi dụng sự không đồng nhất này để "đầu độc" các tham số gửi đi. Hãy tưởng tượng hệ thống bảo vệ (WAF) của bạn dùng Java để kiểm tra tính an toàn của tham số đầu tiên, nhưng máy chủ xử lý logic đằng sau lại dùng PHP và chỉ đọc tham số cuối cùng. Kẻ tấn công có thể gửi một tham số an toàn ở đầu để đánh lừa WAF, nhưng lại giấu tham số độc hại ở cuối để máy chủ backend thực thi. Điều này cho phép kẻ xấu dễ dàng vượt qua các tường lửa bảo mật, thay đổi logic giao dịch (như sửa đổi số tiền hay tài khoản nhận), hoặc thực hiện các hành vi gian lận khác mà hệ thống không hề hay biết.

## Cơ chế tấn công

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

## Biện pháp phòng thủ

- **Tóm tắt**: Kiểm soát và xác thực nghiêm ngặt các tham số trùng lặp trong yêu cầu HTTP để tránh sự bất nhất giữa các lớp xử lý.
- **Các bước chi tiết**:
  - Chọn rõ ràng cách xử lý tham số trùng — reject hoặc chỉ lấy giá trị đầu tiên.
  - Thực hiện kiểm tra và xác thực ở cả tầng WAF và tầng backend.
  - Sử dụng các thư viện xây dựng URL và phân tích tham số an toàn.

## Code Example

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

## Xem thêm

- [SQL Injection](../sql-injection/) — Tấn công tiêm lệnh SQL qua các tham số.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/request-smuggling
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
- CWE: https://cwe.mitre.org/data/definitions/235.html
- Original Paper: https://owasp.org/www-pdf-archive/AppsecEU09_CarssoniDiPaola_v0.8.pdf

## Giải thích thuật ngữ

- **HPP (HTTP Parameter Pollution)**: Ô nhiễm tham số HTTP bằng cách gửi nhiều tham số trùng tên.
- **WAF (Web Application Firewall)**: Tường lửa bảo vệ ứng dụng web khỏi các cuộc tấn công phổ biến.
- **Query String**: Phần tham số đi kèm phía sau dấu hỏi chấm trên URL.
- **Backend**: Hệ thống máy chủ xử lý dữ liệu và logic bên dưới của trang web.
- **Concatenate**: Phép toán ghép nối các chuỗi ký tự lại với nhau.
