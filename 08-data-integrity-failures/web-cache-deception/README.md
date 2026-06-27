# Web Cache Deception

> **OWASP Top 10:2025**: A08 | **CWE**: CWE-524 | **Nguồn**: PortSwigger, Omer Gil Research

## 🧱 Kiến thức Nền tảng

Web cache thường được cấu hình để lưu trữ các **tài nguyên tĩnh** (static resources) như file `.css`, `.js`, `.png`, `.jpg` nhằm giảm tải cho origin server. Quyết định cache hay không thường dựa trên **đuôi file** (file extension) trong URL path.

Khi CDN hoặc reverse proxy nhận request với URL kết thúc bằng `.css` hoặc `.js`, nó mặc định coi đó là static resource và **cache response** — bất kể nội dung thực sự là gì.

Song song đó, nhiều web framework xử lý URL theo kiểu **path normalization** — khi không tìm thấy route chính xác, framework bỏ qua phần path cuối và trả về response của route cha. Ví dụ: `/account/settings/anything.css` sẽ được xử lý như `/account/settings` nếu `/account/settings/anything.css` không tồn tại.

```
# How cache decides what to store — based on file extension
Request: GET /static/style.css → Cache says: "This is CSS, CACHE IT" ✓
Request: GET /api/users         → Cache says: "This is dynamic, DON'T CACHE" ✗
Request: GET /account/info.css  → Cache says: "Looks like CSS, CACHE IT" ✓ ← PROBLEM!
```

```python
# Framework path normalization example (Flask/Django behavior)
# Route defined: /account/settings
# Request to: /account/settings/nonexistent.css

# Step 1: Framework looks for route "/account/settings/nonexistent.css"
# Step 2: Route not found → falls back to "/account/settings"  
# Step 3: Returns the REAL account settings page (with user data!)
# Step 4: Cache sees ".css" extension → stores the response as static content
```

## 🔍 Mô tả lỗ hổng

Web Cache Deception là cuộc tấn công khiến cache **lưu trữ trang chứa thông tin nhạy cảm** (tài khoản, profile, API keys) dưới dạng static resource. Kẻ tấn công lừa nạn nhân truy cập một URL đặc biệt, cache lưu response chứa dữ liệu cá nhân, sau đó kẻ tấn công truy cập cùng URL để đọc dữ liệu từ cache.

Khác với **Cache Poisoning** (tấn công phía response — inject nội dung độc), **Cache Deception** là tấn công phía request — đánh lừa cache lưu nội dung hợp lệ nhưng bí mật.

## ⚔️ Cơ chế tấn công

**Bước 1: Kẻ tấn công tạo URL lừa đảo:**

```
# Attacker crafts a URL that:
# 1. Routes to a sensitive page (path normalization)
# 2. Looks like a static file to the cache (.css extension)

https://bank.com/account/settings/logo.css
https://bank.com/my-account/profile.js
https://bank.com/api/user/details/tracking.png
```

**Bước 2: Lừa nạn nhân click link:**

```html
<!-- Attacker sends this link via email, chat, or social engineering -->
<a href="https://bank.com/account/settings/logo.css">
  Click here to verify your account
</a>

<!-- Or embed as invisible image to trigger automatically -->
<img src="https://bank.com/account/settings/logo.css" width="0" height="0">
```

**Bước 3: Nạn nhân click → Cache lưu trang nhạy cảm:**

```http
# Victim's browser sends (victim is authenticated):
GET /account/settings/logo.css HTTP/1.1
Host: bank.com
Cookie: session=victim_session_token_abc123

# Origin server: "/account/settings/logo.css" not found
# → Path normalization → serves /account/settings
# Response contains victim's sensitive data:

HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: no-cache         # Origin says don't cache...

<html>
<h1>Account Settings</h1>
<p>Name: Alice Johnson</p>
<p>Email: alice@company.com</p>
<p>API Key: sk_live_abc123xyz789</p>
</html>

# BUT the CDN sees ".css" extension → IGNORES Cache-Control → CACHES the response!
```

**Bước 4: Kẻ tấn công truy cập cùng URL:**

```http
# Attacker requests the same URL (no authentication needed!)
GET /account/settings/logo.css HTTP/1.1
Host: bank.com

# CDN: Cache HIT → returns the stored response containing victim's data
# Attacker now has: Name, Email, API Key of the victim!
```

**Biến thể nâng cao — Path delimiter confusion:**

```
# Different servers interpret path delimiters differently
# Semicolon delimiter (Tomcat/Java):
/account/settings;x.css        → Tomcat ignores ";x.css", serves /account/settings
                                → CDN sees ".css", caches it

# Encoded path separators:
/account/settings%2Flogo.css   → Origin decodes %2F as /, serves /account/settings
                                → CDN treats it as one path segment ending in .css

# Dot segment normalization:
/static/..%2Faccount/settings  → Origin normalizes to /account/settings
                                → CDN caches under /static/..%2Faccount/settings
```

## 🛡️ Biện pháp phòng thủ

1. **Chỉ cache dựa trên `Cache-Control` header**, không dựa trên file extension:

```nginx
# Nginx — cache ONLY when origin explicitly allows it
proxy_cache_valid 200 0;  # Don't cache by default

# Only cache when origin sends proper cache headers
proxy_cache_use_stale off;
proxy_cache_bypass $http_cache_control;

# Respect origin's Cache-Control header
proxy_ignore_headers "";  # Do NOT ignore any origin headers
```

2. **Trả về 404 cho path không tồn tại** — tắt path normalization/fallback:

```python
# Flask — disable path normalization, return 404 for unknown paths
from flask import Flask, abort

app = Flask(__name__)
app.url_map.strict_slashes = True  # Strict URL matching

@app.route('/account/settings')
def account_settings():
    return render_account_page()

# /account/settings/anything.css → 404 (not cached)
```

3. **Sử dụng `Cache-Control: no-store`** cho mọi trang có dữ liệu người dùng.

4. **Thêm `Content-Type` validation** tại CDN — chỉ cache khi Content-Type khớp với extension.

5. **Loại bỏ path parameter** trước khi routing — strip `;`, `%2F`, `..` patterns.

## 💻 Code Example

```python
# === VULNERABLE: Path normalization allows cache deception ===
from flask import Flask, request, session

app = Flask(__name__)

@app.route('/account/<path:subpath>')  # Catches /account/ANYTHING
def account_catchall(subpath):
    # Always returns account data regardless of subpath
    user = get_user(session['user_id'])
    return f"""
    <h1>Account: {user.name}</h1>
    <p>Email: {user.email}</p>
    <p>Balance: ${user.balance}</p>
    """  # DANGEROUS: /account/x.css returns this, CDN caches it!

# === SECURE: Strict routing + proper cache headers ===
@app.route('/account/settings')  # Exact match only
def account_settings_secure():
    user = get_user(session['user_id'])
    response = make_response(render_template('settings.html', user=user))
    # Explicitly prevent caching of user-specific content
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Vary'] = 'Cookie'  # Different response per user session
    return response

@app.errorhandler(404)
def not_found(e):
    """Return 404 for non-existent paths — prevents path normalization abuse"""
    response = make_response("Not Found", 404)
    response.headers['Cache-Control'] = 'no-store'
    return response
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/web-cache-deception
- OWASP: https://owasp.org/www-community/attacks/Web_Cache_Deception
- CWE: https://cwe.mitre.org/data/definitions/524.html
- Omer Gil: https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
