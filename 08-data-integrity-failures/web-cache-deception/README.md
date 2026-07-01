# Web Cache Deception

> **CWE**: CWE-524 | **Phân loại**: Data Integrity

## Kiến thức Nền tảng
Hãy tưởng tượng máy chủ lưu trữ trang web của bạn (Origin Server) giống như một siêu thị lớn bán đủ loại hàng hóa. Để giảm tải cho quầy thanh toán chính và giúp khách hàng mua đồ nhanh hơn, siêu thị bố trí một chiếc máy bán hàng tự động (Web Cache/CDN) ở ngay cửa ra vào. Chiếc máy này được lập trình rất máy móc: "Nếu khách hàng mua đồ khô đóng gói sẵn như bánh kẹo, nước ngọt (tương đương các tài nguyên tĩnh như `.css`, `.js`, `.png`, `.jpg`), hãy giữ lại một bản sao trong máy để người sau đến là có thể lấy ngay mà không cần xếp hàng đi vào trong siêu thị."
Cách chiếc máy nhận biết đồ khô đóng gói sẵn vô cùng đơn giản: Nó chỉ nhìn vào cái đuôi của tên sản phẩm (đuôi file extension trong đường dẫn URL).

Tuy nhiên, trong siêu thị còn có một cơ chế tự động xử lý đường đi của khách hàng gọi là **bình thường hóa đường dẫn (path normalization)**. Nếu một khách hàng đi lạc vào quầy hàng không tồn tại dạng `/account/settings/anything.css`, hệ thống định vị của siêu thị sẽ tự động dẫn họ về quầy cha gần nhất là `/account/settings` (quầy hiển thị thông tin tài khoản cá nhân nhạy cảm).
Sự kết hợp này tạo ra một kẽ hở chí mạng: Chiếc máy bán hàng tự động ở cửa thấy đuôi `.css` nên đinh ninh đây là "đồ khô đóng gói" cần được lưu trữ, trong khi thực tế thứ nó vừa lưu trữ lại chính là trang thông tin riêng tư của khách hàng.

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

## Mô tả lỗ hổng
Lỗ hổng **Web Cache Deception (Đánh lừa bộ nhớ đệm Web)** là trò lừa lọc đảo ngược đầy tinh vi. Kẻ tấn công không cần sửa đổi dữ liệu hay chèn mã độc vào hệ thống. Thay vào đó, hắn chỉ đóng vai trò "kẻ chỉ đường" tinh quái. Hắn tạo ra một đường dẫn URL trông giống như file tĩnh (như `/account/settings/logo.css`) và dụ dỗ nạn nhân nhấn vào.

Khi nạn nhân (đang đăng nhập) nhấn vào link, máy chủ web phục vụ trang thông tin cá nhân bảo mật của nạn nhân, nhưng bộ nhớ đệm (Cache) đứng ở giữa lại bị lừa bởi cái đuôi `.css` và lưu giữ lại bản sao của trang đó.
Sau khi cái bẫy đã sập, kẻ tấn công chỉ cần truy cập vào đúng đường dẫn `/account/settings/logo.css` đó. Lúc này, bộ nhớ đệm (Cache) sẽ vui vẻ trả về trang thông tin nhạy cảm của nạn nhân đã lưu từ trước mà không hề hỏi mật khẩu hay quyền truy cập của kẻ tấn công.

Để phân biệt, **Cache Poisoning (Đầu độc bộ nhớ đệm)** là việc kẻ tấn công tìm cách nhét mã độc vào bộ nhớ đệm để lây nhiễm cho tất cả người dùng khác. Còn **Cache Deception (Đánh lừa bộ nhớ đệm)** lại là việc lừa bộ nhớ đệm tự lưu lại thông tin thầm kín của nạn nhân, rồi kẻ tấn công đến "nhặt" đi.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
```nginx
# Nginx — cache ONLY when origin explicitly allows it
proxy_cache_valid 200 0;  # Don't cache by default
# Only cache when origin sends proper cache headers
proxy_cache_use_stale off;
proxy_cache_bypass $http_cache_control;
# Respect origin's Cache-Control header
proxy_ignore_headers "";  # Do NOT ignore any origin headers
```
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

- **Tóm tắt**: Ngăn chặn Web Cache Deception bằng cách cấu hình cache chỉ dựa trên tiêu đề Cache-Control, trả về lỗi 404 cho đường dẫn không tồn tại và tắt path normalization.
- **Các bước chi tiết**:
  - **Chỉ cache dựa trên `Cache-Control` header**, không dựa trên file extension:
  - **Trả về 404 cho path không tồn tại** — tắt path normalization/fallback:
  - **Sử dụng `Cache-Control: no-store`** cho mọi trang có dữ liệu người dùng.
  - **Thêm `Content-Type` validation** tại CDN — chỉ cache khi Content-Type khớp với extension.
  - **Loại bỏ path parameter** trước khi routing — strip `;`, `%2F`, `..` patterns.

## Code Example
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/web-cache-deception
- OWASP: https://owasp.org/www-community/attacks/Web_Cache_Deception
- CWE: https://cwe.mitre.org/data/definitions/524.html
- Omer Gil: https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html

## Giải thích thuật ngữ
- **Web Cache**: Bộ nhớ đệm lưu trữ tạm thời các tài nguyên web (hình ảnh, mã lệnh CSS/JS) để phục vụ người dùng nhanh hơn mà không cần tải lại từ máy chủ gốc.
- **Origin Server**: Máy chủ gốc, nơi lưu trữ mã nguồn và xử lý logic chính của ứng dụng web.
- **Static Resources (Tài nguyên tĩnh)**: Các file không thay đổi nội dung theo người dùng, ví dụ như hình ảnh, file định dạng CSS, file kịch bản JS.
- **Dynamic Content (Nội dung động)**: Nội dung được tạo ra riêng biệt cho từng người dùng hoặc thay đổi theo thời gian thực (như số dư tài khoản, trang cá nhân).
- **File Extension (Đuôi file)**: Phần cuối của tên file sau dấu chấm (như .css, .js, .png), dùng để xác định định dạng file.
- **Path Normalization (Bình thường hóa đường dẫn)**: Quá trình xử lý đường dẫn URL của các web framework nhằm chuẩn hóa các ký tự lạ hoặc tự động chuyển hướng các đường dẫn phụ không tồn tại về trang cha.
- **Cache-Control**: Trường tiêu đề (header) HTTP dùng để hướng dẫn bộ nhớ đệm có được phép lưu trữ trang web này hay không và lưu trong bao lâu.
- **Cache HIT**: Trạng thái bộ nhớ đệm tìm thấy bản sao tài nguyên được yêu cầu và trả về trực tiếp cho người dùng mà không cần gửi yêu cầu tới máy chủ gốc.
- **CDN (Content Delivery Network)**: Mạng lưới máy chủ phân phối nội dung đặt ở nhiều khu vực địa lý khác nhau giúp tăng tốc truyền tải dữ liệu.
- **Path Delimiter (Ký tự phân tách đường dẫn)**: Các ký tự (như `/` hoặc `;`) dùng để phân tách các thư mục hoặc tham số trong địa chỉ URL.
