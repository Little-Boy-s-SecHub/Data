---
schema_version: 1
id: WEB-A11-API-RATE-LIMITING
title: "API Rate Limiting & Resource Abuse"
slug: api-rate-limiting
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - API4:2023
cwe:
  - CWE-770
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Rate Limiting & Resource Abuse

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích API Rate Limiting & Resource Abuse bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống API Rate Limiting & Resource Abuse và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Unrestricted Resource Consumption (Tiêu thụ tài nguyên không giới hạn)** xuất hiện khi hệ thống của bạn quá phóng khoáng và thiếu cảnh giác, cho phép khách hàng yêu cầu phục vụ những công việc cực kỳ tốn kém mà không có giới hạn nào.

Hãy tưởng tượng một vị khách vào nhà hàng và yêu cầu: "Hãy dọn cho tôi 1 triệu đĩa thức ăn cùng lúc" (Pagination abuse) hoặc gửi một yêu cầu dài hàng trang giấy chỉ để ghi một dòng chữ nhỏ (Large payload DoS). Nếu nhà hàng cố phục vụ, nhà bếp sẽ ngay lập tức tê liệt vì quá tải.
Lỗ hổng này mở ra vô vàn hiểm họa:
- Kẻ tấn công thoải mái gửi hàng triệu yêu cầu dò mã OTP hay mật khẩu mà không bao giờ bị chặn.
- Yêu cầu máy chủ xuất ra hàng triệu dòng dữ liệu cùng lúc, khiến RAM máy chủ quá tải và sập nguồn (OOM).
- Gửi các file hoặc gói dữ liệu khổng lồ để làm tràn bộ nhớ máy chủ.
- Chi phí vận hành máy chủ đám mây (cloud) tăng vọt chóng mặt do tài nguyên bị lạm dụng vô tội vạ, tạo nên cú sốc hóa đơn cho doanh nghiệp.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** OTP/reset/login budget, quota theo principal và capacity của handler/backend.
- **Trust boundary:** request đi qua trusted proxy/gateway và distributed counter trước khi chạm logic xác thực hoặc thao tác tốn tài nguyên.
- **Actor:** client local dùng tài khoản/IP/API key tổng hợp; không gửi traffic ra ngoài fixture.
- **Điều kiện cần:** limiter bị thiếu, đặt sau handler, dùng key/scope sai, không atomic giữa worker, hoặc tin `X-Forwarded-For` từ nguồn không trusted.
- **Điều kiện môi trường:** Flask 3.x, Redis 7 local và một trusted reverse proxy; phải ghi policy/key/window/quota và số worker trước test.

Chỉ đổi IP/header hoặc nhận status 200 chưa đủ chứng minh bypass; cần xác nhận counter, side effect và cùng principal/operation tại application log. [S1]

## 6. Cơ chế tấn công

Limiter có thể bị vượt khi cùng principal chia request qua nhiều worker/IP giả, khi batch chứa nhiều operation nhưng chỉ tính một request, hoặc khi side effect xảy ra trước `INCR`. Kiểm thử phải chứng minh counter atomic, đúng dimension và bản sửa trả 429 trước handler sau khi quota cạn. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy Flask 3.x, Redis 7 và proxy local; seed user/OTP giả, đặt quota 5 lần/15 phút và bật counter/handler logs.
2. **Input:** gửi 4 request hợp lệ làm baseline, sau đó tối đa 3 request cùng principal; thử riêng user khác và header IP qua trusted/untrusted hop.
3. **Thao tác:** ghi status, rate-limit headers, Redis key/TTL và số lần handler/side effect được gọi; lặp một lượt concurrency bị giới hạn.
4. **Expected result:** request thứ 6 trả 429/`Retry-After`, không gọi handler; user khác không bị chia sẻ quota và client không tự giả trusted IP.
5. **Cleanup:** xóa Redis namespace, OTP/user giả, dừng proxy/app và xác nhận không còn timer/process.
6. **Giới hạn an toàn:** giới hạn tổng request/concurrency, không thử trên API thật và không dùng OTP hay tài khoản người dùng thực.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Probe OTP có giới hạn — kiểm tra quota theo actor và operation:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-001 -->
<!-- context: Python 3.12 + requests; local OTP fixture tại 127.0.0.1:18080 -->
<!-- prerequisites: fixture dùng tài khoản giả user-42, quota thử là 5 và không có outbound network -->
<!-- encoding: JSON UTF-8; OTP luôn là chuỗi sáu chữ số -->
<!-- expected-result: tối đa năm lần thử được xử lý; lần thứ sáu trả 429 và Retry-After, không thử toàn bộ không gian OTP -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Bounded regression probe; never enumerate the full OTP space
import requests

TARGET = "http://127.0.0.1:18080/verify-otp"
HEADERS = {"Authorization": "Bearer lab-user-42"}

for otp in ("000000", "000001", "000002", "000003", "000004", "000005"):
    response = requests.post(
        TARGET,
        json={"otp": otp},
        headers=HEADERS,
        timeout=2,
    )
    print(otp, response.status_code, response.headers.get("Retry-After"))
```

**2. Pagination abuse — Dump entire database:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-002 -->
<!-- context: HTTP/1.1 GET; pagination parameter is an integer -->
<!-- prerequisites: local fixture contains exactly 150 fake records and documents page_size maximum 100 -->
<!-- encoding: ASCII request target; no request body -->
<!-- expected-result: server rejects page_size=101 with 400 or caps it to 100 and records the policy decision -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/users?page=1&page_size=101 HTTP/1.1
Host: api.victim.lab.test
Accept: application/json
```

**3. Boundary probe cho giới hạn request body:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-003 -->
<!-- context: Python 3.12 + requests; local import fixture tại 127.0.0.1:18080 -->
<!-- prerequisites: fixture đặt body limit 512 byte; container có memory cap và outbound network bị chặn -->
<!-- encoding: JSON UTF-8 do requests tạo Content-Length -->
<!-- expected-result: payload khoảng 1 KiB bị từ chối bằng 413 trước khi JSON/business processing chạy -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Send a small over-limit payload to a disposable local fixture
import requests

over_limit_payload = {"data": "A" * 1024}

response = requests.post(
    "http://127.0.0.1:18080/import",
    json=over_limit_payload,
    timeout=2,
)
assert response.status_code == 413
```

**4. Kiểm tra không tin `X-Forwarded-For` từ client trực tiếp:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-004 -->
<!-- context: HTTP/1.1 GET through a local trusted-proxy fixture -->
<!-- prerequisites: direct client connection is not in the trusted proxy allowlist; no request reaches Internet -->
<!-- encoding: ASCII headers; X-Forwarded-For contains documentation address 192.0.2.10 -->
<!-- expected-result: limiter ignores the client-supplied forwarding header and uses the verified peer identity for the quota key -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/quota-probe HTTP/1.1
Host: api.victim.lab.test
X-Forwarded-For: 192.0.2.10
```

**5. IP/Header rotation không được tách khỏi principal quota:**

<!-- payload-id: WEB-A11-API-RATE-LIMITING-005 -->
<!-- context: Python 3.12 + requests; local OTP fixture at 127.0.0.1:18080 behind a trusted-proxy simulator; case: WEB-A11-API-RATE-LIMITING-005 -->
<!-- prerequisites: fixture uses synthetic user-42, quota is 5 per account and per verified peer; direct client cannot assert trusted proxy headers -->
<!-- encoding: JSON UTF-8 and ASCII headers; documentation IPs are used only inside the local fixture -->
<!-- expected-result: vulnerable fixture counts each rotated header as a new bucket; fixed fixture still returns 429 after the account quota is exhausted -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-18 -->
```python
import requests

target = "http://127.0.0.1:18080/verify-otp"
for i, ip in enumerate(("192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15")):
    response = requests.post(
        target,
        json={"account": "user-42", "otp": f"{i:06d}"},
        headers={"Authorization": "Bearer lab-user-42", "X-Forwarded-For": ip},
        timeout=2,
    )
    print(ip, response.status_code)
```

## 9. Code dễ bị lỗi và code an toàn

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

# === SECURE: body limit before parsing plus operation-specific throttling ===
app.config['MAX_CONTENT_LENGTH'] = 1024

@app.route('/api/login', methods=['POST'])
def login_secure():
    if request.content_length is not None and request.content_length > 1024:
        return jsonify({"error": "Request body too large"}), 413
    data = request.get_json(force=False, silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    email = data.get('email', '')

    # Account and peer quotas use normalized/server-derived identifiers.
    if not consume_login_quotas(
        server_side_identifier(normalize_account(email)),
        verified_peer_id(request),
    ):
        return jsonify({"error": "Rate limit exceeded"}), 429

    user = db.users.find_one({"email": email})
    if user and check_password(data['password'], user['password']):
        return jsonify({"token": generate_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến API Rate Limiting & Resource Abuse, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Áp dụng kiểm soát ở cấp đối tượng, thuộc tính, chức năng và mức tiêu thụ tài nguyên của API.
- Dùng counter atomic/shared, key theo principal và operation, thực thi trước handler tốn tài nguyên/state-changing; với route nhạy cảm phải có policy rõ khi Redis lỗi.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Với API Rate Limiting & Resource Abuse, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

```python
# Redis Lua keeps INCR and first-window expiry atomic.
WINDOW_COUNTER = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return current
"""

def consume_quota(key, limit, window_seconds):
    current = redis_client.eval(WINDOW_COUNTER, 1, key, window_seconds)
    return int(current) <= limit

def verified_peer_id(request):
    # Use proxy-derived identity only when the direct peer is trusted.
    return trusted_proxy_client_ip(request) or request.remote_addr

@app.post('/verify-otp')
def verify_otp():
    body = request.get_json(silent=True) or {}
    account = normalize_account(body.get('account', ''))
    keys = (
        f"otp:account:{server_side_identifier(account)}",
        f"otp:peer:{verified_peer_id(request)}",
    )
    if not account or not all(consume_quota(key, 5, 900) for key in keys):
        return jsonify({"error": "Rate limit exceeded"}), 429, {"Retry-After": "900"}
    return check_synthetic_otp(account, body.get('code', ''))
```
```python
# Enforce maximum page size and request body limits
@app.route('/api/users')
def list_users():
    page = max(1, request.args.get('page', 1, type=int))
    page_size = request.args.get('page_size', 20, type=int)
    page_size = max(1, min(page_size, 100))
    users = db.users.find().skip((page - 1) * page_size).limit(page_size)
    return jsonify(users)
# Limit request body size at framework level
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max body size
```
```http
HTTP/1.1 429 Too Many Requests
RateLimit-Policy: "login";q=100;w=60
RateLimit: "login";r=0;t=30
Retry-After: 30
```

- **Tóm tắt**: Bảo vệ API khỏi lạm dụng tài nguyên bằng counter atomic theo nhiều chiều do server xác định, đồng thời giới hạn kích thước payload và phân trang.
- **Các bước chi tiết**:
  - **Rate limit theo nhiều dimension**: áp quota theo actor đã xác thực, IP/peer đã xác minh, API key, route/operation và hành vi nhạy cảm như login/OTP; các key phải do server chuẩn hóa và dùng counter atomic/shared.
  - **Giới hạn pagination và payload size**: đặt `page_size` tối đa, default an toàn, giới hạn offset/cursor và chặn body/file vượt ngưỡng ở gateway hoặc framework trước khi parse hay xử lý nghiệp vụ.
  - **Trả về rate limit headers**: trả `RateLimit-Policy`, `RateLimit` và `Retry-After` nhất quán cho response 429 để client biết quota còn lại và thời điểm thử lại.
  - **Normalize URL/method** trước khi áp dụng rate limit — tránh bypass bằng case variation.
  - **Không tin tưởng `X-Forwarded-For`** từ client — chỉ dùng IP từ trusted proxy.

## 12. Retest

- **Positive case:** với API Rate Limiting & Resource Abuse, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của API Rate Limiting & Resource Abuse mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Rate Limiting (Giới hạn lưu lượng)**: Cơ chế kiểm soát và giới hạn số lượng yêu cầu mà một người dùng có thể gửi lên hệ thống trong một khoảng thời gian.
- **API Gateway**: Máy chủ trung gian đóng vai trò là cửa ngõ đầu tiên tiếp nhận và định tuyến các yêu cầu API từ bên ngoài vào hệ thống.
- **Middleware**: Các đoạn mã trung gian nằm giữa luồng tiếp nhận yêu cầu và xử lý logic chính của ứng dụng, chuyên dùng để kiểm tra quyền truy cập hoặc áp dụng rate limit.
- **Token**: Thẻ định danh hoặc thẻ quyền hạn được sử dụng để thực hiện các yêu cầu trong thuật toán Token Bucket.
- **Credential Stuffing**: Phương thức tấn công sử dụng danh sách tài khoản/mật khẩu bị rò rỉ từ các nguồn khác để thử đăng nhập tự động trên diện rộng.
- **Pagination (Phân trang)**: Kỹ thuật chia nhỏ danh sách kết quả trả về từ database thành nhiều trang nhỏ để tăng hiệu suất hiển thị.
- **Bill Shock**: Chi phí hóa đơn dịch vụ đám mây tăng đột biến ngoài tầm kiểm soát do tài nguyên hệ thống bị tiêu thụ quá mức.
- **Account Lockout**: Cơ chế tạm khóa tài khoản sau một số lần đăng nhập sai liên tiếp để chống brute force.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** PortSwigger. https://portswigger.net/web-security/authentication/password-based — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/770.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** IETF HTTPAPI. https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/ — phiên bản/trạng thái: draft-ietf-httpapi-ratelimit-headers-11, work in progress, 2026-05-23; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
