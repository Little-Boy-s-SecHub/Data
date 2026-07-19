---
schema_version: 1
id: WEB-A08-WEB-CACHE-DECEPTION
title: "Web Cache Deception"
slug: web-cache-deception
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-524
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Web Cache Deception

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Web Cache Deception bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Web Cache Deception và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Web Cache Deception (Đánh lừa bộ nhớ đệm Web)** là trò lừa lọc đảo ngược đầy tinh vi. Kẻ tấn công không cần sửa đổi dữ liệu hay chèn mã độc vào hệ thống. Thay vào đó, hắn chỉ đóng vai trò "kẻ chỉ đường" tinh quái. Hắn tạo ra một đường dẫn URL trông giống như file tĩnh (như `/account/settings/logo.css`) và dụ dỗ nạn nhân nhấn vào.

Khi nạn nhân (đang đăng nhập) nhấn vào link, máy chủ web phục vụ trang thông tin cá nhân bảo mật của nạn nhân, nhưng bộ nhớ đệm (Cache) đứng ở giữa lại bị lừa bởi cái đuôi `.css` và lưu giữ lại bản sao của trang đó.
Sau khi cái bẫy đã sập, kẻ tấn công chỉ cần truy cập vào đúng đường dẫn `/account/settings/logo.css` đó. Lúc này, bộ nhớ đệm (Cache) sẽ vui vẻ trả về trang thông tin nhạy cảm của nạn nhân đã lưu từ trước mà không hề hỏi mật khẩu hay quyền truy cập của kẻ tấn công.

Để phân biệt, **Cache Poisoning (Đầu độc bộ nhớ đệm)** là việc kẻ tấn công tìm cách nhét mã độc vào bộ nhớ đệm để lây nhiễm cho tất cả người dùng khác. Còn **Cache Deception (Đánh lừa bộ nhớ đệm)** lại là việc lừa bộ nhớ đệm tự lưu lại thông tin thầm kín của nạn nhân, rồi kẻ tấn công đến "nhặt" đi.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** private response và shared-cache entry.
- **Actor, xác thực và role:** actor craft URL; role user đã login tải; anonymous tải lại.
- **Điều kiện khai thác:** cache coi path là static trong khi origin route thành private dynamic content.
- **Browser, proxy, framework và phiên bản:** cache/proxy và origin được pin với Chromium/hai client và namespace riêng; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với web cache deception, cache coi path là static trong khi origin route thành private dynamic content. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy cache/proxy và origin được pin với Chromium/hai client và namespace riêng; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case web cache deception; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “cache coi path là static trong khi origin route thành private dynamic content”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của web cache deception; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Bước 1: Kẻ tấn công tạo URL lừa đảo:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-001 -->
<!-- context: candidate paths sent to a pinned cache/origin pair with a unique namespace -->
<!-- prerequisites: bank.lab.test loopback only; synthetic account routes; maximum three probes; cache initially empty -->
<!-- encoding: paths are ASCII except percent cases tested separately; client preserves path bytes without normalization -->
<!-- expected-result: trace identifies only paths where origin serves private route while cache classifies static; no data returned yet -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Attacker crafts a URL that:
# 1. Routes to a sensitive page (path normalization)
# 2. Looks like a static file to the cache (.css extension)

https://bank.lab.test/account/settings/logo.css
https://bank.lab.test/my-account/profile.js
https://bank.lab.test/api/user/details/tracking.png
```

**Bước 2: Lừa nạn nhân click link:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-002 -->
<!-- context: pinned Chromium normal user loads one candidate URL from untrusted.lab.test -->
<!-- prerequisites: synthetic session/profile; one navigation or image load; no email/social delivery -->
<!-- encoding: UTF-8 HTML; href/src absolute .lab.test URL is parsed by browser without additional application decoding -->
<!-- expected-result: victim request reaches the candidate cache key once; secure response remains private/no-store and uncached -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker sends this link via email, chat, or social engineering -->
<a href="https://bank.lab.test/account/settings/logo.css">
  Click here to verify your account
</a>

<!-- Or embed as invisible image to trigger automatically -->
<img src="https://bank.lab.test/account/settings/logo.css" width="0" height="0">
```

**Bước 3: Nạn nhân click → Cache lưu trang nhạy cảm:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-003 -->
<!-- context: HTTP/1.1 authenticated request to disposable cache/origin for /account/settings/logo.css -->
<!-- prerequisites: synthetic cookie and profile marker only; unique cache namespace; one victim request -->
<!-- encoding: ASCII request with harness-generated CRLF; cookie is synthetic and path bytes are preserved -->
<!-- expected-result: vulnerable misconfiguration stores a response containing LAB_PRIVATE_PROFILE; secure cache records no shared entry -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Victim's browser sends (victim is authenticated):
GET /account/settings/logo.css HTTP/1.1
Host: bank.lab.test
Cookie: session=LAB_VICTIM_SESSION

# Origin server: "/account/settings/logo.css" not found
# → Path normalization → serves /account/settings
# Response contains only a synthetic private marker:

HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=120  # Intentionally unsafe fixture configuration

<html>
<p>LAB_PRIVATE_PROFILE</p>
</html>

# The vulnerable cache rule classifies the .css-looking path as shared and stores it.
```

**Bước 4: Kẻ tấn công truy cập cùng URL:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-004 -->
<!-- context: HTTP/1.1 unauthenticated verification request uses the same disposable cache key -->
<!-- prerequisites: WEB-A08-WEB-CACHE-DECEPTION-003 completed in same namespace; one request; no real personal/API data -->
<!-- encoding: ASCII request with harness-generated CRLF and no Cookie header -->
<!-- expected-result: vulnerable response contains only LAB_PRIVATE_PROFILE from cache; secure response is 401/redirect without marker -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Attacker requests the same URL (no authentication needed!)
GET /account/settings/logo.css HTTP/1.1
Host: bank.lab.test

# Cache HIT returns only the stored synthetic marker LAB_PRIVATE_PROFILE.
```

**Biến thể nâng cao — Path delimiter confusion:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-005 -->
<!-- context: pinned cache/origin versions test semicolon, encoded separator and dot-segment paths separately -->
<!-- prerequisites: synthetic account and unique namespace; maximum three victim plus three verifier requests -->
<!-- encoding: raw client preserves semicolon and percent bytes; each component is decoded exactly once by the documented hop -->
<!-- expected-result: only a parser mismatch observed in fixture is reported; aligned secure routing never creates a shared private entry -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Behaviors below apply only to the pinned cache/origin fixtures and must be observed.
# Semicolon delimiter case:
/account/settings;x.css        → fixture origin routes to /account/settings
                                → fixture cache classifies the key as static

# Encoded path separators:
/account/settings%2Flogo.css   → fixture origin and cache normalize differently

# Dot segment normalization:
/static/..%2Faccount/settings  → fixture trace records each hop's normalized path
```

## 9. Code dễ bị lỗi và code an toàn

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

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Web Cache Deception, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Đặt authenticated response private/no-store và đồng bộ path normalization giữa cache/origin.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Web Cache Deception, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

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

## 12. Retest

- **Positive case:** với Web Cache Deception, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Web Cache Deception mà không xác nhận side effect và log.
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

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/web-cache-deception — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** RFC 9111 — HTTP Caching. https://www.rfc-editor.org/rfc/rfc9111.html — phiên bản/ngày: June 2022; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/524.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** Omer Gil. https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
