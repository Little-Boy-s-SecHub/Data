---
schema_version: 1
id: WEB-A05-HTTP-PARAMETER-POLLUTION
title: "HTTP Parameter Pollution (HPP)"
slug: http-parameter-pollution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A10:2025
cwe:
  - CWE-235
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# HTTP Parameter Pollution (HPP)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích HTTP Parameter Pollution (HPP) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống HTTP Parameter Pollution (HPP) và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Khi một request chứa hai tham số trùng tên, kết quả phụ thuộc parser, API truy xuất tham số, middleware, cấu hình và phiên bản cụ thể. Không nên suy từ tên ngôn ngữ hoặc framework rằng hệ thống luôn chọn giá trị đầu, cuối hay nối mọi giá trị; phải kiểm tra raw request ở từng lớp của chính fixture. [S2]

```http
GET /search?category=electronics&category=books HTTP/1.1
Host: shop.victim.lab.test
```

```python
# Illustrative observations; pin and retest the exact versions in the lab:

# A selected PHP fixture may expose the last scalar value through $_GET.

# A selected ASP.NET API may return a comma-joined representation.

# Flask's MultiDict API can select one value or return a list.
# request.args.get("category") = "electronics"           → Takes FIRST occurrence
# request.args.getlist("category") = ["electronics", "books"]  → Returns list

# A selected Servlet container/API can expose one value or all values.
# request.getParameter("category") = "electronics"       → Takes FIRST occurrence
# request.getParameterValues("category") = ["electronics", "books"]

# Express and Rails behavior also depends on the configured query parser and version.
```

Rủi ro xuất hiện khi hai lớp trong cùng luồng chuẩn hóa hoặc chọn giá trị khác nhau. Ví dụ chỉ hợp lệ sau khi lab chứng minh lớp kiểm tra dùng giá trị thứ nhất còn backend fixture dùng giá trị thứ hai; tên công nghệ riêng lẻ không đủ làm bằng chứng. [S2]

## 4. Mô tả và nguyên nhân gốc

HPP xuất hiện khi cùng một tên tham số có nhiều giá trị nhưng các lớp trong luồng chọn/canonicalize chúng khác nhau. Chỉ kết luận bypass khi log cùng correlation ID chứng minh lớp kiểm tra và lớp nghiệp vụ đã dùng các giá trị khác nhau; không được gán quy tắc “first/last” chỉ từ tên Java, PHP hay WAF. [S2] [S3]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** tham số được validation rồi dùng trong transfer/redirect.
- **Actor, xác thực và role:** role user đã xác thực cho transfer; anonymous cho redirect.
- **Điều kiện khai thác:** hai lớp chuẩn hóa hoặc chọn duplicate parameter khác nhau.
- **Browser, proxy, framework và phiên bản:** Flask 3.x, reverse proxy được pin và mock OAuth 127.0.0.1; raw HTTP/1.1; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S2]

## 6. Cơ chế tấn công

Đối với HTTP parameter pollution, hai lớp chuẩn hóa hoặc chọn duplicate parameter khác nhau. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S2]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Flask 3.x, reverse proxy được pin và mock OAuth 127.0.0.1; raw HTTP/1.1; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case http parameter pollution; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “hai lớp chuẩn hóa hoặc chọn duplicate parameter khác nhau”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của http parameter pollution; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các probe dưới đây chỉ áp dụng cho parser và thứ tự duplicate ghi từ đúng fixture thay vì suy đoán. [S2] [S3]

**Tấn công 1 — Bypass WAF:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-001 -->
<!-- context: HTTP/1.1 query parsed by a two-layer fixture whose validator selects the first id and backend selects the last id -->
<!-- prerequisites: synthetic /user record; pinned parsers with duplicate-value behavior captured in logs; one request; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded query; spaces use + and the quote is literal percent-decoded input -->
<!-- expected-result: validator log records id=1 while backend log records the second id; a fixed pipeline rejects duplicate scalar parameters -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /user?id=allowed&id=blocked-marker HTTP/1.1
Host: victim.lab.test
```

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-002 -->
<!-- context: explanatory trace for the pinned two-layer fixture in WEB-A05-HTTP-PARAMETER-POLLUTION-001 -->
<!-- prerequisites: raw query and parsed values from both fixture layers have been captured for the same correlation ID -->
<!-- encoding: quoted text representation; not an executable payload -->
<!-- expected-result: trace displays the distinct first-layer and backend values without claiming universal PHP or WAF behavior -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
Validator sees: id = "allowed"
Backend sees:   id = "blocked-marker"
```

**Tấn công 2 — Thay đổi logic thanh toán:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-003 -->
<!-- context: HTTP/1.1 baseline POST to a disposable transfer fixture accepting one scalar amount -->
<!-- prerequisites: synthetic alice account and ledger snapshot; authenticated fixture user; exactly one baseline request -->
<!-- encoding: application/x-www-form-urlencoded body generated from UTF-8 ASCII fields -->
<!-- expected-result: fixture records one transfer of 100 USD and one amount value in validation plus execution logs -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/transfer HTTP/1.1
Host: victim.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

to=alice&amount=100&currency=USD
```

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-004 -->
<!-- context: HTTP/1.1 duplicate amount POST to the disposable transfer fixture -->
<!-- prerequisites: synthetic alice account and ledger snapshot; parser selections captured at validation and execution; exactly one request -->
<!-- encoding: application/x-www-form-urlencoded body preserving both amount fields in order -->
<!-- expected-result: vulnerable fixture logs inconsistent selected amounts; fixed fixture rejects the duplicate and leaves the ledger unchanged -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/transfer HTTP/1.1
Host: victim.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

to=alice&amount=100&amount=1
```

**Tấn công 3 — Server-side HPP qua URL building:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-005 -->
<!-- context: Flask fixture builds an authorization URL for a mock provider at 127.0.0.1:9002 -->
<!-- prerequisites: mock provider is loopback-only and records parsed duplicate parameters; outbound network disabled; one request per case -->
<!-- encoding: callback value is percent-encoded once in the incoming query; the vulnerable example fails to encode it again when composing the provider URL -->
<!-- expected-result: mock provider records two client_id values and their order; the test does not assume which value wins until the provider parser is observed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable code that builds URL from user input
# User controls "callback" parameter
@app.route("/oauth")
def oauth():
    callback = request.args.get("callback")  # Takes first occurrence
    # Test input: /oauth?callback=legit.lab.test%26client_id%3Dsynthetic-client
    # After URL decode: callback = "legit.lab.test&client_id=synthetic-client"

    redirect_url = f"http://127.0.0.1:9002/authorize?callback={callback}&client_id=myapp"
    # Result contains two client_id values. The mock provider log determines
    # which value its pinned parser selects; do not assume a universal rule.
    return redirect(redirect_url)
```

**Tấn công 4 — Client-Side HPP:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-006 -->
<!-- context: Chromium fixture renders a duplicate lang value into an HTML href attribute without contextual encoding -->
<!-- prerequisites: local victim.lab.test page with the vulnerable template; synthetic session; no outbound network -->
<!-- encoding: second lang value is URL-encoded in the request, then incorrectly inserted decoded into a double-quoted HTML attribute -->
<!-- expected-result: vulnerable DOM contains an injected script element; fixed template encodes the value and contains only the intended anchor -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Server renders share link using user-controlled parameter -->
<!-- URL: /page?lang=en&lang="><script>document.documentElement.dataset.hpp='client'</script> -->
<a href="/share?utm_source=social&lang="><script>document.documentElement.dataset.hpp='client'</script>">Share</a>
```

## 9. Code dễ bị lỗi và code an toàn

```python
# ❌ VULNERABLE: String concatenation allows HPP
@app.route("/redirect")
def redirect_handler():
    next_url = request.args.get("next")
    # Lab input: /redirect?next=untrusted.lab.test%26admin%3Dtrue
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

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S2]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Canonicalize một lần và từ chối duplicate cho trường scalar trước validation/nghiệp vụ.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với HTTP Parameter Pollution (HPP), các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Kiểm soát và xác thực nghiêm ngặt các tham số trùng lặp trong yêu cầu HTTP để tránh sự bất nhất giữa các lớp xử lý.
- **Các bước chi tiết**:
  - Chọn rõ ràng cách xử lý tham số trùng — reject hoặc chỉ lấy giá trị đầu tiên.
  - Thực hiện kiểm tra và xác thực ở cả tầng WAF và tầng backend.
  - Dùng một parser/canonical representation chung cho validation và nghiệp vụ; kiểm thử duplicate ở query, form body và URL do server tự xây dựng. [S2] [S3]

## 12. Retest

- **Positive case:** với HTTP Parameter Pollution (HPP), luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của HTTP Parameter Pollution (HPP) mà không xác nhận side effect và log.
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

- **HPP (HTTP Parameter Pollution)**: Ô nhiễm tham số HTTP bằng cách gửi nhiều tham số trùng tên.
- **WAF (Web Application Firewall)**: Tường lửa bảo vệ ứng dụng web khỏi các cuộc tấn công phổ biến.
- **Query String**: Phần tham số đi kèm phía sau dấu hỏi chấm trên URL.
- **Backend**: Hệ thống máy chủ xử lý dữ liệu và logic bên dưới của trang web.
- **Canonicalization**: Quy tắc chuyển nhiều biểu diễn đầu vào về một dạng duy nhất trước khi validation và xử lý nghiệp vụ. [S2] [S3]

## 16. Bài liên quan và đọc thêm

- [SQL Injection](../sql-injection/) — Tấn công tiêm lệnh SQL qua các tham số.

## 17. Tài liệu tham khảo

- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/235.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** Original Paper. https://owasp.org/www-pdf-archive/AppsecEU09_CarssoniDiPaola_v0.8.pdf — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
