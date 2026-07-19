---
schema_version: 1
id: WEB-A05-SSI-INJECTION
title: "Server-Side Include (SSI) Injection"
slug: ssi-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-97
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Include (SSI) Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Server-Side Include (SSI) Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Server-Side Include (SSI) Injection và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Thuở sơ khai của mạng internet, khi các ngôn ngữ mạnh mẽ như PHP hay ASP chưa phổ biến, các máy chủ web đã sử dụng một công nghệ đơn giản gọi là Server-Side Includes (SSI). Hãy tưởng tượng SSI giống như những nhãn dán hướng dẫn đặc biệt dạng comment HTML (ví dụ: `<!--#echo var="DATE_LOCAL" -->` để hiển thị ngày giờ) được nhúng sẵn trong các tệp tin của trang web (thường có đuôi `.shtml`). Trước khi gửi trang web tới trình duyệt của người dùng, máy chủ sẽ quét qua toàn bộ trang web, tìm các nhãn dán chỉ thị này để xử lý chúng rồi dán kết quả vào đó. Vì SSI có nhiều directive khác nhau, bài học chỉ dùng marker tổng hợp trong lab để chứng minh user input đã bị parse như SSI.

```html
<!-- Normal SSI directives in a .shtml file -->

<!-- Display current date -->
<!--#echo var="DATE_LOCAL" -->

<!-- Include content from another file -->
<!--#include file="header.html" -->

<!-- Include output of a CGI script -->
<!--#include virtual="/cgi-bin/counter.cgi" -->

<!-- Display file size -->
<!--#fsize file="document.pdf" -->

<!-- Echo a lab-only marker variable -->
<!--#echo var="SECHUB_LAB_MARKER" -->
```

Khi web server nhận request cho file `.shtml`, nó parse toàn bộ nội dung, tìm các directive `<!--#...-->`, xử lý chúng, và thay thế bằng kết quả trước khi trả về cho client. Client chỉ nhận HTML thuần — không thấy SSI directive.

Ví dụ trang web sử dụng SSI để hiển thị footer động:

```html
<!-- page.shtml — using SSI for dynamic footer -->
<html>
<body>
  <h1>Welcome</h1>
  <p>Main content here...</p>
  <footer>
    <!-- SSI directive to include shared footer -->
    <!--#include file="footer.html" -->
    <!-- Display last modified time -->
    <p>Last updated: <!--#echo var="LAST_MODIFIED" --></p>
  </footer>
</body>
</html>
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng SSI Injection xảy ra khi ứng dụng web nhận thông tin từ người dùng (như tên đăng ký hay lời bình luận) và nhúng trực tiếp chúng vào các tệp tin được xử lý bởi công cụ SSI mà không qua bộ lọc an toàn. Người kiểm thử trong lab có thể nhập một marker tổng hợp trông giống directive, chẳng hạn `<!--#echo var="SECHUB_LAB_MARKER" -->` hoặc `<!--#include virtual="/lab/marker.txt" -->`, để xác nhận nội dung user bị SSI parser xử lý thay vì được render như văn bản. Root cause là user input đi vào vùng được SSI-process; mức độ tác động thực tế phụ thuộc cấu hình directive, quyền của web process và dữ liệu có thể chạm tới trong môi trường đó.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** tài liệu SSI render và quyền của web process.
- **Actor, xác thực và role:** role user lưu nội dung được render thành .shtml.
- **Điều kiện khai thác:** nội dung user bị parse như SSI directive thay vì text.
- **Browser, proxy, framework và phiên bản:** Apache HTTP Server 2.4 mod_include trong container non-root; pin trạng thái SSI exec; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với ssi injection, nội dung user bị parse như SSI directive thay vì text. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Apache HTTP Server 2.4 mod_include trong container non-root; pin trạng thái SSI exec; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case ssi injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “nội dung user bị parse như SSI directive thay vì text”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của ssi injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Marker qua echo directive**:

<!-- payload-id: WEB-A05-SSI-INJECTION-001 -->
<!-- context: Apache 2.4 mod_include parses a user-controlled SSI echo directive in .shtml -->
<!-- prerequisites: disposable lab container; environment exposes only the public SECHUB_LAB_MARKER value; one render; no network -->
<!-- encoding: UTF-8 SSI directive in HTML comment syntax; variable name is ASCII -->
<!-- expected-result: vulnerable render returns the public marker value; user-content route with SSI disabled returns the directive literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- The fixture evaluates only a public lab marker variable. -->
<!--#echo var="SECHUB_LAB_MARKER" -->
```

**Include marker tổng hợp trong disposable fixture**:

<!-- payload-id: WEB-A05-SSI-INJECTION-002 -->
<!-- context: Apache httpd 2.4 SSI fixture serves /lab/marker.txt as a synthetic lab file -->
<!-- prerequisites: local synthetic file only; filesystem outside the lab fixture is unavailable; one render -->
<!-- encoding: UTF-8 SSI directive; virtual path is an ASCII absolute URL path, not a host filesystem path -->
<!-- expected-result: response includes the synthetic LAB_MARKER value from /lab/marker.txt -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Include only the synthetic file provided by the lab. -->
<!--#include virtual="/lab/marker.txt" -->
```

**Xác nhận include chỉ chạm marker lab**:

<!-- payload-id: WEB-A05-SSI-INJECTION-003 -->
<!-- context: Apache httpd 2.4 SSI fixture with /fixtures/lab-marker.txt -->
<!-- prerequisites: local synthetic file only; filesystem outside the fixture is unavailable -->
<!-- encoding: UTF-8 SSI directive; virtual path is an ASCII absolute URL path, not a host filesystem path -->
<!-- expected-result: response includes the synthetic LAB_MARKER value -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Include only the synthetic file provided by the lab. -->
<!--#include virtual="/fixtures/lab-marker.txt" -->
```

**Hiển thị biến môi trường lab đã sanitize**:

<!-- payload-id: WEB-A05-SSI-INJECTION-004 -->
<!-- context: Apache 2.4 SSI echo directive in a sanitized environment fixture -->
<!-- prerequisites: environment contains only LAB_ENV_MARKER and generic fixture values; no secrets; one render -->
<!-- encoding: UTF-8 SSI comment directives with ASCII variable names -->
<!-- expected-result: vulnerable output exposes only LAB_ENV_MARKER; secure user-content route does not evaluate directives -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Echo only a sanitized fixture variable. -->
<!--#echo var="LAB_ENV_MARKER" -->
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name')
    message = request.form.get('message')

    # DANGER: User input written directly to .shtml file
    with open('/var/www/html/guestbook.shtml', 'a') as f:
        f.write(f"<p><b>{name}</b>: {message}</p>\n")

    return "Message posted!"


# === SECURE CODE ===
import html
from flask import Flask, request

app = Flask(__name__)

def sanitize_ssi(text):
    """Remove SSI directives and HTML-encode the input"""
    # HTML-encode to neutralize < > characters
    safe_text = html.escape(text, quote=True)
    return safe_text

@app.route('/guestbook', methods=['POST'])
def guestbook():
    name = request.form.get('name', '')
    message = request.form.get('message', '')

    # Validate input length
    if len(name) > 50 or len(message) > 500:
        return "Input too long", 400

    # Sanitize all user input before writing
    safe_name = sanitize_ssi(name)
    safe_message = sanitize_ssi(message)

    # Write to regular .html file instead of .shtml
    # Even if SSI is enabled, .html files are not parsed by default
    with open('/var/www/html/guestbook.html', 'a') as f:
        f.write(f"<p><b>{safe_name}</b>: {safe_message}</p>\n")

    return "Message posted!"
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Server-Side Include (SSI) Injection, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Không SSI-process nội dung người dùng; tắt exec và tách content khỏi đường dẫn bật Includes.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Server-Side Include (SSI) Injection, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Vô hiệu hóa tính năng SSI nếu không sử dụng, hoặc tắt quyền thực thi lệnh và mã hóa dữ liệu người dùng.
- **Các bước chi tiết**:
  - Disable SSI: Nếu không sử dụng, tắt hoàn toàn `mod_include` trong Apache hoặc `ssi off` trong Nginx.
  - Disable `exec` directive: Trong Apache, sử dụng `Options +IncludesNOEXEC` để cho phép SSI nhưng cấm exec.
  - HTML-encode user input: Encode ký tự `<`, `>`, `!`, `#`, `-` trước khi render trong `.shtml`.
  - Không lưu user input vào .shtml files: Tách biệt static SSI template và dynamic user data.
  - Chuyển sang công nghệ hiện đại: Sử dụng template engine (Jinja2, EJS, Blade) thay vì SSI.

## 12. Retest

- **Positive case:** với Server-Side Include (SSI) Injection, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Server-Side Include (SSI) Injection mà không xác nhận side effect và log.
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

- **SSI (Server-Side Includes)**: Công nghệ nhúng các chỉ thị xử lý động phía máy chủ trong file HTML.
- **SSI Injection**: Tiêm chỉ thị SSI vào vùng user-controlled khiến máy chủ xử lý nội dung ngoài ý định.
- **Directive**: Chỉ thị nằm trong cấu trúc comment HTML đặc biệt được SSI quét và chạy.
- **CGI Script**: Giao diện lập trình CGI giúp tạo ra các nội dung web động từ máy chủ.

## 16. Bài liên quan và đọc thêm

- [SSTI](../ssti/) — Khai thác cơ chế thực thi template từ phía máy chủ.

## 17. Tài liệu tham khảo

- **[S1]** Apache HTTP Server 2.4 — Introduction to Server Side Includes. https://httpd.apache.org/docs/2.4/howto/ssi.html — phiên bản/ngày: 2.4; truy cập: 2026-07-17.
- **[S2]** OWASP WSTG — Testing for SSI Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection — phiên bản/trạng thái: latest; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/97.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
