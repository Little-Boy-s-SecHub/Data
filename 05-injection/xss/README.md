---
schema_version: 1
id: WEB-A05-XSS
title: "Cross-Site Scripting (XSS)"
slug: xss
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site Scripting (XSS)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Site Scripting (XSS) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Trình duyệt diễn giải HTML và JavaScript theo context của tài liệu. XSS phát sinh khi dữ liệu không tin cậy đi vào một sink khiến browser diễn giải nó như mã thay vì dữ liệu; tác động thực tế phụ thuộc context, CSP, quyền của origin và dữ liệu mà script có thể truy cập. Output encoding phải khớp đúng context, còn API DOM an toàn hoặc auto-escaping chỉ bảo vệ trong phạm vi mà framework cam kết. [S4] [S5]

```python
# Normal operation: HTML template with proper auto-escaping
from flask import Flask, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    # SAFE: Jinja2 auto-escaping converts HTML metacharacters to entities
    # Use ordinary fixture text here; executable inputs belong in section 8
    name = escape("Alice & Bob")
    return render_template_string('<h1>Hello, {{ name }}!</h1>', name=name)
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng XSS xảy ra khi ứng dụng web nhận thông tin từ người dùng rồi đưa trực tiếp thông tin đó lên trang hiển thị mà không tiến hành làm sạch hoặc mã hóa đúng cách. Việc này giống như bạn cho phép người lạ viết bất kỳ điều gì lên bảng tin công cộng của ứng dụng, kể cả những dòng lệnh nguy hiểm. Khi một người dùng khác đến đọc bảng tin, trình duyệt của họ sẽ chạy đoạn mã độc đó. Kẻ tấn công có thể lợi dụng XSS để âm thầm lấy cắp mã token đăng nhập (session cookie) để chiếm đoạt tài khoản, ghi lại từng phím bấm của bạn (keylogging), làm giả giao diện để lừa đảo (defacement), hoặc phát tán mã độc đến những người dùng khác.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** DOM, session tổng hợp và nội dung user được render.
- **Actor, xác thực và role:** actor public hoặc role user cung cấp input; nạn nhân là user đã đăng nhập.
- **Điều kiện khai thác:** input đi vào sink HTML, attribute, URL hoặc JavaScript sai context.
- **Browser, proxy, framework và phiên bản:** Chromium được pin với Node.js 20/Express trên victim/untrusted .lab.test; no outbound; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với xss, input đi vào sink HTML, attribute, URL hoặc JavaScript sai context. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium được pin với Node.js 20/Express trên victim/untrusted .lab.test; no outbound; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case xss; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input đi vào sink HTML, attribute, URL hoặc JavaScript sai context”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của xss; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Có 3 loại chính:

1. **Stored XSS** — payload lưu vĩnh viễn trong database, tấn công nhiều nạn nhân
2. **Reflected XSS** — payload trong URL/request, chỉ tấn công nạn nhân click link
3. **DOM-based XSS** — khai thác trong client-side JS, không qua server

Payload kiển điển:

<!-- payload-id: WEB-A05-XSS-001 -->
<!-- context: pinned Chromium renders isolated HTML, attribute and URL-context marker cases separately -->
<!-- prerequisites: victim.lab.test loopback page; no cookies/secrets; each case only sets data-lab-executed or calls alert with LAB -->
<!-- encoding: UTF-8 payload is encoded for transport once, then intentionally decoded into the documented sink context -->
<!-- expected-result: vulnerable case sets the local marker; secure context encoding renders text and no marker changes -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
<script>document.body.dataset.labExecuted='script'</script>
<img src=x onerror="document.body.dataset.labExecuted='img'">
<svg onload="document.body.dataset.labExecuted='svg'"></svg>
javascript:document.body.dataset.labExecuted='url'
"><script>document.body.dataset.labExecuted='breakout'</script>
```

Tham khảo chi tiết từng loại:
- Stored XSS → [stored/README.md](stored/README.md)
- Reflected XSS → [reflected/README.md](reflected/README.md)
- DOM-based XSS → [dom-based/README.md](dom-based/README.md)
- XSSI → [xssi/README.md](xssi/README.md)

## 9. Code dễ bị lỗi và code an toàn

```python
# Vulnerable: reflecting user input without encoding
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # DANGEROUS: directly embedding user input into HTML response
    return f'<h1>Kết quả tìm kiếm: {query}</h1>'

# Secure: use template engine auto-escaping
from markupsafe import escape

@app.route('/search-safe')
def search_safe():
    query = request.args.get('q', '')
    # SAFE: markupsafe escapes HTML special characters automatically
    return f'<h1>Kết quả tìm kiếm: {escape(query)}</h1>'
```

```html
<!-- Secure CSP header to block inline scripts -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none';">
```

```javascript
// Safe DOM manipulation using textContent instead of innerHTML
// DANGEROUS: element.innerHTML = userInput; (executes scripts)
// SAFE: element.textContent = userInput; (treats as plain text)
document.getElementById('output').textContent = userInput;

// When HTML is needed, use DOMPurify to sanitize first
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Encode đúng output context và dùng safe DOM API/template auto-escaping.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Mã hóa đầu ra theo ngữ cảnh hiển thị, thiết lập chính sách Content Security Policy (CSP), và bảo vệ cookie với cờ HttpOnly.
- **Các bước chi tiết**:
  - Output encoding: HTML entity encoding khi render user data vào HTML.
  - Content Security Policy (CSP): cấm script inline, chỉ cho phép source tin cậy.
  - HttpOnly cookie: ngăn XSS đánh cắp session cookie qua `document.cookie`.
  - Input validation: whitelist characters, reject dangerous tags.
  - DOMPurify: sanitize HTML trước khi set `innerHTML`.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **XSS (Cross-Site Scripting)**: Lỗ hổng chèn mã kịch bản độc hại (thường là JavaScript) chạy trên trình duyệt người dùng.
- **Execution Context**: Ngữ cảnh mà trình duyệt dùng để biên dịch và chạy các dòng lệnh.
- **Browser Trust Model**: Mô hình tin tưởng mặc định của trình duyệt dành cho các đoạn mã chạy trên cùng một nguồn gốc.
- **HTML Entity Encoding**: Chuyển đổi các ký tự HTML đặc biệt thành dạng hiển thị an toàn (như `<` thành `&lt;`).
- **Session Cookie**: File cookie lưu mã xác thực giúp duy trì trạng thái đăng nhập của người dùng.

## 16. Bài liên quan và đọc thêm

- [Stored XSS](stored/) — Tấn công lưu trữ vĩnh viễn trong database
- [Reflected XSS](reflected/) — Tấn công qua URL/form submit
- [DOM-based XSS](dom-based/) — Tấn công trong client-side JavaScript
- [XSSI](xssi/) — Cross-Site Script Inclusion qua JSONP

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/cross-site-scripting — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/xss/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
