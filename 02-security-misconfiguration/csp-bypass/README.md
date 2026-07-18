---
schema_version: 1
id: WEB-A02-CSP-BYPASS
title: "Content Security Policy (CSP) Bypass"
slug: csp-bypass
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-693
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Content Security Policy (CSP) Bypass

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Content Security Policy (CSP) Bypass bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- CSP Level 3 directive resolution và source expression.

- Inline script, nonce/hash, `base-uri` và DOM sink.

- Chromium fixture có console/report collector local.

## 3. Kiến thức nền tảng

Hãy tưởng tượng trang web của bạn giống như một tòa lâu đài đang mở tiệc đãi khách. Bạn thuê một người quản gia nghiêm khắc và đưa cho người đó một danh sách ghi rõ: "Tối nay, chúng ta chỉ tiếp nhận rượu vang từ hầm nhà mình (`'self'`) và một cửa hàng tin cậy là `cdn.trusted.lab.test`. Bất kỳ ai mang đồ ăn thức uống từ nguồn khác đến đều phải bị chặn lại ở cửa". Danh sách quy tắc an toàn này được gọi là **CSP** (Content Security Policy - Chính sách bảo mật nội dung). Đây là một chiếc khiên chắn cực kỳ vững chắc được gửi từ máy chủ qua tiêu đề HTTP để ra lệnh cho trình duyệt: "Chỉ được phép chạy các đoạn mã (script), hình ảnh hoặc giao diện từ các nguồn nằm trong danh sách an toàn này". [S7]

CSP là lớp defense-in-depth có thể làm nhiều payload **XSS** (Cross-Site Scripting) khó khai thác hơn, nhưng không sửa sink XSS và không bảo vệ tuyệt đối trước mọi context/browser/policy. Với nonce-based CSP, browser chỉ cho phép inline script có nonce khớp policy; nonce phải mới cho từng response, khó đoán và không bị gắn vào nội dung do attacker kiểm soát. Ứng dụng vẫn phải dùng output encoding/sanitization đúng context và API DOM an toàn. [S6]

Mỗi một chỉ thị trong CSP sẽ cai quản một loại tài nguyên riêng: `script-src` quản lý mã JavaScript, `style-src` quản lý giao diện CSS, và `default-src` là chốt chặn cuối cùng cho tất cả những gì còn lại. Trình duyệt sẽ đọc và phân tích các chỉ thị này để áp dụng quy tắc bảo vệ nghiêm ngặt trên trang. [S7]

Trong một response dùng nonce, cùng một giá trị phải xuất hiện trong chỉ thị nguồn script của header và trên phần tử script tin cậy do server tạo. Giá trị phải mới, khó đoán cho từng response và không được gắn vào nội dung do người dùng kiểm soát. Mục 8 chứa hai response fixture đã annotation để quan sát trường hợp nonce thiếu và nonce bị tái sử dụng; mục 9 chứa cấu hình sinh nonce an toàn. [S6] [S7]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Bypass CSP** (Vượt qua chính sách bảo mật nội dung) xảy ra không phải do bản thân công nghệ CSP bị lỗi, mà xuất phát từ việc lập trình viên thiết lập quy tắc bảo vệ quá cẩu thả hoặc quá lỏng lẻo. Nó giống như việc người quản gia cầm một danh sách cho phép ghi: "Chấp nhận đồ ăn từ mọi nguồn ngoài đường (`unsafe-inline`)" hoặc "Cho phép khách tự ý thay đổi địa chỉ giao hàng". Đây không phải lỗi của đặc tả CSP mà là lỗi cấu hình (configuration) — một dạng Security Misconfiguration điển hình. [S7]

Các sai lầm phổ biến bao gồm việc cho phép chạy các đoạn mã trực tiếp không cần kiểm tra (`unsafe-inline`), cho phép thực thi các chuỗi ký tự thành mã (`unsafe-eval`), thiếu chỉ thị `base-uri`, hoặc đưa các tên miền lớn chứa các dịch vụ công cộng (như các CDN dùng chung hoặc các điểm nhận dữ liệu JSONP) vào danh sách tin cậy. [S7]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** quyền chạy script/đổi base URL trong tài liệu lab; marker chỉ nằm trong DOM.

- **Actor:** actor đã có khả năng chèn inline script hoặc markup theo từng testcase.

- **Trust boundary:** CSP Level 3 response header được Chromium áp lên HTML từ Express.js.

- **Điều kiện cần:** directive cho phép đúng sink, ví dụ unsafe-inline hoặc thiếu base-uri; nonce/hash phải xét riêng.

- **Môi trường:** Chromium pin version, page 127.0.0.1:9000, asset mock 9001, không outbound.

Cấu hình yếu là prerequisite; bằng chứng bypass phải là marker thực thi hoặc request asset đúng context và policy. [S6]

## 6. Cơ chế tấn công

Browser áp từng CSP directive lên sink tương ứng. unsafe-inline cho phép marker inline trong context đã nêu; thiếu base-uri chỉ có tác động khi markup injection đổi resolution của tài nguyên tương đối. [S6]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy page/asset fixture loopback, pin Chromium và bật CSP report/DevTools log.
2. **Baseline:** policy nonce/hash hoặc base-uri 'none' chặn payload tương ứng.
3. **Thao tác:** áp từng cặp header/HTML đã annotation, không trộn unsafe-inline và base-uri thành một case.
4. **Expected result:** policy yếu tạo DOM/request marker; policy sửa chặn và tạo violation log.
5. **Boundary:** kiểm tra CSP2/CSP3, nhiều header, report-only và cache.
6. **Cleanup:** xóa browser profile, marker và report; dừng fixture.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**Trường hợp 1: `unsafe-inline` làm yếu `script-src`**

`'unsafe-inline'` cho phép inline script và inline event handler khi policy không có nonce/hash được CSP3 xử lý. Nó không “vô hiệu hóa toàn bộ CSP”: các directive khác vẫn có hiệu lực, và browser hiện đại bỏ qua `'unsafe-inline'` khi có nonce/hash hợp lệ. [S6]

<!-- payload-id: WEB-A02-CSP-BYPASS-001 -->
<!-- context: CSP Level 3 response header; pinned Chromium fixture at 127.0.0.1:9000; CSP processing model [S7] -->
<!-- prerequisites: serve the paired marker HTML from the same local fixture; clear browser cache and CSP reports between cases -->
<!-- encoding: ASCII CSP header value; response harness emits CRLF and exactly one Content-Security-Policy field -->
<!-- expected-result: Chromium executes the inline lab marker under this policy -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S7 -->
<!-- last-verified: 2026-07-17 -->
```http
# Weak script policy allows inline script in this fixture
Content-Security-Policy: script-src 'self' 'unsafe-inline';
```

<!-- payload-id: WEB-A02-CSP-BYPASS-002 -->
<!-- context: UTF-8 HTML under CSP Level 3; pinned Chromium fixture at 127.0.0.1:9000; CSP processing model [S7] -->
<!-- prerequisites: apply WEB-A02-CSP-BYPASS-001 as the response policy; no cookie, storage, or outbound network access -->
<!-- encoding: UTF-8 HTML served as text/html; JavaScript marker is an inline ASCII string literal -->
<!-- expected-result: document.documentElement.dataset.labCsp becomes inline-ran -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S7 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Harmless local marker; no cookie or network access -->
<script>document.documentElement.dataset.labCsp = 'inline-ran';</script>
```

**Trường hợp 2: thiếu `base-uri` làm đổi đích URL tương đối**

Thẻ `<base>` chỉ tạo tác động khi actor chèn được markup và trang có tài nguyên tương đối được policy cho phép. `base-uri 'none'` hoặc `'self'` chặn việc đổi base URL ngoài ý muốn; nó không thay thế việc sửa injection sink. [S6]

<!-- payload-id: WEB-A02-CSP-BYPASS-005 -->
<!-- context: CSP Level 3 response header without base-uri; pinned Chromium fixture at 127.0.0.1:9000; CSP processing model [S7] -->
<!-- prerequisites: pair with the local base-element fixture; /app.js exists only on 127.0.0.1:9001; outbound network is disabled -->
<!-- encoding: ASCII CSP header value; response harness emits CRLF and exactly one Content-Security-Policy field -->
<!-- expected-result: policy lacks base-uri, which is a prerequisite rather than proof of exploitability -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S7 -->
<!-- last-verified: 2026-07-17 -->
```http
# CSP missing base-uri directive
Content-Security-Policy: script-src 'nonce-lab-only-static-nonce';
```

<!-- payload-id: WEB-A02-CSP-BYPASS-006 -->
<!-- context: UTF-8 HTML under CSP Level 3; pinned Chromium; page at 127.0.0.1:9000 and mock asset at 127.0.0.1:9001; CSP processing model [S7] -->
<!-- prerequisites: mock /app.js sets only a DOM marker; no cookies or outbound network; compare policy with and without base-uri 'none' -->
<!-- encoding: UTF-8 HTML served as text/html; base and script URLs are ASCII loopback URLs -->
<!-- expected-result: a local fixture without base-uri resolves /app.js against 127.0.0.1:9001; fixed policy blocks the base element -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S7 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Local-only base URL used by the disposable browser fixture -->
<base href="http://127.0.0.1:9001/">
<script nonce="lab-only-static-nonce" src="/app.js"></script>
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// === VULNERABLE CSP (Express.js) ===
app.use((req, res, next) => {
    // BAD: unsafe-inline + unsafe-eval + wildcard subdomain
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.cdn.lab.test; " +
        "style-src 'self' 'unsafe-inline'"
    );
    next();
});


// === SECURE CSP (Express.js with nonce) ===
const crypto = require('crypto');

app.use((req, res, next) => {
    // Generate cryptographically random nonce per request
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.cspNonce = nonce;

    // GOOD: Strict nonce-based CSP with all critical directives
    res.setHeader('Content-Security-Policy', [
        "default-src 'none'",
        `script-src 'nonce-${nonce}' 'strict-dynamic'`,
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "report-uri /csp-report" // Retain for compatibility while adopting Reporting API
    ].join('; '));
    next();
});

// Render the same per-response value into trusted script elements with the
// template engine's HTML-attribute escaping enabled.
// EJS example: <script nonce="<%= cspNonce %>">...</script>
```

## 10. Phát hiện

- Nạp fixture bằng Chromium và quan sát script marker, console violation và CSP report. [S7]

- Review effective directive, nonce lifecycle, host source và các directive fallback. [S7]

- So sánh header thực tế trên success/error/redirect response, không chỉ config template.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng policy hẹp theo resource type; tạo nonce khó đoán mới cho mỗi response và chỉ gắn vào script tin cậy. [S7]

- Hạn chế `base-uri`, object và các host script theo nhu cầu thực tế. [S7]

### Defense-in-depth

- CSP bổ sung cho output encoding và safe DOM API; không sửa root cause XSS.

- Thu report ở chế độ thử nghiệm trước khi enforce.

## 12. Retest

- **Positive:** script có nonce hợp lệ chạy và tài nguyên cần thiết tải được.

- **Negative:** inline script không nonce và base ngoài policy bị chặn.

- **Boundary:** error page, cached HTML, nonce reuse và directive fallback.

- **Telemetry:** kiểm tra console, violation report và DOM marker.

## 13. Sai lầm thường gặp

- Tái sử dụng nonce hoặc để actor chèn vào thẻ có nonce.

- Allowlist host chứa JSONP/script do người khác kiểm soát.

- Quên `base-uri` khi dùng relative script URL.

- Gọi policy “bypass” chỉ vì còn thiếu directive, chưa có execution path.

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

- **CSP:** chính sách browser kiểm soát nguồn và điều kiện tải/thực thi tài nguyên. [S7]

- **Nonce:** giá trị khó đoán, mới cho mỗi response, dùng để cho phép script/style cụ thể. [S7]

- **Effective directive:** directive thực sự chi phối loại resource sau quy tắc fallback của CSP. [S7]

## 16. Bài liên quan và đọc thêm

- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## 17. Tài liệu tham khảo

- **[S6]** OWASP Content Security Policy Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S7]** W3C Content Security Policy Level 3. https://www.w3.org/TR/CSP/ — phiên bản/trạng thái: Working Draft hiện hành; truy cập: 2026-07-18.
