---
schema_version: 1
id: WEB-A02-LAX-SECURITY-SETTINGS
title: "Lax Security Settings"
slug: lax-security-settings
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  []
content_status: technical-review
payload_status: none
last_verified: null
---

# Lax Security Settings

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Lax Security Settings bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Cookie scope/attributes và session lifecycle.

- Express 4.x, express-session và reverse-proxy trust.

- Cách browser xử lý Secure, HttpOnly và SameSite.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn thuê một công ty bảo an để bảo vệ ngôi nhà của mình. Khi bàn giao, công ty này lắp đặt hệ thống camera an ninh và khóa cửa cho bạn. Tuy nhiên, họ lại để mật khẩu mặc định của camera là `admin123`, chỉ khóa cửa chính mà quên khóa cửa sổ, và dùng loại chìa khóa dễ dàng sao chép. Những sơ hở này chính là biểu hiện của **thiết lập cấu hình bảo mật lỏng lẻo** (Lax Security Settings). Kẻ trộm chẳng cần dùng đến các công cụ bẻ khóa tinh vi, chúng chỉ cần thử mật khẩu mặc định hoặc trèo qua cửa sổ đang mở để đột nhập vào nhà bạn. [S3]

Trong môi trường web, một trong những sơ hở cấu hình phổ biến nhất nằm ở cách ứng dụng quản lý **cookie** (mẩu thông tin lưu trên trình duyệt để giữ trạng thái đăng nhập, tương tự như chiếc thẻ ra vào tòa nhà). Để bảo vệ chiếc thẻ này khỏi bị kẻ xấu sao chép hoặc cướp mất, lập trình viên cần cấu hình 3 chiếc "chốt khóa" bảo mật:
- **HttpOnly**: Chốt này khóa không cho phép các đoạn mã JavaScript (như mã độc XSS) đọc được cookie qua thuộc tính `document.cookie`.
- **Secure**: Chốt này bắt buộc trình duyệt chỉ gửi cookie qua kết nối được mã hóa bằng HTTPS. Nếu bạn dùng Wi-Fi công cộng không có bảo mật, kẻ xấu cũng không thể nghe lén và bắt trộm cookie này.
- **SameSite**: Chốt này hạn chế một số trường hợp gửi cookie chéo site. Đây là defense-in-depth, không thay thế CSRF token hoặc custom header kèm CORS allowlist phù hợp với threat model. [S1]

```javascript
// Express.js session configuration using express-session with secure cookie flags
const express = require('express');
const session = require('express-session');
const app = express();
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be supplied by the deployment secret store');
}

app.use(session({
    name: 'session_id', // Avoid using default cookie names like connect.sid
    secret: sessionSecret, // Load the signing secret from the deployment secret store
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Prevent client-side scripts from reading the cookie
        secure: true,   // Ensure the cookie is only transmitted over HTTPS
        sameSite: 'lax', // Defense in depth; state-changing routes still require CSRF protection
        maxAge: 3600000 // Session expires after 1 hour (value in milliseconds)
    }
}));
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Cấu hình bảo mật lỏng lẻo** (Lax Security Settings) xảy ra khi lập trình viên hoặc quản trị viên hệ thống giữ nguyên các thiết lập mặc định không an toàn, quên bật các cờ bảo mật quan trọng, hoặc mở các cổng mạng và dịch vụ không cần thiết. [S3]

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó mở toang những lối đi dễ dàng nhất cho kẻ tấn công. Chỉ bằng việc thiếu các cờ bảo mật như `HttpOnly` hay `Secure` trên cookie, kẻ tấn công có thể dễ dàng đánh cắp phiên làm việc của người dùng thông qua các cuộc tấn công XSS hoặc nghe lén mạng. Ngoài ra, việc để lộ thông tin phiên bản máy chủ, bật chức năng hiển thị danh sách thư mục (directory listing) hoặc không thiết lập các HTTP response headers bảo vệ (như CSP, X-Frame-Options) sẽ cung cấp cho kẻ tấn công toàn bộ sơ đồ cấu trúc của ứng dụng, giúp chúng dễ dàng lên kế hoạch và thực hiện các cuộc tấn công phá hoại tiếp theo. [S3]


> **Lưu ý mapping:** CWE-16 là category “Configuration”, không phải weakness dùng làm root-cause mapping. Chủ đề cấu hình lỏng lẻo này cần gắn CWE cụ thể theo lỗi cấu hình thực tế; metadata vì vậy để `cwe: []`. [S3]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** session cookie synthetic, response headers và thông tin cấu hình công khai.

- **Actor:** browser user lab và script/origin đối chứng; không dùng session thật.

- **Trust boundary:** Express.js session config, reverse proxy TLS và Apache/Nginx response headers.

- **Điều kiện cần:** một setting cụ thể bị thiếu/sai; impact phụ thuộc XSS, HTTP hoặc cross-site request tương ứng.

- **Môi trường:** Express 4.x, express-session pin version, Chromium pin version và HTTPS loopback.

Không gom mọi header thành một lỗ hổng: từng setting phải có threat model, baseline và bằng chứng riêng; SameSite chỉ là defense-in-depth cho CSRF. [S1]

## 6. Cơ chế tấn công

Mỗi setting sai mở một đường riêng: thiếu HttpOnly cho script đọc cookie, thiếu Secure cho HTTP transport, hoặc policy SameSite không phù hợp cho cross-site flow. Impact chỉ được kết luận theo đúng prerequisite của setting đó. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** nạp SESSION_SECRET từ secret store lab, chạy HTTPS fixture và pin Chromium.
2. **Baseline:** xác nhận Set-Cookie có HttpOnly/Secure/SameSite đúng threat model và header không lộ version.
3. **Thao tác:** bật từng cấu hình lỗi trên snapshot riêng; quan sát document.cookie, HTTP transport hoặc cross-site request phù hợp.
4. **Expected result:** bản lỗi thiếu đúng thuộc tính; bản sửa phát cookie an toàn nhưng CSRF test vẫn dựa vào token/custom header.
5. **Boundary:** kiểm tra reverse-proxy trust, localhost/HTTPS, cookie Domain/Path và error response.
6. **Cleanup:** xóa session/browser profile và secret fixture.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Ứng dụng web thiết lập cookie phiên (session cookie) nhưng không gán các cờ bảo mật như `HttpOnly` và `Secure`.
Bước 2: Kẻ tấn công chèn được một đoạn mã script độc hại (thông qua lỗ hổng XSS khác) vào trang web mà nạn nhân đang truy cập.
Bước 3: Script độc hại chạy trên trình duyệt nạn nhân, đọc cookie thông qua thuộc tính `document.cookie` (do thiếu cờ `HttpOnly`) và gửi nó về máy chủ của kẻ tấn công.
Bước 4: Kẻ tấn công sử dụng cookie lấy được để mạo danh phiên làm việc của nạn nhân trên một trình duyệt khác. [S3]

## 9. Code dễ bị lỗi và code an toàn

```javascript
// VULNERABLE Express 4.x configuration for the session fixture
app.set('trust proxy', true);
app.use(session({
    secret: 'development-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: false, secure: false, sameSite: false },
}));
```

```javascript
// SECURE Express 4.x configuration for the same session use case
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    throw new Error('SESSION_SECRET must come from the deployment secret store');
}

// Trust only the known reverse-proxy hop used by this deployment.
app.set('trust proxy', 1);
app.use(session({
    name: '__Host-session_id',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 1000,
    },
}));
```

Các thuộc tính cookie phải được đặt tại thành phần sở hữu session thay vì sửa chuỗi `Set-Cookie` bằng regex ở reverse proxy. Prefix `__Host-` yêu cầu `Secure`, `Path=/` và không có thuộc tính `Domain`; `SameSite=Lax` chỉ là defense-in-depth và state-changing route vẫn cần kiểm soát CSRF phù hợp. [S3], [S4]

## 10. Phát hiện

- Đăng nhập trên Chromium rồi kiểm tra `Set-Cookie`, cookie jar và hành vi cross-site. [S3]

- Review session secret, proxy trust, cookie name/path/domain và cấu hình production. [S3], [S4]

- Thu header trên cả success/error; không log session ID hoặc secret.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Cấu hình session secret đủ mạnh ngoài source và đặt cookie Secure, HttpOnly, SameSite theo threat model. [S3], [S4]

- Giới hạn proxy trust và dùng HTTPS trước khi bật Secure cookie. [S4]

### Defense-in-depth

- Dùng prefix `__Host-` khi đáp ứng Secure, Path=/ và không Domain. [S3]

- Rotate/invalidate session theo lifecycle thích hợp.

## 12. Retest

- **Positive:** đăng nhập HTTPS tạo cookie đúng thuộc tính và phiên hoạt động.

- **Negative:** HTTP/cross-site context ngoài policy không nhận hoặc không gửi cookie.

- **Boundary:** proxy hop, subdomain, expiry, logout và error response.

- **Telemetry:** kiểm tra cookie jar và session-store event mà không lộ token.

## 13. Sai lầm thường gặp

- Dùng regex ở proxy để sửa mọi `Set-Cookie` mà không hiểu owner.

- Bật `trust proxy` cho mọi nguồn.

- Coi SameSite là biện pháp CSRF duy nhất.

- Ghi session ID hoặc secret vào log kiểm thử.

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

- **HttpOnly:** chặn JavaScript đọc cookie qua API như `Document.cookie`. [S3]

- **Secure:** yêu cầu browser chỉ gửi cookie qua kết nối bảo mật theo cookie semantics. [S3]

- **SameSite:** giới hạn một số trường hợp gửi cookie cross-site; không thay thế CSRF control gốc. [S3]

## 16. Bài liên quan và đọc thêm

- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** MDN — Set-Cookie header. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** express-session documentation — cookie options and proxy deployment. https://expressjs.com/en/resources/middleware/session.html — phiên bản/trạng thái: tài liệu hiện hành; truy cập: 2026-07-18.
