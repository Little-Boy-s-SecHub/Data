# Lax Security Settings

> **OWASP Top 10:2025**: A02:2025 – Security Misconfiguration | **CWE**: CWE-16 (Configuration) | **Phân loại**: Design & Process

## 🧱 Kiến thức Nền tảng
Thiết lập cấu hình bảo mật lỏng lẻo thường liên quan đến việc cấu hình thiếu an toàn các thông số của ứng dụng và máy chủ, đặc biệt là cơ chế quản lý phiên làm việc thông qua HTTP cookie. Cookie là các mẩu dữ liệu nhỏ được máy chủ lưu trữ trên trình duyệt của người dùng để duy trì trạng thái đăng nhập. Trình duyệt tự động gửi đính kèm các cookie này trong mỗi yêu cầu tiếp theo đến máy chủ. Để bảo vệ các cookie phiên nhạy cảm khỏi bị đánh cắp hoặc lạm dụng, các lập trình viên cần cấu hình ba cờ bảo mật quan trọng:
- **HttpOnly**: Khi cờ này được bật (`HttpOnly=true`), trình duyệt sẽ chặn không cho phép các đoạn mã JavaScript (ví dụ: chạy qua lỗ hổng XSS) truy cập vào cookie thông qua đối tượng `document.cookie`. Điều này làm giảm thiểu nguy cơ kẻ tấn công đánh cắp session ID để chiếm quyền điều khiển tài khoản của nạn nhân.
- **Secure**: Cờ này yêu cầu trình duyệt chỉ gửi cookie qua các kết nối được mã hóa bằng HTTPS (`Secure=true`). Nếu người dùng truy cập trang web qua kênh HTTP không mã hóa (ví dụ: trên mạng Wi-Fi công cộng), trình duyệt sẽ không gửi cookie này, ngăn chặn kẻ tấn công nghe lén trên đường truyền mạng (Man-in-the-Middle) bắt trộm cookie.
- **SameSite**: Cờ này kiểm soát xem cookie có được gửi kèm theo các yêu cầu chéo trang (cross-site requests) hay không, giúp ngăn chặn hiệu quả tấn công Cross-Site Request Forgery (CSRF). SameSite có ba chế độ:
  - `Strict`: Cookie chỉ được gửi khi yêu cầu bắt nguồn từ chính trang web đó.
  - `Lax`: Cookie được gửi khi người dùng nhấp vào các liên kết điều hướng thông thường từ trang khác sang (mặc định của các trình duyệt hiện đại).
  - `None`: Cookie được gửi với mọi yêu cầu chéo trang, nhưng bắt buộc phải đi kèm cờ `Secure`.

```javascript
// Express.js session configuration using express-session with secure cookie flags
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
    name: 'session_id', // Avoid using default cookie names like connect.sid
    secret: 'super_secure_random_key_12345', // Secret used to sign the session ID cookie
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Prevent client-side scripts from reading the cookie
        secure: true,   // Ensure the cookie is only transmitted over HTTPS
        sameSite: 'lax', // Protect against CSRF attacks while allowing normal navigation
        maxAge: 3600000 // Session expires after 1 hour (value in milliseconds)
    }
}));
```

## 🔍 Mô tả lỗ hổng
Thiết lập cấu hình lỏng lẻo (Lax Security Settings) xảy ra khi hệ thống hoặc ứng dụng web giữ lại các cấu hình mặc định không an toàn hoặc thiếu các thiết lập bảo mật cơ bản. Điều này bao gồm việc không thiết lập các thuộc tính cookie an toàn (như HttpOnly, Secure, SameSite), cho phép liệt kê thư mục (directory listing), hoặc sử dụng các giao thức mã hóa lỗi thời. Kẻ tấn công có thể khai thác các cấu hình này để đánh cắp session cookie của người dùng hoặc thu thập dữ liệu nhạy cảm.

## ⚔️ Cơ chế tấn công
Bước 1: Ứng dụng web thiết lập cookie phiên (session cookie) nhưng không gán các cờ bảo mật như `HttpOnly` và `Secure`.
Bước 2: Kẻ tấn công chèn được một đoạn mã script độc hại (thông qua lỗ hổng XSS khác) vào trang web mà nạn nhân đang truy cập.
Bước 3: Script độc hại chạy trên trình duyệt nạn nhân, đọc cookie thông qua thuộc tính `document.cookie` (do thiếu cờ `HttpOnly`) và gửi nó về máy chủ của kẻ tấn công.
Bước 4: Kẻ tấn công sử dụng cookie lấy được để mạo danh phiên làm việc của nạn nhân trên một trình duyệt khác.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Prevent security configuration weaknesses by hardening configurations, changing defaults, and utilizing automated vulnerability assessments.
- **Các bước chi tiết**:
  - Change all factory default credentials, paths, and settings immediately during system installation.
  - Establish a continuous patching program to update servers, databases, and dependencies.
  - Disable unnecessary components, legacy protocols, unused modules, and open ports to reduce the attack surface.
  - Configure security response headers (CSP, X-Frame-Options, X-Content-Type-Options) across all web applications.
  - Perform regular automated vulnerability scans and configuration audits.

## 💻 Code Example
```configuration
# Apache security hardening settings in httpd.conf
# 1. Disable server signature and detailed version exposure
ServerSignature Off
ServerTokens Prod

# 2. Inject security response headers (use always to apply to error/redirect responses)
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "default-src 'self';"
Header always set Referrer-Policy "no-referrer-when-downgrade"
Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Bài học tập trung vào việc thiết lập cấu hình an toàn cho cookies (HttpOnly, Secure, SameSite) và tắt các tính năng không cần thiết như directory listing.
- **Nguồn tham khảo**: OWASP A05:2021, CWE-16
