# Lax Security Settings

> **CWE**: CWE-16 (Configuration) | **Phân loại**: Security Misconfiguration

## Kiến thức Nền tảng
Hãy tưởng tượng bạn thuê một công ty bảo an để bảo vệ ngôi nhà của mình. Khi bàn giao, công ty này lắp đặt hệ thống camera an ninh và khóa cửa cho bạn. Tuy nhiên, họ lại để mật khẩu mặc định của camera là `admin123`, chỉ khóa cửa chính mà quên khóa cửa sổ, và dùng loại chìa khóa dễ dàng sao chép. Những sơ hở này chính là biểu hiện của **thiết lập cấu hình bảo mật lỏng lẻo** (Lax Security Settings). Kẻ trộm chẳng cần dùng đến các công cụ bẻ khóa tinh vi, chúng chỉ cần thử mật khẩu mặc định hoặc trèo qua cửa sổ đang mở để đột nhập vào nhà bạn.

Trong môi trường web, một trong những sơ hở cấu hình phổ biến nhất nằm ở cách ứng dụng quản lý **cookie** (mẩu thông tin lưu trên trình duyệt để giữ trạng thái đăng nhập, tương tự như chiếc thẻ ra vào tòa nhà). Để bảo vệ chiếc thẻ này khỏi bị kẻ xấu sao chép hoặc cướp mất, lập trình viên cần cấu hình 3 chiếc "chốt khóa" bảo mật:
- **HttpOnly**: Chốt này khóa không cho phép các đoạn mã JavaScript (như mã độc XSS) đọc được cookie qua thuộc tính `document.cookie`.
- **Secure**: Chốt này bắt buộc trình duyệt chỉ gửi cookie qua kết nối được mã hóa bằng HTTPS. Nếu bạn dùng Wi-Fi công cộng không có bảo mật, kẻ xấu cũng không thể nghe lén và bắt trộm cookie này.
- **SameSite**: Chốt này kiểm soát việc gửi cookie khi người dùng tương tác chéo giữa các trang web khác nhau, giúp ngăn chặn hiệu quả các cuộc tấn công giả mạo yêu cầu chéo trang (CSRF).

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

## Mô tả lỗ hổng
Lỗ hổng **Cấu hình bảo mật lỏng lẻo** (Lax Security Settings) xảy ra khi lập trình viên hoặc quản trị viên hệ thống giữ nguyên các thiết lập mặc định không an toàn, quên bật các cờ bảo mật quan trọng, hoặc mở các cổng mạng và dịch vụ không cần thiết.

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó mở toang những lối đi dễ dàng nhất cho kẻ tấn công. Chỉ bằng việc thiếu các cờ bảo mật như `HttpOnly` hay `Secure` trên cookie, kẻ tấn công có thể dễ dàng đánh cắp phiên làm việc của người dùng thông qua các cuộc tấn công XSS hoặc nghe lén mạng. Ngoài ra, việc để lộ thông tin phiên bản máy chủ, bật chức năng hiển thị danh sách thư mục (directory listing) hoặc không thiết lập các HTTP response headers bảo vệ (như CSP, X-Frame-Options) sẽ cung cấp cho kẻ tấn công toàn bộ sơ đồ cấu trúc của ứng dụng, giúp chúng dễ dàng lên kế hoạch và thực hiện các cuộc tấn công phá hoại tiếp theo.

## Cơ chế tấn công
Bước 1: Ứng dụng web thiết lập cookie phiên (session cookie) nhưng không gán các cờ bảo mật như `HttpOnly` và `Secure`.
Bước 2: Kẻ tấn công chèn được một đoạn mã script độc hại (thông qua lỗ hổng XSS khác) vào trang web mà nạn nhân đang truy cập.
Bước 3: Script độc hại chạy trên trình duyệt nạn nhân, đọc cookie thông qua thuộc tính `document.cookie` (do thiếu cờ `HttpOnly`) và gửi nó về máy chủ của kẻ tấn công.
Bước 4: Kẻ tấn công sử dụng cookie lấy được để mạo danh phiên làm việc của nạn nhân trên một trình duyệt khác.

## Biện pháp phòng thủ
- **Tóm tắt**: Prevent security configuration weaknesses by hardening configurations, changing defaults, and utilizing automated vulnerability assessments.
- **Các bước chi tiết**:
  - Change all factory default credentials, paths, and settings immediately during system installation.
  - Establish a continuous patching program to update servers, databases, and dependencies.
  - Disable unnecessary components, legacy protocols, unused modules, and open ports to reduce the attack surface.
  - Configure security response headers (CSP, X-Frame-Options, X-Content-Type-Options) across all web applications.
  - Perform regular automated vulnerability scans and configuration audits.

## Code Example
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


## Xem thêm
- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A05:2021, CWE-16

## Giải thích thuật ngữ
- **Cookie**: Mẩu dữ liệu nhỏ lưu trên trình duyệt của người dùng để máy chủ nhận diện trạng thái và duy trì phiên đăng nhập.
- **HttpOnly**: Cờ bảo mật của cookie ngăn chặn JavaScript truy cập vào cookie đó nhằm hạn chế rủi ro bị đánh cắp qua lỗ hổng XSS.
- **Secure Flag**: Cờ bảo mật yêu cầu cookie chỉ được truyền đi qua kết nối HTTPS bảo mật.
- **SameSite**: Cờ bảo mật kiểm soát việc gửi cookie trong các yêu cầu chéo trang để chống lại tấn công CSRF.
- **Directory Listing**: Tính năng của máy chủ web tự động hiển thị danh sách tất cả các tệp tin và thư mục bên trong một thư mục khi không có trang mặc định (như index.html).
- **Man-in-the-Middle (MitM - Tấn công nghe lén)**: Dạng tấn công mà kẻ xấu đứng ở giữa đường truyền mạng để đánh chặn và đọc trộm hoặc sửa đổi dữ liệu trao đổi giữa client và server.
- **XSS (Cross-Site Scripting)**: Lỗ hổng chèn mã độc JavaScript vào trang web để chạy trên trình duyệt của nạn nhân.
- **CSRF (Cross-Site Request Forgery)**: Tấn công giả mạo yêu cầu chéo trang, lừa trình duyệt của người dùng tự động thực thi các hành động ngoài ý muốn trên một trang web khác mà họ đã đăng nhập.
