# Weak Session IDs

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-330 (Use of Insufficiently Random Values), CWE-331 (Insufficient Entropy) | **Phân loại**: Authentication

## 🧱 Kiến thức Nền tảng
ID phiên làm việc (Session ID) đóng vai trò là "chìa khóa" tạm thời để nhận diện người dùng sau khi đăng nhập thành công. Để ngăn chặn kẻ tấn công đoán hoặc brute-force ID phiên, việc tạo sinh ID phải dựa trên các thuật toán an toàn với độ hỗn loạn (**Entropy**) cao. Có sự khác biệt lớn giữa **PRNG (Pseudo-Random Number Generator - Trình sinh số giả ngẫu nhiên thông thường)** và **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator - Trình sinh số giả ngẫu nhiên an toàn về mặt mật mã)**.

PRNG (như `Math.random()` trong JavaScript hoặc `rand()` trong C) được thiết kế cho tốc độ nhanh, sử dụng các công thức toán học có tính chu kỳ xác định. Nếu kẻ tấn công thu thập được một vài ID phiên hoặc biết được thời gian khởi tạo (seed), họ có thể dự đoán chính xác trạng thái tiếp theo của bộ sinh số này. Ngược lại, CSPRNG được thiết kế chuyên biệt cho mật mã học, thu thập entropy từ các nguồn vật lý của hệ điều hành (như độ trễ ổ đĩa, nhiệt độ phần cứng, ngắt thiết bị). CSPRNG đảm bảo tính chất phi tính toán (non-predictability)—tức là không thể suy ra các số ngẫu nhiên tiếp theo ngay cả khi biết toàn bộ các số đã sinh ra trước đó.

Để đảm bảo an toàn tối thiểu, một Session ID cần có độ dài ít nhất là 128 bit (16 byte) entropy thực tế và được biểu diễn dưới dạng mã hóa không dự đoán được (như Hex hoặc Base64url). Điều này tạo ra một không gian khóa khổng lồ lên tới $2^{128}$ khả năng, khiến việc dò tìm ngẫu nhiên trở nên bất khả thi trong thực tế.

```javascript
const crypto = require('crypto');

function generateSecureSessionId(byteLength = 24) {
    // Generate cryptographically secure random bytes (CSPRNG)
    // 24 bytes of entropy provides 192 bits of security
    const randomBuffer = crypto.randomBytes(byteLength);
    
    // Encode buffer to a URL-safe Base64 string to be used as a Session ID
    const sessionId = randomBuffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
        
    return sessionId;
}

// Example usage
const secureSessionToken = generateSecureSessionId();
console.log(`Generated Secure Session ID: ${secureSessionToken}`);
```

## 🔍 Mô tả lỗ hổng
Lỗ hổng ID phiên yếu xảy ra khi các token nhận diện phiên làm việc của người dùng quá ngắn, được sinh tuần tự, hoặc sử dụng các thuật toán sinh số ngẫu nhiên có thể dự đoán được (PRNG yếu). Kẻ tấn công có thể dự đoán hoặc thực hiện brute-force các ID phiên đang hoạt động của người dùng khác để chiếm đoạt tài khoản mà không cần mật khẩu.

## ⚔️ Cơ chế tấn công
Kẻ tấn công truy cập trang web, xem giá trị cookie phiên được gán cho chính mình (ví dụ `session_id=142983010`) và nhận thấy nó ngắn và có tính quy luật. Kẻ tấn công viết một kịch bản tự động gửi các yêu cầu HTTP với giá trị cookie tăng dần hoặc thay đổi nhẹ (quét song song thông qua botnet). Khi trúng một ID phiên hợp lệ của một người dùng khác đang trực tuyến, máy chủ chấp nhận yêu cầu và cho phép kẻ tấn công đăng nhập trái phép vào tài khoản của nạn nhân.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Tạo các ID phiên mạnh bằng thuật toán CSPRNG có entropy cao, gán các thuộc tính bảo mật như HttpOnly, Secure, SameSite, và quản lý thời gian hết hạn chặt chẽ trên máy chủ.
- **Các bước chi tiết**:
  - Tạo mã định danh phiên bằng cách sử dụng công cụ sinh số ngẫu nhiên giả ngẫu nhiên an toàn về mặt mật mã (CSPRNG).
  - Đảm bảo ID phiên có độ dài tối thiểu (ít nhất 128 bit / 16 byte entropy) để chống lại các cuộc tấn công brute-force.
  - Đặt cờ `HttpOnly` trên cookie phiên để ngăn chặn các tập lệnh phía client (JavaScript) truy cập nhằm giảm thiểu rủi ro bị đánh cắp qua XSS.
  - Đặt cờ `Secure` để bắt buộc cookie chỉ được truyền tải qua các kết nối được mã hóa TLS/HTTPS.
  - Thiết lập thuộc tính `SameSite` (như Lax hoặc Strict) để ngăn chặn các cuộc tấn công CSRF.
  - Quản lý việc hết hạn phiên (bao gồm hết hạn khi không hoạt động và hết hạn tuyệt đối) và hủy trạng thái phiên trên server khi người dùng đăng xuất.

## 💻 Code Example
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

let redisClient = createClient({ url: 'redis://localhost:6379' });
redisClient.connect().catch(console.error);

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET, // Strong secret key
    name: '__Host-SessionId',          // Use secure prefix
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,                 // Block access from JS (mitigate XSS session theft)
        secure: true,                   // Force HTTPS
        sameSite: 'lax',                // Protect against CSRF
        maxAge: 30 * 60 * 1000          // Idle timeout: 30 minutes
    }
}));
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Khắc phục lỗi cú pháp trong kịch bản thăm dò Python tại Slide 5 bằng cách đổi toán tử so sánh `===` (cú pháp JS) thành toán tử `==` chuẩn của Python, bổ sung import thư viện `urllib2` bị thiếu và định nghĩa biến `url`.
- **Nguồn tham khảo**: OWASP A07:2021, CWE-330, CWE-331
