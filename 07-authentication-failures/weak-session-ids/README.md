# Weak Session IDs

> **CWE**: CWE-330 (Use of Insufficiently Random Values), CWE-331 (Insufficient Entropy) | **Phân loại**: Session Management

## Kiến thức Nền tảng
Hãy tưởng tượng khi bạn gửi tiền ở ngân hàng, nhân viên phát cho bạn một chiếc vé giữ đồ có ghi số thứ tự: `001`. Bạn nhìn xung quanh và thấy người trước đó cầm vé số `000`, còn người sau cầm vé số `002`. Bạn lập tức nhận ra quy luật và chỉ cần tự vẽ một chiếc vé có số `000` hoặc `002` là có thể đến quầy lấy đồ của người khác. Sơ hở này tương tự như việc hệ thống sử dụng **mã định danh phiên yếu (Weak Session ID)**.

Để chiếc vé giữ đồ (Session ID) an toàn, nó phải là một chuỗi ký tự dài, ngẫu nhiên và hoàn toàn không thể đoán trước. Độ phức tạp ngẫu nhiên này được gọi là **Entropy**. Để tạo ra độ ngẫu nhiên này, máy tính sử dụng hai loại bộ sinh số ngẫu nhiên:
- **PRNG (Bộ sinh số giả ngẫu nhiên thông thường)**: Hoạt động dựa trên các công thức toán học nhanh chóng nhưng có quy luật tuần hoàn. Nếu kẻ xấu thu thập đủ số lượng vé được phát hoặc biết được thời điểm hệ thống bắt đầu chạy (seed), chúng có thể tính toán chính xác số vé tiếp theo được phát ra là gì.
- **CSPRNG (Bộ sinh số giả ngẫu nhiên an toàn mật mã)**: Trái lại, CSPRNG thu thập sự hỗn loạn từ thế giới vật lý của hệ điều hành (như tiếng ồn phần cứng, nhiệt độ CPU, thời gian phản hồi của ổ cứng). Các số ngẫu nhiên tạo ra từ đây không thể bị tính toán ngược hoặc đoán trước, ngay cả khi tin tặc biết tất cả các số đã tạo trước đó.

Để đảm bảo an toàn, một mã Session ID tiêu chuẩn cần có độ dài tối thiểu 128 bit (16 byte) entropy thực tế và được mã hóa dưới dạng chuỗi Base64 hoặc Hex. Điều này tạo ra một không gian khóa khổng lồ lên tới $2^{128}$ khả năng, khiến việc dò tìm ngẫu nhiên trở nên bất khả thi dù có sử dụng các siêu máy tính mạnh nhất.

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

## Mô tả lỗ hổng
Lỗ hổng Mã định danh phiên yếu (Weak Session IDs) xảy ra khi máy chủ tạo ra các mã Session ID quá ngắn, chạy theo số thứ tự tăng dần, hoặc sử dụng các thuật toán sinh số giả ngẫu nhiên thông thường (PRNG) dễ đoán. 

Mối nguy hiểm của lỗ hổng này rất lớn: kẻ tấn công chỉ cần đăng ký một tài khoản, phân tích quy luật tạo mã Session ID của hệ thống, rồi dùng script để tự động tạo ra và thử hàng loạt mã ID của những người dùng khác. Nếu thành công, chúng có thể cướp quyền điều khiển phiên làm việc (Session Hijacking) của nạn nhân và truy cập vào tài khoản của họ mà không cần mật khẩu hay đi qua lớp xác thực 2FA.

## Cơ chế tấn công
Kẻ tấn công truy cập trang web, xem giá trị cookie phiên được gán cho chính mình (ví dụ `session_id=142983010`) và nhận thấy nó ngắn và có tính quy luật. Kẻ tấn công viết một kịch bản tự động gửi các yêu cầu HTTP với giá trị cookie tăng dần hoặc thay đổi nhẹ (quét song song thông qua botnet). Khi trúng một ID phiên hợp lệ của một người dùng khác đang trực tuyến, máy chủ chấp nhận yêu cầu và cho phép kẻ tấn công đăng nhập trái phép vào tài khoản của nạn nhân.

### Ví dụ Python bruteforce session ID tuần tự:
```python
import requests

# Session ID của attacker là 142983010
# Attacker nhận ra: số tăng tuần tự → đoán session của nạn nhân
known_session = 142983010

for i in range(1000):  # thử 1000 session ID gần đó
    target_session = known_session + i

    response = requests.get(
        "https://vulnerable-app.com/dashboard",
        cookies={"session_id": str(target_session)}
    )

    if "Welcome" in response.text:  # tìm thấy session hợp lệ
        print(f"Chiếm được session: {target_session}")
        break

# Vì session_id được tạo bằng timestamp hoặc counter
# → Dễ đoán, dễ bruteforce trong vài giây
```

## Biện pháp phòng thủ
- **Tóm tắt**: Tạo các ID phiên mạnh bằng thuật toán CSPRNG có entropy cao, gán các thuộc tính bảo mật như HttpOnly, Secure, SameSite, và quản lý thời gian hết hạn chặt chẽ trên máy chủ.
- **Các bước chi tiết**:
  - Tạo mã định danh phiên bằng cách sử dụng công cụ sinh số ngẫu nhiên giả ngẫu nhiên an toàn về mặt mật mã (CSPRNG).
  - Đảm bảo ID phiên có độ dài tối thiểu (ít nhất 128 bit / 16 byte entropy) để chống lại các cuộc tấn công brute-force.
  - Đặt cờ `HttpOnly` trên cookie phiên để ngăn chặn các tập lệnh phía client (JavaScript) truy cập nhằm giảm thiểu rủi ro bị đánh cắp qua XSS.
  - Đặt cờ `Secure` để bắt buộc cookie chỉ được truyền tải qua các kết nối được mã hóa TLS/HTTPS.
  - Thiết lập thuộc tính `SameSite` (như Lax hoặc Strict) để ngăn chặn các cuộc tấn công CSRF.
  - Quản lý việc hết hạn phiên (bao gồm hết hạn khi không hoạt động và hết hạn tuyệt đối) và hủy trạng thái phiên trên server khi người dùng đăng xuất.

## Code Example
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

## Xem thêm
- [JWT Attacks](../jwt-attacks/README.md)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A07:2021, CWE-330, CWE-331

## Giải thích thuật ngữ
- **Session ID (Mã phiên)**: Chuỗi ký tự duy nhất đóng vai trò làm chìa khóa nhận diện người dùng trên hệ thống sau khi họ đã đăng nhập thành công.
- **Entropy (Độ hỗn loạn)**: Đại lượng đo lường độ phức tạp và tính ngẫu nhiên của dữ liệu. Entropy càng cao thì chuỗi dữ liệu càng khó bị đoán trước hoặc bẻ khóa.
- **PRNG (Pseudo-Random Number Generator)**: Bộ sinh số giả ngẫu nhiên, sử dụng công thức toán học để tạo ra chuỗi số trông có vẻ ngẫu nhiên nhưng thực tế có tính xác định và có chu kỳ.
- **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)**: Bộ sinh số ngẫu nhiên an toàn về mặt mật mã, sử dụng các nguồn nhiễu loạn vật lý để đảm bảo các số tạo ra hoàn toàn không thể dự đoán trước.
- **Base64url**: Biến thể của mã hóa Base64 giúp chuyển đổi dữ liệu nhị phân thành chuỗi văn bản an toàn khi truyền qua các tham số URL hoặc Cookie mà không bị lỗi ký tự đặc biệt.
