# Cross-Site Script Inclusion

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) | **Phân loại**: Information Exposure

## 🧱 Kiến thức Nền tảng
Chính sách đồng nguồn gốc (Same-Origin Policy - SOP) là nguyên tắc bảo mật nền tảng của trình duyệt nhằm ngăn chặn mã kịch bản từ một nguồn gốc (origin) này truy cập trái phép vào tài liệu hoặc cookie của một nguồn gốc khác. Tuy nhiên, để cho phép các trang web sử dụng thư viện JavaScript từ bên ngoài (như CDN, jQuery), trình duyệt áp dụng một ngoại lệ đặc biệt: cơ chế SOP không áp dụng cho nguồn kịch bản của thẻ `<script>`. Điều này có nghĩa là thẻ `<script>` được phép nhúng và thực thi tài nguyên kịch bản từ bất kỳ nguồn gốc chéo nào (cross-origin script inclusion).

Lỗ hổng Cross-Site Script Inclusion (XSSI) khai thác trực tiếp ngoại lệ này. Nếu một ứng dụng đặt các thông tin nhạy cảm của người dùng (như thông tin cá nhân hoặc API tokens) trong một tệp JavaScript động được sinh ra dựa trên phiên đăng nhập của người dùng. Một trang web độc hại có thể nhúng tệp JavaScript động này bằng thẻ `<script src="https://target.com/api/profile.js">`. Khi nạn nhân truy cập trang web độc hại, trình duyệt tự động gửi cookie phiên làm việc hợp lệ kèm theo yêu cầu, máy chủ target.com phản hồi tệp JS chứa dữ liệu nhạy cảm, và trang độc hại có thể đọc các thông tin này thông qua các biến toàn cục.

Để ngăn chặn XSSI, dữ liệu nhạy cảm không được đặt trong file JS mà phải chuyển sang định dạng JSON thuần túy, kèm theo tiêu đề `X-Content-Type-Options: nosniff` và tiền tố chống thực thi `)]}',\n` nhằm ngăn chặn trình duyệt chạy nhầm JSON như một tệp script.

### Code ví dụ hoạt động bình thường (Secure JSON Response with Anti-XSSI)
```javascript
const express = require('express');
const app = express();

// Secure middleware setting HTTP headers to prevent MIME-sniffing
app.use((req, res, next) => {
    // Force browser to respect the declared Content-Type (prevents executing non-JS as JS)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// Secure API endpoint returning user profile details
app.get('/api/user-profile', (req, res) => {
    const userProfile = {
        username: "johndoe",
        email: "johndoe@example.com",
        role: "user"
    };

    // Return content type as application/json rather than application/javascript
    res.setHeader('Content-Type', 'application/json');

    // Prepend a non-executable prefix to protect against JSON hijacking and XSSI
    // If loaded inside a <script> tag cross-site, this prefix triggers a syntax error
    const antiXssiPrefix = ")]}',\n";
    res.send(antiXssiPrefix + JSON.stringify(userProfile));
});
```

## 🔍 Mô tả lỗ hổng
Cross-Site Script Inclusion (XSSI) khai thác việc trình duyệt miễn trừ các thẻ `<script>` khỏi các quy định của Chính sách đồng nguồn gốc (Same-Origin Policy - SOP). Khi ứng dụng đưa các thông tin nhạy cảm của người dùng (như API key, dữ liệu hồ sơ) vào các file JavaScript động, một trang web độc hại của bên thứ ba có thể nhúng tệp kịch bản này để đọc các thông tin nhạy cảm của nạn nhân khi họ đang đăng nhập.

## ⚔️ Cơ chế tấn công
Kẻ tấn công tạo một trang web độc hại và thêm thẻ `<script src="https://victim-site.com/js/user-profile.js"></script>`. Khi nạn nhân (đã đăng nhập vào `victim-site.com`) truy cập trang của kẻ tấn công, trình duyệt tự động gửi kèm cookie phiên của nạn nhân và tải file JS động đó về. Do thẻ `<script>` không bị chặn bởi SOP, file JS được thực thi trong ngữ cảnh của trang web kẻ tấn công, cho phép kẻ tấn công đọc toàn bộ biến chứa API key hoặc thông tin nhạy cảm được nhúng trong đó.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống XSSI bằng cách tách biệt dữ liệu nhạy cảm ra khỏi file JavaScript, sử dụng JSON thay cho JS động, thêm tiền tố không thực thi được vào JSON, và sử dụng header nosniff.
- **Các bước chi tiết**:
  - Tuyệt đối không nhúng các thông tin nhạy cảm, dữ liệu cá nhân của người dùng dưới dạng biến số trong các file kịch bản JavaScript tĩnh hoặc động.
  - Sử dụng định dạng dữ liệu JSON để truyền tải thông tin, và xác thực các yêu cầu API bằng token chống CSRF hoặc header Authorization thay vì chỉ dựa vào session cookie.
  - Ngăn chặn việc hijack JSON bằng cách chèn thêm các tiền tố không thể thực thi (như `)]}',\n`) vào đầu nội dung phản hồi JSON để ngăn trình duyệt biên dịch nó thành JS.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để bắt buộc trình duyệt không thực thi các tệp định dạng phi kịch bản (như JSON, CSV) dưới dạng script.
  - Cấu hình chính sách CORS để giới hạn các nguồn truy cập hợp lệ tới các endpoint nhạy cảm.

## 💻 Code Example
```javascript
// Express middleware to set secure headers
app.use((req, res, next) => {
    // Prevent browsers from mime-sniffing response as script
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// Endpoint returning sensitive data with anti-XSSI JSON prefix
app.get('/api/user-profile', (req, res) => {
    const profile = { name: "John Doe", email: "john@example.com" };
    
    // Return non-executable JSON prefix to prevent JSON hijacking / XSSI
    res.type('application/json');
    res.send(")]}',\n" + JSON.stringify(profile));
});
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa đổi cách giải thích bị sai lệch về cơ chế Same-Origin Policy (SOP) trong tài liệu cũ (tuyên bố sai rằng SOP cho phép fetch cross-origin). Bản sửa đổi khẳng định SOP ngăn cản `fetch` cross-origin nhưng thẻ `<script>` thì được miễn trừ. Khắc phục lỗi chính tả tên miền `facebooke.com` và lỗi cú pháp Python trong Slide 5 (`def javascript:` sửa thành `def javascript():`).
- **Nguồn tham khảo**: OWASP XSSI, CWE-200
