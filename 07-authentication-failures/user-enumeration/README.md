# User Enumeration

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-204 (Response Contains Information Concerning Username Validity), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) | **Phân loại**: Authentication

## 🧱 Kiến thức Nền tảng
Lỗ hổng dò tìm tài khoản (User Enumeration) xảy ra khi ứng dụng vô tình tiết lộ sự hiện diện của một tài khoản thông qua các manh mối khác biệt trong phản hồi. Một trong những vectơ khai thác tinh vi nhất là **Timing differences in execution (sự khác biệt về thời gian thực thi)**. Khi người dùng cố gắng đăng nhập, máy chủ cần xác thực mật khẩu. Nếu tài khoản tồn tại, máy chủ sẽ chạy hàm so khớp mật mã chậm (như `bcrypt.compare`), tốn khoảng vài trăm mili-giây. Ngược lại, nếu tài khoản không tồn tại, máy chủ thường lập tức trả về lỗi "Không tìm thấy tài khoản" mà không thực hiện phép toán băm nào. Kẻ tấn công có thể đo độ trễ phản hồi của hàng loạt yêu cầu để suy ra email nào đã được đăng ký.

Để khắc phục rủi ro Timing Attack này, nhà phát triển cần triển khai kỹ thuật **Dummy Hash**. Khi truy vấn cơ sở dữ liệu không tìm thấy người dùng, thay vì trả về lỗi ngay, ứng dụng sẽ thực thi một phép so sánh giả định bằng cách so khớp mật khẩu người dùng nhập vào với một chuỗi hash giả có độ phức tạp tương đương hash thật. Việc này đảm bảo luồng tính toán phía máy chủ luôn tiêu thụ một lượng tài nguyên và thời gian đồng đều bất kể tài khoản có tồn tại hay không.

Ngoài ra, ứng dụng cần kết hợp thông điệp phản hồi chung (ví dụ: "Email hoặc mật khẩu không đúng") và áp dụng cơ chế **Rate Limiting (giới hạn tần suất)** nghiêm ngặt trên các endpoint xác thực nhằm ngăn chặn kẻ tấn công tự động gửi hàng ngàn yêu cầu liên tiếp để thăm dò dữ liệu hệ thống.

```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// A generic dummy hash conforming to bcrypt's standard format
const DUMMY_HASH = "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');
    
    // Always use a generic message to prevent authentication disclosure
    const genericMessage = "Invalid email or password.";
    
    try {
        const user = await db.findUserByEmail(email);
        
        // Determine whether a valid hash exists for the fetched user
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;
        
        // If user doesn't exist, use the DUMMY_HASH to prevent timing differences
        const passwordHash = hasValidHash ? user.passwordHash : DUMMY_HASH;
        
        // Always execute the hashing function (bcrypt.compare) to ensure equal timing
        const isMatch = await bcrypt.compare(passwordStr, passwordHash);
        
        if (!user || !hasValidHash || !isMatch) {
            return res.status(401).json({ success: false, message: genericMessage });
        }
        
        // Handle successful login and issue token
        const token = generateToken(user);
        return res.json({ success: true, token });
    } catch (error) {
        return res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 🔍 Mô tả lỗ hổng
Lỗ hổng dò tìm tài khoản (User Enumeration) xuất hiện khi ứng dụng phản hồi các thông điệp khác biệt hoặc phản hồi với độ trễ thời gian khác nhau tùy thuộc vào việc tài khoản đầu vào có tồn tại trong hệ thống hay không. Kẻ tấn công có thể lợi dụng điều này để lập danh sách các tài khoản người dùng hợp lệ, hỗ trợ đắc lực cho các cuộc tấn công brute-force mật khẩu hoặc lừa đảo đích danh (phishing).

## ⚔️ Cơ chế tấn công
Kẻ tấn công gửi danh sách email đăng nhập tới trang đăng nhập, đăng ký hoặc khôi phục mật khẩu của ứng dụng. Nếu trang đăng nhập báo "Tài khoản không tồn tại" thay vì một thông báo chung "Thông tin đăng nhập không hợp lệ", kẻ tấn công sẽ biết ngay email đó có đăng ký hay chưa. Tương tự, nếu máy chủ băm mật khẩu bằng thuật toán chậm (như bcrypt) khi tìm thấy tài khoản nhưng lại bỏ qua băm khi tài khoản không tồn tại, kẻ tấn công có thể đo thời gian phản hồi (Timing Attack) để xác định sự hiện diện của người dùng.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Chống dò tìm tài khoản bằng cách sử dụng thông điệp phản hồi đồng nhất, đồng bộ hóa thời gian xử lý bằng dummy hash cho tài khoản không tồn tại, và triển khai giới hạn tần suất (rate limiting).
- **Các bước chi tiết**:
  - Trả về thông báo lỗi chung, giống hệt nhau (ví dụ: 'Email hoặc mật khẩu không hợp lệ' hoặc 'Nếu email tồn tại, link khôi phục đã được gửi') cho cả tài khoản tồn tại và không tồn tại.
  - Đảm bảo mọi luồng xử lý trên máy chủ có độ trễ thời gian tương đương nhau bằng cách sử dụng dummy hash có độ phức tạp (work factor) bằng với hash thật khi tài khoản không tồn tại.
  - Triển khai cơ chế rate limiting trên tất cả các endpoint liên quan đến xác thực để ngăn cản việc rà quét tự động hàng loạt.
  - Tránh trả về các mã trạng thái HTTP khác nhau (như 200 OK vs 404 Not Found) hoặc giao diện hiển thị khác nhau dựa trên sự tồn tại của người dùng.

## 💻 Code Example
```javascript
const bcrypt = require('bcrypt');

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');
    
    // Use a generic message for all authentication failures
    const genericMessage = "Invalid email or password.";

    try {
        const user = await db.findUserByEmail(email);
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;
        const passwordHash = hasValidHash ? user.passwordHash : "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";
        
        const match = await bcrypt.compare(passwordStr, passwordHash);
        
        if (!user || !hasValidHash || !match) {
            return res.status(401).json({ success: false, message: genericMessage });
        }

        // Successful authentication logic
        res.json({ success: true, token: generateToken(user) });
    } catch (error) {
        res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Mã nguồn JS đã được sửa đổi toàn diện: loại bỏ chú thích dạng `#` của Python, định dạng lại dummy hash đạt chuẩn 60 ký tự để không ném ra lỗi 500 khi chạy `bcrypt.compare`, lấy tham số từ `req.body` thay vì `req.params`. Bổ sung ép kiểu dữ liệu chuỗi `String(password || '')` và xử lý an toàn cho tài khoản OAuth (tồn tại trong DB nhưng có passwordHash trống hoặc không hợp lệ) để tránh lỗi lệch thời gian phản hồi (Timing Attack).
- **Nguồn tham khảo**: OWASP Authentication Cheat Sheet, CWE-204, CWE-200, PortSwigger
