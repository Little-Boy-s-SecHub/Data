# User Enumeration

> **CWE**: CWE-204 (Response Contains Information Concerning Username Validity), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) | **Phân loại**: Authentication

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đến gõ cửa một văn phòng để tìm một người tên là "Nam". 
- Nếu người bảo vệ kiểm tra danh sách và lập tức trả lời: "Ở đây không có ai tên Nam cả", bạn biết ngay người này không làm việc tại đây.
- Nhưng nếu có người tên Nam, người bảo vệ phải đi vào phòng trong, gọi Nam ra, xác nhận thông tin, mất khoảng 5 phút. 

Tin tặc có thể khai thác sự khác biệt này thông qua một cuộc tấn công đo thời gian phản hồi (**Timing Attack**). Khi đăng nhập, nếu tài khoản tồn tại, máy chủ sẽ thực hiện một thuật toán băm mật khẩu rất phức tạp và chậm (như `bcrypt.compare`) để đối chiếu mật khẩu, mất khoảng vài trăm mili-giây. Nhưng nếu tài khoản không tồn tại, máy chủ lập tức báo lỗi ngay ở bước tìm kiếm mà không băm gì cả. Bằng cách đo thời gian phản hồi siêu nhỏ này, tin tặc sẽ biết chính xác email nào đã đăng ký trên hệ thống của bạn.

Để ngăn chặn, lập trình viên sử dụng kỹ thuật băm giả lập (**Dummy Hash**). Nếu không tìm thấy người dùng trong cơ sở dữ liệu, máy chủ sẽ không báo lỗi ngay mà tự động lôi một chuỗi mật mã giả ra để băm thử với mật khẩu người dùng nhập vào. Việc này làm máy chủ tiêu tốn khoảng thời gian giống hệt như khi đối chiếu với tài khoản thật. Kết quả là dù tài khoản có tồn tại hay không, thời gian trả về phản hồi đều như nhau, đồng thời máy chủ hiển thị một thông điệp chung chung giống hệt nhau (như "Email hoặc mật khẩu không đúng").

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

## Mô tả lỗ hổng
Lỗ hổng Dò tìm tài khoản (User Enumeration) xảy ra khi ứng dụng vô tình để lộ việc một tên đăng nhập hoặc email có tồn tại trên hệ thống hay không thông qua các thông báo lỗi khác nhau hoặc qua độ trễ thời gian phản hồi của máy chủ.

Mối nguy hiểm của lỗ hổng này nằm ở chỗ nó giúp kẻ tấn công dễ dàng quét và lập ra một danh sách chứa toàn bộ các tài khoản có thực của khách hàng. Đây là bước đệm lý tưởng để chúng thực hiện các cuộc tấn công tiếp theo như dò mật khẩu hàng loạt (Brute-Force), tấn công lừa đảo đích danh (Phishing), hoặc tống tiền bằng cách đe dọa công bố danh tính người dùng của một dịch vụ nhạy cảm nào đó.

## Cơ chế tấn công
Kẻ tấn công gửi danh sách email đăng nhập tới trang đăng nhập, đăng ký hoặc khôi phục mật khẩu của ứng dụng. Nếu trang đăng nhập báo "Tài khoản không tồn tại" thay vì một thông báo chung "Thông tin đăng nhập không hợp lệ", kẻ tấn công sẽ biết ngay email đó có đăng ký hay chưa. Tương tự, nếu máy chủ băm mật khẩu bằng thuật toán chậm (như bcrypt) khi tìm thấy tài khoản nhưng lại bỏ qua băm khi tài khoản không tồn tại, kẻ tấn công có thể đo thời gian phản hồi (Timing Attack) để xác định sự hiện diện của người dùng.

## Biện pháp phòng thủ
- **Tóm tắt**: Chống dò tìm tài khoản bằng cách sử dụng thông điệp phản hồi đồng nhất, đồng bộ hóa thời gian xử lý bằng dummy hash cho tài khoản không tồn tại, và triển khai giới hạn tần suất (rate limiting).
- **Các bước chi tiết**:
  - Trả về thông báo lỗi chung, giống hệt nhau (ví dụ: 'Email hoặc mật khẩu không hợp lệ' hoặc 'Nếu email tồn tại, link khôi phục đã được gửi') cho cả tài khoản tồn tại và không tồn tại.
  - Đảm bảo mọi luồng xử lý trên máy chủ có độ trễ thời gian tương đương nhau bằng cách sử dụng dummy hash có độ phức tạp (work factor) bằng với hash thật khi tài khoản không tồn tại.
  - Triển khai cơ chế rate limiting trên tất cả các endpoint liên quan đến xác thực để ngăn cản việc rà quét tự động hàng loạt.
  - Tránh trả về các mã trạng thái HTTP khác nhau (như 200 OK vs 404 Not Found) hoặc giao diện hiển thị khác nhau dựa trên sự tồn tại của người dùng.

## Code Example
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

## Xem thêm
- [2FA/MFA Bypass](../2fa-mfa-bypass/README.md)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP Authentication Cheat Sheet, CWE-204, CWE-200, PortSwigger

## Giải thích thuật ngữ
- **User Enumeration (Dò tìm tài khoản)**: Lỗ hổng cho phép kẻ tấn công xác định xem một tài khoản người dùng hoặc email cụ thể có tồn tại trên hệ thống hay không bằng cách phân tích sự khác biệt trong phản hồi của ứng dụng.
- **Timing Attack (Tấn công đo thời gian)**: Phương pháp tấn công gián tiếp bằng cách đo lượng thời gian máy chủ cần để xử lý các yêu cầu khác nhau, từ đó suy đoán ra cấu trúc logic hoặc sự hiện diện của dữ liệu bên trong.
- **Dummy Hash (Băm giả định)**: Kỹ thuật chạy thuật toán băm với một khóa giả khi tài khoản không tồn tại, nhằm làm giả thời gian xử lý của máy chủ sao cho tương đương với trường hợp tài khoản có thật.
- **Rate Limiting (Giới hạn tần suất)**: Biện pháp kiểm soát số lượng yêu cầu mà một địa chỉ IP hoặc người dùng được phép thực hiện trong một đơn vị thời gian để ngăn chặn việc dò quét tự động.
- **Authentication Disclosure (Lộ lọt thông tin xác thực)**: Tình trạng ứng dụng cung cấp quá nhiều chi tiết về quá trình đăng nhập (như "mật khẩu sai" hoặc "tài khoản không tồn tại"), gián tiếp giúp tin tặc thu hẹp phạm vi tấn công.
