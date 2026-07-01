# Cross-Site Script Inclusion

> **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

Để giữ an toàn cho bạn khi lướt web, trình duyệt sử dụng một lá chắn bảo mật vô cùng quan trọng gọi là Chính sách đồng nguồn gốc (SOP). Lá chắn này ngăn không cho trang web này tự tiện đọc dữ liệu của trang web khác. Tuy nhiên, để các nhà phát triển có thể sử dụng các thư viện tiện ích (như jQuery) từ các nguồn bên ngoài, trình duyệt có một ngoại lệ: nó cho phép thẻ `<script>` được tải và thực thi các tệp JavaScript từ bất kỳ địa chỉ nào mà không bị lá chắn SOP ngăn chặn.

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

## Mô tả lỗ hổng

Lỗ hổng Cross-Site Script Inclusion (XSSI) xuất hiện khi lập trình viên vô tình đặt các dữ liệu nhạy cảm của người dùng (như email, số dư tài khoản hoặc mã token) bên trong các file JavaScript được sinh ra động dựa trên phiên đăng nhập. Kẻ tấn công có thể tạo ra một trang web độc hại và nhúng trực tiếp file JavaScript động này bằng thẻ `<script>`. Khi nạn nhân truy cập trang web độc hại trong lúc vẫn đang đăng nhập ở trang web chính thức, trình duyệt sẽ tự động gửi kèm cookie xác thực để tải file JavaScript chứa thông tin mật về. Trang web của kẻ tấn công nhờ đó có thể dễ dàng đọc sạch thông tin nhạy cảm của nạn nhân thông qua các biến toàn cục. Sự nguy hiểm của XSSI là nó âm thầm vượt qua lá chắn SOP nhờ lợi dụng chính kẽ hở thiết kế của thẻ `<script>`.

## Cơ chế tấn công

Kẻ tấn công tạo một trang web độc hại và thêm thẻ `<script src="https://victim-site.com/js/user-profile.js"></script>`. Khi nạn nhân (đã đăng nhập vào `victim-site.com`) truy cập trang của kẻ tấn công, trình duyệt tự động gửi kèm cookie phiên của nạn nhân và tải file JS động đó về. Do thẻ `<script>` không bị chặn bởi SOP, file JS được thực thi trong ngữ cảnh của trang web kẻ tấn công, cho phép kẻ tấn công đọc toàn bộ biến chứa API key hoặc thông tin nhạy cảm được nhúng trong đó.

## Biện pháp phòng thủ

- **Tóm tắt**: Phòng chống XSSI bằng cách tách biệt dữ liệu nhạy cảm ra khỏi file JavaScript, sử dụng JSON thay cho JS động, thêm tiền tố không thực thi được vào JSON, và sử dụng header nosniff.
- **Các bước chi tiết**:
  - Tuyệt đối không nhúng các thông tin nhạy cảm, dữ liệu cá nhân của người dùng dưới dạng biến số trong các file kịch bản JavaScript tĩnh hoặc động.
  - Sử dụng định dạng dữ liệu JSON để truyền tải thông tin, và xác thực các yêu cầu API bằng token chống CSRF hoặc header Authorization thay vì chỉ dựa vào session cookie.
  - Ngăn chặn việc hijack JSON bằng cách chèn thêm các tiền tố không thể thực thi (như `)]}',\n`) vào đầu nội dung phản hồi JSON để ngăn trình duyệt biên dịch nó thành JS.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để bắt buộc trình duyệt không thực thi các tệp định dạng phi kịch bản (như JSON, CSV) dưới dạng script.
  - Cấu hình chính sách CORS để giới hạn các nguồn truy cập hợp lệ tới các endpoint nhạy cảm.

## Code Example

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

## Xem thêm

- [Reflected XSS](../reflected/) — Lỗ hổng phản xạ tập lệnh.

## Nguồn tham khảo

- OWASP XSSI, CWE-200

## Giải thích thuật ngữ

- **XSSI (Cross-Site Script Inclusion)**: Lỗ hổng cho phép trang web độc hại đọc dữ liệu nhạy cảm được nhúng trong file JavaScript động của trang web khác.
- **SOP (Same-Origin Policy)**: Cơ chế bảo mật chặn quyền truy cập chéo tài nguyên giữa các nguồn khác nhau.
- **Dynamic JavaScript**: File JavaScript được tạo ra động theo ngữ cảnh cụ thể của từng phiên người dùng.
- **MIME Sniffing**: Tính năng tự nhận diện định dạng file thực tế của trình duyệt bất chấp khai báo trên header.
- **Nosniff**: Giá trị cấu hình của tiêu đề X-Content-Type-Options ngăn cản MIME sniffing của trình duyệt.
