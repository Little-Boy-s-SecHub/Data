# Cross-Site Request Forgery

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-352 | **Phân loại**: Software and Data Integrity Failures

## 🧱 Kiến thức Nền tảng
Tấn công giả mạo yêu cầu chéo trang (CSRF) lợi dụng cách thức hoạt động mặc định của trình duyệt đối với **Cross-origin request credentials (thông tin xác thực trong yêu cầu chéo nguồn gốc)**. Khi người dùng truy cập một trang web độc hại của bên thứ ba trong lúc vẫn đang duy trì phiên đăng nhập tại trang web mục tiêu (ví dụ: `bank.com`), trang web độc hại đó có thể kích hoạt ngầm các yêu cầu HTTP (qua thẻ `<img>`, `<iframe>` hoặc lệnh `fetch`) hướng tới trang mục tiêu. Theo cơ chế mặc định lịch sử của trình duyệt, các cookie phiên (session credentials) tương ứng với tên miền mục tiêu sẽ tự động được gửi đính kèm theo yêu cầu này, khiến máy chủ nhận diện sai lệch rằng đó là hành động hợp pháp do chính người dùng chủ động thực hiện.

Để phòng thủ chống CSRF hiệu quả, hai biện pháp cốt lõi được áp dụng song song. Thứ nhất là cấu hình thuộc tính **SameSite** cho session cookie. Khi đặt `SameSite=Lax` hoặc `SameSite=Strict`, trình duyệt sẽ chặn việc tự động gửi kèm cookie phiên trong các yêu cầu chéo trang (ngoại trừ một số điều hướng GET an toàn ở chế độ Lax).

Thứ hai là sử dụng **Anti-CSRF Token** (thường áp dụng mô hình Double Submit Cookie hoặc Synchronizer Token). Mỗi khi có yêu cầu thay đổi trạng thái hệ thống (như POST, PUT, DELETE), máy chủ yêu cầu một token ngẫu nhiên, bí mật được sinh riêng cho phiên đó. Token này phải được gửi kèm trong phần thân yêu cầu hoặc HTTP header. Vì trang web độc hại ở nguồn gốc khác bị giới hạn bởi Chính sách đồng nguồn gốc (Same-Origin Policy), chúng không thể đọc hoặc chèn token hợp lệ này vào yêu cầu, từ đó máy chủ sẽ dễ dàng phát hiện và từ chối các yêu cầu giả mạo chéo trang.

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const app = express();

app.use(express.json());
app.use(cookieParser("secure-random-cookie-secret"));

// Initialize doubleCsrf helper configuration
const {
    generateToken,
    doubleCsrfProtection
} = doubleCsrf({
    getSecret: () => "secure-random-cookie-secret",
    cookieName: "x-csrf-token",
    cookieOptions: {
        sameSite: "lax", // Protects cookies from being sent in cross-site requests
        path: "/",
        secure: true,    // Requires HTTPS execution environment
        httpOnly: true   // Protects against client-side script access
    },
});

// Route to fetch CSRF token for the frontend form
app.get('/api/csrf-token', (req, res) => {
    const token = generateToken(req, res);
    res.json({ csrfToken: token });
});

// Secure API endpoint protected by CSRF verification middleware
app.post('/api/transfer-funds', doubleCsrfProtection, (req, res) => {
    // Process secure database transaction after successful verification
    res.json({ message: "Transaction completed successfully" });
});
```

## 🔍 Mô tả lỗ hổng
CSRF xảy ra khi một trang web bên thứ ba độc hại lừa trình duyệt của người dùng thực hiện một yêu cầu trái phép đến một ứng dụng mà họ hiện đang được xác thực. Bởi vì các trình duyệt tự động gửi kèm cookie phiên làm việc với các yêu cầu chéo trang, máy chủ mục tiêu sẽ thực thi yêu cầu như thể nó được cho phép một cách rõ ràng bởi người dùng.

## ⚔️ Cơ chế tấn công
Kẻ tấn công nhận thấy rằng một ứng dụng cho phép tạo bài viết bằng các yêu cầu GET đơn giản. Hắn gửi cho nạn nhân một liên kết trỏ đến URL đăng bài viết với một payload tùy chỉnh. Khi nạn nhân nhấp vào liên kết trong khi đã đăng nhập, trình duyệt sẽ tự động truyền các cookie xác thực, tạo ra một bài đăng rác đóng vai trò như một sâu máy tính (worm).

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Sử dụng các token chống CSRF duy nhất và an toàn về mặt mật mã, áp dụng thuộc tính cookie SameSite, và giới hạn các hành động thay đổi trạng thái trong các phương thức POST/PUT/DELETE.
- **Các bước chi tiết**:
  - Triển khai các token chống CSRF duy nhất và an toàn về mặt mật mã cho tất cả các hoạt động thay đổi trạng thái.
  - Cấu hình cookie phiên làm việc với thuộc tính SameSite=Lax hoặc SameSite=Strict để ngăn chặn việc truyền tải chéo trang.
  - Đảm bảo tất cả các hành động thay đổi trạng thái yêu cầu các phương thức HTTP như POST, PUT, hoặc DELETE, thay vì GET.
  - Sử dụng các thư viện hiện đại, được duy trì (như csrf-csrf cho mẫu Double Submit Cookie) để quản lý và xác thực các token chống CSRF.

## 💻 Code Example
```javascript
// Express.js Double Submit Cookie CSRF protection using the maintained 'csrf-csrf' package
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("your-cookie-secret-key"));

// Initialize doubleCsrf helper functions
const {
  generateToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => "your-cookie-secret-key",
  cookieName: "x-csrf-token",
  cookieOptions: {
    sameSite: "lax",
    path: "/",
    secure: true,
  },
});

app.get('/transfer-form', (req, res) => {
  const csrfToken = generateToken(req, res);
  res.render('transfer', { csrfToken });
});

app.post('/transfer', doubleCsrfProtection, (req, res) => {
  res.send('Transfer processed successfully');
});
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lại phân loại của bài học từ 'Request Attacks' thành 'Software and Data Integrity Failures'. Đã thay thế thư viện 'csurf' lỗi thời và không an toàn bằng gói hoạt động tốt và an toàn 'csrf-csrf' (mẫu Double Submit Cookie).
- **Nguồn tham khảo**: OWASP A08:2021-Software and Data Integrity Failures, CWE-352 (Cross-Site Request Forgery)
