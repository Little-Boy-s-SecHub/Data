# Cross-Site Request Forgery

> **CWE**: CWE-352 | **Phân loại**: Session Management

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang đăng nhập vào tài khoản ngân hàng của mình trên trình duyệt để chuyển tiền. Sau khi giao dịch xong, bạn không đăng xuất mà mở một tab mới để đọc tin tức giải trí. Vô tình, bạn bấm vào một bài báo giật gân dẫn đến một trang web lạ độc hại. 

Trang web độc hại này lập tức chạy một đoạn code ngầm để gửi một yêu cầu chuyển tiền từ tài khoản của bạn đến tài khoản của kẻ xấu. Vì bạn vẫn chưa đăng xuất khỏi trang ngân hàng, trình duyệt của bạn theo thói quen mặc định sẽ tự động đính kèm "chìa khóa phiên" (session cookie) của bạn vào yêu cầu đó và gửi đi. Ngân hàng nhận được yêu cầu kèm chìa khóa hợp lệ của bạn, nên lập tức chuyển tiền mà không hề biết rằng yêu cầu đó được gửi từ tab độc hại bên cạnh. Đây chính là cuộc tấn công **Giả mạo yêu cầu chéo trang (CSRF)**.

Để ngăn chặn trò lừa gạt này, các hệ thống sử dụng hai lớp khiên bảo vệ:
1. **SameSite Cookie**: Giống như việc bạn dán một chiếc nhãn lên chìa khóa phiên, ra lệnh cho trình duyệt: "Chỉ được dùng chiếc chìa khóa này khi tôi trực tiếp đứng ở trang web ngân hàng (SameSite). Nếu có yêu cầu chuyển tiền từ một trang web lạ khác (Cross-Site), hãy giấu chiếc chìa khóa này đi!".
2. **Anti-CSRF Token**: Máy chủ sẽ phát cho bạn một mật mã bí mật, dùng một lần (token) mỗi khi bạn mở biểu mẫu chuyển tiền. Khi bạn nhấn gửi, máy chủ bắt buộc phải thấy mật mã này. Vì trang web độc hại ở tab khác bị trình duyệt chặn không cho đọc thông tin từ tab ngân hàng (Chính sách đồng nguồn gốc - **Same-Origin Policy**), nó không thể biết mật mã này là gì để gửi kèm, giúp ngân hàng dễ dàng phát hiện và chặn đứng yêu cầu giả mạo.

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

## Mô tả lỗ hổng
Lỗ hổng CSRF (Cross-Site Request Forgery) xảy ra khi ứng dụng web tin tưởng một cách tuyệt đối vào các yêu cầu do trình duyệt gửi lên chỉ dựa vào việc có đính kèm cookie xác thực hay không. 

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể lợi dụng phiên đăng nhập còn hiệu lực của nạn nhân để thực hiện các hành động phá hoại mà họ không hề hay biết, chẳng hạn như tự động đổi mật khẩu tài khoản, thay đổi email liên kết, hoặc thực hiện các giao dịch chuyển tiền trái phép chỉ bằng cách lừa nạn nhân truy cập vào một liên kết độc hại do chúng chuẩn bị sẵn.

## Cơ chế tấn công
Kẻ tấn công nhận thấy rằng một ứng dụng cho phép tạo bài viết bằng các yêu cầu GET đơn giản. Hắn gửi cho nạn nhân một liên kết trỏ đến URL đăng bài viết với một payload tùy chỉnh. Khi nạn nhân nhấp vào liên kết trong khi đã đăng nhập, trình duyệt sẽ tự động truyền các cookie xác thực, tạo ra một bài đăng rác đóng vai trò như một sâu máy tính (worm).

### JSON CSRF via Content-Type
Nhiều framework bảo vệ CSRF bằng cách kiểm tra Content-Type. Tuy nhiên nếu endpoint chấp nhận cả `text/plain` và parse nội dung như JSON:

```html
<!-- Malicious page: sends JSON data via form with text/plain enctype -->
<form action="https://target.com/api/update-email" method="POST"
      enctype="text/plain">
  <!-- text/plain enctype bypasses CORS preflight check -->
  <input name='{"email":"attacker@evil.com", "_dummy":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```
Phòng thủ: Kiểm tra `Content-Type: application/json` chính xác, sử dụng `SameSite=Strict` cookie.

## Biện pháp phòng thủ
- **Tóm tắt**: Sử dụng các token chống CSRF duy nhất và an toàn về mặt mật mã, áp dụng thuộc tính cookie SameSite, và giới hạn các hành động thay đổi trạng thái trong các phương thức POST/PUT/DELETE.
- **Các bước chi tiết**:
  - Triển khai các token chống CSRF duy nhất và an toàn về mặt mật mã cho tất cả các hoạt động thay đổi trạng thái.
  - Cấu hình cookie phiên làm việc với thuộc tính SameSite=Lax hoặc SameSite=Strict để ngăn chặn việc truyền tải chéo trang.
  - Đảm bảo tất cả các hành động thay đổi trạng thái yêu cầu các phương thức HTTP như POST, PUT, hoặc DELETE, thay vì GET.
  - Sử dụng các thư viện hiện đại, được duy trì (như csrf-csrf cho mẫu Double Submit Cookie) để quản lý và xác thực các token chống CSRF.

## Code Example
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A08:2021-Software and Data Integrity Failures, CWE-352 (Cross-Site Request Forgery)

## Giải thích thuật ngữ
- **SameSite Cookie**: Một thuộc tính của cookie cho phép lập trình viên kiểm soát việc cookie có được gửi kèm theo các yêu cầu từ trang web khác hay không, giúp chống lại việc lạm dụng cookie phiên trong tấn công CSRF.
- **Anti-CSRF Token**: Một chuỗi ký tự ngẫu nhiên, bí mật và duy nhất được máy chủ tạo ra cho mỗi phiên làm việc hoặc yêu cầu của người dùng, dùng để xác thực rằng yêu cầu đó thực sự bắt nguồn từ ứng dụng hợp pháp.
- **Same-Origin Policy (Chính sách đồng nguồn gốc)**: Cơ chế bảo mật quan trọng của trình duyệt ngăn cản các đoạn mã script ở một trang web truy cập vào dữ liệu của một trang web khác ở nguồn gốc (Domain/Port/Protocol) khác.
- **Cross-origin request credentials (Thông tin xác thực chéo nguồn)**: Các thông tin dùng để nhận diện người dùng (như cookie, header xác thực) được tự động gửi kèm theo các yêu cầu mạng hướng tới một tên miền khác với tên miền hiện tại của trang web.
- **Double Submit Cookie**: Kỹ thuật phòng thủ CSRF bằng cách gửi token chống CSRF ở cả cookie và tham số yêu cầu (hoặc header). Máy chủ sẽ so sánh hai giá trị này, nếu trùng khớp thì yêu cầu được chấp nhận.
