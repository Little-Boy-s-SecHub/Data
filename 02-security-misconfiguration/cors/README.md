# Cross-Origin Resource Sharing

> **OWASP Top 10:2025**: A02:2025 – Security Misconfiguration | **CWE**: CWE-942 | **Phân loại**: Security Misconfiguration

## 🧱 Kiến thức Nền tảng
Same-Origin Policy (SOP) và Cross-Origin Resource Sharing (CORS) là các cơ chế an ninh cốt lõi của trình duyệt nhằm quản lý tương tác giữa các nguồn (origins) khác nhau trên Internet. Một nguồn được xác định bằng bộ ba: giao thức (protocol), tên miền (domain), và cổng (port).
- **Same-Origin Policy (SOP)**: Đây là chính sách bảo mật cơ bản ngăn chặn các tập lệnh (scripts) chạy trên một trang web truy cập vào các tài nguyên hoặc dữ liệu nhạy cảm của một trang web khác thuộc nguồn khác. Ví dụ, JavaScript chạy trên trang `evil.com` không thể đọc nội dung email của bạn tại `mail.google.com`. SOP bảo vệ dữ liệu người dùng khỏi bị xâm hại bởi mã độc chéo trang.
- **CORS Preflight Request**: Nhằm đáp ứng nhu cầu chia sẻ tài nguyên hợp lệ giữa các nguồn, CORS được sinh ra để nới lỏng SOP một cách có kiểm soát. Đối với các yêu cầu HTTP "không đơn giản" (ví dụ: sử dụng phương thức PUT, DELETE, hoặc có các header tùy chỉnh như Authorization, Content-Type là application/json), trình duyệt sẽ tự động gửi trước một yêu cầu thăm dò gọi là **preflight request** bằng phương thức `OPTIONS`. Yêu cầu này chứa các header đặc trưng như `Access-Control-Request-Method` và `Access-Control-Request-Headers`. Máy chủ mục tiêu phải phản hồi với các tiêu đề CORS phù hợp (như `Access-Control-Allow-Origin` và `Access-Control-Allow-Methods`) để xác nhận cho phép yêu cầu thực sự được gửi đi. Nếu máy chủ đồng ý, trình duyệt mới tiến hành gửi yêu cầu chính thức.

```javascript
// Express.js middleware for safe CORS policy handling
const express = require('express');
const app = express();

// Whitelist of trusted origins allowed to access the API
const allowedOrigins = ['https://www.example.com', 'https://api.example.com'];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Check if the incoming request origin is in the trusted whitelist
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    
    // Handle the CORS preflight request (OPTIONS method)
    if (req.method === 'OPTIONS') {
        // Preflight requests do not require body processing, return HTTP 204 No Content
        return res.sendStatus(204);
    }
    
    next();
});
```

## 🔍 Mô tả lỗ hổng
Chia sẻ tài nguyên chéo nguồn gốc (CORS) quản lý cách các trình duyệt web cho phép các tập lệnh trên một tên miền đọc tài nguyên từ một tên miền khác. Các cấu hình quá thoải mái—cụ thể là phản ánh động tiêu đề Origin trong khi cho phép gửi thông tin xác thực (credentials)—để lộ các API nhạy cảm cho các trang web độc hại, cho phép chúng thu hoạch dữ liệu người dùng.

## ⚔️ Cơ chế tấn công
Nhà phát triển tạm thời kích hoạt tính năng phản ánh nguồn gốc CORS để gỡ lỗi và triển khai nó lên môi trường production. Một người dùng đã đăng nhập truy cập một blog nấu ăn độc hại. Tập lệnh chạy ngầm của blog thực hiện các yêu cầu API đến ngân hàng; vì thông tin xác thực được cho phép, trình duyệt sẽ gửi các cookie xác thực, cho phép tập lệnh độc hại đọc và đánh cắp số dư tài khoản của người dùng.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Thực thi các danh sách trắng nghiêm ngặt về các nguồn gốc được phép và tránh phản ánh động các nguồn gốc tùy ý khi thông tin xác thực được kích hoạt.
- **Các bước chi tiết**:
  - Cấu hình một danh sách trắng rõ ràng về các nguồn gốc được phép và so sánh các tiêu đề Origin gửi đến với danh sách này.
  - Không bao giờ phản ánh động tiêu đề Origin trong Access-Control-Allow-Origin khi Access-Control-Allow-Credentials được đặt thành true.
  - Tránh sử dụng nguồn gốc ký tự đại diện '*' cho các endpoint yêu cầu xác thực hoặc xử lý dữ liệu người dùng nhạy cảm.
  - Giới hạn các quyền CORS chỉ đối với các phương thức HTTP và tiêu đề được yêu cầu bởi ứng dụng.

## 💻 Code Example
```javascript
// Express.js safe CORS middleware using CORS module with strict whitelist
const express = require('express');
const cors = require('cors');
const app = express();

const allowedOrigins = ['https://trusted.example.com', 'https://admin.example.com'];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lại phân loại của bài học từ 'Request Attacks' thành 'Security Misconfiguration'. Giải quyết một lỗi triển khai hàm callback CORS của Express.js, trong đó việc ném ra một Error làm dừng thực thi hoàn toàn thay vì từ chối yêu cầu tiêu đề CORS một cách duyên dáng. Loại bỏ các thuộc tính lang='js' lỗi thời trong các thẻ script.
- **Nguồn tham khảo**: OWASP A05:2021-Security Misconfiguration, CWE-942 (Permissive CORS Policy)
