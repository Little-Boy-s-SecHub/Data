# Cross-Origin Resource Sharing

> **CWE**: CWE-942 | **Phân loại**: Security Misconfiguration

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang sống trong một khu chung cư cao cấp. Ban quản lý tòa nhà có một quy định an ninh cực kỳ nghiêm ngặt: "Người lạ ở bên ngoài không được phép tự ý vào căn hộ của cư dân để lục lọi đồ đạc hay đọc trộm thư từ". Quy định an toàn cơ bản này trong thế giới trình duyệt được gọi là **SOP** (Same-Origin Policy - Chính sách cùng nguồn gốc). Nó đảm bảo rằng một đoạn mã độc hại chạy trên trang web giải trí `evil.com` không thể nào tự ý đọc tin nhắn Facebook hay dữ liệu tài khoản ngân hàng của bạn đang mở ở tab bên cạnh. Một "nguồn" (origin) ở đây được xác định chặt chẽ bằng sự kết hợp của: giao thức (http/https), tên miền (domain) và cổng kết nối (port).

Tuy nhiên, trong thực tế, các ứng dụng web hiện đại cần phải hợp tác với nhau. Ví dụ, trang web bán hàng của bạn (`shop.com`) cần gọi API lấy danh sách sản phẩm từ máy chủ dữ liệu (`api.shop.com`). Để cho phép sự hợp tác chéo nguồn này một cách an toàn, cơ chế **CORS** (Cross-Origin Resource Sharing - Chia sẻ tài nguyên chéo nguồn gốc) ra đời. CORS giống như một người bảo vệ đứng ở cửa. Đối với các hành động nhạy cảm (như cập nhật thông tin hay xóa dữ liệu), trình duyệt sẽ tự động cử một "sứ giả" gửi yêu cầu thăm dò gọi là **preflight request** (sử dụng lệnh `OPTIONS`) để hỏi máy chủ: "Tôi đến từ `shop.com`, tôi có được phép thực hiện hành động này không?". Nếu máy chủ gật đầu đồng ý và trả về thẻ thông hành phù hợp (qua tiêu đề `Access-Control-Allow-Origin`), trình duyệt mới cho phép gửi yêu cầu thực sự đi.

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

## Mô tả lỗ hổng
Lỗ hổng CORS (CORS Misconfiguration) xảy ra khi người bảo vệ đứng cửa (cấu hình CORS trên máy chủ API) quá lỏng lẻo, lười biếng hoặc thiết lập sai quy trình. 

Sai lầm phổ biến nhất là lập trình viên cấu hình máy chủ chấp nhận "bất kỳ ai hỏi cũng cho vào" bằng cách tự động phản hồi: "Đồng ý cho trang của bạn truy cập" (phản ánh động tiêu đề `Origin` của khách gửi lên), đồng thời vẫn cho phép gửi kèm theo thông tin đăng nhập của người dùng (`Access-Control-Allow-Credentials: true`). Lỗ hổng này cực kỳ nguy hiểm. Kẻ tấn công chỉ cần dụ dỗ bạn truy cập vào một trang web xem phim hay đọc truyện chứa mã độc của chúng. Khi bạn đang mải mê xem phim, mã độc chạy ngầm trên trang đó sẽ âm thầm gửi yêu cầu lấy dữ liệu cá nhân hay thực hiện giao dịch từ trình duyệt của bạn tới trang ngân hàng. Vì cấu hình CORS của ngân hàng bị lỗi và trình duyệt tự động gửi theo cookie đăng nhập của bạn, máy chủ ngân hàng sẽ vui vẻ dâng toàn bộ thông tin nhạy cảm của bạn cho trang web độc hại của kẻ tấn công.

## Cơ chế tấn công
Nhà phát triển tạm thời kích hoạt tính năng phản ánh nguồn gốc CORS để gỡ lỗi và triển khai nó lên môi trường production. Một người dùng đã đăng nhập truy cập một blog nấu ăn độc hại. Tập lệnh chạy ngầm của blog thực hiện các yêu cầu API đến ngân hàng; vì thông tin xác thực được cho phép, trình duyệt sẽ gửi các cookie xác thực, cho phép tập lệnh độc hại đọc và đánh cắp số dư tài khoản của người dùng.

## Biện pháp phòng thủ
- **Tóm tắt**: Thực thi các danh sách trắng nghiêm ngặt về các nguồn gốc được phép và tránh phản ánh động các nguồn gốc tùy ý khi thông tin xác thực được kích hoạt.
- **Các bước chi tiết**:
  - Cấu hình một danh sách trắng rõ ràng về các nguồn gốc được phép và so sánh các tiêu đề Origin gửi đến với danh sách này.
  - Không bao giờ phản ánh động tiêu đề Origin trong Access-Control-Allow-Origin khi Access-Control-Allow-Credentials được đặt thành true.
  - Tránh sử dụng nguồn gốc ký tự đại diện '*' cho các endpoint yêu cầu xác thực hoặc xử lý dữ liệu người dùng nhạy cảm.
  - Giới hạn các quyền CORS chỉ đối với các phương thức HTTP và tiêu đề được yêu cầu bởi ứng dụng.

## Code Example
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


## Xem thêm
- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A05:2021-Security Misconfiguration, CWE-942 (Permissive CORS Policy)

## Giải thích thuật ngữ
- **Same-Origin Policy (SOP)**: Chính sách bảo mật cùng nguồn gốc của trình duyệt, ngăn các trang web từ các nguồn khác nhau truy cập dữ liệu của nhau.
- **Origin (Nguồn gốc)**: Sự kết hợp của giao thức (HTTP/HTTPS), tên miền và cổng (port) dùng để định danh một ứng dụng web trên môi trường mạng.
- **CORS (Cross-Origin Resource Sharing)**: Cơ chế chia sẻ tài nguyên chéo nguồn gốc, cho phép nới lỏng chính sách SOP một cách có kiểm soát.
- **Preflight Request**: Yêu cầu kiểm tra trước, sử dụng HTTP method OPTIONS để thăm dò xem máy chủ đích có cho phép gửi yêu cầu chéo nguồn thực tế hay không.
- **Access-Control-Allow-Origin**: Tiêu đề phản hồi (header) của máy chủ chỉ định những nguồn gốc (origins) nào được phép truy cập tài nguyên của nó.
- **Credentials (Thông tin xác thực)**: Các dữ liệu chứng minh danh tính như cookie, token xác thực hoặc thông tin đăng nhập HTTP được gửi kèm trong request.
- **Whitelist (Danh sách trắng)**: Danh sách ghi nhận các nguồn gốc tin cậy được phép truy cập tài nguyên.
