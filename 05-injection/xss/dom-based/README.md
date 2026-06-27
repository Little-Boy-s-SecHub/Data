# DOM-based XSS

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: XSS

## 🧱 Kiến thức Nền tảng
DOM (Document Object Model) là cấu trúc phân cấp dạng cây đại diện cho tài liệu HTML. Khi trình duyệt tải một trang web, nó phân tích cú pháp mã nguồn HTML và dựng nên cây DOM, trong đó mỗi phần tử, thuộc tính hay văn bản đều là một nút (node). Trình duyệt sử dụng mô hình thực thi JavaScript đơn luồng để tương tác với cây DOM này. Khi JavaScript chạy, nó có thể đọc dữ liệu từ các nguồn (sources) như URL hash (`location.hash`) hoặc query string (`location.search`) và đẩy vào các điểm nhận (sinks).

Lỗ hổng DOM-based XSS xảy ra khi dữ liệu từ một source không an toàn được ghi trực tiếp vào một sink nhạy cảm mà không qua kiểm tra hay mã hóa. Sự khác biệt giữa `innerHTML` và `textContent` là yếu tố cốt lõi trong phòng thủ:
- `innerHTML` yêu cầu trình duyệt phân tích cú pháp chuỗi ký tự nhận vào dưới dạng mã HTML. Nếu chuỗi chứa các thẻ thực thi (như `<img src=x onerror=...>`), công cụ JavaScript của trình duyệt sẽ biên dịch và chạy kịch bản độc hại đó ngay lập tức.
- `textContent` (hoặc `innerText`) chỉ gán văn bản thuần túy vào DOM. Trình duyệt sẽ hiển thị chuỗi ký tự thô mà không biên dịch nó thành mã HTML/JS, triệt tiêu hoàn toàn khả năng thực thi kịch bản độc hại.

Do đó, lập trình viên cần hiểu rõ mô hình thực thi của trình duyệt: mọi thao tác thay đổi giao diện động nên ưu tiên sử dụng `textContent` hoặc các phương thức tạo phần tử an toàn (`document.createElement`), chỉ sử dụng `innerHTML` kèm theo các thư viện làm sạch HTML chuyên dụng như DOMPurify khi thực sự cần hiển thị định dạng văn bản giàu.

### Code ví dụ hoạt động bình thường (Secure DOM Manipulation)
```javascript
// Secure JavaScript implementation for handling user input in DOM
window.addEventListener('DOMContentLoaded', () => {
    // Extract user profile name from URL query parameter safely
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get('username') || 'Guest';

    // Get DOM elements
    const welcomeTextNode = document.getElementById('welcome-message');
    const customContainer = document.getElementById('custom-content');

    // Safe Method 1: Using textContent to prevent DOM XSS
    // Browser treats the content strictly as text, not HTML/JS
    welcomeTextNode.textContent = `Welcome back, ${username}!`;

    // Safe Method 2: Creating elements programmatically to render structured markup
    const paragraphElement = document.createElement('p');
    paragraphElement.textContent = 'Your profile is loaded successfully.';
    customContainer.appendChild(paragraphElement);
});
```

## 🔍 Mô tả lỗ hổng
DOM-based XSS xảy ra hoàn toàn ở phía client khi các kịch bản JavaScript của trang web đọc dữ liệu từ các nguồn không an toàn (như URL fragment, tham số truy vấn) và ghi trực tiếp vào các hàm/thuộc tính nhạy cảm (sinks như innerHTML, eval) mà không qua kiểm tra hoặc vệ sinh dữ liệu. Trình duyệt của nạn nhân sau đó sẽ thực thi mã độc trong ngữ cảnh bảo mật của trang web. Lỗ hổng này rất phổ biến ở các ứng dụng Single-Page (SPA) quản lý định tuyến bằng URL hash.

## ⚔️ Cơ chế tấn công
Kẻ tấn công tạo một liên kết chứa mã độc JavaScript trong phần hash fragment của URL (ví dụ `http://example.com/#<img src=x onerror=alert(1)>`) và lừa nạn nhân truy cập. JavaScript chạy trên trình duyệt của nạn nhân đọc giá trị này qua `window.location.hash` và chèn trực tiếp vào một Sink như `document.getElementById('page').innerHTML = page`. Trình duyệt phân tích chuỗi HTML đó, phát hiện lỗi tải ảnh và ngay lập tức chạy mã độc trong thuộc tính `onerror` của ảnh.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn DOM-based XSS bằng cách hạn chế sử dụng innerHTML, ưu tiên dùng textContent, vệ sinh HTML bằng các thư viện mạnh như DOMPurify khi cần render markup, và áp dụng Trusted Types.
- **Các bước chi tiết**:
  - Tránh sử dụng các sink diễn giải chuỗi ký tự thành mã thực thi hoặc HTML (như `element.innerHTML`, `document.write`, `eval`, `setTimeout(string)`).
  - Sử dụng các API an toàn hơn chỉ xử lý văn bản thô (text content) thay vì phân tích cú pháp HTML, chẳng hạn như `element.textContent` hoặc `element.innerText`.
  - Khi bắt buộc phải hiển thị mã HTML từ dữ liệu ngoài, hãy sử dụng thư viện vệ sinh uy tín như `DOMPurify` để loại bỏ toàn bộ kịch bản độc hại.
  - Xây dựng chính sách bảo mật nội dung (CSP) chặt chẽ (ví dụ: cấm dùng `unsafe-inline`).
  - Cấu hình Trusted Types trong trình duyệt để cưỡng chế việc kiểm duyệt và vệ sinh dữ liệu trước khi chèn vào các sink.

## 💻 Code Example
```javascript
// Unsafe sink example:
// element.innerHTML = location.hash; // Vulnerable to DOM XSS

// Secure approach 1: Use textContent for text data
const userInput = location.hash.substring(1);
const textElement = document.getElementById("user-display");
textElement.textContent = userInput; // Safe: content is not parsed as HTML/JS

// Secure approach 2: Sanitize HTML using DOMPurify when markup is needed
import DOMPurify from 'dompurify';

const handleHashChange = () => {
    const dirtyHtml = window.location.hash.substring(1);
    const cleanHtml = DOMPurify.sanitize(dirtyHtml);
    document.getElementById("html-display").innerHTML = cleanHtml;
};
window.addEventListener('hashchange', handleHashChange);
handleHashChange();
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Sửa đổi đoạn mã bảo mật thứ hai trong ví dụ DOMPurify, thay thế việc gán cứng một chuỗi tĩnh `dirtyHtml` bằng logic thu thập dữ liệu động thực tế từ `window.location.hash.substring(1)` và bổ sung window event listener cho sự kiện `hashchange` để xử lý kịp thời các thay đổi trên URL.
- **Nguồn tham khảo**: OWASP DOM Based XSS Cheat Sheet, PortSwigger, CWE-79
