# DOM-based XSS

> **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

Khi trình duyệt tải một trang web, nó sẽ dịch mã nguồn HTML thành một sơ đồ cấu trúc cây gọi là DOM (Document Object Model) để quản lý. Sau đó, JavaScript sẽ chạy để thay đổi động các nút trên cây DOM này (như đổi màu, thêm chữ). Trong quá trình này, JavaScript thường đọc dữ liệu từ các nguồn có sẵn trên trình duyệt (gọi là sources - ví dụ như phần đuôi URL sau dấu `#`) và đưa chúng vào các điểm tiếp nhận dữ liệu trên trang (gọi là sinks - ví dụ như thuộc tính `innerHTML`). Điểm mấu chốt ở đây là cách JavaScript đưa dữ liệu vào: nếu sử dụng `innerHTML`, trình duyệt sẽ cố gắng dịch dữ liệu đó thành mã lập trình thực thi; còn nếu dùng `textContent`, trình duyệt chỉ coi đó là chữ viết thô vô hại và không bao giờ chạy bất kỳ đoạn mã nào ẩn chứa bên trong.

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

## Mô tả lỗ hổng

Lỗ hổng DOM-based XSS xảy ra hoàn toàn bên trong trình duyệt của người dùng (phía client) mà không cần sự can thiệp trực tiếp của máy chủ. Nó xuất hiện khi các đoạn mã JavaScript của trang web lấy dữ liệu từ một nguồn không an sau (source) rồi đẩy thẳng vào một điểm tiếp nhận nhạy cảm (sink như innerHTML hoặc eval) mà quên không kiểm tra hay làm sạch. Kẻ tấn công có thể dụ nạn nhân bấm vào một liên kết có phần đuôi URL chứa mã độc. Khi trang web tải lên, JavaScript phía client tự động lấy đoạn mã độc này từ URL và ghi vào trang web thông qua `innerHTML`, khiến trình duyệt thực thi mã độc ngay lập tức. Lỗ hổng này cực kỳ phổ biến trong các ứng dụng hiện đại (Single Page Application) vốn sử dụng JavaScript rất nhiều để thay đổi giao diện động.

## Cơ chế tấn công

Kẻ tấn công tạo một liên kết chứa mã độc JavaScript trong phần hash fragment của URL (ví dụ `http://example.com/#<img src=x onerror=alert(1)>`) và lừa nạn nhân truy cập. JavaScript chạy trên trình duyệt của nạn nhân đọc giá trị này qua `window.location.hash` và chèn trực tiếp vào một Sink như `document.getElementById('page').innerHTML = page`. Trình duyệt phân tích chuỗi HTML đó, phát hiện lỗi tải ảnh và ngay lập tức chạy mã độc trong thuộc tính `onerror` của ảnh.

## Biện pháp phòng thủ

- **Tóm tắt**: Ngăn chặn DOM-based XSS bằng cách hạn chế sử dụng innerHTML, ưu tiên dùng textContent, vệ sinh HTML bằng các thư viện mạnh như DOMPurify khi cần render markup, và áp dụng Trusted Types.
- **Các bước chi tiết**:
  - Tránh sử dụng các sink diễn giải chuỗi ký tự thành mã thực thi hoặc HTML (như `element.innerHTML`, `document.write`, `eval`, `setTimeout(string)`).
  - Sử dụng các API an toàn hơn chỉ xử lý văn bản thô (text content) thay vì phân tích cú pháp HTML, chẳng hạn như `element.textContent` hoặc `element.innerText`.
  - Khi bắt buộc phải hiển thị mã HTML từ dữ liệu ngoài, hãy sử dụng thư viện vệ sinh uy tín như `DOMPurify` để loại bỏ toàn bộ kịch bản độc hại.
  - Xây dựng chính sách bảo mật nội dung (CSP) chặt chẽ (ví dụ: cấm dùng `unsafe-inline`).
  - Cấu hình Trusted Types trong trình duyệt để cưỡng chế việc kiểm duyệt và vệ sinh dữ liệu trước khi chèn vào các sink.

## Code Example

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

## Xem thêm

- [DOM Clobbering](../../dom-clobbering/) — Lỗ hổng thao túng DOM.

## Nguồn tham khảo

- OWASP DOM Based XSS Cheat Sheet, PortSwigger, CWE-79

## Giải thích thuật ngữ

- **DOM-based XSS**: Lỗ hổng XSS xảy ra hoàn toàn ở phía trình duyệt người dùng do lỗi xử lý dữ liệu trong JavaScript.
- **DOM (Document Object Model)**: Mô hình đối tượng tài liệu cấu trúc phân cấp thể hiện nội dung trang web.
- **Source**: Các nguồn dữ liệu đầu vào mà JavaScript có thể đọc được trên trình duyệt (như location.hash, document.referrer).
- **Sink**: Các điểm hàm hoặc thuộc tính JavaScript nhạy cảm có khả năng thực thi mã (như innerHTML, eval).
- **DOMPurify**: Thư viện lọc và làm sạch mã HTML phía client để ngăn chặn XSS.
