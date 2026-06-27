# Clickjacking

> **OWASP Top 10:2025**: A02:2025 – Security Misconfiguration | **CWE**: CWE-1021 | **Phân loại**: Security Misconfiguration

## 🧱 Kiến thức Nền tảng
Clickjacking (tấn công đánh cắp cú nhấp chuột) là một kỹ thuật tấn công giao diện (UI redressing), nơi kẻ tấn công đánh lừa người dùng thực hiện các hành động ngoài ý muốn bằng cách lồng ghép một trang web mục tiêu vào bên trong một khung giao diện của trang web độc hại. Để hiểu được Clickjacking, chúng ta cần nắm vững ba khái niệm nền tảng:
- **HTML iframe (`<iframe>`)**: Thẻ HTML này cho phép nhúng một tài liệu HTML khác trực tiếp vào trang hiện tại. Trong Clickjacking, kẻ tấn công dùng `iframe` để nhúng trang web mục tiêu (ví dụ: trang chuyển tiền của ngân hàng) vào trang web bẫy của chúng.
- **CSS z-index**: Đây là thuộc tính kiểm soát thứ tự hiển thị của các phần tử theo trục Z (chiều sâu). Phần tử có `z-index` lớn hơn sẽ nằm đè lên phần tử có `z-index` nhỏ hơn. Kẻ tấn công đặt `z-index` của `iframe` chứa trang web mục tiêu cao hơn giao diện giả mạo bên dưới để đảm bảo người dùng thực sự nhấp vào trang mục tiêu khi click.
- **CSS opacity**: Thuộc tính này điều chỉnh độ trong suốt của phần tử, nhận giá trị từ `0` (hoàn toàn trong suốt) đến `1` (hoàn toàn hiển thị). Bằng cách đặt `opacity: 0` (hoặc cực kỳ gần 0) cho `iframe` mục tiêu, kẻ tấn công làm cho nó trở nên vô hình đối với người dùng. Người dùng chỉ nhìn thấy giao diện hấp dẫn (ví dụ: nút "Nhận quà miễn phí") ở bên dưới, nhưng khi họ nhấp vào đó, cú click thực tế sẽ được gửi tới nút chức năng vô hình của trang mục tiêu (ví dụ: nút "Xác nhận chuyển tiền") đang đè lên trên.

```html
<!-- A legitimate HTML page showing a modal dialog with z-index and opacity, embedding a safe widget inside an iframe -->
<div class="page-container">
    <h1>Welcome to Our Service</h1>
    <p>Click below to preview our location map.</p>
    <button id="openMapBtn">View Map</button>

    <!-- Legitimate overlay using opacity for backdrop and z-index for proper layering -->
    <div id="modalBackdrop" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: none;"></div>

    <!-- Modal box placed above backdrop with higher z-index -->
    <div id="mapModal" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 600px; background: #fff; border-radius: 8px; z-index: 1001; display: none; padding: 20px;">
        <h2>Our Location</h2>
        <!-- Safe, visible iframe embedding a map with opacity set to 1 (visible) -->
        <iframe 
            src="https://maps.google.com/maps?q=London&t=&z=13&ie=UTF8&iwloc=&output=embed" 
            width="100%" 
            height="350" 
            style="border: 0; opacity: 1.0;" 
            title="Location Map"
            sandbox="allow-scripts allow-same-origin">
        </iframe>
        <button id="closeMapBtn" style="margin-top: 10px;">Close</button>
    </div>
</div>
```

## 🔍 Mô tả lỗ hổng
Clickjacking (đánh cắp cú nhấp chuột) là một kỹ thuật trong đó kẻ tấn công phủ một khung (frame) trong suốt lên trên một trang web hợp pháp để chiếm đoạt các cú nhấp chuột. Người dùng tin rằng họ đang nhấp vào các phần tử hiển thị phía trước, nhưng thực tế họ đang nhấp vào các hành động trong iframe bị ẩn, chẳng hạn như tải xuống phần mềm độc hại hoặc xác nhận các giao dịch chuyển tiền.

## ⚔️ Cơ chế tấn công
Kẻ tấn công lưu trữ một trang web độc hại chứa một iframe trỏ đến ứng dụng mục tiêu (ví dụ: www.kittens.com). Chúng phủ một thẻ div trong suốt có chỉ số z-index cao được bao bọc trong một thẻ liên kết trỏ đến một URL độc hại. Khi người dùng nhấp chuột để tương tác với trang web bên dưới, họ vô tình kích hoạt liên kết phủ của tin tặc.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn việc nhúng khung bằng cách cấu hình các tiêu đề phản hồi HTTP phù hợp (Content-Security-Policy frame-ancestors và X-Frame-Options).
- **Các bước chi tiết**:
  - Cấu hình chỉ thị 'frame-ancestors' của Content-Security-Policy (CSP) để giới hạn việc nhúng khung chỉ cho các nguồn gốc đáng tin cậy.
  - Cấu hình tiêu đề X-Frame-Options (đặt thành DENY hoặc SAMEORIGIN) bằng cách sử dụng tham số 'always' để đảm bảo nó được áp dụng cho cả các phản hồi lỗi.
  - Cấu hình cookie với thuộc tính 'SameSite' (Lax hoặc Strict) để ngăn chúng bị gửi đi trong các ngữ cảnh iframe chéo trang.
  - Sử dụng JavaScript chống nhúng khung (frame-busting) để phòng thủ như một phương án dự phòng thứ hai để xác minh cửa sổ hiện tại là cửa sổ trên cùng.

## 💻 Code Example
```configuration
# Nginx header configuration to prevent Clickjacking
add_header Content-Security-Policy "frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lại phân loại của bài học từ 'Social Engineering' thành 'Security Misconfiguration'. Đã thêm công cụ sửa đổi 'always' vào các tiêu đề Nginx để đảm bảo chúng được áp dụng cho các trang lỗi (như phản hồi 4xx/5xx) và sửa các giao thức bị thiếu trong các nguồn iframe của slide.
- **Nguồn tham khảo**: OWASP A05:2021-Security Misconfiguration, CWE-1021 (Improper Restriction of Frame Source)
