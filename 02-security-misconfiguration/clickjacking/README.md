# Clickjacking

> **CWE**: CWE-1021 | **Phân loại**: Client-Side Attacks

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang lướt một ứng dụng trò chơi trên điện thoại và nhìn thấy một nút bấm to màu đỏ ghi: "Nhấn vào đây để nhận 1.000.000đ miễn phí!". Bạn hào hứng nhấn vào nút đó. Nhưng bạn không hề biết rằng, kẻ xấu đã khéo léo phủ một tấm kính trong suốt vô hình đè lên màn hình điện thoại của bạn. Trên tấm kính đó, ở đúng vị trí của nút "Nhận quà", có một nút bấm thực tế khác ghi: "Xác nhận chuyển khoản 1.000.000đ từ tài khoản ngân hàng của bạn". Khi ngón tay của bạn chạm xuống, cú nhấp chuột thực tế đã xuyên qua tấm kính vô hình đó và kích hoạt giao dịch chuyển tiền chứ không phải là nhận quà. 

Kỹ thuật lừa đảo tinh vi này trong thế giới web được gọi là **Clickjacking** (Đánh cắp cú nhấp chuột) hay **UI Redressing** (Trang trí lại giao diện). Để thực hiện trò ảo thuật này, kẻ tấn công dựa vào ba công cụ cơ bản của HTML và CSS:
- **Thẻ iframe (`<iframe>`)**: Giống như một khung cửa sổ kính, thẻ này cho phép nhúng nguyên vẹn một trang web này vào bên trong một trang web khác. Kẻ tấn công sẽ nhúng trang web mục tiêu (như trang ngân hàng hoặc mạng xã hội) vào trang web bẫy của chúng.
- **CSS z-index**: Thuộc tính quyết định xem vật thể nào nằm đè lên vật thể nào. Kẻ tấn công đặt khung cửa sổ iframe này nằm ở lớp trên cùng, đè lên giao diện giả mạo.
- **CSS opacity**: Thuộc tính điều chỉnh độ trong suốt. Bằng cách đặt `opacity: 0`, kẻ tấn công làm cho khung cửa sổ iframe chứa trang web thật trở nên hoàn toàn vô hình đối với mắt thường, trong khi nó vẫn nằm sờ sờ ở đó chờ người dùng click vào.

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

## Mô tả lỗ hổng
Lỗ hổng Clickjacking xảy ra khi một trang web hợp pháp cho phép bản thân nó bị nhúng vào các trang web khác (qua thẻ iframe) mà không hề có bất kỳ biện pháp tự vệ nào. 

Lỗ hổng này vô cùng nguy hiểm vì nó biến sự tin tưởng và thao tác tự nguyện của người dùng thành công cụ gây hại cho chính họ. Người dùng nghĩ rằng họ đang click để chơi game, xem ảnh, hoặc tắt quảng cáo trên một trang web giải trí thông thường. Thế nhưng, thực tế là họ đang vô tình thực hiện các thao tác cực kỳ nhạy cảm trên trang web bị nhúng ẩn bên trên như: nhấn nút "Theo dõi" một tài khoản lạ, nhấn "Xóa tài khoản", hoặc tệ hơn là bấm "Xác nhận giao dịch tài chính". Do hành động này được thực hiện bởi chính người dùng đã đăng nhập hợp lệ, máy chủ của trang web thật sẽ xử lý yêu cầu đó như một hành động hoàn toàn bình thường, khiến người dùng bị thiệt hại mà không thể đổ lỗi cho lỗi hệ thống.

## Cơ chế tấn công
Kẻ tấn công lưu trữ một trang web độc hại chứa một iframe trỏ đến ứng dụng mục tiêu (ví dụ: www.kittens.com). Chúng phủ một thẻ div trong suốt có chỉ số z-index cao được bao bọc trong một thẻ liên kết trỏ đến một URL độc hại. Khi người dùng nhấp chuột để tương tác với trang web bên dưới, họ vô tình kích hoạt liên kết phủ của tin tặc.

### Ví dụ HTML iframe overlay minh họa Clickjacking:
```html
<!-- Trang của kẻ tấn công -->
<div style="position: relative;">
  <!-- Lớp nhìn thấy: nút "Nhận thưởng" giả -->
  <button style="position: absolute; z-index: 1;">🎁 Nhận thưởng ngay!</button>

  <!-- Iframe vô hình phủ lên trên: thực ra là trang ngân hàng -->
  <iframe src="https://your-bank.com/transfer?to=attacker&amount=1000000"
    style="position: absolute;
           z-index: 2;        /* z-index cao hơn → ở lớp trên cùng */
           opacity: 0;        /* opacity: 0 → vô hình hoàn toàn */
           width: 200px;
           height: 50px;">
  </iframe>
</div>
<!-- Khi nạn nhân click "Nhận thưởng", thực ra họ đang click nút Transfer trên iframe vô hình -->
```

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn việc nhúng khung bằng cách cấu hình các tiêu đề phản hồi HTTP phù hợp (Content-Security-Policy frame-ancestors và X-Frame-Options).
- **Các bước chi tiết**:
  - Cấu hình chỉ thị 'frame-ancestors' của Content-Security-Policy (CSP) để giới hạn việc nhúng khung chỉ cho các nguồn gốc đáng tin cậy.
  - Cấu hình tiêu đề X-Frame-Options (đặt thành DENY hoặc SAMEORIGIN) bằng cách sử dụng tham số 'always' để đảm bảo nó được áp dụng cho cả các phản hồi lỗi.
  - Cấu hình cookie với thuộc tính 'SameSite' (Lax hoặc Strict) để ngăn chúng bị gửi đi trong các ngữ cảnh iframe chéo trang.
  - Sử dụng JavaScript chống nhúng khung (frame-busting) để phòng thủ như một phương án dự phòng thứ hai để xác minh cửa sổ hiện tại là cửa sổ trên cùng.

## Code Example
```configuration
# Nginx header configuration to prevent Clickjacking
add_header Content-Security-Policy "frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```


## Xem thêm
- [Cross-Origin Resource Sharing](../cors/) — Xem thêm bài học về Cross-Origin Resource Sharing.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A05:2021-Security Misconfiguration, CWE-1021 (Improper Restriction of Frame Source)

## Giải thích thuật ngữ
- **Clickjacking**: Tấn công đánh cắp cú nhấp chuột bằng cách lừa người dùng nhấp vào một phần tử vô hình đè lên giao diện hiển thị.
- **UI Redressing**: Kỹ thuật ngụy trang giao diện, làm thay đổi giao diện thực tế của ứng dụng để đánh lừa người dùng.
- **HTML iframe**: Thẻ HTML cho phép nhúng một trang web khác trực tiếp vào trang web hiện hành dưới dạng một khung độc lập.
- **CSS z-index**: Thuộc tính CSS xác định thứ tự hiển thị của các phần tử trên màn hình theo chiều sâu (phần tử nào nằm trên, phần tử nào nằm dưới).
- **CSS opacity**: Thuộc tính CSS điều chỉnh độ mờ hoặc độ trong suốt của một phần tử, nhận giá trị từ 0 (trong suốt hoàn toàn) đến 1 (hiển thị rõ nét).
- **Content-Security-Policy (CSP)**: Chính sách bảo mật nội dung, là một HTTP header giúp quản trị viên kiểm soát các nguồn tài nguyên (như script, ảnh, iframe) mà trình duyệt được phép tải.
- **X-Frame-Options**: Một HTTP response header truyền thống dùng để chỉ định xem trình duyệt có được phép hiển thị trang web trong các thẻ `<iframe>` hay không.
- **SameSite Cookie**: Thuộc tính của cookie giúp kiểm soát việc cookie có được gửi kèm theo trong các yêu cầu liên kết chéo trang (cross-site requests) hay không, giúp phòng chống clickjacking và CSRF.
