# Host Header Poisoning

> **CWE**: CWE-644 (Improper Handling of HTTP Headers) | **Phân loại**: Security Misconfiguration

## Kiến thức Nền tảng
Hãy tưởng tượng bạn gửi một lá thư chuyển phát nhanh qua bưu điện. Ở mặt trước lá thư, bưu điện yêu cầu bạn phải ghi rõ thông tin ở ô "Tên miền/Địa chỉ người nhận" (đây chính là **Host Header**). Bưu điện sử dụng ô thông tin này để biết phải chuyển lá thư đó đến tòa nhà nào. Tuy nhiên, nếu nhân viên bưu điện quá ngây thơ, khi lá thư đến nơi, họ lại dùng chính địa chỉ do bạn tự viết tay ở ô "Host Header" để in lên toàn bộ các giấy tờ phản hồi, biên lai chuyển tiền hoặc phiếu hẹn gặp lại của tòa nhà mà không thèm đối chiếu xem địa chỉ đó có thuộc hệ thống chi nhánh chính thức của họ hay không. Kẻ xấu có thể điền một địa chỉ mạo danh vào ô này, lừa bưu điện gửi các phản hồi quan trọng chứa thông tin mật thẳng về hòm thư của chúng.

Trong giao thức HTTP, **Host Header** là một tiêu đề bắt buộc từ phiên bản HTTP/1.1. Khi bạn truy cập một trang web, trình duyệt sẽ tự động gửi tiêu đề này để thông báo cho máy chủ biết bạn đang muốn truy cập tên miền nào. Điều này cho phép một máy chủ vật lý duy nhất có thể chạy song song nhiều trang web khác nhau (được gọi là **Virtual Hosting - Lưu trữ ảo**). Máy chủ web (như Nginx hay Apache) sẽ đọc Host Header để dẫn đường (định tuyến) yêu cầu của bạn đến đúng thư mục chứa mã nguồn. Lỗ hổng xảy ra khi ứng dụng web tin tưởng hoàn toàn vào giá trị Host Header do người dùng gửi lên để tự động tạo ra các đường link tuyệt đối (như liên kết đổi mật khẩu, link kích hoạt tài khoản) mà không xác thực lại.

```configuration
# Nginx configuration for secure virtual hosting

# 1. Default server block to reject any unrecognized Host headers
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _; # Match any request that does not match other blocks
    return 444; # Connection closed without response (mitigates scanning and poisoning)
}

# 2. Main virtual host configuration for the legitimate application domain
server {
    listen 80;
    server_name app.example.com www.app.example.com; # Explicitly whitelisted domains

    location / {
        # Forward only valid host header to the backend application pool
        proxy_set_header Host $host;
        proxy_pass http://localhost:8080;
    }
}
```

## Mô tả lỗ hổng
Lỗ hổng **Đầu độc Host Header** (Host Header Poisoning) xảy ra khi ứng dụng web tin cậy một cách mù quáng vào giá trị của header Host trong yêu cầu HTTP để tạo ra các liên kết hoặc thực thi logic hệ thống. Do header này do client gửi lên và hoàn toàn có thể bị chỉnh sửa bởi kẻ tấn công, đây là một điểm yếu cấu hình cực kỳ nguy hiểm.

Kẻ tấn công có thể thay đổi giá trị Host Header thành một tên miền độc hại do chúng sở hữu (ví dụ: từ `bank.com` thành `evil-bank.com`) khi gửi yêu cầu khôi phục mật khẩu cho tài khoản của bạn. Máy chủ web, do thiếu cấu hình bảo vệ, vẫn xử lý yêu cầu và gửi một email khôi phục mật khẩu chính chủ đến hộp thư của bạn. Tuy nhiên, đường link bên trong email lại bị "đầu độc" và trỏ về trang web giả mạo của kẻ tấn công: `https://evil-bank.com/reset?token=secret_code`. Nếu bạn không chú ý và click vào link, mã khóa đổi mật khẩu (token) của bạn sẽ ngay lập tức bị gửi thẳng đến máy chủ của kẻ tấn công, giúp chúng dễ dàng chiếm đoạt tài khoản của bạn.

## Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện chức năng khôi phục mật khẩu của ứng dụng sinh liên kết khôi phục bằng cách lấy giá trị trực tiếp từ HTTP Host Header của yêu cầu.
Bước 2: Kẻ tấn công gửi yêu cầu khôi phục mật khẩu cho tài khoản của nạn nhân (ví dụ: `vic@email.com`), đồng thời sửa đổi Host Header trong HTTP request thành tên miền độc hại do mình kiểm soát (ví dụ: `evil.com`).
Bước 3: Máy chủ xử lý yêu cầu và tạo email khôi phục mật khẩu gửi cho nạn nhân chứa liên kết có dạng `https://evil.com/reset?token=XYZ`.
Bước 4: Nạn nhân nhận email, tin tưởng vào nội dung và nhấn vào link khôi phục mật khẩu. Yêu cầu chứa token khôi phục sẽ được gửi tới máy chủ `evil.com`, giúp kẻ tấn công đánh cắp token và đổi mật khẩu tài khoản.

## Biện pháp phòng thủ
- **Tóm tắt**: Prevent Host Header Poisoning by configuring web servers to reject unrecognized host headers and avoiding dynamic host header references in application code.
- **Các bước chi tiết**:
  - Configure the web server with a default server block that drops requests containing invalid or missing Host headers.
  - Explicitly define server names in web server configurations to restrict acceptable Host headers strictly to whitelisted domains.
  - Avoid relying on the incoming HTTP Host header for generating password-reset links, redirects, or absolute URLs within application code.
  - Configure load balancers and reverse proxies to normalize and validate Host and X-Forwarded-Host headers before forwarding to backend apps.

## Code Example
```configuration
# Hardened Nginx virtual host configuration
# 1. Default server block to reject unrecognized hostnames
server {
    listen 80 default_server;
    server_name _;
    return 444; # Terminate connection immediately
}

# 2. Virtual host config for the authorized domain
server {
    listen 80;
    server_name app.example.com www.app.example.com;

    location / {
        proxy_set_header Host $host;
        proxy_pass http://backend_pool;
    }
}
```


## Xem thêm
- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A03:2021, CWE-644, PortSwigger Web Security Academy

## Giải thích thuật ngữ
- **HTTP Host Header**: Tiêu đề HTTP bắt buộc, chứa tên miền của máy chủ mà client muốn gửi yêu cầu tới.
- **Virtual Hosting**: Công nghệ cho phép một máy chủ vật lý đơn lẻ lưu trữ và chạy cùng lúc nhiều trang web với các tên miền khác nhau.
- **Header (Tiêu đề HTTP)**: Các dòng thông tin bổ sung được gửi kèm theo yêu cầu hoặc phản hồi HTTP để cung cấp ngữ cảnh về cuộc giao tiếp web.
- **Absolute URL (Liên kết tuyệt đối)**: Đường dẫn đầy đủ chứa cả giao thức và tên miền (ví dụ: `https://example.com/page.html`), khác với đường dẫn tương đối (relative path).
- **Token**: Một chuỗi ký tự ngẫu nhiên duy nhất được hệ thống sinh ra để xác thực một hành động cụ thể (ví dụ: mã reset mật khẩu, mã xác nhận email).
- **Load Balancer (Bộ cân bằng tải)**: Thiết bị hoặc phần mềm phân phối lưu lượng mạng đến nhiều máy chủ phía sau để tối ưu hóa hiệu năng và độ tin cậy.
- **Reverse Proxy**: Máy chủ trung gian đứng trước các máy chủ web nội bộ để nhận yêu cầu từ client, xử lý bảo mật hoặc cân bằng tải trước khi chuyển tiếp vào bên trong.
