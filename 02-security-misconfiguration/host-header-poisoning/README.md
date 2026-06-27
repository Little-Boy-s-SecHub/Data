# Host Header Poisoning

> **OWASP Top 10:2025**: A02:2025 – Security Misconfiguration | **CWE**: CWE-644 (Improper Handling of HTTP Headers) | **Phân loại**: Request Attacks

## 🧱 Kiến thức Nền tảng
Tấn công đầu độc Host Header (Host Header Poisoning) phát sinh từ việc cấu hình sai hoặc thiếu kiểm tra giá trị của HTTP Host header trên máy chủ và ứng dụng. Khi một yêu cầu HTTP được gửi đi, nó bắt buộc phải chứa một tiêu đề Host để chỉ ra tài nguyên đang được yêu cầu nằm ở tên miền nào. Để hiểu cơ chế của lỗ hổng này, chúng ta cần nắm rõ:
- **HTTP Host Header**: Đây là một tiêu đề HTTP bắt buộc từ phiên bản HTTP/1.1. Khi một trình duyệt gửi yêu cầu đến máy chủ (ví dụ: `GET /index.html`), tiêu đề `Host: example.com` giúp máy chủ biết người dùng muốn truy cập trang web nào. Do tiêu đề này được gửi trực tiếp từ client, kẻ tấn công có thể dễ dàng thay đổi giá trị của nó (ví dụ thành `Host: evil.com`) trước khi gửi lên máy chủ.
- **Virtual Hosting (Lưu trữ ảo)**: Đây là một kỹ thuật cho phép một máy chủ vật lý duy nhất (với một địa chỉ IP duy nhất) lưu trữ và phục vụ nhiều trang web với các tên miền khác nhau (ví dụ: `site1.com`, `site2.com`). Khi có yêu cầu gửi tới địa chỉ IP đó, máy chủ web (như Apache hoặc Nginx) sẽ đọc giá trị trong `Host` header để định tuyến yêu cầu đó đến đúng thư mục chứa mã nguồn của trang web tương ứng. Nếu máy chủ web không được cấu hình chặt chẽ để từ chối các giá trị `Host` lạ, hoặc ứng dụng web tự động sử dụng giá trị `Host` động này để xây dựng các liên kết tuyệt đối (như liên kết đổi mật khẩu), kẻ tấn công có thể lừa ứng dụng tạo ra các liên kết độc hại trỏ về máy chủ của chúng, dẫn đến rò rỉ token khôi phục tài khoản.

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

## 🔍 Mô tả lỗ hổng
Tấn công đầu độc Host Header (Host Header Poisoning) tận dụng việc ứng dụng web tin cậy một cách mù quáng vào giá trị của header 'Host' trong yêu cầu HTTP. Do header này do phía máy khách gửi lên và hoàn toàn có thể bị chỉnh sửa, việc sử dụng nó để sinh các liên kết tuyệt đối (như email khôi phục mật khẩu) sẽ dẫn tới rủi ro nghiêm trọng. Kẻ tấn công có thể thay thế Host header bằng tên miền do chúng kiểm soát, khiến hệ thống gửi email khôi phục mật khẩu chứa liên kết dẫn tới máy chủ của kẻ tấn công, từ đó đánh cắp mã khôi phục.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện chức năng khôi phục mật khẩu của ứng dụng sinh liên kết khôi phục bằng cách lấy giá trị trực tiếp từ HTTP Host Header của yêu cầu.
Bước 2: Kẻ tấn công gửi yêu cầu khôi phục mật khẩu cho tài khoản của nạn nhân (ví dụ: `vic@email.com`), đồng thời sửa đổi Host Header trong HTTP request thành tên miền độc hại do mình kiểm soát (ví dụ: `evil.com`).
Bước 3: Máy chủ xử lý yêu cầu và tạo email khôi phục mật khẩu gửi cho nạn nhân chứa liên kết có dạng `https://evil.com/reset?token=XYZ`.
Bước 4: Nạn nhân nhận email, tin tưởng vào nội dung và nhấn vào link khôi phục mật khẩu. Yêu cầu chứa token khôi phục sẽ được gửi tới máy chủ `evil.com`, giúp kẻ tấn công đánh cắp token và đổi mật khẩu tài khoản.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Prevent Host Header Poisoning by configuring web servers to reject unrecognized host headers and avoiding dynamic host header references in application code.
- **Các bước chi tiết**:
  - Configure the web server with a default server block that drops requests containing invalid or missing Host headers.
  - Explicitly define server names in web server configurations to restrict acceptable Host headers strictly to whitelisted domains.
  - Avoid relying on the incoming HTTP Host header for generating password-reset links, redirects, or absolute URLs within application code.
  - Configure load balancers and reverse proxies to normalize and validate Host and X-Forwarded-Host headers before forwarding to backend apps.

## 💻 Code Example
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Mã nguồn Python ví dụ ngăn chặn việc giả mạo Host header bằng cách kiểm tra giá trị Host với danh sách host được cho phép cố định hoặc cấu hình máy chủ web chỉ chấp nhận các Host được cấu hình cụ thể.
- **Nguồn tham khảo**: OWASP A03:2021, CWE-644, PortSwigger Web Security Academy
