# SSL Stripping

> **OWASP Top 10:2025**: A04:2025 – Cryptographic Failures | **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **Phân loại**: Network

## 🧱 Kiến thức Nền tảng
SSL Stripping (tấn công hạ cấp HTTP) là kỹ thuật chuyển đổi kết nối HTTPS an toàn của người dùng thành kết nối HTTP không mã hóa. Để thực hiện điều này, kẻ tấn công đứng ở vị trí trung gian (Man-in-the-Middle - MitM), thường bắt đầu bằng cách xâm nhập mạng cục bộ thông qua **ARP spoofing**. Giao thức **ARP (Address Resolution Protocol)** chịu trách nhiệm ánh xạ địa chỉ IP thành địa chỉ vật lý MAC trong mạng nội bộ. Bằng cách gửi các gói tin ARP giả mạo, kẻ tấn công lừa thiết bị của nạn nhân và bộ định tuyến gửi toàn bộ lưu lượng qua máy của mình.

Tại đây, khi nạn nhân yêu cầu truy cập một trang web bằng HTTP thông thường, kẻ tấn công chặn yêu cầu và thiết lập kết nối HTTPS an toàn với máy chủ đích. Kết nối này sử dụng **mã hóa bất đối xứng** để xác thực, trao đổi khóa và dùng **mã hóa đối xứng** để bảo vệ dữ liệu. Tuy nhiên, kẻ tấn công lại phản hồi nạn nhân bằng phiên bản HTTP không mã hóa. Toàn bộ các liên kết HTTPS trong trang phản hồi đều bị chuyển thành HTTP thô. Do đó, dữ liệu của nạn nhân được truyền tải dưới dạng văn bản rõ (**cleartext**). Kẻ tấn công chỉ cần chạy một chương trình bắt gói tin (**packet sniffer**) trên máy của mình để dễ dàng ghi lại toàn bộ thông tin nhạy cảm của người dùng như mật khẩu hay cookie phiên mà không cần giải mã.

### Minh họa hoạt động bình thường (Normal Operation)
```configuration
# Nginx virtual host configuration enforcing HTTPS and HSTS to mitigate SSL Stripping
server {
    listen 80 default_server;
    server_name example.com www.example.com;

    # Redirect all insecure HTTP requests to canonical HTTPS permanently
    # This prevents the initial unencrypted communication attempt
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name example.com www.example.com;

    # SSL Certificate Configuration
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Configure secure TLS protocols and cipher suites
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    # Strict-Transport-Security (HSTS) prevents SSL Stripping by forcing 
    # the browser to only interact with this domain using HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

## 🔍 Mô tả lỗ hổng
SSL Stripping (hay tấn công hạ cấp HTTP) là kỹ thuật chuyển đổi kết nối HTTPS an toàn của người dùng thành kết nối HTTP không mã hóa. Khi ứng dụng cho phép truy cập song song hoặc chuyển hướng không an toàn, kẻ tấn công ở vị trí trung gian có thể đánh cắp thông tin đăng nhập và token phiên của người dùng. Lỗ hổng này thường xuất hiện trên các hệ thống không ép buộc HTTPS toàn phần hoặc thiếu cấu hình HSTS.

## ⚔️ Cơ chế tấn công
Kẻ tấn công thực hiện tấn công Man-in-the-Middle (MitM) trên cùng phân đoạn mạng với nạn nhân. Khi nạn nhân yêu cầu truy cập trang web bằng giao thức HTTP thông thường, kẻ tấn công sẽ chặn yêu cầu này, thiết lập kết nối HTTPS an toàn với máy chủ thực tế, nhưng trả về một trang web dạng HTTP không mã hóa cho nạn nhân. Công cụ như `sslstrip` sẽ thay thế toàn bộ liên kết HTTPS trong trang thành HTTP, cho phép kẻ tấn công đọc toàn bộ thông tin đăng nhập và token truyền tải dưới dạng văn bản thô, trong khi máy chủ vẫn tin rằng kết nối đang được bảo vệ bằng HTTPS.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Thực thi HTTPS toàn diện, cấu hình HTTP Strict Transport Security (HSTS) với thời hạn lâu dài, đặt cờ bảo mật cho cookie và đăng ký tên miền vào danh sách HSTS preload của trình duyệt.
- **Các bước chi tiết**:
  - Chuyển hướng ngay lập tức tất cả các yêu cầu HTTP sang HTTPS ở phía máy chủ bằng các cấu hình canonical cố định.
  - Triển khai header phản hồi HTTP Strict Transport Security (HSTS) với thời gian dài (tối thiểu 1 năm) cùng các chỉ thị `includeSubDomains` và `preload`.
  - Thiết lập cờ `Secure` cho tất cả các cookie phiên làm việc để ngăn chặn chúng bị truyền qua kết nối HTTP không mã hóa.
  - Đăng ký tên miền vào danh sách HSTS preload được duy trì bởi các nhà sản xuất trình duyệt lớn để bắt buộc kết nối HTTPS ngay từ lần truy cập đầu tiên.

## 💻 Code Example
Cấu hình máy chủ Nginx chuyển hướng HTTP sang HTTPS và bật HSTS:
```configuration
# Nginx server configuration redirecting HTTP to HTTPS and enabling HSTS
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl;
    server_name example.com www.example.com;
    
    # SSL Configuration (required for server to start)
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Secure HSTS header (1 year, includes subdomains, eligible for preload)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

Cấu hình VirtualHost Apache tương đương phòng thủ HSTS:
```configuration
# Apache virtual host configuration for HSTS
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</VirtualHost>
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã cấu hình lại Nginx để khắc phục việc thiếu tên miền phụ `www.example.com` trong khối HTTPS cổng 443 (tránh gây lỗi chứng chỉ khi truy cập qua `www`). Đồng thời thay thế việc sử dụng biến `$host` động bằng domain canonical cố định để chống lại lỗ hổng Host Header Injection và Open Redirect.
- **Nguồn tham khảo**: OWASP Transport Layer Protection, CWE-319, RFC 6797
