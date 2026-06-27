# Downgrade Attacks

> **OWASP Top 10:2025**: A04:2025 – Cryptographic Failures | **CWE**: CWE-327 | **Phân loại**: Network

## 🧱 Kiến thức Nền tảng
Giao thức TLS (Transport Layer Security) bảo vệ dữ liệu truyền tải trên mạng bằng cách mã hóa và xác thực. Quá trình bắt tay TLS (**TLS handshake sequence**) bắt đầu bằng thông điệp **Client Hello** gửi từ trình duyệt, chứa các phiên bản TLS hỗ trợ và danh sách các bộ mã hóa (cipher suites) có sẵn. Máy chủ phản hồi bằng **Server Hello**, chọn phiên bản TLS cao nhất và bộ mã hóa an toàn nhất được hỗ trợ bởi cả hai bên (gọi là thương lượng mật mã - **cipher negotiation**).

Trong quá trình bắt tay này, hệ thống sử dụng cả **mã hóa đối xứng (symmetric encryption)** và **mã hóa bất đối xứng (asymmetric encryption)**. Mã hóa bất đối xứng (sử dụng cặp khóa công khai và khóa bí mật) được áp dụng trong giai đoạn bắt tay để xác minh danh tính của máy chủ thông qua chứng chỉ số và thiết lập khóa phiên một cách an toàn sau khi xác thực. Khi khóa phiên được tạo ra, hai bên chuyển sang dùng mã hóa đối xứng (sử dụng cùng một khóa duy nhất cho cả mã hóa và giải mã) để bảo vệ toàn bộ dữ liệu trao đổi thực tế, vì thuật toán đối xứng xử lý nhanh hơn và ít tiêu tốn tài nguyên hơn. Tấn công hạ cấp (Downgrade Attack) can thiệp vào quá trình thương lượng cipher để ép máy chủ và máy khách sử dụng các giao thức TLS lỗi thời hoặc thuật toán mã hóa yếu, từ đó giúp kẻ tấn công bẻ khóa và đọc thông tin.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Python code demonstrating a secure SSL/TLS client connection that prevents downgrade attacks
import socket
import ssl

hostname = 'www.example.com'
port = 443

# Create a secure SSL context enforcing strong cryptographic protocols
# We restrict the communication to TLSv1.2 or TLSv1.3 only, disabling outdated versions
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3

# Configure modern, strong cipher suites for secure cipher negotiation
context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')

# Load default CA certificates to verify the server's identity via asymmetric encryption
context.load_default_certs()

# Establish the connection under secure handshake parameters
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        # Secure TLS handshake occurs here under the hood
        print(f"Successfully negotiated protocol version: {ssock.version()}")
        print(f"Negotiated cipher suite: {ssock.cipher()[0]}")
        
        # Safe communication using symmetric encryption begins
        ssock.sendall(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
```

## 🔍 Mô tả lỗ hổng
Transport Layer Security (TLS) là một giao thức liên tục phát triển. Trong quá trình bắt tay TLS, các máy khách và máy chủ thương lượng các giao thức mật mã và thuật toán mã hóa (ciphers). Trong một cuộc tấn công hạ cấp (downgrade attack), kẻ tấn công đứng ở giữa (Man-in-the-Middle - MitM) sẽ chặn cuộc bắt tay và thao túng các thương lượng nhằm buộc kết nối phải sử dụng các thuật toán mã hóa lỗi thời, yếu hơn mà kẻ tấn công có thể bẻ khóa.

## ⚔️ Cơ chế tấn công
Kẻ tấn công chèn chính mình làm kẻ đứng giữa (MitM). Trong quá trình bắt tay TLS, chúng sửa đổi danh sách các thuật toán mã hóa được hỗ trợ của máy khách để chỉ hiển thị các tùy chọn đã lỗi thời (như SSLv3 hoặc RC4). Máy chủ đồng ý sử dụng tiêu chuẩn yếu hơn này, cho phép kẻ tấn công giải mã và nghe lén lưu lượng truy cập phiên làm việc.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Cấu hình các máy chủ web để từ chối các phiên bản TLS yếu và các thuật toán mã hóa không an toàn, thực thi các giao thức hiện đại (TLS 1.2/1.3), và triển khai HSTS.
- **Các bước chi tiết**:
  - Cấu hình các máy chủ web để chỉ chấp nhận TLS 1.2 và TLS 1.3, vô hiệu hóa SSLv3, TLS 1.0 và TLS 1.1.
  - Thực thi các bộ cipher mạnh mẽ, hiện đại (như AES-GCM và ChaCha20) và ưu tiên cấu hình lựa chọn của máy chủ.
  - Triển khai HTTP Strict Transport Security (HSTS) với max-age dài và bao gồm các tên miền phụ (subdomains) để bắt buộc sử dụng HTTPS.
  - Sử dụng Giá trị Bộ Cipher Tín hiệu Dự phòng TLS (TLS_FALLBACK_SCSV) để ngăn chặn các cuộc tấn công hạ cấp giao thức.
  - Cấu hình cookie phiên làm việc với các cờ Secure và HttpOnly để đảm bảo các định danh phiên không bao giờ được gửi qua các kênh HTTP không được mã hóa.

## 💻 Code Example
```configuration
# Secure TLS and HSTS configuration in Nginx
server {
    listen 443 ssl http2;
    server_name secure.example.com;

    ssl_certificate /etc/ssl/certs/app.crt;
    ssl_certificate_key /etc/ssl/private/app.key;

    # Restrict to TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Enforce secure modern ciphers only
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # Enforce HTTP Strict Transport Security (HSTS)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa các khối mã bị trùng lặp trên Slide 5. Đã cập nhật bộ cipher cấu hình SSL của Nginx để bao gồm các cipher tương thích với TLS 1.2, khắc phục lỗi kết nối tiềm ẩn cho các máy khách cũ hơn trong khi vẫn duy trì tính bảo mật cao.
- **Nguồn tham khảo**: OWASP A02:2021-Cryptographic Failures, CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
