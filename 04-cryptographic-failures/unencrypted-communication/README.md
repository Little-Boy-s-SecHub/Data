# Unencrypted Communication

> **OWASP Top 10:2025**: A04:2025 – Cryptographic Failures | **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **Phân loại**: Network

## 🧱 Kiến thức Nền tảng
Giao tiếp không mã hóa là việc truyền tải thông tin giữa máy khách và máy chủ dưới dạng văn bản rõ (**cleartext**), thiếu đi sự bảo vệ của các thuật toán mật mã. Kẻ tấn công trên cùng phân đoạn mạng có thể thực hiện tấn công Man-in-the-Middle bằng cách gửi các bản tin giả mạo thuộc giao thức **ARP** (Address Resolution Protocol) nhằm chuyển hướng lưu lượng mạng của nạn nhân qua thiết bị của mình. Sau khi chuyển hướng thành công, kẻ tấn công sử dụng các công cụ bắt gói tin (**packet sniffer**) để thu thập và đọc trực tiếp toàn bộ dữ liệu thô nhạy cảm như mật khẩu hay cookie phiên.

Để ngăn chặn lỗ hổng này, luồng giao tiếp bắt buộc phải được mã hóa bằng TLS/HTTPS. Hệ thống kết hợp cả hai cơ chế mã hóa chính: **mã hóa bất đối xứng (asymmetric encryption)** dùng cặp khóa công khai/bí mật để xác thực danh tính máy chủ thông qua chứng chỉ số và trao đổi khóa đối xứng an toàn; sau đó **mã hóa đối xứng (symmetric encryption)** dùng chung một khóa phiên (session key) sẽ mã hóa toàn bộ dữ liệu thực tế truyền qua lại giữa hai đầu kết nối. Sự kết hợp này đảm bảo dữ liệu truyền đi không thể bị đọc hiểu bởi các sniffer, bảo vệ toàn vẹn thông điệp và ngăn chặn các cuộc tấn công nghe lén trên đường truyền.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Python client showing secure HTTPS connection using standard libraries
import urllib.request
import ssl

def fetch_secure_data(url):
    # Create a default secure SSL context that enforces certificate validation
    # and secure TLS configuration, protecting against cleartext sniffing
    context = ssl.create_default_context()
    
    try:
        # Making a secure request over HTTPS (TLS encryption)
        with urllib.request.urlopen(url, context=context) as response:
            html = response.read()
            print(f"Successfully retrieved secure payload. Status: {response.status}")
            return html
    except ssl.SSLError as e:
        print(f"SSL/TLS handshake or certificate verification failed: {e}")
        return None

# Normal operation: Fetching data securely over HTTPS
target_url = "https://www.python.org"
secure_content = fetch_secure_data(target_url)
```

## 🔍 Mô tả lỗ hổng
Giao tiếp không mã hóa xảy ra khi dữ liệu nhạy cảm được truyền tải giữa máy khách và máy chủ dưới dạng văn bản thô (cleartext), ví dụ như qua giao thức HTTP, FTP. Điều này khiến toàn bộ lưu lượng dữ liệu dễ dàng bị nghe lén, đánh cắp hoặc sửa đổi bởi các bên không được phép. Đây là một lỗ hổng nghiêm trọng có thể dẫn đến việc lộ khóa phiên, mật khẩu và dữ liệu cá nhân.

## ⚔️ Cơ chế tấn công
Kẻ tấn công nằm cùng phân đoạn mạng cục bộ với nạn nhân (như mạng Wi-Fi công cộng) và thực hiện các kỹ thuật như giả mạo gói tin ARP (ARP Spoofing) để lừa bộ định tuyến gửi lưu lượng mạng của nạn nhân qua máy của kẻ tấn công. Sử dụng các công cụ bắt gói tin (sniffers), kẻ tấn công dễ dàng trích xuất các thông tin nhạy cảm từ các gói tin HTTP không mã hóa được truyền đi mà không cần bất kỳ thao tác giải mã phức tạp nào.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Bảo vệ dữ liệu truyền tải bằng cách thực thi mã hóa HTTPS (TLS) bắt buộc, tắt các giao thức không mã hóa, sử dụng HSTS cứng và đảm bảo cấu hình cipher suite an sau khi cấu hình.
- **Các bước chi tiết**:
  - Bắt buộc sử dụng HTTPS/TLS trên toàn bộ ứng dụng và từ chối xử lý tất cả các yêu cầu HTTP thường.
  - Cấu hình tiêu đề Strict-Transport-Security (HSTS) với giá trị chỉ thị `max-age` dài hạn, có kèm `includeSubDomains` and `preload`.
  - Chỉ cho phép các phiên bản giao thức TLS hiện đại và an toàn (TLS 1.2 hoặc TLS 1.3) và vô hiệu hóa các thuật toán cipher suite yếu hoặc đã lỗi thời.
  - Thiết lập thuộc tính `Secure` trên toàn bộ cookie để ngăn trình duyệt tự động gửi chúng qua các kênh HTTP không được bảo vệ.
  - Xác thực chứng chỉ TLS/SSL khi thực hiện các kết nối ra ngoài (như gọi API, kết nối cơ sở dữ liệu).

## 💻 Code Example
```configuration
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name example.com www.example.com;
    # Redirect to the specific, hardcoded host to prevent Host Header Injection
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name example.com www.example.com;

    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # TLS protocols and ciphers hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA256';

    # HSTS (Strict-Transport-Security)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã chỉnh sửa cấu hình chuyển hướng HTTP sang HTTPS của Nginx cổng 80 để không sử dụng biến `$host` động nữa, ngăn chặn hoàn toàn nguy cơ bị lợi dụng để thực hiện tấn công Host Header Injection hoặc Open Redirect. Thay vào đó cấu hình chuyển hướng cứng sang tên miền canonical cố định (`example.com`).
- **Nguồn tham khảo**: OWASP A02:2021, CWE-319, PortSwigger
