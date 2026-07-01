# Unencrypted Communication

> **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **Phân loại**: Cryptographic Failures

## Kiến thức Nền tảng
Hãy tưởng tượng việc gửi thông tin trên mạng Internet giống như việc bạn gửi những bức thư giấy. Nếu bạn sử dụng giao thức không mã hóa (như HTTP thường), bức thư của bạn sẽ được gửi đi mà không hề có phong bì, ai đứng dọc đường cũng có thể dễ dàng đọc trọn vẹn nội dung bên trong (**cleartext**). 

Trong thực tế, khi bạn kết nối vào một mạng Wi-Fi công cộng ở quán cà phê, kẻ tấn công có thể sử dụng các kỹ thuật như **ARP Spoofing** để lừa thiết bị của bạn gửi mọi bức thư qua máy của chúng trước khi đi ra Internet. Tại đây, chúng chỉ cần bật một công cụ gọi là **packet sniffer** (giống như một chiếc máy quét thư tự động) là có thể chụp lại toàn bộ dữ liệu thô của bạn: từ mật khẩu, tài khoản ngân hàng cho tới nội dung tin nhắn riêng tư.

Để bảo vệ bức thư đó, chúng ta cần bọc nó bằng một chiếc phong bì siêu bảo mật gọi là HTTPS (hay giao thức TLS). Đầu tiên, hệ thống sử dụng **mã hóa bất đối xứng** (với cặp khóa công-tư) giống như một quy trình xác thực nghiêm ngặt để đảm bảo bạn đang nói chuyện đúng với máy chủ thật chứ không phải kẻ mạo danh, đồng thời giúp hai bên trao đổi một chiếc khóa bí mật an toàn. Sau đó, toàn bộ cuộc trò chuyện thực sự sẽ được bảo vệ bằng **mã hóa đối xứng** (hai bên dùng chung chiếc khóa bí mật vừa tạo) để mã hóa dữ liệu siêu tốc. Khi đã được mã hóa, bức thư giấy ban đầu biến thành những ký tự vô nghĩa đối với bất kỳ kẻ nghe lén nào dọc đường.

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

## Mô tả lỗ hổng
Lỗ hổng "Giao tiếp không mã hóa" (Unencrypted Communication) xảy ra khi một ứng dụng truyền tải các thông tin nhạy cảm của người dùng (như mật khẩu, cookie phiên đăng nhập, thông tin thẻ) qua các giao thức không bảo mật (như HTTP thô, FTP). 

Mối nguy hiểm lớn nhất của lỗ hổng này là nó mở toang cánh cửa cho bất kỳ kẻ xấu nào ở cùng mạng nội bộ (hoặc trên đường truyền Internet) dễ dàng xem trộm và đánh cắp dữ liệu của bạn mà không cần tốn nhiều công sức bẻ khóa. Nếu cookie phiên đăng nhập của bạn bị đọc trộm, kẻ tấn công có thể giả mạo bạn để đăng nhập vào tài khoản ngay lập tức mà không cần biết mật khẩu.

## Cơ chế tấn công
Kẻ tấn công nằm cùng phân đoạn mạng cục bộ với nạn nhân (như mạng Wi-Fi công cộng) và thực hiện các kỹ thuật như giả mạo gói tin ARP (ARP Spoofing) để lừa bộ định tuyến gửi lưu lượng mạng của nạn nhân qua máy của kẻ tấn công. Sử dụng các công cụ bắt gói tin (sniffers), kẻ tấn công dễ dàng trích xuất các thông tin nhạy cảm từ các gói tin HTTP không mã hóa được truyền đi mà không cần bất kỳ thao tác giải mã phức tạp nào.

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo vệ dữ liệu truyền tải bằng cách thực thi mã hóa HTTPS (TLS) bắt buộc, tắt các giao thức không mã hóa, sử dụng HSTS cứng và đảm bảo cấu hình cipher suite an toàn sau khi cấu hình.
- **Các bước chi tiết**:
  - Bắt buộc sử dụng HTTPS/TLS trên toàn bộ ứng dụng và từ chối xử lý tất cả các yêu cầu HTTP thường.
  - Cấu hình tiêu đề Strict-Transport-Security (HSTS) với giá trị chỉ thị `max-age` dài hạn, có kèm `includeSubDomains` and `preload`.
  - Chỉ cho phép các phiên bản giao thức TLS hiện đại và an toàn (TLS 1.2 hoặc TLS 1.3) và vô hiệu hóa các thuật toán cipher suite yếu hoặc đã lỗi thời.
  - Thiết lập thuộc tính `Secure` trên toàn bộ cookie để ngăn trình duyệt tự động gửi chúng qua các kênh HTTP không được bảo vệ.
  - Xác thực chứng chỉ TLS/SSL khi thực hiện các kết nối ra ngoài (như gọi API, kết nối cơ sở dữ liệu).

## Code Example
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


## Xem thêm
- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A02:2021, CWE-319, PortSwigger

## Giải thích thuật ngữ
- **HTTP (HyperText Transfer Protocol)**: Giao thức truyền tải siêu văn bản không mã hóa — dữ liệu đi dạng văn bản thuần túy (cleartext), bất kỳ ai nghe lén trên đường truyền đều có thể đọc được.
- **HTTPS (HTTP Secure)**: Phiên bản bảo mật của HTTP, sử dụng TLS/SSL để mã hóa toàn bộ dữ liệu trong quá trình truyền — ngay cả khi bị chặn, kẻ tấn công chỉ thấy dữ liệu đã mã hóa.
- **Cleartext (Văn bản rõ / văn bản thô)**: Dữ liệu ở dạng nguyên bản ban đầu, chưa qua bất kỳ thuật toán mã hóa hay biến đổi nào, khiến cho bất kỳ ai cũng có thể đọc và hiểu được nội dung.
- **ARP Spoofing**: Kỹ thuật tấn công giả mạo các bản tin ARP trong mạng cục bộ để liên kết địa chỉ IP của một thiết bị hợp pháp (như Router) với địa chỉ MAC của kẻ tấn công, nhằm điều hướng lưu lượng dữ liệu đi qua máy kẻ tấn công.
- **Packet Sniffer**: Các chương trình hoặc thiết bị dùng để nghe lén, thu thập và phân tích các gói tin dữ liệu truyền đi trên môi trường mạng.
- **Asymmetric Encryption (Mã hóa bất đối xứng)**: Kỹ thuật mã hóa dùng một cặp khóa gồm khóa công khai (Public Key) để mã hóa dữ liệu và khóa bí mật (Private Key) để giải mã.
- **Symmetric Encryption (Mã hóa đối xứng)**: Kỹ thuật mã hóa dùng chung một khóa bí mật cho cả hai chiều mã hóa và giải mã, có ưu điểm là xử lý nhanh chóng.
- **TLS (Transport Layer Security)**: Giao thức mật mã được thiết kế để cung cấp bảo mật truyền thông qua mạng máy tính, là nền tảng bảo mật cho giao thức HTTPS.
