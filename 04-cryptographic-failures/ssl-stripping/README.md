# SSL Stripping

> **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **Phân loại**: Cryptographic Failures

## Kiến thức Nền tảng
Hãy hình dung khi bạn truy cập một trang web ngân hàng, bạn mong đợi một kết nối HTTPS an toàn – giống như việc bạn gửi tiền trong một chiếc xe bọc thép được khóa chặt. Tuy nhiên, nếu bạn chỉ gõ tên web thông thường (ví dụ `nganhang.com` thay vì `https://nganhang.com`), trình duyệt của bạn sẽ cố gắng kết nối bằng HTTP thông thường (không mã hóa) trước, rồi máy chủ mới bảo trình duyệt chuyển hướng sang HTTPS. 

Kẻ tấn công đứng ở giữa đường truyền (Man-in-the-Middle - MitM) có thể khai thác sơ hở này bằng một kỹ thuật gọi là **ARP Spoofing**. Giao thức ARP vốn có nhiệm vụ giúp các máy tính trong cùng mạng nội bộ tìm thấy địa chỉ vật lý (MAC) của nhau dựa trên địa chỉ IP. Bằng cách gửi hàng loạt thông điệp giả mạo, kẻ tấn công lừa máy tính của bạn tin rằng máy của chúng chính là cổng ra Internet (Router), đồng thời lừa Router tin rằng máy của chúng là máy của bạn. Thế là toàn bộ thông tin của bạn gửi đi đều phải đi qua tay kẻ tấn công trước.

Khi bạn gửi yêu cầu kết nối không an sau ban đầu, kẻ tấn công sẽ chặn nó lại. Chúng thay bạn thiết lập một kết nối HTTPS an toàn (sử dụng mã hóa đối xứng và bất đối xứng) với máy chủ ngân hàng để lấy dữ liệu. Nhưng sau đó, chúng lột bỏ lớp bảo mật HTTPS đó đi, biến trang web thành HTTP thông thường (văn bản thô) rồi mới gửi lại cho bạn. Kẻ tấn công lúc này chỉ cần bật một công cụ bắt gói tin (**packet sniffer**) để ngồi đọc toàn bộ mật khẩu, số tài khoản của bạn truyền qua dưới dạng văn bản không mã hóa (**cleartext**).

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

## Mô tả lỗ hổng
Lỗ hổng SSL Stripping (hay tấn công hạ cấp HTTP) là việc hệ thống cho phép kẻ tấn công tước đoạt lớp bảo mật HTTPS và ép nạn nhân giao tiếp bằng giao thức HTTP không mã hóa mà họ không hề hay biết. 

Điều này xảy ra khi một trang web hỗ trợ song song cả HTTP và HTTPS nhưng lại không ép buộc người dùng chuyển hẳn sang HTTPS ngay lập tức, hoặc thiếu cấu hình HSTS (công cụ ra lệnh cho trình duyệt luôn luôn dùng HTTPS). 

Mối nguy hiểm của lỗ hổng này nằm ở chỗ, nạn nhân vẫn thấy trang web hoạt động bình thường, chỉ khác là biểu tượng "ổ khóa xanh" trên thanh địa chỉ biến mất. Nếu không để ý kỹ, họ sẽ dễ dàng nhập thông tin đăng nhập, cookie phiên làm việc, hay thông tin thẻ tín dụng trực tiếp vào tay kẻ xấu đang đứng giữa nghe lén.

## Cơ chế tấn công
Kẻ tấn công thực hiện tấn công Man-in-the-Middle (MitM) trên cùng phân đoạn mạng với nạn nhân. Khi nạn nhân yêu cầu truy cập trang web bằng giao thức HTTP thông thường, kẻ tấn công sẽ chặn yêu cầu này, thiết lập kết nối HTTPS an toàn với máy chủ thực tế, nhưng trả về một trang web dạng HTTP không mã hóa cho nạn nhân. Công cụ như `sslstrip` sẽ thay thế toàn bộ liên kết HTTPS trong trang thành HTTP, cho phép kẻ tấn công đọc toàn bộ thông tin đăng nhập và token truyền tải dưới dạng văn bản thô, trong khi máy chủ vẫn tin rằng kết nối đang được bảo vệ bằng HTTPS.

## Biện pháp phòng thủ
- **Tóm tắt**: Thực thi HTTPS toàn diện, cấu hình HTTP Strict Transport Security (HSTS) với thời hạn lâu dài, đặt cờ bảo mật cho cookie và đăng ký tên miền vào danh sách HSTS preload của trình duyệt.
- **Các bước chi tiết**:
  - Chuyển hướng ngay lập tức tất cả các yêu cầu HTTP sang HTTPS ở phía máy chủ bằng các cấu hình canonical cố định.
  - Triển khai header phản hồi HTTP Strict Transport Security (HSTS) với thời gian dài (tối thiểu 1 năm) cùng các chỉ thị `includeSubDomains` và `preload`.
  - Thiết lập cờ `Secure` cho tất cả các cookie phiên làm việc để ngăn chặn chúng bị truyền qua kết nối HTTP không mã hóa.
  - Đăng ký tên miền vào danh sách HSTS preload được duy trì bởi các nhà sản xuất trình duyệt lớn để bắt buộc kết nối HTTPS ngay từ lần truy cập đầu tiên.

## Code Example
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


## Xem thêm
- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP Transport Layer Protection, CWE-319, RFC 6797

## Giải thích thuật ngữ
- **ARP Spoofing**: Kỹ thuật tấn công trong mạng nội bộ bằng cách gửi các thông điệp ARP giả mạo để liên kết địa chỉ MAC của kẻ tấn công với địa chỉ IP của một máy khác (thường là Router), cho phép kẻ tấn công chặn luồng dữ liệu của nạn nhân.
- **Packet Sniffer**: Phần mềm hoặc thiết bị phần cứng có khả năng theo dõi, đánh chặn và phân tích các gói tin dữ liệu đang truyền tải trên mạng.
- **Cleartext (Văn bản rõ / văn bản thô)**: Thông tin được truyền đi mà không có bất kỳ hình thức mã hóa nào, khiến cho bất kỳ ai chặn được gói tin cũng có thể đọc trực tiếp nội dung một cách dễ dàng.
- **HSTS (HTTP Strict Transport Security)**: Một cơ chế bảo mật phản hồi từ máy chủ web, yêu cầu trình duyệt của người dùng chỉ được phép kết nối qua HTTPS an toàn trong tương lai, ngăn chặn các nỗ lực hạ cấp xuống HTTP.
