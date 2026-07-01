# Downgrade Attacks

> **CWE**: CWE-327 | **Phân loại**: Cryptographic Failures

## Kiến thức Nền tảng
Để bảo vệ thông tin cá nhân của bạn khi di chuyển trên không gian mạng, các trình duyệt và máy chủ sử dụng một "đường ống bảo mật" gọi là giao thức TLS. Quá trình thiết lập đường ống này bắt đầu bằng một cuộc trò chuyện xã giao (gọi là **TLS handshake sequence**). Đầu tiên, trình duyệt của bạn sẽ gửi một lời chào (**Client Hello**) kèm theo danh sách những ngôn ngữ mã hóa mà nó biết nói (các cipher suites) và các phiên bản TLS nó hỗ trợ. Máy chủ sẽ lịch sự phản hồi lại bằng một lời chào từ máy chủ (**Server Hello**), chọn phiên bản TLS cao nhất và bộ mật mã an toàn nhất mà cả hai bên cùng hiểu để trò chuyện (gọi là thương lượng mật mã - **cipher negotiation**).

Để quá trình này diễn ra an toàn và nhanh chóng, hệ thống kết hợp hai loại kỹ thuật: **mã hóa bất đối xứng (asymmetric encryption)** và **mã hóa đối xứng (symmetric encryption)**. Trong bước bắt tay đầu tiên, mã hóa bất đối xứng (sử dụng một cặp khóa công-tư) giống như một tấm thẻ chứng minh thư giúp xác thực danh tính của máy chủ và giúp hai bên trao đổi một "mật mã bí mật" một cách an toàn. Khi cuộc bắt tay hoàn tất và chiếc khóa bí mật đã được thống nhất, họ chuyển sang sử dụng mã hóa đối xứng (sử dụng chung một chiếc khóa bí mật này cho cả việc khóa và mở) để truyền tải toàn bộ dữ liệu thực tế. Cách làm này vừa giúp bảo mật dữ liệu tuyệt đối, vừa giúp hệ thống hoạt động cực kỳ nhanh chóng mà không làm chậm thiết bị của bạn.

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

## Mô tả lỗ hổng
Lỗ hổng tấn công hạ cấp (Downgrade Attack) xảy ra khi có một kẻ xấu đứng ở giữa đường truyền (Man-in-the-Middle - MitM) can thiệp vào cuộc trò chuyện ban đầu của bạn. 

Giống như một kẻ trung gian ác ý cố tình sửa bức thư chào hỏi của bạn, chúng xóa bỏ hết các ngôn ngữ bảo mật hiện đại (như TLS 1.3) và chỉ để lại các ngôn ngữ cũ kỹ, đầy lỗ hổng (như SSLv3 hay các thuật toán mã hóa lỗi thời). Máy chủ khi nhận được bức thư bị chỉnh sửa này sẽ nghĩ rằng trình duyệt của bạn quá cũ kỹ và đành phải chấp nhận sử dụng một ngôn ngữ bảo mật yếu ớt hơn để nói chuyện. 

Sự nguy hiểm nằm ở chỗ, một khi kết nối đã bị hạ cấp xuống phiên bản yếu, kẻ tấn công đứng ở giữa có thể dễ dàng bẻ gãy lớp mã hóa lỏng lẻo này, đọc trộm hoặc chỉnh sửa mọi thông tin nhạy cảm của bạn (như mật khẩu, tài khoản ngân hàng) mà không hề bị phát hiện.

## Cơ chế tấn công
Kẻ tấn công chèn chính mình làm kẻ đứng giữa (MitM). Trong quá trình bắt tay TLS, chúng sửa đổi danh sách các thuật toán mã hóa được hỗ trợ của máy khách để chỉ hiển thị các tùy chọn đã lỗi thời (như SSLv3 hoặc RC4). Máy chủ đồng ý sử dụng tiêu chuẩn yếu hơn này, cho phép kẻ tấn công giải mã và nghe lén lưu lượng truy cập phiên làm việc.

## Biện pháp phòng thủ
- **Tóm tắt**: Cấu hình các máy chủ web để từ chối các phiên bản TLS yếu và các thuật toán mã hóa không an toàn, thực thi các giao thức hiện đại (TLS 1.2/1.3), và triển khai HSTS.
- **Các bước chi tiết**:
  - Cấu hình các máy chủ web để chỉ chấp nhận TLS 1.2 và TLS 1.3, vô hiệu hóa SSLv3, TLS 1.0 và TLS 1.1.
  - Thực thi các bộ cipher mạnh mẽ, hiện đại (như AES-GCM và ChaCha20) và ưu tiên cấu hình lựa chọn của máy chủ.
  - Triển khai HTTP Strict Transport Security (HSTS) với max-age dài và bao gồm các tên miền phụ (subdomains) để bắt buộc sử dụng HTTPS.
  - Sử dụng Giá trị Bộ Cipher Tín hiệu Dự phòng TLS (TLS_FALLBACK_SCSV) để ngăn chặn các cuộc tấn công hạ cấp giao thức.
  - Cấu hình cookie phiên làm việc với các cờ Secure và HttpOnly để đảm bảo các định danh phiên không bao giờ được gửi qua các kênh HTTP không được mã hóa.

### Các tấn công downgrade nổi tiếng:
- **POODLE** (Padding Oracle On Downgraded Legacy Encryption): Khai thác SSL 3.0 CBC mode padding oracle. Attacker ép client và server dùng SSL 3.0 để decrypt session.
- **BEAST** (Browser Exploit Against SSL/TLS): Tấn công TLS 1.0 CBC IV predictability, dùng chosen-plaintext attack để decrypt.
- **DROWN** (Decrypting RSA with Obsolete and Weakened eNcryption): Khai thác SSLv2 export-grade cipher. Nếu server hỗ trợ SSLv2, TLS kết nối mới cũng bị ảnh hưởng.

## Code Example
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


## Xem thêm
- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A02:2021-Cryptographic Failures, CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

## Giải thích thuật ngữ
- **TLS (Transport Layer Security)**: Giao thức bảo mật giúp mã hóa thông tin truyền tải trên Internet, đảm bảo dữ liệu không bị đọc trộm hay sửa đổi trên đường đi.
- **TLS Handshake**: Quá trình bắt tay TLS, là giai đoạn khởi đầu của một kết nối an toàn, nơi máy khách và máy chủ thương lượng phiên bản giao thức, xác thực chứng chỉ số và thiết lập các khóa mã hóa.
- **Cipher Suite**: Bộ thuật toán mã hóa, bao gồm một tập hợp các quy tắc và thuật toán mật mã dùng để thiết lập kết nối an toàn (như thuật toán trao đổi khóa, thuật toán mã hóa dữ liệu, thuật toán kiểm tra tính toàn vẹn).
- **Symmetric Encryption (Mã hóa đối xứng)**: Phương pháp mã hóa sử dụng duy nhất một khóa bí mật chung cho cả quá trình mã hóa (khóa dữ liệu) và giải mã (mở dữ liệu). Xử lý rất nhanh và hiệu quả với lượng dữ liệu lớn.
- **Asymmetric Encryption (Mã hóa bất đối xứng)**: Phương pháp mã hóa sử dụng một cặp khóa liên kết với nhau: khóa công khai (Public Key - chia sẻ rộng rãi) để mã hóa và khóa bí mật (Private Key - giữ kín) để giải mã. Thường dùng trong giai đoạn xác thực và trao đổi khóa ban đầu.
- **MitM (Man-in-the-Middle)**: Tấn công kẻ đứng giữa, là hình thức tấn công mà kẻ xấu bí mật can thiệp, nghe lén hoặc sửa đổi thông tin truyền tải giữa hai bên đang giao tiếp trực tiếp với nhau.
- **HSTS (HTTP Strict Transport Security)**: Một chính sách bảo mật web buộc các trình duyệt web luôn sử dụng kết nối HTTPS an toàn thay vì HTTP thông thường, giúp chống lại các cuộc tấn công hạ cấp.
