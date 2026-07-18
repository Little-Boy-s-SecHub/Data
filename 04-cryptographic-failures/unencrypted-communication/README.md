---
schema_version: 1
id: WEB-A04-UNENCRYPTED-COMMUNICATION
title: "Unencrypted Communication"
slug: unencrypted-communication
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-319
content_status: technical-review
payload_status: none
last_verified: null
---

# Unencrypted Communication

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Unencrypted Communication bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- HTTP cleartext, HTTPS và TLS certificate/hostname validation.

- Application data khác network metadata.

- Packet capture trong namespace lab với CA synthetic.

## 3. Kiến thức nền tảng

Hãy tưởng tượng việc gửi thông tin trên mạng Internet giống như việc bạn gửi những bức thư giấy. Nếu bạn sử dụng giao thức không mã hóa (như HTTP thường), bức thư của bạn sẽ được gửi đi mà không hề có phong bì, ai đứng dọc đường cũng có thể dễ dàng đọc trọn vẹn nội dung bên trong (**cleartext**). [S5]

Trong thực tế, khi bạn kết nối vào một mạng Wi-Fi công cộng ở quán cà phê, kẻ tấn công có thể sử dụng các kỹ thuật như **ARP Spoofing** để lừa thiết bị của bạn gửi mọi bức thư qua máy của chúng trước khi đi ra Internet. Tại đây, chúng chỉ cần bật một công cụ gọi là **packet sniffer** (giống như một chiếc máy quét thư tự động) là có thể chụp lại toàn bộ dữ liệu thô của bạn: từ mật khẩu, tài khoản ngân hàng cho tới nội dung tin nhắn riêng tư. [S5]

HTTPS dùng TLS để thương lượng tham số, thiết lập shared keying material, xác thực server (và tùy chọn client), rồi bảo vệ record ứng dụng bằng authenticated encryption. Trong TLS 1.3, không nên mô tả handshake chung là “public key mã hóa khóa phiên”: key exchange, chữ ký và AEAD có vai trò riêng, còn chi tiết phụ thuộc phiên bản/cipher suite. Certificate và hostname validation là điều kiện để client gắn kết kênh TLS với đúng origin. [S5]

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
target_url = "https://service.lab.test:8443/fixture"
secure_content = fetch_secure_data(target_url)
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng "Giao tiếp không mã hóa" (Unencrypted Communication) xảy ra khi một ứng dụng truyền tải các thông tin nhạy cảm của người dùng (như mật khẩu, cookie phiên đăng nhập, thông tin thẻ) qua các giao thức không bảo mật (như HTTP thô, FTP). [S5]

Mối nguy hiểm lớn nhất của lỗ hổng này là nó mở toang cánh cửa cho bất kỳ kẻ xấu nào ở cùng mạng nội bộ (hoặc trên đường truyền Internet) dễ dàng xem trộm và đánh cắp dữ liệu của bạn mà không cần tốn nhiều công sức bẻ khóa. Nếu cookie phiên đăng nhập của bạn bị đọc trộm, kẻ tấn công có thể giả mạo bạn để đăng nhập vào tài khoản ngay lập tức mà không cần biết mật khẩu. [S5]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** credential/cookie/marker synthetic trên kênh ứng dụng.

- **Actor:** observer on-path trong network namespace lab; không sniff Wi-Fi hay mạng thật.

- **Trust boundary:** client Python/browser kết nối HTTP/FTP hoặc TLS tới Nginx service.

- **Điều kiện cần:** dữ liệu nhạy cảm đi qua plaintext hoặc TLS validation bị tắt; metadata công khai không tự tạo finding. [S5]

- **Môi trường:** Python 3.12, Nginx/OpenSSL container, CA lab và packet capture local.

Chỉ kết luận khi capture đọc được marker plaintext; HTTPS với certificate validation phải làm capture chỉ thấy ciphertext/metadata. [S1]

## 6. Cơ chế tấn công

Client gửi application bytes trực tiếp trên HTTP/plaintext protocol nên observer on-path đọc được marker. Với TLS đã xác thực, application bytes được bảo vệ và certificate/hostname mismatch làm client fail closed. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy HTTP và HTTPS fixture trong network namespace, seed marker LAB_CREDENTIAL và bật capture giới hạn.
2. **Baseline:** urllib với default SSL context truy cập service.lab.test bằng CA lab.
3. **Thao tác:** gửi marker qua HTTP fixture rồi HTTPS fixture; không dùng secret thật.
4. **Expected result:** marker thấy trong HTTP capture nhưng không thấy trong TLS application data; invalid certificate bị client từ chối.
5. **Boundary:** kiểm tra redirect, mixed content, proxy termination và TLS version riêng.
6. **Cleanup:** xóa pcap/key/marker và dừng namespace.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công nằm cùng phân đoạn mạng cục bộ với nạn nhân (như mạng Wi-Fi công cộng) và thực hiện các kỹ thuật như giả mạo gói tin ARP (ARP Spoofing) để lừa bộ định tuyến gửi lưu lượng mạng của nạn nhân qua máy của kẻ tấn công. Sử dụng các công cụ bắt gói tin (sniffers), kẻ tấn công dễ dàng trích xuất các thông tin nhạy cảm từ các gói tin HTTP không mã hóa được truyền đi mà không cần bất kỳ thao tác giải mã phức tạp nào. [S5]

## 9. Code dễ bị lỗi và code an toàn

```configuration
# VULNERABLE Nginx server: application data is served over cleartext HTTP
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    location / { proxy_pass http://web_backend; }
}
```

```configuration
# SECURE Nginx server for the same application
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name victim.lab.test www.victim.lab.test;
    # Redirect to the specific, hardcoded host to prevent Host Header Injection
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name victim.lab.test www.victim.lab.test;

    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # TLS versions; ssl_ciphers below applies to TLS 1.2 in this fixture.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA256';

    # Keep reviewed OpenSSL TLS 1.3 defaults or configure its Ciphersuites
    # separately through a supported API; verify negotiated suites in CI.

    # Roll out HSTS after HTTPS readiness; preload is a separate opt-in program.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
}
```

## 10. Phát hiện

- Gửi marker qua HTTP và HTTPS rồi đối chiếu packet capture; chỉ plaintext đọc được mới là bằng chứng. [S5]

- Review URL scheme, TLS validation, internal hop và client error handling. [S5]

- Không capture credential thật hoặc khóa production.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Bảo vệ dữ liệu nhạy cảm bằng TLS đã xác thực trên mọi hop cần thiết; fail closed khi certificate/hostname sai. [S5]

- Loại bỏ protocol cleartext khỏi flow chứa credential, session hoặc dữ liệu nhạy cảm. [S5]

### Defense-in-depth

- HSTS hỗ trợ browser duy trì HTTPS sau khi policy có hiệu lực.

- Network segmentation giảm exposure nhưng không mã hóa payload.

## 12. Retest

- **Positive:** client tin đúng CA/hostname và ứng dụng hoạt động qua HTTPS.

- **Negative:** HTTP bị chặn/chuyển an toàn; certificate hoặc hostname sai làm client fail.

- **Boundary:** internal hop, proxy termination, redirect, client legacy và metadata.

- **Telemetry:** so sánh application marker với packet capture và TLS error.

## 13. Sai lầm thường gặp

- Gọi mọi HTTP metadata công khai là finding nhạy cảm.

- Tắt certificate validation để “dùng HTTPS”.

- Chỉ mã hóa client-to-proxy nhưng bỏ cleartext proxy-to-origin.

- Nói HTTPS che mọi IP, hostname và kích thước traffic.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Cleartext:** application data truyền trên chặng không có cơ chế bảo mật mật mã phù hợp. [S5]

- **Authenticated TLS:** kênh TLS có certificate/hostname hoặc peer identity được xác minh. [S5]

- **Network metadata:** thông tin như peer IP và kích thước/timing không nhất thiết được TLS che giấu. [S5]

## 16. Bài liên quan và đọc thêm

- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — phiên bản/ngày: August 2018; truy cập: 2026-07-18.
