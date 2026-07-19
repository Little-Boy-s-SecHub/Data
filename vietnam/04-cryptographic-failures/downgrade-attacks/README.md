---
schema_version: 1
id: WEB-A04-DOWNGRADE-ATTACKS
title: "Downgrade Attacks"
slug: downgrade-attacks
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-327
content_status: technical-review
payload_status: none
last_verified: null
---

# Downgrade Attacks

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Downgrade Attacks bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- TLS handshake, supported versions và cipher suite.

- Client/server minimum-version policy và fallback.

- OpenSSL/Nginx fixture với certificate lab.

## 3. Kiến thức nền tảng

Để bảo vệ thông tin cá nhân của bạn khi di chuyển trên không gian mạng, các trình duyệt và máy chủ sử dụng một "đường ống bảo mật" gọi là giao thức TLS. Quá trình thiết lập đường ống này bắt đầu bằng một cuộc trò chuyện xã giao (gọi là **TLS handshake sequence**). Đầu tiên, trình duyệt của bạn sẽ gửi một lời chào (**Client Hello**) kèm theo danh sách những ngôn ngữ mã hóa mà nó biết nói (các cipher suites) và các phiên bản TLS nó hỗ trợ. Máy chủ sẽ lịch sự phản hồi lại bằng một lời chào từ máy chủ (**Server Hello**), chọn phiên bản TLS cao nhất và bộ mật mã an toàn nhất mà cả hai bên cùng hiểu để trò chuyện (gọi là thương lượng mật mã - **cipher negotiation**). [S3]

Trong TLS hiện đại, chữ ký bất đối xứng xác thực transcript và ephemeral key agreement tạo shared secret; dữ liệu ứng dụng sau đó được bảo vệ bằng AEAD đối xứng. Các chi tiết này phụ thuộc phiên bản và cipher suite, nên không nên mô tả mọi TLS handshake như “dùng khóa công khai để mã hóa một khóa phiên”. [S3]

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Python code demonstrating a secure SSL/TLS client connection that prevents downgrade attacks
import socket
import ssl

hostname = 'www.victim.lab.test'
port = 443

# Create a secure SSL context enforcing strong cryptographic protocols
# We restrict the communication to TLSv1.2 or TLSv1.3 only, disabling outdated versions
context = ssl.create_default_context(cafile="/lab/ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3

# Establish the connection under secure handshake parameters
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        # Secure TLS handshake occurs here under the hood
        print(f"Successfully negotiated protocol version: {ssock.version()}")
        print(f"Negotiated cipher suite: {ssock.cipher()[0]}")

        # Safe communication using symmetric encryption begins
        ssock.sendall(b"GET / HTTP/1.1\r\nHost: www.victim.lab.test\r\n\r\n")
```

## 4. Mô tả và nguyên nhân gốc

Downgrade attack xảy ra khi actor có vị trí MitM làm hai endpoint thực sự hỗ trợ cấu hình mạnh hơn lại hoàn tất kết nối bằng phiên bản hoặc primitive yếu hơn. Actor không thể chỉ sửa `ClientHello` của một TLS handshake hiện đại rồi giữ kết nối trong suốt: transcript/`Finished` và cơ chế downgrade sentinel của TLS 1.3 sẽ phát hiện nhiều dạng can thiệp. Kịch bản thực tế cần fallback không an toàn, negotiation ngoài kênh chưa được bảo vệ, legacy implementation hoặc lỗi giao thức cụ thể. [S3]

Tác động không tự động là “giải mã mọi lưu lượng”. Phải chứng minh primitive đã thương lượng có điểm yếu có thể khai thác trong đúng threat model. TLS 1.0 và 1.1 đã bị IETF deprecate; baseline hiện hành tối thiểu là TLS 1.2. [S4]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** phiên TLS và thuật toán/protocol được hai endpoint thương lượng.

- **Actor:** legacy peer hoặc logic fallback trong fixture; proxy on-path chỉ tác động nếu điều khiển được fallback/negotiation ngoài TLS đã xác thực. [S3]

- **Trust boundary:** TLS terminator Nginx/OpenSSL chấp nhận version/cipher từ ClientHello.

- **Điều kiện cần:** endpoint còn bật protocol yếu hoặc fallback không được bảo vệ; certificate validation vẫn phải xét.

- **Môi trường:** OpenSSL 3.x client/server container, TLS 1.0-1.3 fixture, packet log local.

Handshake failure hay hỗ trợ legacy không tự chứng minh downgrade; phải chứng minh phiên hoàn tất ở mức yếu ngoài policy mong muốn. [S1]

## 6. Cơ chế tấn công

Peer/proxy làm hai endpoint thương lượng hoặc fallback xuống version/cipher dưới policy. Finding cần một handshake hoàn tất ở mức yếu, không chỉ danh sách cấu hình có chuỗi legacy. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy TLS server disposable với cấu hình legacy/modern riêng và certificate CA lab.
2. **Baseline:** client thương lượng TLS 1.2/1.3 theo policy hiện hành.
3. **Thao tác:** cấu hình legacy client hoặc fallback fixture yêu cầu version/cipher cũ theo ma trận bounded; không giả định transparent proxy có thể sửa ClientHello mà handshake vẫn hợp lệ.
4. **Expected result:** baseline lỗi hoàn tất phiên yếu; cấu hình sửa từ chối và vẫn cho phép client hiện hành.
5. **Boundary:** kiểm tra SNI, ALPN, fallback và subdomain HSTS như vấn đề riêng.
6. **Cleanup:** xóa key/certificate lab và dừng containers.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Trong lab, dùng hai endpoint pin version: baseline chỉ cho TLS 1.2/1.3; negative fixture cố ý bật legacy fallback. Xác nhận phiên bản/cipher đã thương lượng từ cả client và server log. Không dùng MitM trên mạng thật và không kết luận lỗ hổng chỉ vì server còn hỗ trợ TLS 1.2. [S3], [S4]

## 9. Code dễ bị lỗi và code an toàn

```configuration
# VULNERABLE BASELINE: legacy versions remain enabled
# ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

# Secure TLS and HSTS configuration in Nginx
server {
    listen 443 ssl http2;
    server_name secure.victim.lab.test;

    ssl_certificate /etc/ssl/certs/app.crt;
    ssl_certificate_key /etc/ssl/private/app.key;

    # Restrict to TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # TLS 1.2 cipher allowlist for this pinned OpenSSL fixture
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # ssl_ciphers does not pin TLS 1.3 suites. Keep the reviewed OpenSSL 3.x
    # defaults, or configure Ciphersuites through a supported ssl_conf_command
    # only after compatibility tests. Verify the negotiated suite in CI. [S6]

    # Enable includeSubDomains only after every subdomain is HTTPS-ready;
    # HSTS preload is a separate operational decision and enrollment process.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
}
```

## 10. Phát hiện

- Ghi negotiated protocol/cipher cho baseline và đường fallback; hỗ trợ legacy chưa tự chứng minh downgrade. [S3]

- Review minimum version tại mọi TLS terminator và client fallback logic. [S3], [S4]

- Thu handshake transcript và policy result; không tắt certificate validation ngoài case riêng.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Tắt TLS 1.0/1.1 và primitive ngoài policy tại mọi endpoint/terminator. [S4]

- Không tự xây fallback; dùng thư viện hiện hành có downgrade protection. [S3]

### Defense-in-depth

- Inventory client legacy trước khi nâng minimum version.

- Alert khi negotiation xuống mức thấp hơn baseline mong đợi.

## 12. Retest

- **Positive:** client/server hiện hành thương lượng version/cipher trong policy.

- **Negative:** legacy-only peer bị từ chối, không silently fallback.

- **Boundary:** SNI, session resumption, alternate terminator và client khác.

- **Telemetry:** lưu negotiated version/cipher và điểm áp policy.

## 13. Sai lầm thường gặp

- Gọi mọi hỗ trợ legacy là downgrade đã khai thác.

- Kiểm tra một load balancer nhưng bỏ sót origin/sidecar.

- Tắt certificate validation để làm test rồi suy rộng kết quả.

- Mô tả TLS 1.3 cipher suite theo cấu trúc của TLS cũ.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Downgrade:** kết nối hoàn tất với version/primitive yếu hơn policy do fallback hoặc negotiation bị tác động. [S3]

- **TLS negotiation:** handshake chọn version và tham số chung theo protocol. [S3]

- **Minimum version:** ngưỡng protocol thấp nhất endpoint cho phép; TLS 1.0/1.1 đã bị deprecate. [S4]

## 16. Bài liên quan và đọc thêm

- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — phiên bản/ngày: August 2018; truy cập: 2026-07-17.
- **[S4]** RFC 8996 — Deprecating TLS 1.0 and TLS 1.1. https://www.rfc-editor.org/rfc/rfc8996.html — phiên bản/ngày: March 2021; truy cập: 2026-07-17.
- **[S6]** Nginx — ngx_http_ssl_module (`ssl_ciphers`, `ssl_conf_command`, `ssl_protocols`). https://nginx.org/en/docs/http/ngx_http_ssl_module.html — phiên bản/trạng thái: tài liệu hiện hành; truy cập: 2026-07-17.
