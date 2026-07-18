---
schema_version: 1
id: WEB-A04-SSL-STRIPPING
title: "SSL Stripping"
slug: ssl-stripping
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

# SSL Stripping

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích SSL Stripping bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- HTTP-to-HTTPS redirect, HSTS state và preload.

- Khác biệt actor on-path với việc phá TLS.

- Browser profile mới và proxy loopback cô lập.

## 3. Kiến thức nền tảng

Hãy hình dung khi bạn truy cập một trang web ngân hàng, bạn mong đợi một kết nối HTTPS an toàn – giống như việc bạn gửi tiền trong một chiếc xe bọc thép được khóa chặt. Tuy nhiên, nếu bạn chỉ gõ tên host (ví dụ `victim.lab.test` thay vì `https://victim.lab.test`), user agent chưa có HSTS state có thể thử HTTP trước rồi mới nhận chuyển hướng sang HTTPS. Chính request HTTP đầu tiên đó chưa được redirect bảo vệ. HSTS chỉ có hiệu lực sau khi browser nhận header qua HTTPS; preload có thể bảo vệ lần truy cập đầu nếu domain thực sự đã được đưa vào danh sách preload. [S3], [S4]

Điều kiện cốt lõi là actor có vị trí **on-path** và sửa được lưu lượng HTTP ban đầu. ARP spoofing chỉ là một cách có thể tạo vị trí đó trong một số mạng cục bộ; nó không phải điều kiện bắt buộc và bài không thực hiện kỹ thuật này trên mạng thật. [S3]

Actor duy trì kết nối HTTP với browser trong khi có thể mở kết nối HTTPS riêng tới origin. Nếu browser chưa có HSTS/preload state và người dùng tiếp tục trên HTTP, application bytes gửi qua chặng browser–actor là cleartext. Đây không phải là phá TLS: kết nối actor–origin vẫn có thể là một phiên TLS độc lập được xác thực cho origin. [S3], [S5]

### Minh họa hoạt động bình thường (Normal Operation)
```configuration
# Nginx virtual host configuration enforcing HTTPS and HSTS to mitigate SSL Stripping
server {
    listen 80 default_server;
    server_name victim.lab.test www.victim.lab.test;

    # Redirect HTTP to canonical HTTPS, but this response cannot protect the
    # first HTTP request from an on-path attacker.
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name victim.lab.test www.victim.lab.test;

    # SSL Certificate Configuration
    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # TLS versions; ssl_ciphers below applies to TLS 1.2 in this fixture.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    # HSTS applies only after receipt over HTTPS. Roll out max-age gradually;
    # enable includeSubDomains only after every subdomain is HTTPS-ready.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

## 4. Mô tả và nguyên nhân gốc

SSL stripping trong threat model của bài là việc actor on-path giữ browser trên HTTP trước khi HSTS có hiệu lực, đồng thời giao tiếp HTTPS riêng với origin. Nó khai thác bootstrap HTTP không được bảo vệ, không hạ cấp thuật toán bên trong một TLS handshake đã xác thực. [S3], [S5]

Redirect HTTP sang HTTPS là cần cho compatibility nhưng actor on-path có thể sửa redirect đầu tiên. HSTS bảo vệ sau khi browser nhận policy qua HTTPS; preload có thể bảo vệ lần đầu chỉ khi domain đáp ứng yêu cầu và thực sự nằm trong danh sách của user agent. [S3], [S4]

Tác động chỉ được xác nhận khi dữ liệu nhạy cảm synthetic thực sự đi qua chặng HTTP hoặc thao tác bị actor sửa. Sự vắng mặt của chỉ báo HTTPS là tín hiệu cho người dùng, nhưng không thay thế capture/log chứng minh marker đã đi qua cleartext. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** credential/cookie synthetic trong phiên web lab.

- **Actor:** proxy on-path giữa Chromium và victim.lab.test; user chưa có HSTS state là case chính.

- **Trust boundary:** lần điều hướng HTTP đầu, redirect HTTPS và HSTS state của browser.

- **Điều kiện cần:** user bắt đầu bằng HTTP, attacker sửa được traffic và browser chưa có HSTS/preload bảo vệ.

- **Môi trường:** Chromium pin version, Nginx HTTPS loopback, CA lab và proxy local; không ARP spoof mạng thật.

Redirect 301 không bảo vệ request HTTP đầu; HSTS chỉ áp dụng sau khi nhận qua HTTPS, trừ khi preload đã có hiệu lực. [S3], [S4]

## 6. Cơ chế tấn công

Proxy on-path giữ kết nối browser ở HTTP trong khi tự dùng HTTPS tới origin. Browser chưa có HSTS state không biết cần nâng cấp; redirect từ server có thể bị sửa trước khi tới browser. [S3]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** tạo browser profile mới và profile đã có HSTS; chạy Nginx/proxy loopback với certificate lab.
2. **Baseline:** HTTPS trực tiếp hợp lệ; profile HSTS nâng cấp trước khi gửi HTTP.
3. **Thao tác:** nhập victim.lab.test từ profile mới và quan sát request đầu qua proxy; không gửi credential thật.
4. **Expected result:** profile mới có thể phát HTTP đầu; sau HSTS hoặc preload simulation, browser nâng cấp nội bộ và proxy không thấy HTTP.
5. **Boundary:** kiểm tra includeSubDomains chỉ khi mọi subdomain HTTPS-ready và phân biệt preload enrollment.
6. **Cleanup:** xóa profile, certificate/key và proxy capture.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Trong fixture, proxy on-path chỉ thay liên kết/redirect của trang synthetic và ghi marker vô hại. Không dùng credential thật, không ARP spoof và không tuyên bố công cụ có thể “thay mọi liên kết”: URL tuyệt đối, nội dung động, HSTS, mixed-content policy và logic ứng dụng tạo các boundary case riêng. [S3]

## 9. Code dễ bị lỗi và code an toàn

Baseline lỗi vẫn phục vụ nội dung/credential form qua HTTP:
```configuration
# VULNERABLE Nginx server for the fixture
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    location / { proxy_pass http://web_backend; }
}
```

Cấu hình an toàn hơn trên cùng Nginx chuyển hướng HTTP sang HTTPS và bật HSTS:
```configuration
# SECURE Nginx configuration for the same fixture
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl;
    server_name victim.lab.test www.victim.lab.test;

    # SSL Configuration (required for server to start)
    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # Enable includeSubDomains only after every subdomain is HTTPS-ready
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

Cấu hình VirtualHost Apache tương đương phòng thủ HSTS:
```configuration
# Apache virtual host configuration for HSTS
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/victim.lab.test.crt
    SSLCertificateKeyFile /etc/ssl/private/victim.lab.test.key

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

## 10. Phát hiện

- Với profile mới, capture request HTTP đầu, redirect và trạng thái HSTS; chỉ cleartext marker mới chứng minh tác động. [S3]

- Kiểm tra HSTS trên response HTTPS, scope subdomain và trạng thái preload thực tế. [S3], [S4]

- Thu browser network/proxy capture local; không ARP spoof mạng thật.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Phục vụ flow nhạy cảm qua HTTPS và triển khai HSTS sau khi host trong scope đã sẵn sàng. [S3]

- Dùng preload chỉ sau khi đáp ứng yêu cầu và domain thực sự được đưa vào danh sách. [S4]

### Defense-in-depth

- Redirect HTTP hỗ trợ compatibility nhưng không bảo vệ request đầu.

- Secure cookie giảm rò rỉ cookie trên chặng HTTP.

## 12. Retest

- **Positive:** HTTPS hợp lệ hoạt động và HSTS được lưu trên profile.

- **Negative:** sau HSTS/preload, browser không phát request HTTP tới host.

- **Boundary:** profile mới, subdomain, expiry, captive portal và mixed content.

- **Telemetry:** đối chiếu HSTS state, redirect chain và packet capture.

## 13. Sai lầm thường gặp

- Khẳng định redirect 301 bảo vệ request HTTP đầu tiên.

- Nói SSL stripping phá mã hóa của phiên TLS.

- Coi token `preload` trong header là đã có trong preload list.

- Dùng ARP spoofing trên mạng thật để kiểm chứng.

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

- **On-path actor:** actor có khả năng quan sát hoặc sửa traffic trên một chặng mạng. [S3]

- **HSTS:** policy nhận qua HTTPS yêu cầu user agent nâng cấp/kết nối host bằng HTTPS trong thời hạn. [S3]

- **Preload:** trạng thái HSTS được phân phối sẵn; header token không tự đưa domain vào danh sách. [S4]

## 16. Bài liên quan và đọc thêm

- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## 17. Tài liệu tham khảo

- **[S3]** RFC 6797 — HTTP Strict Transport Security. https://www.rfc-editor.org/rfc/rfc6797.html — phiên bản/ngày: November 2012; truy cập: 2026-07-17.
- **[S4]** Chromium HSTS Preload — submission requirements and deployment guidance. https://hstspreload.org/ — phiên bản/trạng thái: trang hiện hành; truy cập: 2026-07-17.
- **[S5]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — phiên bản/ngày: August 2018; truy cập: 2026-07-18.
