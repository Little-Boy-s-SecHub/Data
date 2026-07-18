---
schema_version: 1
id: WEB-A02-HOST-HEADER-POISONING
title: "Host Header Poisoning"
slug: host-header-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-644
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Host Header Poisoning

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Host Header Poisoning bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- HTTP authority qua `Host`/`:authority` và virtual hosting.

- Reverse-proxy trusted headers và canonical public origin.

- Luồng tạo reset URL qua mail catcher local.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn gửi một lá thư chuyển phát nhanh qua bưu điện. Ở mặt trước lá thư, bưu điện yêu cầu bạn phải ghi rõ thông tin ở ô "Tên miền/Địa chỉ người nhận" (đây chính là **Host Header**). Bưu điện sử dụng ô thông tin này để biết phải chuyển lá thư đó đến tòa nhà nào. Tuy nhiên, nếu nhân viên bưu điện quá ngây thơ, khi lá thư đến nơi, họ lại dùng chính địa chỉ do bạn tự viết tay ở ô "Host Header" để in lên toàn bộ các giấy tờ phản hồi, biên lai chuyển tiền hoặc phiếu hẹn gặp lại của tòa nhà mà không thèm đối chiếu xem địa chỉ đó có thuộc hệ thống chi nhánh chính thức của họ hay không. Kẻ xấu có thể điền một địa chỉ mạo danh vào ô này, lừa bưu điện gửi các phản hồi quan trọng chứa thông tin mật thẳng về hòm thư của chúng. [S3]

Trong giao thức HTTP, **Host Header** là một tiêu đề bắt buộc từ phiên bản HTTP/1.1. Khi bạn truy cập một trang web, trình duyệt sẽ tự động gửi tiêu đề này để thông báo cho máy chủ biết bạn đang muốn truy cập tên miền nào. Điều này cho phép một máy chủ vật lý duy nhất có thể chạy song song nhiều trang web khác nhau (được gọi là **Virtual Hosting - Lưu trữ ảo**). Máy chủ web (như Nginx hay Apache) sẽ đọc Host Header để dẫn đường (định tuyến) yêu cầu của bạn đến đúng thư mục chứa mã nguồn. Lỗ hổng xảy ra khi ứng dụng web tin tưởng hoàn toàn vào giá trị Host Header do người dùng gửi lên để tự động tạo ra các đường link tuyệt đối (như liên kết đổi mật khẩu, link kích hoạt tài khoản) mà không xác thực lại. [S3]

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
    server_name app.victim.lab.test www.app.victim.lab.test; # Explicitly whitelisted domains

    location / {
        # Forward canonical values; strip client-supplied forwarding metadata.
        proxy_set_header Host app.victim.lab.test;
        proxy_set_header X-Forwarded-Host app.victim.lab.test;
        proxy_set_header Forwarded "";
        proxy_pass http://localhost:8080;
    }
}
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Đầu độc Host Header** (Host Header Poisoning) xảy ra khi ứng dụng web tin cậy một cách mù quáng vào giá trị của header Host trong yêu cầu HTTP để tạo ra các liên kết hoặc thực thi logic hệ thống. Do header này do client gửi lên và hoàn toàn có thể bị chỉnh sửa bởi kẻ tấn công, đây là một điểm yếu cấu hình cực kỳ nguy hiểm. [S3]

Kẻ tấn công có thể thay đổi Host từ `app.victim.lab.test` thành `callback.lab.test` khi gửi yêu cầu khôi phục mật khẩu cho tài khoản synthetic. Máy chủ lỗi vẫn xử lý request và mail sink nhận một link bị đầu độc như `https://callback.lab.test/reset?token=LAB_TOKEN`. Nếu user đi theo link, token có thể bị gửi tới origin không tin cậy; fixture chỉ ghi marker cục bộ, không dùng token hay email thật. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** reset URL synthetic và routing tới virtual host hợp lệ.

- **Actor:** client chưa xác thực có thể gửi Host/X-Forwarded-Host tới reverse proxy lab.

- **Trust boundary:** Nginx/ứng dụng xây absolute URL từ forwarded host.

- **Điều kiện cần:** proxy tin header client hoặc ứng dụng không dùng canonical origin; email sink ghi link tạo ra.

- **Môi trường:** Nginx 1.26 và mail catcher loopback, TLS termination cố định, không gửi email Internet.

Response 200 với Host lạ chưa đủ; phải chứng minh link/caching/routing nhạy cảm chứa host không tin cậy. [S1]

## 6. Cơ chế tấn công

Proxy chuyển Host/forwarded-host do client kiểm soát và ứng dụng dùng giá trị đó để tạo absolute reset URL hoặc cache key. Sink email/cache vì thế chứa origin không tin cậy. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy Nginx, app và mail catcher loopback; seed tài khoản synthetic.
2. **Baseline:** Host canonical tạo reset link `app.victim.lab.test`.
3. **Thao tác:** đổi Host và forwarded-host riêng từng request; ghi raw request và email sink.
4. **Expected result:** bản lỗi tạo link callback.lab.test; bản sửa từ chối host hoặc dùng canonical origin.
5. **Boundary:** thử port, nhiều Host, absolute-form và cấu hình proxy đáng tin.
6. **Cleanup:** xóa token/email fixture và dừng services.

## 8. Payload và phạm vi áp dụng

`static-verified` chỉ xác nhận request có framing hợp lệ và dùng dữ liệu synthetic. Chỉ gửi request tới Nginx/app/mail catcher trên loopback hoặc container network cô lập; không gửi email hay request ra Internet. [S3]

<!-- payload-id: WEB-A02-HOST-HEADER-POISONING-001 -->
<!-- context: Nginx 1.26 password-reset fixture with a loopback mail catcher; callback.lab.test is a local reserved-name fixture; HTTP authority model [S3] -->
<!-- prerequisites: synthetic learner account exists; vulnerable app builds absolute reset URLs from Host; no outbound email or network access -->
<!-- encoding: ASCII HTTP/1.1 request; application/x-www-form-urlencoded body is exactly 24 bytes -->
<!-- expected-result: vulnerable mail sink stores a reset URL with host callback.lab.test; secure fixture rejects the Host or uses its configured canonical origin -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /password-reset HTTP/1.1
Host: callback.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close

email=learner%40lab.test
```

Chỉ nội dung trong mail sink local mới được dùng làm bằng chứng. Response thành công nhưng reset URL vẫn dùng canonical origin không chứng minh Host Header Poisoning. [S3]

## 9. Code dễ bị lỗi và code an toàn

```configuration
# VULNERABLE Nginx virtual host: accepts arbitrary Host and forwards it
server {
    listen 80 default_server;
    server_name _;
    location / {
        proxy_set_header Host $http_host;
        proxy_pass http://backend_pool;
    }
}

# SECURE Nginx configuration for the same backend
# 1. Default server block to reject unrecognized hostnames
server {
    listen 80 default_server;
    server_name _;
    return 444; # Terminate connection immediately
}

# 2. Virtual host config for the authorized domain
server {
    listen 80;
    server_name app.victim.lab.test www.app.victim.lab.test;

    location / {
        proxy_set_header Host app.victim.lab.test;
        proxy_set_header X-Forwarded-Host app.victim.lab.test;
        proxy_set_header Forwarded "";
        proxy_pass http://backend_pool;
    }
}
```

## 10. Phát hiện

- Gửi authority hợp lệ/sai rồi kiểm tra URL được lưu trong mail sink, không chỉ response. [S3]

- Review nơi ứng dụng dựng absolute URL từ Host hoặc forwarded headers và cấu hình trusted proxy. [S3]

- Log authority nhận được, canonical origin và nhánh reject; không ghi reset token.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dựng URL nhạy cảm từ canonical origin cấu hình sẵn, không từ authority chưa tin cậy. [S3]

- Validate `Host`/`:authority`; chỉ tin forwarded header từ proxy đã xác định. [S3]

### Defense-in-depth

- Token reset phải single-use, thời hạn ngắn và ràng buộc đúng account.

- Monitoring authority lạ chỉ hỗ trợ phát hiện.

## 12. Retest

- **Positive:** authority hợp lệ tạo URL canonical.

- **Negative:** host lạ bị từ chối hoặc không ảnh hưởng URL gửi mail.

- **Boundary:** absolute-form, port, duplicate Host và proxy chain.

- **Telemetry:** đối chiếu ingress authority, app decision và mail sink.

## 13. Sai lầm thường gặp

- Tin trực tiếp `Host` để dựng reset link.

- Tin `X-Forwarded-Host` từ mọi client.

- Chỉ validate ở proxy nhưng app còn đường truy cập trực tiếp.

- Chỉ nhìn response mà không kiểm tra URL trong side channel.

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

- **Authority:** HTTP/1.1 biểu diễn bằng `Host`; HTTP/2/3 dùng pseudo-header `:authority`. [S3]

- **Canonical origin:** scheme, host và port do ứng dụng cấu hình làm origin công khai tin cậy. [S3]

- **Absolute URL:** URL chứa scheme và authority thay vì chỉ relative path. [S3]

## 16. Bài liên quan và đọc thêm

- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** RFC 9110 — HTTP Semantics, Section 7.2 Host and `:authority`. https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2 — phiên bản/ngày: June 2022; truy cập: 2026-07-18.
