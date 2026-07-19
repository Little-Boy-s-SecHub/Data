---
schema_version: 1
id: WEB-A01-SSRF
title: "Server-Side Request Forgery"
slug: ssrf
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Request Forgery

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Server-Side Request Forgery bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- URL parsing, DNS resolution và HTTP redirect.

- Private, loopback, link-local IPv4/IPv6 và egress policy.

- Hành vi DNS/cache của HTTP client được pin trong fixture.

## 3. Kiến thức nền tảng

Hãy tưởng tượng máy chủ web của bạn giống như một nhân viên hành chính ngồi trong văn phòng bảo mật của một tổng công ty. Văn phòng này nằm bên trong hàng rào bảo mật nghiêm ngặt. Người ngoài không thể tự ý đi vào các phòng ban nội bộ hay xem máy chủ cơ sở dữ liệu của công ty. Tuy nhiên, nhân viên hành chính này có một nhiệm vụ: "Nếu có ai gửi thư yêu cầu tải ảnh hoặc thông tin từ một địa chỉ web bên ngoài để đính kèm vào hồ sơ, nhân viên sẽ tự mình truy cập đường link đó, tải ảnh về và hiển thị lên màn hình". [S3]

Mối nguy hiểm xuất hiện khi một vị khách xấu gửi một yêu cầu có nội dung: "Hãy tải ảnh tại địa chỉ: `http://localhost/admin` hoặc `http://192.168.1.100` (địa chỉ của máy chủ nội bộ)". Vì nhân viên hành chính này đang ngồi *bên trong* mạng nội bộ tin cậy, nên anh ta có thể dễ dàng đi đến các địa chỉ nội hạt này mà không bị tường lửa ngăn chặn (được gọi là bypass tường lửa). Anh ta ngoan ngoãn truy cập vào trang quản trị nội bộ hoặc máy chủ chứa dữ liệu nhạy cảm, lấy thông tin về và gửi ngược lại cho kẻ tấn công bên ngoài. Trong thế giới mạng, hành vi lừa máy chủ thực hiện các yêu cầu nội bộ hoặc tùy ý này được gọi là **SSRF** (Server-Side Request Forgery - Yêu cầu giả mạo từ phía máy chủ). [S3]

Mối nguy hiểm này liên quan trực tiếp đến các địa chỉ **loopback/private IP** (IP vòng lặp hoặc IP nội bộ). Các dải địa chỉ IP riêng tư (như `10.0.0.0/8`, `192.168.0.0/16` theo định nghĩa RFC 1918), loopback (`127.0.0.1` / `localhost`) và dải link-local dành cho dịch vụ metadata đám mây chỉ được sử dụng phía sau ranh giới mạng. Vì máy chủ nằm bên trong ranh giới tin cậy này, server-side HTTP client có thể gửi yêu cầu trực tiếp đến tài nguyên nội bộ, bỏ qua kiểm soát truy cập vòng ngoài. Kẻ tấn công lợi dụng việc này để quét cổng, truy cập trang quản trị cục bộ hoặc đánh cắp token metadata nhạy cảm. [S3]

Chỉ phân giải hostname một lần để kiểm tra IP rồi để HTTP client phân giải lại khi kết nối **không** ngăn DNS rebinding. Kiểm soát an toàn hơn là loại URL tùy ý khỏi input khi có thể; nếu business bắt buộc fetch URL, dùng egress fetch service kiểm tra mọi A/AAAA record, pin destination tại kết nối thực tế, tắt hoặc revalidate từng redirect, giới hạn scheme/port/response và áp egress ACL độc lập. [S3]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng SSRF xảy ra khi ứng dụng cho phép người dùng truyền vào một địa chỉ URL và máy chủ sẽ tự động gửi yêu cầu đến URL đó mà không có bất kỳ bộ lọc hoặc bước xác thực an toàn nào. [S3]

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó biến máy chủ của bạn thành một "nội gián" hoặc một cầu nối trung gian (proxy) để kẻ tấn công khám phá và tấn công mạng nội bộ của bạn. Kẻ xấu có thể lợi dụng điều này để quét các cổng mạng đang mở trong hệ thống nội bộ, truy cập các cơ sở dữ liệu không công khai, hoặc nghiêm trọng hơn là đánh cắp mã khóa truy cập (metadata tokens) từ các dịch vụ điện toán đám mây (như AWS, Google Cloud, Azure). Điều này có thể dẫn đến việc kẻ tấn công chiếm toàn quyền kiểm soát toàn bộ cơ sở hạ tầng đám mây của doanh nghiệp. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** mock metadata và dịch vụ nội bộ chỉ nghe trên loopback/container network.

- **Actor:** client điều khiển URL của chức năng fetch; authentication phụ thuộc route fixture.

- **Trust boundary:** Python requests thực hiện DNS, redirect và kết nối từ server.

- **Điều kiện cần:** URL tới được sink; allowlist/egress policy thiếu; response hoặc side effect quan sát được.

- **Môi trường:** Python 3.12, mock metadata, DNS fixture IPv4/IPv6, outbound Internet bị chặn.

Không dùng endpoint metadata thật: lab phải ánh xạ endpoint metadata giả và xác nhận egress bằng log mock. [S1]

## 6. Cơ chế tấn công

Fetcher phía server parse URL, resolve DNS, theo redirect và kết nối bằng network authority của server. Nếu validation/egress không áp lại ở từng hop, URL client có thể chạm mock internal/metadata service. Full-read SSRF trả nội dung đích về client; semi-blind chỉ lộ khác biệt trạng thái/thời gian; blind SSRF cần callback hoặc egress log để chứng minh server đã kết nối. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy fetcher Python và mock HTTP/DNS trong container network; chặn mọi egress khác.
2. **Baseline:** fetch URL allowlist public-fixture thành công.
3. **Thao tác:** thử loopback, IP literal, redirect tới mock metadata và IPv6 bằng danh sách bounded.
4. **Expected result:** bản lỗi chạm mock internal log; bản sửa chặn trước kết nối hoặc sau mỗi redirect.
5. **Boundary:** kiểm tra DNS đổi kết quả, userinfo, mixed encoding và response size/timeout cap.
6. **Cleanup:** xóa callback log, dừng container và xác nhận egress counter ngoài fixture bằng 0.

## 8. Payload và phạm vi áp dụng

Payload dưới đây chỉ áp dụng cho URL fixture và điều kiện an toàn đã mô tả đầy đủ. Host `.test` phải được ánh xạ tới mock service trong container network cô lập; lab phải chặn toàn bộ outbound Internet. [S3]

<!-- payload-id: WEB-A01-SSRF-001 -->
<!-- context: Python 3.12 link-preview fixture; ssrf-mock.test resolves only inside an isolated container network; destination validation model [S3] -->
<!-- prerequisites: local mock service listens on port 9080; outbound Internet is denied; application accepts an http URL -->
<!-- encoding: ASCII URL with percent-encoding applied by the HTTP client when required -->
<!-- expected-result: vulnerable fixture reaches the mock and its log records marker SSRF_LOCAL_001; secure fixture rejects the destination before connecting -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```text
http://ssrf-mock.test:9080/health?marker=SSRF_LOCAL_001
```

Không thay host fixture bằng địa chỉ nội bộ, link-local hoặc endpoint cloud thật. Chỉ log tại mock service mới chứng minh server đã thực hiện request; nội dung phản hồi khác biệt đơn lẻ chưa đủ kết luận SSRF. [S3]

**Blind/Semi-blind SSRF callback probe**

<!-- payload-id: WEB-A01-SSRF-002 -->
<!-- context: Python 3.12 link-preview fixture where callback.lab.test resolves only inside the isolated container network -->
<!-- prerequisites: local callback recorder listens on 127.0.0.1:9081; outbound Internet is denied; application does not return upstream response body -->
<!-- encoding: ASCII URL; marker is a public fixture string and no secret is included -->
<!-- expected-result: blind vulnerable fixture records one callback hit with marker SSRF_BLIND_002; secure fixture rejects destination before connecting and callback log stays empty -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-18 -->
```text
http://callback.lab.test:9081/ssrf-blind?marker=SSRF_BLIND_002
```

Với semi-blind SSRF, response body không lộ nhưng latency, status hoặc error class thay đổi. Bằng chứng vẫn phải gắn request với egress log hoặc callback recorder trong lab, không dựa riêng vào thông báo lỗi. [S1]

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
import re
from urllib.parse import quote

import requests

def fetch_preview_unsafe(user_url):
    # BAD: the caller controls the destination and redirect chain
    return requests.get(user_url, timeout=5).content


# === SECURE CODE ===
# Users choose a server-side identifier, not a URL. The dedicated fetcher
# enforces DNS/IP policy at connect time and revalidates every redirect hop.
TRUSTED_DESTINATIONS = {
    "public-avatar-cdn": "https://assets.victim.lab.test:8443",
}

def fetch_preview(destination_id, object_id, egress_fetcher):
    base_url = TRUSTED_DESTINATIONS.get(destination_id)
    if base_url is None or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", object_id) is None:
        raise ValueError("Unsupported destination or object identifier")

    # The client selects one opaque identifier, not URL path/query syntax.
    object_path = "/avatars/" + quote(object_id, safe="") + ".png"

    return egress_fetcher.fetch(
        base_url=base_url,
        path=object_path,
        methods={"GET"},
        schemes={"https"},
        ports={8443},
        follow_redirects=False,
        max_response_bytes=2 * 1024 * 1024,
        connect_timeout_seconds=2,
        total_timeout_seconds=5,
    )
```

`egress_fetcher` là security boundary riêng, không phải wrapper chỉ gọi lại hostname bằng HTTP client thông thường. Regression test phải bao phủ IPv4/IPv6, mixed records, DNS rebinding và redirect sang loopback/private/link-local/metadata. [S3]

## 10. Phát hiện

- Gửi URL tới mock public và mock internal; xác nhận socket peer cuối cùng cùng redirect chain. [S3]

- Review parse, resolve, connect, redirect và proxy behavior của server-side client. [S3]

- Log normalized destination, resolved IP, connected peer và redirect hop; không log response secret.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Allowlist đích/protocol theo business need; resolve và kiểm tra mọi IP trước connect, kể cả mỗi redirect. [S3]

- Ràng buộc socket với đích đã kiểm tra hoặc xác minh connected peer để tránh check-then-connect/DNS rebinding. [S3]

### Defense-in-depth

- Chặn egress tới private/link-local và metadata ở network layer.

- Giới hạn timeout, response size và redirect count.

## 12. Retest

- **Positive:** URL allowlisted tới mock public vẫn hoạt động.

- **Negative:** loopback, private, link-local và scheme ngoài policy bị chặn.

- **Boundary:** IPv6, decimal/hex IP, redirect chain và DNS answer thay đổi.

- **Telemetry:** xác nhận resolved IP, socket peer và egress counter.

## 13. Sai lầm thường gặp

- Validate hostname một lần rồi cho client tự follow redirect.

- Chỉ chặn IPv4 dạng dấu chấm.

- Dùng regex URL thay parser chuẩn.

- Cho rằng network egress/WAF thay thế allowlist ở application.

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

- **SSRF:** input không tin cậy khiến server gửi request tới đích ngoài policy ứng dụng. [S3]

- **Loopback/link-local:** address scope nội bộ không nên được URL fetcher công khai truy cập mặc định. [S3]

- **DNS rebinding:** DNS answer thay đổi giữa bước kiểm tra và kết nối, phá check-then-connect. [S3]

## 16. Bài liên quan và đọc thêm

- [XML External Entities](../../05-injection/xxe/) — Lỗ hổng XXE có thể được sử dụng để thực hiện các yêu cầu mạng SSRF trực tiếp từ máy chủ phân tích XML.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Server-Side Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
