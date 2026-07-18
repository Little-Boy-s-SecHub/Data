---
schema_version: 1
id: WEB-A03-SUBDOMAIN-SQUATTING
title: "Subdomain Squatting"
slug: subdomain-squatting
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A03:2025
cwe:
  []
content_status: technical-review
payload_status: none
last_verified: null
---

# Subdomain Squatting

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Subdomain Squatting bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- DNS CNAME/alias và provider custom-domain binding.

- Asset inventory, owner và thứ tự deprovision.

- Phân biệt dangling DNS, takeover và typosquatting.

## 3. Kiến thức nền tảng

Hãy tưởng tượng một thương hiệu thời trang nổi tiếng có tên "A-Shop" sở hữu trang web chính thức `a-shop.com`. Để chia sẻ các xu hướng thời trang mới, họ quyết định viết blog trên một nền tảng viết blog trực tuyến có tên là "EasyBlog". Để giữ uy tín thương hiệu, họ cấu hình hệ thống sao cho khi khách hàng truy cập địa chỉ `blog.a-shop.com`, hệ thống DNS sẽ tự động chuyển hướng (thông qua **bản ghi CNAME - CNAME record**) đến địa chỉ thực tế là `a-shop.easyblog.com` (quá trình này được gọi là **ánh xạ tên miền phụ - subdomain mapping**). [S2]

Sau vài năm, A-Shop quyết định dừng viết blog và hủy đăng ký dịch vụ với EasyBlog. Nền tảng EasyBlog ngay lập tức giải phóng tên miền `a-shop.easyblog.com` để người khác có thể sử dụng. Thế nhưng, một sơ hở nghiêm trọng đã xảy ra: bộ phận kỹ thuật của A-Shop quên không xóa bản ghi CNAME trong cấu hình DNS của họ. Biển chỉ dẫn `blog.a-shop.com` vẫn tiếp tục hướng về `a-shop.easyblog.com` dù trang blog thật sự đã bị xóa. Đây được gọi là bản ghi DNS "mồ côi" (dangling DNS). Một kẻ tấn công phát hiện ra điều này, nhanh chóng đăng ký một tài khoản trên EasyBlog và chiếm đoạt đúng cái tên `a-shop.easyblog.com` đang bị bỏ hoang. Kể từ giây phút đó, kẻ tấn công đã hoàn tất việc chiếm đóng và làm chủ tên miền phụ của A-Shop. [S2]

### Minh họa hoạt động bình thường (Normal Operation)
```text
; BIND zone file snippet showing normal DNS configurations
$TTL 86400
@   IN  SOA     ns1.victim.lab.test. admin.victim.lab.test. (
                2026062701 ; Serial
                3600       ; Refresh
                1800       ; Retry
                604800     ; Expire
                86400 )    ; Minimum TTL

; Name Server records representing authorized DNS servers
    IN  NS      ns1.victim.lab.test.

; Normal A record pointing to the main web server IP
www IN  A       192.0.2.10

; Normal CNAME record mapping a subdomain to an active, verified external cloud service
status IN CNAME  status-page.uptime-provider.com.
```

## 4. Mô tả và nguyên nhân gốc

Nội dung kỹ thuật trong bài này là **dangling DNS dẫn tới subdomain takeover**. Cụm “subdomain squatting” trong tên bài là nhãn cũ, không phải thuật ngữ chuẩn cho cơ chế này và không được nhầm với typosquatting/domain registration. Takeover chỉ có thể xảy ra khi DNS vẫn trỏ tới tài nguyên đã deprovision **và** nhà cung cấp cho actor khác claim đúng binding đó. [S2]

Nếu binding bị claim, actor kiểm soát nội dung nhận traffic của subdomain. Phishing hoặc brand abuse là tác động trực tiếp có thể xảy ra; cookie, CORS, CSP hoặc OAuth chỉ bị ảnh hưởng khi cấu hình tương ứng thực sự mở rộng trust tới subdomain đó. Dangling CNAME hoặc fingerprint 404 đơn lẻ chưa chứng minh claimability. [S2]


> **Lưu ý mapping:** chủ đề này không có một CWE duy nhất đủ chính xác; không gán CWE chỉ vì tên hoặc hậu quả có vẻ tương tự.

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** DNS mapping và ownership của tài nguyên third-party synthetic.

- **Actor:** reviewer offline; không tạo bucket/site/account trên dịch vụ công khai.

- **Trust boundary:** IaC lifecycle giữa DNS record và resource provider.

- **Điều kiện cần:** DNS còn trỏ tới resource đã deprovision và provider cho phép binding được tái claim.

- **Môi trường:** zone/provider mock .lab.test và Terraform plan local; không public DNS.

Dangling CNAME là tín hiệu chứ không chứng minh takeover; cookie/CSP impact chỉ tồn tại khi cấu hình tương ứng thực sự tin subdomain. [S1]

## 6. Cơ chế tấn công

Resource provider bị deprovision nhưng DNS mapping sống lâu hơn. Nếu provider cho tái claim cùng binding, traffic tới subdomain tổ chức được định tuyến sang resource của actor khác. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** tạo state Terraform và zone/provider mock cho resource bound/unbound.
2. **Baseline:** plan của resource active giữ record tương ứng.
3. **Thao tác:** mô phỏng deprovision trong state disposable và kiểm tra plan/remove lifecycle.
4. **Expected result:** cấu hình lỗi để record dangling; cấu hình sửa xóa record cùng resource.
5. **Boundary:** kiểm tra CNAME chain, wildcard và resource đổi owner trong mock.
6. **Cleanup:** destroy fixture local; không claim tên ngoài lab.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Trong fixture, reviewer kiểm tra một CNAME synthetic như `subdomain.victim.lab.test` trỏ tới `unused.provider.lab.test`. Dangling record chỉ là tín hiệu; không claim tài nguyên nhà cung cấp thật. Bài phải phân biệt rõ subdomain takeover do binding nhà cung cấp bị bỏ với typosquatting/domain registration, và chỉ kết luận theo evidence của đúng cơ chế. [S2]

## 9. Code dễ bị lỗi và code an toàn

```configuration
# VULNERABLE Terraform: a standalone DNS record can outlive its provider resource
resource "aws_route53_record" "dangling_cname" {
  zone_id = var.route53_zone_id
  name    = "subdomain.victim.lab.test"
  type    = "CNAME"
  ttl     = 300
  records = ["unused.provider.lab.test"]
}
```

```configuration
# SECURE Terraform showing one reviewed lifecycle for the provider resource
# and its corresponding Route53 record.

resource "aws_s3_bucket" "static_site" {
  bucket = "subdomain.victim.lab.test"
}

resource "aws_s3_bucket_website_configuration" "static_site_config" {
  bucket = aws_s3_bucket.static_site.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_route53_record" "cname_record" {
  zone_id = var.route53_zone_id
  name    = "subdomain.victim.lab.test"
  type    = "CNAME"
  ttl     = "300"

  # The reference gives Terraform dependency ordering during a coordinated
  # plan/apply. The decommission review must still remove/rebind DNS before
  # deleting the provider resource through any separate control plane.
  records = [aws_s3_bucket_website_configuration.static_site_config.website_endpoint]
}
```

## 10. Phát hiện

- Resolve subdomain và đối chiếu provider binding/inventory; record dangling chưa tự chứng minh actor claim được. [S2]

- Review workflow xóa resource, DNS record và custom-domain verification. [S2]

- Chỉ dùng mock provider local; không đăng ký domain hay resource ngoài lab.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xóa DNS trước khi giải phóng provider resource và xác nhận custom-domain binding được thu hồi. [S2]

- Duy trì inventory record–owner–resource, gồm account và region. [S2]

### Defense-in-depth

- Quét dangling record định kỳ và cảnh báo thay đổi ownership.

- Hạn chế wildcard trust cho cookie, CORS, CSP và OAuth redirect.

## 12. Retest

- **Positive:** resource đang dùng khớp inventory và owner.

- **Negative:** workflow không để lại khoảng thời gian record trỏ tới resource claimable.

- **Boundary:** alias chain, wildcard, multi-account và propagation delay.

- **Telemetry:** lưu DNS answer, resource ID, owner và thời điểm lifecycle.

## 13. Sai lầm thường gặp

- Dùng “subdomain squatting” như đồng nghĩa typosquatting.

- Gọi NXDOMAIN hoặc mọi CNAME lỗi là takeover.

- Claim tài nguyên thật khi chưa có ủy quyền.

- Tin `prevent_destroy` sẽ điều phối DNS ở control plane khác.

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

- **Dangling DNS:** record còn tồn tại sau khi provider resource đích đã được giải phóng. [S2]

- **Provider binding:** custom-domain mapping có ownership/lifecycle riêng tại nhà cung cấp. [S2]

- **Subdomain takeover:** actor khác claim binding mà DNS của tổ chức vẫn tham chiếu. [S2]

## 16. Bài liên quan và đọc thêm

- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** Microsoft Learn — Prevent dangling DNS entries and avoid subdomain takeover. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover — cập nhật: 2026-01-12; truy cập: 2026-07-18.
