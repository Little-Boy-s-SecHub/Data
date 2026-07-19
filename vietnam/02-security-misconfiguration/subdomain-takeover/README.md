---
schema_version: 1
id: WEB-A02-SUBDOMAIN-TAKEOVER
title: "Subdomain Takeover"
slug: subdomain-takeover
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-284
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Subdomain Takeover

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Subdomain Takeover bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- DNS CNAME/alias và vòng đời resource tại provider.

- Khác biệt dangling DNS với NXDOMAIN.

- Kiểm kê owner, zone và provider binding.

## 3. Kiến thức nền tảng

Hãy tưởng tượng công ty của bạn thuê một gian hàng tại một trung tâm thương mại lớn để trưng bày sản phẩm. Để khách hàng dễ tìm đường, bạn đặt một biển chỉ dẫn lớn ở ngã tư ghi: "Gian hàng Đồ gia dụng của Công ty A: Đi thẳng vào Lô 12 trong trung tâm thương mại". Mọi việc diễn ra rất suôn sẻ. Sau một thời gian, công ty của bạn quyết định đóng cửa gian hàng này và trả lại mặt bằng Lô 12 cho trung tâm thương mại. Thế nhưng, nhân viên của bạn lại quên không đi gỡ bỏ biển chỉ dẫn ở ngã tư. Biển hiệu đó vẫn nằm trơ trọi ở đó, tiếp tục hướng dẫn khách hàng tìm đến Lô 12. [S5]

Một kẻ xấu đi ngang qua, nhìn thấy Lô 12 hiện đang trống và biển chỉ dẫn vẫn còn hiệu lực. Hắn lập tức đến gặp ban quản lý trung tâm thương mại, thuê lại đúng Lô 12 này, trang trí nó giống hệt gian hàng cũ của bạn nhưng bên trong lại bán hàng giả, hàng nhái để lừa gạt những vị khách tin cậy đi theo biển chỉ dẫn. [S5]

Trong thế giới mạng, sơ hở này xảy ra với hệ thống **DNS (Domain Name System)**. Các doanh nghiệp thường tạo các bản ghi **CNAME (Canonical Name)** để trỏ tên miền phụ của mình (ví dụ: `docs.company.lab.test`) đến các dịch vụ lưu trữ đám mây bên thứ ba (như AWS S3, GitHub Pages, Heroku, Azure). Khi doanh nghiệp ngừng sử dụng dịch vụ đám mây đó (xóa bucket, xóa ứng dụng) nhưng lại quên xóa bản ghi CNAME tương ứng trong cấu hình DNS của mình, họ đã tạo ra một bản ghi "mồ côi" (dangling CNAME). [S5]

```bash
# Normal DNS configuration in the loopback fixture
$ dig @127.0.0.1 -p 5353 blog.company.lab.test CNAME +short
bound.provider.lab.test.

# DNS resolution chain:
# blog.company.lab.test → CNAME → bound.provider.lab.test → A → 127.0.0.1
# Browser requests the lab subdomain and receives content from the provider mock
```

```text
# Example synthetic DNS zone; no public provider names
; Subdomain CNAME records pointing to external services
blog.company.lab.test.     IN  CNAME  bound.provider.lab.test.
docs.company.lab.test.     IN  CNAME  unused.provider.lab.test.
status.company.lab.test.   IN  CNAME  status.provider.lab.test.
landing.company.lab.test.  IN  CNAME  landing.provider.lab.test.
```

Quy trình hoạt động bình thường: DNS CNAME trỏ đến cloud service → cloud service nhận request → trả về nội dung hợp lệ. Tuy nhiên, vấn đề phát sinh khi tổ chức **ngừng sử dụng dịch vụ cloud** (xóa S3 bucket, unprovision Heroku app) nhưng **quên xóa bản ghi CNAME** trong DNS. [S5]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Chiếm đoạt tên miền phụ** (Subdomain Takeover) cần hai điều kiện: DNS của tổ chức còn trỏ tới tài nguyên đã deprovision, và nhà cung cấp vẫn cho phép actor khác claim binding đó. Dangling CNAME hoặc chuỗi 404 đơn lẻ chỉ là tín hiệu; không phải bằng chứng claimability. Nếu takeover thành công, actor có thể kiểm soát nội dung trên subdomain. Rò rỉ cookie chỉ xảy ra với cookie có `Domain` bao phủ subdomain hoặc logic khác gửi secret tới host đó; host-only cookie không tự động được gửi. CSP/CORS chỉ bị ảnh hưởng nếu policy thực sự tin cậy origin đã bị chiếm. [S5], [S6]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** DNS binding synthetic giữa docs.company.lab.test và provider mock.

- **Actor:** reviewer được ủy quyền; không đăng ký/claim tài nguyên nhà cung cấp thật.

- **Trust boundary:** lifecycle DNS của tổ chức và ownership binding tại provider.

- **Điều kiện cần:** bản ghi dangling và provider xác nhận actor khác có thể claim đúng binding; fingerprint/404 chưa đủ.

- **Môi trường:** DNS 127.0.0.1:5353, provider mock 127.0.0.1:9080, no public resolver/Internet.

Kết quả lab chỉ là DANGLING_SIGNAL_ONLY; kết luận takeover thật cần evidence claimability được provider/owner cho phép. [S5], [S6]

## 6. Cơ chế tấn công

DNS vẫn phân giải subdomain tới binding đã bị provider bỏ. Takeover chỉ hình thành nếu provider cho actor khác claim đúng binding; fingerprint response chỉ hỗ trợ điều tra. [S5], [S6]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** nạp DNS và provider-state synthetic; chặn Internet; bật query/mock log.
2. **Baseline:** record bound trả BOUND_IN_FIXTURE.
3. **Thao tác:** kiểm tra record unused bằng dig/curl local hoặc hàm offline, không resolve domain công khai.
4. **Expected result:** tool trả DANGLING_SIGNAL_ONLY, không trả VULNERABLE và không tự claim tài nguyên.
5. **Boundary:** kiểm tra CNAME chain, record thiếu và provider state unknown.
6. **Cleanup:** xóa zone/mock state và xác nhận network log chỉ có loopback.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Kiểm tra dangling CNAME trong fixture local**

<!-- payload-id: WEB-A02-SUBDOMAIN-TAKEOVER-001 -->
<!-- context: dig 9.18 and curl; DNS fixture at 127.0.0.1:5353; HTTP fixture at 127.0.0.1:9080; dangling-DNS model [S5] -->
<!-- prerequisites: no public resolver, provider account, or Internet route is used -->
<!-- encoding: UTF-8 shell source with ASCII DNS names; dig/curl construct DNS and HTTP framing; no user-controlled byte sequence -->
<!-- expected-result: DNS returns unused.provider.lab.test and the mock provider reports UNBOUND; this proves only the lab fixture state -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S5 -->
<!-- last-verified: 2026-07-17 -->
```bash
dig @127.0.0.1 -p 5353 docs.company.lab.test CNAME +short
curl --fail-with-body -H 'Host: unused.provider.lab.test' \
  http://127.0.0.1:9080/status
```

## 9. Code dễ bị lỗi và code an toàn

Ví dụ dùng Python 3.12 và cùng một fixture inventory DNS offline; nó không phân giải DNS hay gửi HTTP. Fingerprint chỉ là tín hiệu điều tra, còn trạng thái claimable phải được xác nhận bằng bằng chứng được nhà cung cấp cho phép. [S5]

### Không an toàn (vulnerable): coi fingerprint là bằng chứng takeover

```python
FIXTURE_RECORDS = {
    "docs.company.lab.test": "unused.provider.lab.test",
    "status.company.lab.test": "bound.provider.lab.test",
}

FIXTURE_BINDINGS = {
    "unused.provider.lab.test": False,
    "bound.provider.lab.test": True,
}

def classify_vulnerable(fingerprint_seen):
    # Vulnerable: a response fingerprint cannot prove provider claimability
    return "TAKEOVER_CONFIRMED" if fingerprint_seen else "NO_FINDING"
```

### An toàn (secure): giữ kết quả ở trạng thái cần provider review

```python
def review_fixture(subdomain, records, bindings):
    # Secure: classify synthetic evidence without claiming real-world takeover
    cname_target = records.get(subdomain)
    if cname_target is None:
        return {"subdomain": subdomain, "status": "NO_CNAME_IN_FIXTURE"}

    if cname_target not in bindings:
        return {
            "subdomain": subdomain,
            "cname": cname_target,
            "status": "MANUAL_PROVIDER_REVIEW_REQUIRED",
        }

    if bindings[cname_target] is False:
        return {
            "subdomain": subdomain,
            "cname": cname_target,
            "status": "DANGLING_SIGNAL_ONLY",
            "note": "Provider-authorized claimability evidence is still required",
        }

    return {
        "subdomain": subdomain,
        "cname": cname_target,
        "status": "BOUND_IN_FIXTURE",
    }


result = review_fixture(
    "docs.company.lab.test",
    FIXTURE_RECORDS,
    FIXTURE_BINDINGS,
)
assert result["status"] == "DANGLING_SIGNAL_ONLY"
```

Việc phòng ngừa phải gắn lifecycle DNS với lifecycle tài nguyên. Terraform dependency chỉ sắp thứ tự trong cùng plan/apply hoặc full-stack destroy; nó không tự xóa record khi một người deprovision tài nguyên provider qua luồng khác. [S5]

```terraform
# resource "aws_s3_bucket" "docs" {
#   bucket = "company-docs"
# }
#
# resource "aws_route53_record" "docs_cname" {
#   zone_id = aws_route53_zone.main.zone_id
#   name    = "docs.company.lab.test"
#   type    = "CNAME"
#   ttl     = 300
#   records = [aws_s3_bucket.docs.website_endpoint]
#   # Remove or rebind this record in the same reviewed change BEFORE the
#   # provider resource is deprovisioned; inspect the plan for both actions.
# }
```

## 10. Phát hiện

- Resolve record rồi kiểm tra provider binding bằng mock; DNS trỏ tới đích chưa đủ chứng minh takeover. [S5]

- Review asset inventory và thứ tự deprovision giữa resource với DNS. [S5]

- Log zone, record, resource owner và trạng thái binding; không thử claim dịch vụ thật.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xóa hoặc cập nhật DNS trước khi giải phóng resource bên thứ ba; xác nhận binding không còn claimable. [S5]

- Duy trì inventory liên kết record với owner và lifecycle của provider resource. [S5]

### Defense-in-depth

- Quét định kỳ dangling record và alert khi target đổi trạng thái.

- Giảm trust cookie/CORS/CSP đối với wildcard subdomain.

## 12. Retest

- **Positive:** record đang dùng vẫn ánh xạ tới resource do tổ chức sở hữu.

- **Negative:** deprovision workflow xóa DNS trước khi resource được giải phóng.

- **Boundary:** alias chain, wildcard, nhiều account/region và propagation delay.

- **Telemetry:** đối chiếu DNS answer, inventory và provider ownership.

## 13. Sai lầm thường gặp

- Gọi mọi CNAME lỗi là takeover.

- Claim resource thật để “xác minh” khi chưa được ủy quyền.

- Xóa resource trước rồi chờ TTL mới xóa DNS.

- Bỏ sót wildcard và record do team khác quản lý.

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

- **Dangling DNS:** record còn trỏ tới resource bên thứ ba đã bị xóa hoặc giải phóng. [S5]

- **Provider binding:** liên kết phía provider giữa custom domain và resource/account sở hữu nó. [S5]

- **Subdomain takeover:** actor khác claim binding còn được DNS của tổ chức tham chiếu. [S5]

## 16. Bài liên quan và đọc thêm

- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## 17. Tài liệu tham khảo

- **[S5]** Microsoft Learn — Prevent dangling DNS entries and avoid subdomain takeover. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover — cập nhật: 2026-01-12; truy cập: 2026-07-17.
- **[S6]** MDN — Set-Cookie `Domain` and host-only cookies. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
