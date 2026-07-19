---
schema_version: 1
id: WEB-A03-SUBDOMAIN-SQUATTING
title: "Domain/Subdomain Squatting & Lookalike Domains"
slug: subdomain-squatting
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A03:2025
cwe:
  - CWE-1007
  - CWE-451
content_status: technical-review
payload_status: none
last_verified: null
---

# Domain/Subdomain Squatting & Lookalike Domains

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích domain/subdomain squatting, typosquatting và homoglyph/lookalike bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể gây nhầm lẫn cho người dùng.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- DNS, eTLD+1, subdomain, IDN/punycode và cách trình duyệt hiển thị host.

- Asset inventory cho domain, subdomain, certificate, email sender và redirect allowlist.

- Phân biệt squatting/lookalike domain với dangling DNS dẫn tới subdomain takeover.

## 3. Kiến thức nền tảng

Hãy tưởng tượng thương hiệu hợp lệ dùng `a-shop.lab.test` để bán hàng và `help.a-shop.lab.test` để hỗ trợ khách hàng. Người dùng thường nhìn rất nhanh vào thanh địa chỉ, email hoặc đường link trong tin nhắn; họ có thể tin một tên miền chỉ vì nó trông gần giống thương hiệu thật.

**Domain/subdomain squatting** xảy ra khi một actor kiểm soát tên miền, tên miền phụ hoặc namespace trông như có liên quan tới thương hiệu nhưng thực tế không thuộc inventory hợp lệ. Các biến thể phổ biến gồm:

- **Typosquatting:** thay, thêm hoặc bỏ ký tự để tạo lỗi gõ như `a-sh0p.lab.test` hoặc `ashop-support.lab.test`.
- **Homoglyph/lookalike:** dùng ký tự Unicode có hình dạng giống ký tự Latin, ví dụ `а-shop.lab.test` trong đó ký tự đầu là Cyrillic `а`.
- **Subdomain lookalike:** dùng cấu trúc tên khiến người dùng hiểu nhầm, ví dụ `login.a-shop.example-owner.lab.test` không phải subdomain của `a-shop.lab.test`.

```yaml
# Local fixture only: canonical inventory and suspicious candidates
canonical_domains:
  - a-shop.lab.test
approved_subdomains:
  - www.a-shop.lab.test
  - help.a-shop.lab.test
  - checkout.a-shop.lab.test
review_candidates:
  - a-sh0p.lab.test
  - ashop-support.lab.test
  - а-shop.lab.test
  - login.a-shop.example-owner.lab.test
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng trong bài này không phải là chiếm quyền tài nguyên DNS mồ côi. Root cause ở đây là **người dùng hoặc hệ thống bị dẫn tới một domain/subdomain có vẻ hợp lệ nhưng không thuộc quyền kiểm soát hoặc không được phép đại diện cho thương hiệu**.

Các nguyên nhân thường gặp:

- Inventory domain/subdomain không đầy đủ nên ứng dụng, email, SSO hoặc tài liệu nội bộ chấp nhận nhầm domain ngoài.
- UI chỉ hiển thị brand label hoặc một phần host, không làm rõ eTLD+1/canonical domain khi người dùng sắp thực hiện hành động nhạy cảm.
- Redirect allowlist, CORS, OAuth callback hoặc email-link validator kiểm tra bằng substring như `contains("a-shop")` thay vì allowlist host đã chuẩn hóa.
- Quy trình phát hiện lookalike, homoglyph và punycode không tồn tại hoặc không được đưa vào review trước khi phát hành chiến dịch.

Subdomain takeover do dangling DNS là bài liên quan nhưng khác cơ chế: takeover cần DNS còn trỏ tới provider resource đã bị giải phóng và provider cho actor khác claim lại binding đó. Bài này chỉ nhắc takeover để phân biệt, không dạy quy trình claim hoặc khai thác binding. [S2]

> **Lưu ý mapping:** metadata dùng CWE-1007 cho trường hợp giao diện không phân biệt đủ homoglyph/punycode và CWE-451 cho việc trình bày domain/brand khiến người dùng hiểu sai thông tin quan trọng. Đây là mapping gần nhất cho user/domain misrepresentation, không bao phủ mọi dạng domain abuse. [S3], [S4]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** canonical domain, approved subdomain, user trust, email sender, redirect URI, OAuth callback và domain inventory synthetic.

- **Actor:** reviewer offline trong lab; không đăng ký domain, không claim subdomain, không gửi email hoặc traffic ra Internet.

- **Trust boundary:** nơi người dùng hoặc hệ thống quyết định một host có đại diện cho thương hiệu hay không: browser UI, email template, redirect handler, CORS/OAuth allowlist và tài liệu nội bộ.

- **Điều kiện cần:** candidate domain/subdomain gây nhầm lẫn với brand hoặc host hợp lệ, đồng thời hệ thống/UI/process không phân biệt đủ host thật với lookalike.

- **Môi trường:** danh sách domain `.lab.test`, script phân loại offline và fixture redirect local; không public DNS.

Chỉ thấy một chuỗi tên "giống giống" chưa đủ kết luận rủi ro. Evidence phải nêu rõ canonical host, candidate host, quy tắc so khớp bị lỗi, vị trí người dùng nhìn thấy domain và hành động nhạy cảm có thể bị ảnh hưởng.

## 6. Cơ chế tấn công

Lookalike domain đánh vào quyết định tin cậy của người dùng hoặc logic allowlist của ứng dụng. Nếu hệ thống chỉ kiểm tra chuỗi con, rút gọn host trong UI hoặc không hiển thị punycode/homoglyph rõ ràng, người dùng có thể nhầm candidate với domain hợp lệ; ứng dụng cũng có thể chấp nhận redirect hoặc callback không thuộc inventory. Cơ chế này khác với subdomain takeover vì không cần DNS của tổ chức trỏ nhầm tới tài nguyên đã deprovision.

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** tạo inventory canonical `.lab.test`, danh sách candidate synthetic và fixture redirect local; không cấu hình resolver/public DNS.
2. **Baseline:** xác nhận host hợp lệ như `a-shop.lab.test` và `help.a-shop.lab.test` được nhận diện đúng sau chuẩn hóa IDNA/lowercase/trailing dot.
3. **Thao tác:** kiểm tra candidate typosquatting, homoglyph và subdomain lookalike bằng script offline; kiểm tra redirect handler chỉ chấp nhận allowlist chính xác.
4. **Expected result:** candidate không thuộc inventory bị cảnh báo hoặc từ chối; UI hiển thị domain đầy đủ/punycode khi có IDN hoặc hành động nhạy cảm.
5. **Boundary:** kiểm tra mixed case, trailing dot, punycode, subdomain nhiều cấp, dấu gạch nối, chữ số thay chữ cái và host có brand nằm ở label không phải eTLD+1.
6. **Cleanup:** xóa fixture local và output test; không đăng ký domain, không claim tenant, không gửi email thật.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu expected result và risk; chỉ chạy trong fixture local có ủy quyền. Bài này không cung cấp payload đăng ký domain, claim dịch vụ hoặc gửi phishing.

```yaml
# Synthetic domain review cases for offline validation
case_id: WEB-A03-SUBDOMAIN-SQUATTING-001
canonical:
  - a-shop.lab.test
approved:
  - www.a-shop.lab.test
  - help.a-shop.lab.test
candidates:
  - host: a-sh0p.lab.test
    reason: digit-substitution typo
  - host: ashop-support.lab.test
    reason: brand-plus-suffix lookalike
  - host: а-shop.lab.test
    reason: Cyrillic homoglyph for Latin a
  - host: login.a-shop.example-owner.lab.test
    reason: brand appears in a non-authoritative label
expected_result: candidates require review or rejection unless explicitly approved in inventory
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: substring matching trusts unrelated lookalike hosts.
from urllib.parse import urlparse

BRAND_FRAGMENT = "a-shop"

def is_trusted_redirect(url):
    host = urlparse(url).hostname or ""
    return BRAND_FRAGMENT in host
```

```python
# SECURE: trust only exact normalized hosts from the owned inventory.
from urllib.parse import urlparse

ALLOWED_HOSTS = {
    "a-shop.lab.test",
    "www.a-shop.lab.test",
    "help.a-shop.lab.test",
}

def normalize_host(host):
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return ""

def is_trusted_redirect(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    host = normalize_host(parsed.hostname or "")
    return host in ALLOWED_HOSTS
```

Host allowlist phải dựa trên canonical inventory đã chuẩn hóa, không dựa vào substring, regex mơ hồ hoặc brand keyword. Với IDN, UI nên hiển thị domain đầy đủ và làm rõ punycode/homoglyph trước hành động nhạy cảm. [S3], [S4]

## 10. Phát hiện

- Đối chiếu URL trong email template, redirect allowlist, OAuth callback, CORS origin, certificate inventory và tài liệu public với canonical domain inventory.

- Flag candidate có edit distance gần brand, chữ số thay chữ cái, dấu gạch nối/đuôi hỗ trợ bất thường, punycode hoặc Unicode homoglyph.

- Kiểm tra UI ở màn hình nhạy cảm có hiển thị host đầy đủ, không chỉ brand label hoặc logo.

- Trong lab chỉ dùng danh sách synthetic; không resolve public DNS, không gửi email và không đăng ký domain để chứng minh.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Duy trì canonical domain/subdomain inventory có owner, mục đích, email/cert/SSO liên quan và ngày review.

- So khớp redirect, OAuth callback, CORS origin và email-link validation bằng exact normalized host allowlist thay vì substring.

- Hiển thị domain đầy đủ hoặc punycode rõ ràng ở bước đăng nhập, thanh toán, cấp quyền OAuth và các hành động nhạy cảm.

### Defense-in-depth

- Theo dõi lookalike/homoglyph domain từ nguồn được ủy quyền và đưa vào quy trình phản hồi thương hiệu.

- Dùng SPF, DKIM, DMARC và template review để giảm khả năng email giả mạo làm người dùng tin domain ngoài inventory.

- Đào tạo người vận hành phân biệt domain hợp lệ, subdomain lookalike và subdomain takeover do dangling DNS.

## 12. Retest

- **Positive:** host canonical và subdomain được approve vẫn hoạt động đúng sau chuẩn hóa.

- **Negative:** typosquatting, homoglyph, punycode lạ và host chứa brand ở label không có thẩm quyền bị từ chối hoặc cảnh báo.

- **Boundary:** mixed case, trailing dot, nhiều cấp subdomain, IDN, brand fragment trong path/query và redirect URL encoded.

- **Telemetry:** lưu candidate, normalized host, rule quyết định, screen/context và owner inventory mà không thu dữ liệu người dùng thật.

## 13. Sai lầm thường gặp

- Đồng nhất subdomain squatting với dangling DNS/subdomain takeover.

- Dùng `contains("brand")` để xác định domain đáng tin.

- Chỉ nhìn domain bằng mắt thường mà không chuẩn hóa IDNA/punycode.

- Chỉ kiểm tra domain chính nhưng bỏ qua email sender, OAuth redirect, CORS và tài liệu người dùng.

- Đăng ký domain hoặc claim tenant thật trong khi lab chỉ cần fixture synthetic.

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

- **Domain squatting:** kiểm soát một domain gây hiểu nhầm là thuộc hoặc được ủy quyền bởi thương hiệu khác.

- **Subdomain squatting:** dùng subdomain hoặc namespace có cấu trúc gây hiểu nhầm về chủ sở hữu thật, ví dụ brand nằm dưới parent domain không thuộc tổ chức.

- **Typosquatting:** tạo biến thể gần giống bằng lỗi gõ, thay chữ bằng số, thêm/bớt dấu gạch nối hoặc đổi TLD.

- **Homoglyph:** ký tự khác mã Unicode nhưng nhìn giống ký tự quen thuộc, có thể làm người dùng đọc nhầm domain.

- **Lookalike domain:** domain/subdomain trông giống domain hợp lệ nhờ typo, homoglyph, brand suffix hoặc bố cục label gây nhầm lẫn.

- **Punycode/IDNA:** cơ chế biểu diễn domain Unicode dưới dạng ASCII; hữu ích để phát hiện và hiển thị IDN đáng ngờ.

- **Subdomain takeover:** bài liên quan nhưng khác cơ chế; xảy ra khi DNS của tổ chức vẫn trỏ tới provider resource đã bị giải phóng và actor khác claim được binding đó. [S2]

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)
- Subdomain takeover/dangling DNS — bài liên quan nhưng khác cơ chế, tập trung vào lifecycle DNS/provider binding thay vì user/domain misrepresentation.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** Microsoft Learn — Prevent dangling DNS entries and avoid subdomain takeover. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover — cập nhật: 2026-01-12; truy cập: 2026-07-18.
- **[S3]** CWE-1007 — Insufficient Visual Distinction of Homoglyphs Presented to User. https://cwe.mitre.org/data/definitions/1007.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** CWE-451 — User Interface (UI) Misrepresentation of Critical Information. https://cwe.mitre.org/data/definitions/451.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
