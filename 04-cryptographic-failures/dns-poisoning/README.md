---
schema_version: 1
id: WEB-A04-DNS-POISONING
title: "DNS Poisoning"
slug: dns-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-345
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# DNS Poisoning

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích DNS Poisoning bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Recursive DNS, transaction ID, source port và cache.

- Authoritative data, TTL và DNSSEC validation state.

- Đọc packet transcript trong network namespace cô lập.

## 3. Kiến thức nền tảng

Hãy tưởng tượng internet giống như một thành phố khổng lồ, nơi mỗi trang web là một ngôi nhà có địa chỉ số (được gọi là địa chỉ IP). Vì con người chúng ta không thể nhớ nổi những dãy số phức tạp này, chúng ta sử dụng tên miền (như `wikipedia.org`). Để tìm đường đi, các thiết bị của chúng ta phải hỏi một "người dẫn đường" gọi là **DNS resolver** (thường do nhà mạng cung cấp). [S3]

Khi bạn yêu cầu truy cập một trang web, người dẫn đường này sẽ thay bạn đi hỏi qua một chuỗi các máy chủ tên miền khác nhau (gọi là cơ chế phân giải đệ quy - **recursive resolution**), cho đến khi gặp được máy chủ giữ cuốn sổ địa chỉ gốc (gọi là máy chủ có thẩm quyền - **authoritative name server**). Sau khi nhận được địa chỉ IP chính xác, người dẫn đường sẽ ghi chép lại vào một cuốn sổ tay tạm thời (gọi là bộ nhớ đệm - **DNS cache**) với một thời hạn nhất định (**TTL**). Lần sau, nếu bạn hay ai đó trong khu vực hỏi lại tên miền đó, người dẫn đường chỉ cần lật sổ tay ra trả lời ngay lập tức mà không cần đi hỏi lại từ đầu, giúp việc lướt web nhanh hơn rất nhiều. [S3]

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Normal lookup against an OS resolver configured to use the local lab resolver
import socket

def resolve_domain_normally(domain_name):
    # gethostbyname uses the OS resolver configuration; it does not itself
    # request or prove DNSSEC validation.
    try:
        ip_address = socket.gethostbyname(domain_name)
        print(f"Resolved '{domain_name}' to IP: {ip_address}")
        return ip_address
    except socket.gaierror as error:
        print(f"Failed to resolve domain {domain_name}: {error}")
        return None

# The fixture maps this reserved lab name and has no route to public DNS.
target_domain = "service.lab.test"
ip = resolve_domain_normally(target_domain)
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng "Đầu độc DNS" (**DNS Poisoning** hay **DNS Cache Poisoning**) giống như việc kẻ xấu lẻn vào và tráo đổi địa chỉ ghi trong cuốn sổ tay (bộ nhớ đệm) của người dẫn đường. [S3]

Khi người dẫn đường đang gửi câu hỏi đi tìm địa chỉ của một trang web phổ biến, kẻ tấn công nhanh tay gửi hàng loạt câu trả lời giả mạo chứa địa chỉ IP của một "ngôi nhà giả mạo" do chúng dựng sẵn. Nếu kẻ tấn công nhanh chân hơn máy chủ có thẩm quyền thật sự, người dẫn đường sẽ tin câu trả lời giả này và ghi địa chỉ độc hại vào bộ nhớ đệm. [S3]

Hậu quả là từ thời điểm đó, bất kỳ người dùng nào yêu cầu truy cập trang web hợp pháp kia đều sẽ bị người dẫn đường chỉ sang trang web lừa đảo của kẻ tấn công. Lỗ hổng này cực kỳ nguy hiểm bởi vì nạn nhân hoàn toàn gõ đúng địa chỉ trang web trên trình duyệt, không hề có cảnh báo rõ ràng nào, nhưng dữ liệu nhạy cảm hay thông tin đăng nhập của họ lại trực tiếp đi vào tay kẻ xấu. [S3]

> **📌 Phân biệt các cơ chế:**
> - **DNS cache poisoning** (bài này): dữ liệu DNS giả được chấp nhận và lưu trong cache của resolver. Phạm vi ảnh hưởng phụ thuộc resolver đó phục vụ một máy hay nhiều client.
> - **DNS hijacking**: thuật ngữ rộng cho việc đổi trái phép đường phân giải, như chiếm tài khoản registrar/authoritative DNS hoặc sửa cấu hình resolver ở router/client. Nó có thể ảnh hưởng một endpoint, cả mạng hoặc toàn domain.
> - **Hosts-file tampering**: sửa ánh xạ tên cục bộ trên một host; đây không phải là đầu độc cache DNS protocol, dù hậu quả điều hướng có thể giống nhau. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** cache của recursive resolver fixture và tính xác thực DNS answer.

- **Actor:** nguồn trả lời giả trong mô hình; lesson không tạo hay gửi packet.

- **Trust boundary:** BIND 9.18 nhận response cho outstanding query và thực hiện DNSSEC validation.

- **Điều kiện cần:** reply khớp question/ID/addresses/port, tới trước authentic reply và dữ liệu không được DNSSEC xác thực.

- **Môi trường:** resolver/authoritative mock trong container, zone synthetic, không public DNS.

Transcript chỉ giải thích điều kiện; kết luận poisoning cần cache/log fixture đổi sang answer giả, không dựa vào một response lạ. [S3]

## 6. Cơ chế tấn công

Resolver có outstanding query và nhận response giả trước response thật. Chỉ response khớp transaction tuple/question và vượt qua validation mới có thể thay cache; DNSSEC hợp lệ làm dữ liệu giả bị loại. [S3]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy BIND/authoritative mock với zone .lab.test, CPU/network cap và no Internet.
2. **Baseline:** query hợp lệ cache answer của authoritative fixture và DNSSEC case hợp lệ pass.
3. **Thao tác:** dùng harness mô phỏng response matching/mismatching; lesson payload không tự phát packet.
4. **Expected result:** legacy fixture chỉ nhận bản khớp điều kiện; DNSSEC-validating fixture từ chối dữ liệu giả.
5. **Boundary:** kiểm tra ID, source port, question, timing và unsigned delegation riêng.
6. **Cleanup:** flush cache, xóa zone/log và dừng network namespace.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Trong phạm vi bài này, actor nhắm vào outstanding query của recursive resolver để dữ liệu giả đi vào cache. Sửa file hosts, đổi nameserver ở router hoặc chiếm authoritative DNS phải được phân loại và kiểm thử như cơ chế khác, không dùng làm bằng chứng cache poisoning. [S3]

Resolver chỉ nên chấp nhận response khớp question, query ID, địa chỉ và port của truy vấn đang chờ; query ID và source port khó dự đoán làm tăng không gian phải đoán. [S3] Với BIND 9.18, `dnssec-validation auto` dùng root trust anchor được quản lý; khác với `yes`, vốn cần trust anchor được cấu hình. [S4]

### Minh họa DNS Cache Poisoning (Kaminsky Attack 2008):
<!-- payload-id: WEB-A04-DNS-POISONING-001 -->
<!-- context: conceptual transcript for an isolated legacy recursive-resolver fixture; no packet generator; forged-answer matching model [S3] -->
<!-- prerequisites: resolver accepts unsigned forged replies and has weak or predictable query-ID/source-port selection -->
<!-- encoding: UTF-8 explanatory transcript only; no DNS wire-format message, compression pointer, or packet length is emitted -->
<!-- expected-result: the transcript explains every field that must match; no traffic is emitted -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```
# Conceptual DNS cache-poisoning transcript
1. The resolver sends an outstanding query after a cache miss.
2. A forged reply must match the question, query ID, source address,
   destination address, and destination port used by that query.
3. The matching forged reply must arrive before the authentic reply.
4. A modern resolver expands the guess space with unpredictable query IDs
   and source ports; DNSSEC validation rejects forged signed data.
```

## 9. Code dễ bị lỗi và code an toàn

```configuration
// VULNERABLE BIND 9.18 legacy fixture
options {
    recursion yes;
    allow-recursion { any; };
    dnssec-validation no;
};
```

```configuration
// SECURE BIND 9.18 recursive-resolver fixture
acl trusted_clients {
    192.0.2.0/24;
    localhost;
};

options {
    directory "/var/named";
    recursion yes;
    allow-recursion { trusted_clients; };

    // Use BIND's managed root trust anchor for DNSSEC validation
    dnssec-validation auto;
};
```

## 10. Phát hiện

- Đối chiếu query với response về ID, question, source và timing; chỉ cache entry thay đổi mới là side effect. [S3]

- Review resolver recursion, randomization, bailiwick và DNSSEC validation configuration. [S3]

- Thu query/response/cache log local; không phát packet spoof ra mạng thật.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng resolver hiện hành với source-port/transaction randomization và validation phù hợp. [S3]

- Bật DNSSEC validation khi zone/trust model hỗ trợ và xử lý failure đúng policy. [S3]

### Defense-in-depth

- Giới hạn recursion cho client được phép.

- Monitoring cache anomaly hỗ trợ phát hiện, không xác thực dữ liệu.

## 12. Retest

- **Positive:** response authoritative hợp lệ được cache theo TTL.

- **Negative:** response sai transaction/question/source hoặc DNSSEC fail bị bỏ.

- **Boundary:** retry, fragment, CNAME chain, TTL zero và clock skew.

- **Telemetry:** đối chiếu packet transcript, validation state và cache entry.

## 13. Sai lầm thường gặp

- Chỉ thấy DNS trả IP lạ rồi kết luận cache poisoning.

- Bỏ qua source port, question và timing của response.

- Gọi HTTPS certificate warning là bằng chứng DNS bị đầu độc.

- Phát spoof packet ra interface thật để minh họa.

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

- **Recursive resolver:** server thay client truy vấn chuỗi DNS và cache kết quả. [S3]

- **Forged answer:** response giả phải khớp các trường/timing mà resolver dùng để nhận diện query. [S3]

- **DNSSEC validation:** kiểm tra chuỗi chữ ký/trust trước khi coi dữ liệu là secure. [S4]

## 16. Bài liên quan và đọc thêm

- [Downgrade Attacks](../downgrade-attacks/) — Xem thêm bài học về Downgrade Attacks.

## 17. Tài liệu tham khảo

- **[S3]** RFC 5452 — Measures for Making DNS More Resilient against Forged Answers. https://www.rfc-editor.org/rfc/rfc5452.html — phiên bản/ngày: January 2009; truy cập: 2026-07-17.
- **[S4]** ISC BIND 9.18 DNSSEC Guide. https://bind9.readthedocs.io/en/v9.18.38/dnssec-guide.html — phiên bản: BIND 9.18.38; truy cập: 2026-07-17.
