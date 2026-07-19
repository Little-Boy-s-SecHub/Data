---
schema_version: 1
id: WEB-A07-EMAIL-SPOOFING
title: "Email Spoofing"
slug: email-spoofing
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A08:2025
cwe:
  - CWE-345
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Email Spoofing

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Email Spoofing bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Email Spoofing và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng hòm thư truyền thống trước cửa nhà bạn. Ai đó có thể viết một lá thư tay, dán nhãn người gửi là "Cục Thuế" hoặc "Ngân hàng của bạn" rồi nhét vào hòm thư. Vì không có nhân viên bưu điện nào đi xác minh xem người gửi thực sự viết bức thư đó là ai, bạn rất dễ tin tưởng và làm theo hướng dẫn trong thư. Sự thiếu sót này tương tự như cách hoạt động của giao thức gửi email cơ bản trên Internet, gọi là **SMTP (Simple Mail Transfer Protocol)**.

SMTP cơ bản tách danh tính trong envelope (`MAIL FROM`) khỏi trường `From:` hiển thị trong nội dung thư; bản thân trường hiển thị không chứng minh người gửi sở hữu domain đó. Hệ thống thư hiện đại có thể yêu cầu xác thực khi relay và áp dụng SPF, DKIM, DMARC cùng các bộ lọc khác, vì vậy khả năng thư giả được chấp nhận phụ thuộc chính sách của máy chủ gửi/nhận. [S3]

Để vá lỗ hổng nghiêm trọng này, người ta đã bổ sung ba "chốt chặn bảo mật" trong hệ thống DNS của tên miền (SPF, DKIM, và DMARC):
1. **SPF (Xác thực nguồn gốc gửi)**: Giống như một danh sách đăng ký các bưu cục được ủy quyền. Khi nhận thư từ `nganhang.com`, máy chủ nhận sẽ tra cứu DNS để xem địa chỉ IP của máy chủ gửi thư có nằm trong danh sách SPF được ngân hàng cho phép hay không.
2. **DKIM (Chữ ký xác thực nội bộ)**: Hoạt động giống như việc đóng dấu sáp niêm phong bảo mật lên lá thư. Máy chủ gửi thư sẽ dùng một khóa bí mật mật mã để ký số vào email. Máy chủ nhận thư sẽ lấy khóa công khai từ DNS của tên miền người gửi để đối chiếu. Nếu dấu niêm phong bị vỡ hoặc không khớp, bức thư bị coi là giả mạo hoặc đã bị sửa đổi dọc đường.
3. **DMARC (chính sách và alignment)**: DMARC so khớp domain trong trường `From:` với định danh đã xác thực bởi SPF hoặc DKIM. Thư đạt DMARC khi có ít nhất một cơ chế vượt qua kiểm tra **và** aligned; nếu không đạt, receiver cân nhắc chính sách `none`, `quarantine` hoặc `reject` do domain công bố. Receiver vẫn có quyền áp dụng chính sách cục bộ. [S3]

```dns
; DNS TXT Records for SPF, DKIM, and DMARC configurations

; 1. SPF Record: Only allow Google Workspace and the server IP 198.51.100.1 to send mail, hard-fail all others
victim.lab.test.             IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.mail-provider.lab.test -all"

; 2. DKIM Record: Publishes the RSA public key for verification of signing signature under selector 'default'
default._domainkey.victim.lab.test. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

; 3. DMARC Record: Request reject policy when neither SPF nor DKIM produces an aligned pass
_dmarc.victim.lab.test.      IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@victim.lab.test"
```

## 4. Mô tả và nguyên nhân gốc

Giả mạo email xảy ra khi người nhận hoặc hạ tầng nhận thư tin vào danh tính hiển thị mà không có kết quả xác thực và alignment đủ mạnh, hoặc khi chính sách SPF/DKIM/DMARC bị thiếu hay triển khai sai. Đây không phải là tuyên bố rằng mọi SMTP server đều cho phép relay không xác thực. [S3]

Mối nguy hiểm của lỗ hổng này cực kỳ lớn, là vũ khí đắc lực cho các cuộc tấn công lừa đảo (Phishing). Tin tặc có thể giả mạo email của ngân hàng thông báo tài khoản bị khóa, hoặc giả danh đối tác yêu cầu thanh toán hợp đồng vào một số tài khoản khác. Do tiêu đề thư hiển thị giống hệt địa chỉ thật, người dùng rất dễ bị lừa nhấn vào các liên kết độc hại, nhập thông tin đăng nhập hoặc chuyển tiền trực tiếp cho tin tặc mà không hề nghi ngờ.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** độ tin cậy visible From và kết quả SPF/DKIM/DMARC.
- **Actor, xác thực và role:** SMTP sender ngoài không sở hữu victim.lab.test; không có application role.
- **Điều kiện khai thác:** receiver/display tin visible From khi authentication/alignment thiếu hoặc fail-open.
- **Browser, proxy, framework và phiên bản:** SMTP/DNS resolver local được pin với domain/IP dành riêng; không gửi Internet; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với email spoofing, receiver/display tin visible From khi authentication/alignment thiếu hoặc fail-open. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy SMTP/DNS resolver local được pin với domain/IP dành riêng; không gửi Internet; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case email spoofing; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “receiver/display tin visible From khi authentication/alignment thiếu hoặc fail-open”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của email spoofing; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công giả mạo địa chỉ email 'From' để trông giống như một nhà cung cấp dịch vụ hợp pháp và gửi một cảnh báo thay đổi mật khẩu. Liên kết này dẫn nạn nhân đến một trang thu thập thông tin xác thực trông rất thực tế. Khi nạn nhân nhập mật khẩu cũ của họ, trang web sẽ ghi lại mật khẩu đó và chuyển hướng họ đến trang web thực tế để tránh bị nghi ngờ.

### Ví dụ raw SMTP session giả mạo địa chỉ người gửi:
<!-- payload-id: WEB-A07-EMAIL-SPOOFING-001 -->
<!-- context: SMTP test server that accepts mail only inside an isolated lab -->
<!-- prerequisites: local sink mailbox; no Internet relay; SPF/DKIM/DMARC result headers observable -->
<!-- encoding: SMTP commands are ASCII with CRLF line endings; DATA headers/body end with CRLF dot CRLF -->
<!-- expected-result: sink mailbox preserves distinct envelope-from and RFC5322.From values for policy inspection -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```smtp
# Connect only to the isolated SMTP fixture.
EHLO callback.lab.test
MAIL FROM: <sender@callback.lab.test>
RCPT TO: <learner@victim.lab.test>
DATA

From: Lab Executive <executive@victim.lab.test>
To: learner@victim.lab.test
Subject: SMTP identity-alignment lab
Reply-To: sender@callback.lab.test

This message contains no link, credential request, or financial instruction.
.
# The sink must show the header From separately from the envelope sender.
```

## 9. Code dễ bị lỗi và code an toàn

Hai cấu hình DNS sau áp dụng cho cùng domain lab. SPF cho phép mọi sender không tạo ranh giới ủy quyền; ở cấu hình an toàn, SPF giới hạn sender và DMARC yêu cầu reject khi cả SPF lẫn DKIM đều không tạo aligned pass. DMARC chỉ nên chuyển sang enforcement sau khi inventory luồng mail hợp lệ đã được xác nhận. [S3] [S4]

### Không an toàn (vulnerable): SPF cho phép mọi sender, DMARC không enforcement

```configuration
victim.lab.test. IN TXT "v=spf1 +all"
_dmarc.victim.lab.test. IN TXT "v=DMARC1; p=none; pct=100"
```

### An toàn (secure): chỉ ủy quyền sender đã inventory và bật DMARC enforcement

```configuration
# Authorize only reviewed senders and fail all other SPF evaluations
victim.lab.test. IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.mail-provider.lab.test -all"

# Reject messages when neither SPF nor DKIM produces an aligned pass
_dmarc.victim.lab.test. IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@victim.lab.test"
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Email Spoofing, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Triển khai SPF, DKIM aligned và DMARC enforcement; bảo vệ signing key.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Email Spoofing, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Triển khai các bản ghi DNS SPF, DKIM, và DMARC để xác thực người gửi hợp pháp và xác minh tính toàn vẹn của thư email.
- **Các bước chi tiết**:
  - Tạo bản ghi DNS Sender Policy Framework (SPF) xác định chính xác những máy chủ thư nào được phép gửi thư cho tên miền của bạn.
  - Triển khai DomainKeys Identified Mail (DKIM) để ký các tiêu đề thư gửi đi bằng khóa riêng mật mã, xác thực tính toàn vẹn của thư.
  - Công bố DMARC và kiểm tra alignment với trường `From:`. DMARC đạt khi SPF hoặc DKIM có kết quả pass được aligned; chính sách `quarantine`/`reject` áp dụng khi DMARC không đạt, tùy quyết định của receiver. [S3]
  - Kích hoạt các tính năng báo cáo DMARC để giám sát những ai đang gửi email bằng cách sử dụng danh tính tên miền của bạn.
  - Tích hợp bộ lọc thư đầu vào chặn thư đến không đạt các kiểm tra người gửi và đào tạo nhân viên cách nhận diện kỹ thuật xã hội (social engineering).

## 12. Retest

- **Positive case:** với Email Spoofing, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Email Spoofing mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

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

- **SMTP (Simple Mail Transfer Protocol)**: Giao thức mạng tiêu chuẩn dùng để gửi và truyền tải thư điện tử (email) giữa các máy chủ trên Internet.
- **SPF (Sender Policy Framework)**: Bản ghi DNS giúp xác thực email bằng cách chỉ định danh sách các địa chỉ IP của máy chủ được phép gửi email thay mặt cho một tên miền cụ thể.
- **DKIM (DomainKeys Identified Mail)**: Phương pháp xác thực email bằng cách gắn chữ ký số mật mã vào email, giúp máy chủ nhận xác minh email thực sự gửi từ tên miền đó và nội dung không bị chỉnh sửa.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Chính sách bảo mật kết hợp hai cơ chế SPF và DKIM, hướng dẫn máy chủ nhận cách xử lý các email giả mạo (chấp nhận, cách ly hoặc từ chối) và gửi báo cáo về cho chủ sở hữu tên miền.
- **Phishing (Tấn công lừa đảo)**: Kỹ thuật lừa đảo qua mạng, sử dụng email hoặc trang web giả mạo để dụ người dùng tiết lộ thông tin nhạy cảm như mật khẩu, thông tin thẻ tín dụng.
- **DNS Record (Bản ghi DNS)**: Các dòng cấu hình lưu trữ trong hệ thống tên miền, chứa các thông tin như địa chỉ IP của tên miền (bản ghi A), cấu hình máy chủ thư (bản ghi MX) hoặc các cấu hình xác thực (bản ghi TXT).

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-345. https://cwe.mitre.org/data/definitions/345.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC). https://www.rfc-editor.org/rfc/rfc7489.html — phiên bản/trạng thái: RFC 7489; truy cập: 2026-07-18.
- **[S4]** RFC 7208 — Sender Policy Framework (SPF) for Authorizing Use of Domains in Email. https://www.rfc-editor.org/rfc/rfc7208.html — phiên bản/trạng thái: RFC 7208; truy cập: 2026-07-18.
