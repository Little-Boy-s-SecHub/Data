# Email Spoofing

> **CWE**: CWE-345 | **Phân loại**: Supply Chain

## Kiến thức Nền tảng
Hãy tưởng tượng hòm thư truyền thống trước cửa nhà bạn. Ai đó có thể viết một lá thư tay, dán nhãn người gửi là "Cục Thuế" hoặc "Ngân hàng của bạn" rồi nhét vào hòm thư. Vì không có nhân viên bưu điện nào đi xác minh xem người gửi thực sự viết bức thư đó là ai, bạn rất dễ tin tưởng và làm theo hướng dẫn trong thư. Sự thiếu sót này tương tự như cách hoạt động của giao thức gửi email cơ bản trên Internet, gọi là **SMTP (Simple Mail Transfer Protocol)**. 

Khi được thiết kế vào những ngày đầu của Internet, SMTP chỉ chú trọng vào việc truyền tải thư nhanh chóng chứ hoàn toàn không có cơ chế xác thực người gửi. Tiêu đề người gửi (`From:`) chỉ là một chuỗi văn bản tự do do người gửi tự điền, cho phép bất kỳ ai cũng có thể giả mạo thành sếp của bạn, đối tác làm ăn hoặc một thương hiệu lớn để gửi email lừa đảo.

Để vá lỗ hổng nghiêm trọng này, người ta đã bổ sung ba "chốt chặn bảo mật" trong hệ thống DNS của tên miền (SPF, DKIM, và DMARC):
1. **SPF (Xác thực nguồn gốc gửi)**: Giống như một danh sách đăng ký các bưu cục được ủy quyền. Khi nhận thư từ `nganhang.com`, máy chủ nhận sẽ tra cứu DNS để xem địa chỉ IP của máy chủ gửi thư có nằm trong danh sách SPF được ngân hàng cho phép hay không.
2. **DKIM (Chữ ký xác thực nội bộ)**: Hoạt động giống như việc đóng dấu sáp niêm phong bảo mật lên lá thư. Máy chủ gửi thư sẽ dùng một khóa bí mật mật mã để ký số vào email. Máy chủ nhận thư sẽ lấy khóa công khai từ DNS của tên miền người gửi để đối chiếu. Nếu dấu niêm phong bị vỡ hoặc không khớp, bức thư bị coi là giả mạo hoặc đã bị sửa đổi dọc đường.
3. **DMARC (Quy tắc xử lý tối cao)**: Đây là vị thủ lĩnh điều phối hành động. Nó liên kết SPF và DKIM lại và ra lệnh cho máy chủ nhận thư: "Nếu bức thư này không vượt qua được kiểm tra SPF hoặc DKIM, hãy vứt nó vào thư rác (quarantine) hoặc từ chối nhận hoàn toàn (reject)". Nó cũng gửi báo cáo thống kê về các vụ giả mạo lại cho chủ sở hữu tên miền.

```dns
; DNS TXT Records for SPF, DKIM, and DMARC configurations

; 1. SPF Record: Only allow Google Workspace and the server IP 198.51.100.1 to send mail, hard-fail all others
example.com.             IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.google.com -all"

; 2. DKIM Record: Publishes the RSA public key for verification of signing signature under selector 'default'
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

; 3. DMARC Record: Reject 100% of emails failing SPF/DKIM verification, and request XML reports sent to security alias
_dmarc.example.com.      IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com"
```

## Mô tả lỗ hổng
Lỗ hổng Giã mạo email (Email Spoofing) xảy ra do giao thức gửi thư SMTP không có cơ chế xác minh xem người gửi thực sự có đúng là chủ sở hữu của địa chỉ email đó hay không. 

Mối nguy hiểm của lỗ hổng này cực kỳ lớn, là vũ khí đắc lực cho các cuộc tấn công lừa đảo (Phishing). Tin tặc có thể giả mạo email của ngân hàng thông báo tài khoản bị khóa, hoặc giả danh đối tác yêu cầu thanh toán hợp đồng vào một số tài khoản khác. Do tiêu đề thư hiển thị giống hệt địa chỉ thật, người dùng rất dễ bị lừa nhấn vào các liên kết độc hại, nhập thông tin đăng nhập hoặc chuyển tiền trực tiếp cho tin tặc mà không hề nghi ngờ.

## Cơ chế tấn công
Kẻ tấn công giả mạo địa chỉ email 'From' để trông giống như một nhà cung cấp dịch vụ hợp pháp và gửi một cảnh báo thay đổi mật khẩu. Liên kết này dẫn nạn nhân đến một trang thu thập thông tin xác thực trông rất thực tế. Khi nạn nhân nhập mật khẩu cũ của họ, trang web sẽ ghi lại mật khẩu đó và chuyển hướng họ đến trang web thực tế để tránh bị nghi ngờ.

### Ví dụ raw SMTP session giả mạo địa chỉ người gửi:
```smtp
# Kết nối trực tiếp đến SMTP server (không cần xác thực From)
EHLO attacker.com
MAIL FROM: <attacker@attacker.com>      ← địa chỉ thật (envelope sender)
RCPT TO: <victim@company.com>
DATA

From: CEO <ceo@company.com>             ← địa chỉ GIẢ MẠO (header From)
To: victim@company.com
Subject: Chuyển khoản khẩn cấp
Reply-To: attacker@gmail.com            ← reply về attacker

Anh/Chị ơi, chuyển ngay 500 triệu sang TK 1234567890 nhé.
                                                        - CEO
.
# Email client của nạn nhân hiển thị: "From: CEO <ceo@company.com>"
# Nhưng envelope sender thật là attacker@attacker.com
```

## Biện pháp phòng thủ
- **Tóm tắt**: Triển khai các bản ghi DNS SPF, DKIM, và DMARC để xác thực người gửi hợp pháp và xác minh tính toàn vẹn của thư email.
- **Các bước chi tiết**:
  - Tạo bản ghi DNS Sender Policy Framework (SPF) xác định chính xác những máy chủ thư nào được phép gửi thư cho tên miền của bạn.
  - Triển khai DomainKeys Identified Mail (DKIM) để ký các tiêu đề thư gửi đi bằng khóa riêng mật mã, xác thực tính toàn vẹn của thư.
  - Công bố bản ghi DMARC (Domain-based Message Authentication, Reporting, and Conformance) thực thi các quy tắc chính sách như cách ly hoặc từ chối đối với các kiểm tra SPF/DKIM không thành công.
  - Kích hoạt các tính năng báo cáo DMARC để giám sát những ai đang gửi email bằng cách sử dụng danh tính tên miền của bạn.
  - Tích hợp bộ lọc thư đầu vào chặn thư đến không đạt các kiểm tra người gửi và đào tạo nhân viên cách nhận diện kỹ thuật xã hội (social engineering).

## Code Example
```configuration
# DNS TXT records for SPF, DKIM, and DMARC configurations

# SPF TXT Record: Restricts mail sending to specific IPs and includes, failing all others (-all)
example.com. IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.google.com -all"

# DKIM TXT Record: Publishes public key for signature validation
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

# DMARC TXT Record: Rejects 100% of failed mails and requests XML reports
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com"
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: CWE-345 (Insufficient Verification of Data Authenticity), RFC 6376

## Giải thích thuật ngữ
- **SMTP (Simple Mail Transfer Protocol)**: Giao thức mạng tiêu chuẩn dùng để gửi và truyền tải thư điện tử (email) giữa các máy chủ trên Internet.
- **SPF (Sender Policy Framework)**: Bản ghi DNS giúp xác thực email bằng cách chỉ định danh sách các địa chỉ IP của máy chủ được phép gửi email thay mặt cho một tên miền cụ thể.
- **DKIM (DomainKeys Identified Mail)**: Phương pháp xác thực email bằng cách gắn chữ ký số mật mã vào email, giúp máy chủ nhận xác minh email thực sự gửi từ tên miền đó và nội dung không bị chỉnh sửa.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Chính sách bảo mật kết hợp hai cơ chế SPF và DKIM, hướng dẫn máy chủ nhận cách xử lý các email giả mạo (chấp nhận, cách ly hoặc từ chối) và gửi báo cáo về cho chủ sở hữu tên miền.
- **Phishing (Tấn công lừa đảo)**: Kỹ thuật lừa đảo qua mạng, sử dụng email hoặc trang web giả mạo để dụ người dùng tiết lộ thông tin nhạy cảm như mật khẩu, thông tin thẻ tín dụng.
- **DNS Record (Bản ghi DNS)**: Các dòng cấu hình lưu trữ trong hệ thống tên miền, chứa các thông tin như địa chỉ IP của tên miền (bản ghi A), cấu hình máy chủ thư (bản ghi MX) hoặc các cấu hình xác thực (bản ghi TXT).
