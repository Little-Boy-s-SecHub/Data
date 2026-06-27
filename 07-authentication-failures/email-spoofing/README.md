# Email Spoofing

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-345 | **Phân loại**: Social Engineering

## 🧱 Kiến thức Nền tảng
Lỗ hổng giả mạo email (Email Spoofing) bắt nguồn trực tiếp từ sự thiếu sót trong thiết kế ban đầu của **SMTP mail protocol (giao thức SMTP - Simple Mail Transfer Protocol)**. SMTP là giao thức cốt lõi được sử dụng để gửi và định tuyến email trên Internet. Khi được đặc tả lần đầu, SMTP hoàn toàn không tích hợp cơ chế xác thực danh tính người gửi. Tiêu đề người gửi (`From:`) chỉ đơn thuần là một chuỗi văn bản tự do, cho phép bất kỳ ai thiết lập kết nối SMTP đều có thể giả mạo thành bất kỳ địa chỉ email hoặc tên miền của tổ chức tin cậy nào nhằm lừa đảo người nhận.

Để giải quyết vấn đề bảo mật nghiêm trọng này, ba bản ghi cấu hình DNS (**SPF/DKIM/DMARC DNS records**) đã được phát triển để bổ sung lớp xác thực mật mã cho email:

1. **SPF (Sender Policy Framework)**: Là một bản ghi cấu hình dạng văn bản (TXT) trong DNS của tên miền. SPF định nghĩa danh sách các máy chủ (IP) được ủy quyền gửi thư thay mặt cho tên miền đó. Máy chủ nhận thư sẽ đối chiếu IP của máy chủ gửi với bản ghi SPF này.
2. **DKIM (DomainKeys Identified Mail)**: Sử dụng chữ ký số mã hóa khóa công khai. Máy chủ gửi sẽ ký lên nội dung email bằng khóa riêng, và máy chủ nhận thư sẽ truy vấn khóa công khai của tên miền đó từ bản ghi DNS DKIM để xác thực tính toàn vẹn và nguồn gốc của thư.
3. **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Đóng vai trò là lớp điều phối tối cao, liên kết kết quả của SPF và DKIM. Bản ghi DMARC đưa ra chỉ dẫn rõ ràng cho máy chủ nhận cách xử lý thư lỗi xác thực (chấp nhận, cách ly trong hòm spam `quarantine`, hoặc từ chối hoàn toàn `reject`), đồng thời gửi báo cáo XML thống kê về các hành vi giả mạo tên miền của doanh nghiệp.

```dns
; DNS TXT Records for SPF, DKIM, and DMARC configurations

; 1. SPF Record: Only allow Google Workspace and the server IP 198.51.100.1 to send mail, hard-fail all others
example.com.             IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.google.com -all"

; 2. DKIM Record: Publishes the RSA public key for verification of signing signature under selector 'default'
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

; 3. DMARC Record: Reject 100% of emails failing SPF/DKIM verification, and request XML reports sent to security alias
_dmarc.example.com.      IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com"
```

## 🔍 Mô tả lỗ hổng
Giao thức Truyền tải Thư tín Đơn giản (SMTP) thiếu cơ chế xác thực tích hợp, cho phép kẻ tấn công giả mạo địa chỉ 'From' (Người gửi) để đóng giả các người gửi đáng tin cậy. Lỗ hổng này được khai thác mạnh mẽ trong các chiến dịch lừa đảo (phishing) để đánh lừa người nhận và thu thập thông tin xác thực thông qua các trang đích giả mạo.

## ⚔️ Cơ chế tấn công
Kẻ tấn công giả mạo địa chỉ email 'From' để trông giống như một nhà cung cấp dịch vụ hợp pháp và gửi một cảnh báo thay đổi mật khẩu. Liên kết này dẫn nạn nhân đến một trang thu thập thông tin xác thực trông rất thực tế. Khi nạn nhân nhập mật khẩu cũ của họ, trang web sẽ ghi lại mật khẩu đó và chuyển hướng họ đến trang web thực tế để tránh bị nghi ngờ.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Triển khai các bản ghi DNS SPF, DKIM, và DMARC để xác thực người gửi hợp pháp và xác minh tính toàn vẹn của thư email.
- **Các bước chi tiết**:
  - Tạo bản ghi DNS Sender Policy Framework (SPF) xác định chính xác những máy chủ thư nào được phép gửi thư cho tên miền của bạn.
  - Triển khai DomainKeys Identified Mail (DKIM) để ký các tiêu đề thư gửi đi bằng khóa riêng mật mã, xác thực tính toàn vẹn của thư.
  - Công bố bản ghi DMARC (Domain-based Message Authentication, Reporting, and Conformance) thực thi các quy tắc chính sách như cách ly hoặc từ chối đối với các kiểm tra SPF/DKIM không thành công.
  - Kích hoạt các tính năng báo cáo DMARC để giám sát những ai đang gửi email bằng cách sử dụng danh tính tên miền của bạn.
  - Tích hợp bộ lọc thư đầu vào chặn thư đến không đạt các kiểm tra người gửi và đào tạo nhân viên cách nhận diện kỹ thuật xã hội (social engineering).

## 💻 Code Example
```configuration
# DNS TXT records for SPF, DKIM, and DMARC configurations

# SPF TXT Record: Restricts mail sending to specific IPs and includes, failing all others (-all)
example.com. IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.google.com -all"

# DKIM TXT Record: Publishes public key for signature validation
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

# DMARC TXT Record: Rejects 100% of failed mails and requests XML reports
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com"
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi mã trợ giúp Ruby DKIM trên slide 9 vốn đưa các chữ ký nhị phân thô và tóm tắt phần thân trực tiếp vào các tiêu đề thay vì mã hóa chúng bằng Base64 (thông qua Base64.strict_encode64), điều này vi phạm các đặc tả kỹ thuật của SMTP và RFC 6376.
- **Nguồn tham khảo**: CWE-345 (Insufficient Verification of Data Authenticity), RFC 6376
