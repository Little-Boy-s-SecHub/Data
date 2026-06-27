# Subdomain Squatting

> **OWASP Top 10:2025**: A03:2025 – Software Supply Chain Failures | **CWE**: CWE-350 (Reliance on Reverse DNS Resolution for Security-Critical Decisions) | **Phân loại**: Infrastructure/DNS

## 🧱 Kiến thức Nền tảng
Lỗ hổng Subdomain Squatting (chiếm đoạt tên miền phụ) là một rủi ro cấu hình sai trong hệ thống quản lý DNS khi tổ chức sử dụng dịch vụ đám mây của bên thứ ba. Để hiểu rõ cơ chế hoạt động, cần nắm rõ hai khái niệm kỹ thuật nền tảng:

1. **DNS CNAME record (Canonical Name)**: Đây là một loại bản ghi DNS đóng vai trò như một bí danh (alias). Thay vì ánh xạ trực tiếp một tên miền phụ (ví dụ: `blog.example.com`) sang địa chỉ IP, bản ghi CNAME sẽ trỏ nó tới một tên miền chính tắc (canonical domain) khác (ví dụ: `my-org.github.io`). Khi người dùng truy cập tên miền phụ, hệ thống DNS sẽ tự động chuyển tiếp để phân giải IP thông qua tên miền đích được trỏ tới.
2. **Subdomain mapping (Ánh xạ tên miền phụ)**: Là quá trình cấu hình để liên kết tên miền phụ thuộc sở hữu của tổ chức với tài nguyên lưu trữ trên hệ thống của nhà cung cấp dịch vụ bên thứ ba (chẳng hạn như AWS S3 bucket, GitHub Pages, hay Zendesk). Cơ chế này giúp tổ chức giữ nguyên thương hiệu trên thanh địa chỉ của khách hàng (ví dụ: `support.example.com`) trong khi toàn bộ hạ tầng kỹ thuật và nội dung trang web được vận hành hoàn toàn bởi đối tác bên thứ ba. Khi tài nguyên bên thứ ba bị xóa nhưng bản ghi CNAME vẫn tồn tại, lỗ hổng 'dangling DNS' xuất hiện, cho phép kẻ tấn công đăng ký lại tên tài nguyên cũ và chiếm quyền kiểm soát tên miền phụ.

### Minh họa hoạt động bình thường (Normal Operation)
```text
; BIND zone file snippet showing normal DNS configurations
$TTL 86400
@   IN  SOA     ns1.example.com. admin.example.com. (
                2026062701 ; Serial
                3600       ; Refresh
                1800       ; Retry
                604800     ; Expire
                86400 )    ; Minimum TTL

; Name Server records representing authorized DNS servers
    IN  NS      ns1.example.com.

; Normal A record pointing to the main web server IP
www IN  A       192.0.2.10

; Normal CNAME record mapping a subdomain to an active, verified external cloud service
status IN CNAME  status-page.uptime-provider.com.
```

## 🔍 Mô tả lỗ hổng
Subdomain Squatting (chiếm đoạt tên miền phụ) xảy ra khi một bản ghi DNS (như CNAME) vẫn tiếp tục trỏ tới một tài nguyên bên thứ ba (AWS S3, GitHub Pages, Heroku) sau khi tài nguyên đó đã bị xóa hoặc hủy kích hoạt. Kẻ tấn công có thể đăng ký một tài nguyên mới trên dịch vụ bên thứ ba đó trùng khớp với giá trị CNAME cũ, từ đó nắm quyền kiểm soát nội dung phân phối trên tên miền phụ đó. Điều này cho phép kẻ tấn công phát tán mã độc, tổ chức các cuộc tấn công lừa đảo (phishing) dưới tên miền chính thức của tổ chức.

## ⚔️ Cơ chế tấn công
Kẻ tấn công liên tục thực hiện các kịch bản quét các bản ghi DNS của tổ chức để tìm kiếm các bản ghi CNAME "lơ lửng" (dangling) trỏ về các dịch vụ đám mây bị bỏ hoang (ví dụ: `subdomain.example.com` trỏ về `example-blog.medium.com` hoặc `subdomain.s3.amazonaws.com` nhưng bucket/tài khoản này đã bị xóa). Kẻ tấn công truy cập vào dịch vụ đó và đăng ký lại đúng tên tài nguyên bỏ hoang đó. Do bản ghi DNS của tổ chức chưa bị xóa, mọi lượt truy cập của người dùng đến tên miền phụ đó sẽ được điều hướng tới máy chủ do kẻ tấn công kiểm soát, cho phép chúng đánh cắp cookie, giả mạo chứng thư bảo mật hoặc thực hiện lừa đảo.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Loại bỏ rủi ro chiếm đoạt tên miền phụ bằng cách thực hiện quy trình hủy tài nguyên nghiêm ngặt, tự động hóa kiểm tra các bản ghi DNS rỗng, và áp dụng các cơ chế xác thực sở hữu tên miền của bên thứ ba.
- **Các bước chi tiết**:
  - Thiết lập một danh mục kiểm tra (checklist) bắt buộc khi gỡ bỏ dịch vụ, đảm bảo các bản ghi DNS liên quan phải bị xóa ngay lập tức khi hủy tài nguyên bên thứ ba.
  - Thực hiện các đợt kiểm tra tự động thường kỳ trên các vùng DNS để nhanh chóng phát hiện các bản ghi CNAME rác trỏ tới các tài nguyên không tồn tại.
  - Áp dụng cơ chế xác minh quyền sở hữu tên miền phụ (Domain Verification) do các nhà cung cấp đám mây/dịch vụ bên thứ ba hỗ trợ để ngăn kẻ xấu đăng ký trùng lặp.
  - Áp dụng nguyên tắc đặc quyền tối thiểu đối với quyền truy cập và chỉnh sửa giao diện quản lý DNS.

## 💻 Code Example
```configuration
# Example Terraform configuration showing explicit binding between an AWS S3 Bucket 
# and its corresponding Route53 CNAME record to avoid dangling resources.

resource "aws_s3_bucket" "static_site" {
  bucket = "subdomain.example.com"
}

resource "aws_s3_bucket_website_configuration" "static_site_config" {
  bucket = aws_s3_bucket.static_site.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_route53_record" "cname_record" {
  zone_id = var.route53_zone_id
  name    = "subdomain.example.com"
  type    = "CNAME"
  ttl     = "300"
  
  # Points directly to the website endpoint, ensuring they are created/destroyed together
  records = [aws_s3_bucket_website_configuration.static_site_config.website_endpoint]
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Bài học đạt trạng thái PASS (không phát hiện lỗi cấu trúc dữ liệu hoặc kỹ thuật trong quá trình rà soát).
- **Nguồn tham khảo**: OWASP A05:2021, CWE-350, HackTricks
