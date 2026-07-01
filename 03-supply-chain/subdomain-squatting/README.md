# Subdomain Squatting

> **CWE**: CWE-350 (Reliance on Reverse DNS Resolution for Security-Critical Decisions) | **Phân loại**: Supply Chain

## Kiến thức Nền tảng
Hãy tưởng tượng một thương hiệu thời trang nổi tiếng có tên "A-Shop" sở hữu trang web chính thức `a-shop.com`. Để chia sẻ các xu hướng thời trang mới, họ quyết định viết blog trên một nền tảng viết blog trực tuyến có tên là "EasyBlog". Để giữ uy tín thương hiệu, họ cấu hình hệ thống sao cho khi khách hàng truy cập địa chỉ `blog.a-shop.com`, hệ thống DNS sẽ tự động chuyển hướng (thông qua **bản ghi CNAME - CNAME record**) đến địa chỉ thực tế là `a-shop.easyblog.com` (quá trình này được gọi là **ánh xạ tên miền phụ - subdomain mapping**). 

Sau vài năm, A-Shop quyết định dừng viết blog và hủy đăng ký dịch vụ với EasyBlog. Nền tảng EasyBlog ngay lập tức giải phóng tên miền `a-shop.easyblog.com` để người khác có thể sử dụng. Thế nhưng, một sơ hở nghiêm trọng đã xảy ra: bộ phận kỹ thuật của A-Shop quên không xóa bản ghi CNAME trong cấu hình DNS của họ. Biển chỉ dẫn `blog.a-shop.com` vẫn tiếp tục hướng về `a-shop.easyblog.com` dù trang blog thật sự đã bị xóa. Đây được gọi là bản ghi DNS "mồ côi" (dangling DNS). Một kẻ tấn công phát hiện ra điều này, nhanh chóng đăng ký một tài khoản trên EasyBlog và chiếm đoạt đúng cái tên `a-shop.easyblog.com` đang bị bỏ hoang. Kể từ giây phút đó, kẻ tấn công đã hoàn tất việc chiếm đóng và làm chủ tên miền phụ của A-Shop.

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

## Mô tả lỗ hổng
Lỗ hổng **Chiếm dụng tên miền phụ** (Subdomain Squatting) xảy ra khi các bản ghi DNS của ứng dụng tiếp tục trỏ tới một dịch vụ hoặc tài nguyên bên thứ ba (như AWS S3, GitHub Pages, Heroku) đã bị ngừng sử dụng nhưng chưa được thu hồi bản ghi DNS tương ứng.

Lỗ hổng này cực kỳ nguy hiểm vì nó cho phép kẻ tấn công sở hữu một trang web có địa chỉ hoàn toàn chính chủ và đáng tin cậy của doanh nghiệp nạn nhân. Người dùng khi truy cập sẽ không hề nghi ngờ vì thanh địa chỉ trình duyệt vẫn hiển thị đúng tên miền phụ quen thuộc của công ty. Kẻ tấn công có thể lợi dụng sự tin tưởng tuyệt đối này để treo các quảng cáo độc hại, cài đặt các mã kịch bản chạy ngầm nhằm đánh cắp thông tin đăng nhập (phishing), chiếm đoạt các cookie bảo mật của hệ thống chính, hoặc làm bàn đạp để phá vỡ các chính sách an toàn thông tin của doanh nghiệp.

## Cơ chế tấn công
Kẻ tấn công liên tục thực hiện các kịch bản quét các bản ghi DNS của tổ chức để tìm kiếm các bản ghi CNAME "lơ lửng" (dangling) trỏ về các dịch vụ đám mây bị bỏ hoang (ví dụ: `subdomain.example.com` trỏ về `example-blog.medium.com` hoặc `subdomain.s3.amazonaws.com` nhưng bucket/tài khoản này đã bị xóa). Kẻ tấn công truy cập vào dịch vụ đó và đăng ký lại đúng tên tài nguyên bỏ hoang đó. Do bản ghi DNS của tổ chức chưa bị xóa, mọi lượt truy cập của người dùng đến tên miền phụ đó sẽ được điều hướng tới máy chủ do kẻ tấn công kiểm soát, cho phép chúng đánh cắp cookie, giả mạo chứng thư bảo mật hoặc thực hiện lừa đảo.

## Biện pháp phòng thủ
- **Tóm tắt**: Loại bỏ rủi ro chiếm đoạt tên miền phụ bằng cách thực hiện quy trình hủy tài nguyên nghiêm ngặt, tự động hóa kiểm tra các bản ghi DNS rỗng, và áp dụng các cơ chế xác thực sở hữu tên miền của bên thứ ba.
- **Các bước chi tiết**:
  - Thiết lập một danh mục kiểm tra (checklist) bắt buộc khi gỡ bỏ dịch vụ, đảm bảo các bản ghi DNS liên quan phải bị xóa ngay lập tức khi hủy tài nguyên bên thứ ba.
  - Thực hiện các đợt kiểm tra tự động thường kỳ trên các vùng DNS để nhanh chóng phát hiện các bản ghi CNAME rác trỏ tới các tài nguyên không tồn tại.
  - Áp dụng cơ chế xác minh quyền sở hữu tên miền phụ (Domain Verification) do các nhà cung cấp đám mây/dịch vụ bên thứ ba hỗ trợ để ngăn kẻ xấu đăng ký trùng lặp.
  - Áp dụng nguyên tắc đặc quyền tối thiểu đối với quyền truy cập và chỉnh sửa giao diện quản lý DNS.

## Code Example
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


## Xem thêm
- [Malvertising](../malvertising/) — Xem thêm bài học về Malvertising.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A05:2021, CWE-350, HackTricks

## Giải thích thuật ngữ
- **Subdomain Squatting**: Hành vi đầu cơ hoặc chiếm giữ trái phép một tên miền phụ bị bỏ hoang hoặc cấu hình sai của một tổ chức.
- **DNS CNAME Record**: Bản ghi tên miền chính tắc trong DNS dùng để liên kết một tên miền phụ này với một tên miền khác.
- **Subdomain Mapping**: Kỹ thuật liên kết tên miền phụ thuộc sở hữu của doanh nghiệp với hạ tầng lưu trữ của một nhà cung cấp dịch vụ bên thứ ba.
- **Dangling DNS**: Bản ghi DNS mồ côi, vẫn tồn tại và trỏ tới một tài nguyên mạng đã bị xóa bỏ hoặc ngừng hoạt động.
- **Domain Verification**: Quy trình xác minh quyền sở hữu tên miền, bắt buộc người dùng cấu hình một bản ghi TXT cụ thể để chứng minh họ thực sự làm chủ tên miền đó trước khi liên kết dịch vụ.
- **Terraform**: Công cụ quản lý và triển khai hạ tầng dưới dạng mã nguồn, giúp tự động đồng bộ hóa vòng đời của tài nguyên mạng và bản ghi DNS.
