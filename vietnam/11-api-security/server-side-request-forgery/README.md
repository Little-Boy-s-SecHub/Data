---
schema_version: 1
id: WEB-A11-SERVER-SIDE-REQUEST-FORGERY
title: "API Server-Side Request Forgery"
slug: server-side-request-forgery
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - network-basics
owasp:
  - API7:2023
cwe:
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Server-Side Request Forgery

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Nhận diện API endpoint cho server fetch URL do client cung cấp.
- Phân biệt full-read, semi-blind và blind SSRF.
- Thiết kế egress allowlist và URL canonicalization an toàn.

## 2. Kiến thức cần có

- URL parsing, DNS resolution và redirect.
- Internal metadata service và loopback/private network.
- Logging egress trong lab local.

## 3. Kiến thức nền tảng

SSRF trong API xảy ra khi backend thay client gửi request tới URL hoặc host do client điều khiển. API7:2023 nhấn mạnh các API hiện đại thường có webhook, import URL, preview, callback và integration connector. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause là server-side fetcher thiếu allowlist theo business destination, validate URL trước khi canonicalize, theo redirect ra ngoài policy hoặc cho truy cập địa chỉ nội bộ. [S1]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** metadata endpoint, internal admin API, service mesh, cloud credentials.
- **Actor:** user có quyền gọi integration/import endpoint.
- **Trust boundary:** URL client gửi vào fetcher backend.
- **Điều kiện cần:** fetcher kết nối tới destination ngoài allowlist hoặc internal.
- **Môi trường:** mock HTTP/DNS/metadata chỉ chạy loopback.

## 6. Cơ chế tấn công

Actor gửi URL trỏ tới destination nội bộ hoặc callback lab. Với full-read SSRF, response được trả về client; với blind SSRF, chỉ log callback/egress chứng minh server đã kết nối.

## 7. Kiểm thử trong lab được ủy quyền

1. Seed allowlist `https://assets.lab.test`.
2. Gửi baseline tới destination hợp lệ.
3. Gửi URL loopback/private/callback và redirect.
4. Kỳ vọng bản sửa chặn trước DNS/connect hoặc sau redirect revalidation.
5. Cleanup callback log và mock DNS.

## 8. Payload và phạm vi áp dụng

**Blind callback probe**

<!-- payload-id: WEB-A11-SERVER-SIDE-REQUEST-FORGERY-001 -->
<!-- context: HTTP/1.1 POST against local import fixture at 127.0.0.1:18080; case: WEB-A11-SERVER-SIDE-REQUEST-FORGERY-001 -->
<!-- prerequisites: callback.lab.test resolves only to loopback mock; outbound Internet blocked -->
<!-- encoding: JSON UTF-8; URL is parsed exactly once by the fixture -->
<!-- expected-result: vulnerable fixture records one loopback callback; fixed fixture rejects destination before connect -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/import-url HTTP/1.1
Host: api.victim.lab.test
Content-Type: application/json

{"url":"http://callback.lab.test/ssrf-probe"}
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: fetches arbitrary client-supplied URL.
def import_url(url):
    return requests.get(url, timeout=2).text

# SECURE: canonicalizes, allowlists and blocks redirects outside policy.
def import_url_secure(url):
    target = canonicalize_url(url)
    if target.host not in {"assets.lab.test"}:
        raise ValueError("destination not allowed")
    return fetch_without_cross_policy_redirect(target)
```

## 10. Phát hiện

- Correlate request ID with DNS/connect log.
- Record final URL after redirect.
- Do not infer SSRF only from accepted URL syntax.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Use positive allowlist for business destinations.
- Re-validate after DNS and redirect.
- Block loopback, link-local, private and metadata ranges.

### Defense-in-depth

- Egress proxy, network policy and metadata service hardening.
- Response size/time limits.
- Separate fetcher identity with least privilege.

## 12. Retest

- **Positive:** allowed host works.
- **Negative:** loopback/private/callback blocked.
- **Boundary:** redirect, DNS rebinding, IPv6, encoded host.
- **Telemetry:** no blocked destination connection in fixed fixture.

## 13. Sai lầm thường gặp

- Validate string prefix before URL parsing.
- Allow redirect without revalidation.
- Depend only on WAF while backend can still connect internal network.

## 14. Tóm tắt và checklist

- [ ] Fetcher has business allowlist.
- [ ] URL is canonicalized before policy.
- [ ] DNS/connect/redirect telemetry is captured.
- [ ] Blind and full-read cases are separated.

## 15. Giải thích thuật ngữ

- **Full-read SSRF:** client thấy response từ destination.
- **Blind SSRF:** client không thấy response nhưng server egress được ghi nhận.
- **Egress:** kết nối outbound từ backend.

## 16. Bài liên quan và đọc thêm

- [SSRF](../../01-broken-access-control/ssrf/)
- [Cloud SSRF patterns](../../01-broken-access-control/ssrf/)
- [Shadow APIs](../shadow-apis/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API7 Server Side Request Forgery. https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-918 — Server-Side Request Forgery. https://cwe.mitre.org/data/definitions/918.html — bản hiện hành; truy cập: 2026-07-18.
