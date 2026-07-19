---
schema_version: 1
id: WEB-A11-BROKEN-AUTHENTICATION
title: "API Broken Authentication"
slug: broken-authentication
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API2:2023
cwe:
  - CWE-287
  - CWE-306
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Broken Authentication

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

- Nhận diện lỗi authentication trong API token, session, API key và OAuth flow.
- Phân biệt authentication failure với authorization failure.
- Retest bằng token hết hạn, token sai audience, token bị thu hồi và request không token.

## 2. Kiến thức cần có

- Bearer token, API key, session cookie và OAuth/OIDC cơ bản.
- JWT claim như `iss`, `aud`, `exp`, `sub`.
- Rate limiting và lockout ở endpoint đăng nhập.

## 3. Kiến thức nền tảng

Authentication xác định actor là ai. API Broken Authentication xảy ra khi server chấp nhận credential yếu, token sai ngữ cảnh, token hết hạn, API key lộ hoặc flow đăng nhập không giới hạn đúng cách. [S1]

## 4. Mô tả và nguyên nhân gốc

Root cause thường là xác thực token thiếu kiểm tra issuer/audience/expiry, API key không được rotate, endpoint nhạy cảm cho anonymous access, hoặc logic refresh token không ràng buộc client/session. [S1]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** identity, access token, refresh token, API key và session.
- **Actor:** client chưa đăng nhập, user thường, token hết hạn hoặc token của môi trường khác.
- **Trust boundary:** credential từ request đi vào middleware xác thực.
- **Điều kiện cần:** middleware chấp nhận credential không hợp lệ hoặc bỏ qua xác thực cho route nhạy cảm.
- **Môi trường:** fixture local có issuer, audience và token synthetic.

## 6. Cơ chế tấn công

Actor thử request không token, token hết hạn, token sai audience hoặc API key bị thu hồi. Evidence cần chứng minh request được xử lý như actor hợp lệ, không chỉ là thông báo lỗi khác thường.

## 7. Kiểm thử trong lab được ủy quyền

1. Seed một token hợp lệ và ba token lỗi: expired, wrong audience, revoked.
2. Gọi endpoint nhạy cảm bằng từng token.
3. Ghi middleware decision, route handler log và status.
4. Kỳ vọng bản sửa chỉ cho token hợp lệ đi tới handler.
5. Cleanup token/key fixture và log.

## 8. Payload và phạm vi áp dụng

**Token sai audience**

<!-- payload-id: WEB-A11-BROKEN-AUTHENTICATION-001 -->
<!-- context: HTTP/1.1 GET against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-AUTHENTICATION-001 -->
<!-- prerequisites: token is synthetic, signed by lab issuer, but aud is api-staging instead of api-prod -->
<!-- encoding: ASCII request headers; token placeholder is not a real secret -->
<!-- expected-result: vulnerable fixture accepts the wrong-audience token; fixed fixture rejects it before route handling -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
GET /api/me HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer TOKEN_WITH_WRONG_AUDIENCE
Accept: application/json
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: verifies signature but not audience or revocation.
claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})

# SECURE: pins issuer, audience, expiry and revocation state.
claims = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    issuer="https://issuer.lab.test",
    audience="api-prod",
)
if is_revoked(claims["jti"]):
    raise Unauthorized()
```

## 10. Phát hiện

- Log credential type, token issuer/audience, expiry class và auth decision.
- Không log raw token hoặc API key.
- Cảnh báo token sai audience/issuer được chấp nhận.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xác thực issuer, audience, expiry, signature và revocation.
- Không cho route nhạy cảm bypass authentication middleware.
- Rotate API key và ràng buộc key với scope/client.

### Defense-in-depth

- Rate limit login/refresh token.
- Dùng short-lived access token và refresh token rotation.
- Cảnh báo credential reuse bất thường.

## 12. Retest

- **Positive:** token hợp lệ truy cập được endpoint đúng scope.
- **Negative:** missing/expired/wrong-audience/revoked token bị từ chối.
- **Boundary:** clock skew, key rotation, multi-issuer.
- **Telemetry:** middleware decision khớp response.

## 13. Sai lầm thường gặp

- Decode JWT mà không verify đầy đủ claim.
- Dùng một API key dài hạn cho nhiều client.
- Chỉ bảo vệ UI mà bỏ qua endpoint mobile/internal.

## 14. Tóm tắt và checklist

- [ ] Mọi route nhạy cảm đi qua authentication middleware.
- [ ] Token validation pin issuer, audience, expiry và algorithm.
- [ ] Refresh/API key có rotation và revocation.
- [ ] Test negative không chạm route handler.

## 15. Giải thích thuật ngữ

- **Authentication:** xác minh actor là ai.
- **Audience:** API nhận token dự kiến.
- **Revocation:** thu hồi credential trước hạn tự nhiên.

## 16. Bài liên quan và đọc thêm

- [JWT Attacks](../../07-authentication-failures/jwt-attacks/)
- [OAuth Vulnerabilities](../../07-authentication-failures/oauth-vulnerabilities/)
- [API Rate Limiting](../api-rate-limiting/)

## 17. Tài liệu tham khảo

- **[S1]** OWASP API Security Top 10 2023 — API2 Broken Authentication. https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-287 — Improper Authentication. https://cwe.mitre.org/data/definitions/287.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-306 — Missing Authentication for Critical Function. https://cwe.mitre.org/data/definitions/306.html — bản hiện hành; truy cập: 2026-07-18.
