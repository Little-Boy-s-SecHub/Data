---
schema_version: 1
id: WEB-A07-JWT-ATTACKS
title: "JWT Attacks"
slug: jwt-attacks
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A04:2025
  - A05:2025
  - A08:2025
cwe:
  - CWE-345
  - CWE-347
  - CWE-20
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# JWT Attacks

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích JWT Attacks bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng JWT (JSON Web Token) giống như một tấm thẻ căn cước công dân kỹ thuật số được ép nhựa cứng. Tấm thẻ này gồm ba phần riêng biệt ghép lại:
1. **Header (Ảnh chân dung và quốc huy)**: Nơi ghi rõ tấm thẻ này sử dụng công nghệ bảo mật nào để ký xác nhận (thuật toán mã hóa).
2. **Payload (Thông tin cá nhân)**: Nơi ghi họ tên, chức vụ, ngày cấp và ngày hết hạn của bạn (dữ liệu truyền tải).
3. **Signature (Con dấu đỏ của cơ quan công an)**: Chữ ký số mã hóa để đảm bảo thông tin trên thẻ không bị cạo sửa.

Để tạo ra con dấu đỏ này, cơ quan cấp thẻ có hai cách chọn công nghệ ký:
- **Ký đối xứng (HS256)**: Dùng chung một chiếc con dấu bí mật (Secret Key) để vừa đóng dấu lúc cấp thẻ, vừa dùng chính chiếc dấu đó để đối chiếu lúc kiểm tra.
- **Ký bất đối xứng (RS256)**: Dùng một chiếc chìa khóa riêng mật (Private Key) được cất kỹ ở trụ sở để đóng dấu, và phát hành rộng rãi một chiếc kính lúp công khai (Public Key) cho tất cả các chốt an ninh tự đối chiếu chữ ký.

Hệ thống sẽ hoàn toàn tin tưởng bạn là Admin nếu bạn xuất trình một tấm thẻ có ghi chữ "Role: Admin" và đi kèm một con dấu đỏ hợp lệ. Sự nguy hiểm bắt đầu khi chốt an ninh kiểm tra thẻ bị lơ là, hoặc người làm thẻ cẩu thả, tạo điều kiện cho kẻ xấu tự đóng dấu giả hoặc cạo sửa thông tin trên thẻ.

```javascript
// Normal JWT creation and verification flow
const jwt = require('jsonwebtoken');

// Server creates JWT after successful login
function generateToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600  // 1 hour expiry
    };

    // Sign with secret key (HS256) or private key (RS256)
    return jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
}

// Server verifies JWT on each request
function verifyToken(token) {
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}
```

Server tin tưởng nội dung JWT nếu chữ ký hợp lệ. Nhưng nếu quá trình xác minh bị cấu hình sai, attacker có thể giả mạo token để leo thang đặc quyền.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Tấn công JWT (JWT Attacks) xảy ra khi quá trình xác minh chữ ký số của token trên máy chủ bị cấu hình sai hoặc thiếu chặt chẽ.

Mối nguy hiểm của lỗ hổng này rất lớn: kẻ tấn công có thể tự tạo ra một tấm thẻ căn cước giả bằng cách đổi thuật toán ký thành `none` (yêu cầu máy chủ không cần kiểm tra con dấu), tự dùng khóa công khai để ký giả mạo thẻ (lợi dụng sự nhầm lẫn thuật toán HS256/RS256), hoặc lừa máy chủ đi lấy con dấu xác thực từ một địa chỉ web độc hại do chúng kiểm soát (JWK/JKU injection). Khi máy chủ tin tưởng tấm thẻ giả mạo này, kẻ tấn công có thể giả danh bất kỳ người dùng nào hoặc tự nâng quyền của mình lên Admin để kiểm soát hệ thống.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5], [S6].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** identity/role claim và trust của signing key.
- **Actor, xác thực và role:** client sở hữu hoặc tạo token tổng hợp và nhắm role admin.
- **Điều kiện khai thác:** verifier tin alg/kid/jku/jwk hoặc lifecycle claim ngoài trust policy cố định.
- **Browser, proxy, framework và phiên bản:** Node.js 20 jsonwebtoken, JWKS local và Redis được pin; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với jwt attacks, verifier tin alg/kid/jku/jwk hoặc lifecycle claim ngoài trust policy cố định. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Node.js 20 jsonwebtoken, JWKS local và Redis được pin; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case jwt attacks; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “verifier tin alg/kid/jku/jwk hoặc lifecycle claim ngoài trust policy cố định”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của jwt attacks; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**1. Algorithm "none" Attack — bỏ hoàn toàn chữ ký:**
Attacker thay đổi trường `alg` trong header thành `none` và xóa bỏ chữ ký để qua mặt cơ chế kiểm tra.

<!-- payload-id: WEB-A07-JWT-ATTACKS-001 -->
<!-- context: Python 3.12 constructs an unsigned alg=none token for a deliberately vulnerable verifier -->
<!-- prerequisites: synthetic sub/role only; loopback verifier; one token; no production key or endpoint -->
<!-- encoding: header/payload are UTF-8 JSON encoded with unpadded Base64url and an empty signature segment -->
<!-- expected-result: legacy vulnerable verifier accepts synthetic admin; fixed verifier pinned RS256 rejects before authorization -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Craft a JWT with algorithm set to "none"
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "1", "username": "admin", "role": "admin"}).encode()).decode().rstrip('=')
forged_token = f"{header}.{payload}."
# If server accepts alg:none, attacker is now admin
```

**2. HS256/RS256 Confusion — hành vi legacy, không phải bypass mặc định của PyJWT hiện hành:**
Lỗi chỉ tồn tại khi verifier tự chọn thuật toán từ header và tái sử dụng cùng key material cho cả RSA lẫn HMAC. PyJWT hiện hành từ chối dùng PEM/SSH asymmetric key làm HMAC secret bằng `InvalidKeyError`; vì vậy không được trình bày lời gọi `jwt.encode(..., public_key, algorithm="HS256")` như một payload hoạt động trên phiên bản hiện đại. [S7]

<!-- payload-id: WEB-A07-JWT-ATTACKS-002 -->
<!-- context: Python 3.12 with PyJWT 2.10.x checks modern handling of an RSA PEM passed to HS256 -->
<!-- prerequisites: generated lab keypair only; no token is sent to an endpoint; run once in a disposable fixture -->
<!-- encoding: claims are UTF-8 JSON; the RSA public key is PEM bytes generated only for the fixture -->
<!-- expected-result: PyJWT raises InvalidKeyError before producing a token; a separate legacy/custom fixture is required to study historical algorithm confusion -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S7 -->
<!-- last-verified: 2026-07-17 -->
```python
import jwt
from jwt.exceptions import InvalidKeyError

public_key = open('public_key.pem').read()

try:
    jwt.encode({"sub": "fixture-user"}, public_key, algorithm="HS256")
except InvalidKeyError:
    print("EXPECTED_REJECT_RSA_PEM_AS_HMAC_SECRET")
else:
    raise AssertionError("Pinned modern PyJWT unexpectedly accepted RSA PEM for HS256")
```

**3. Weak Secret Brute Force:**
Sử dụng công cụ để dò tìm khóa bí mật HS256 nếu nó quá ngắn hoặc dễ đoán.

<!-- payload-id: WEB-A07-JWT-ATTACKS-003 -->
<!-- context: hashcat JWT mode tests a deliberately weak synthetic HS256 token -->
<!-- prerequisites: ten-entry fixture wordlist; --runtime=5; CPU-only disposable container; no leaked token/rockyou list -->
<!-- encoding: jwt_token.txt contains one ASCII compact JWT line; wordlist is UTF-8 with one candidate per line -->
<!-- expected-result: tool recovers only LAB_WEAK_SECRET within five seconds; strong-key fixture has no match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
hashcat -a 0 -m 16500 --runtime=5 jwt_token.txt tests/fixtures/jwt-lab-wordlist.txt
```

**4. JWK Header Injection:**
Attacker nhúng trực tiếp public key của mình vào tham số `jwk` trong JWT header và ký token bằng private key tương ứng. Nếu máy chủ tin cậy key này mà không đối chiếu với danh sách đáng tin cậy, nó sẽ dùng chính public key do attacker gửi để xác minh chữ ký.

**5. JKU Header Injection:**
Attacker tạo một file JWKS chứa public key của mình, tải lên một server độc lập và chèn đường dẫn URL đó vào tham số `jku` trong JWT header. Server mục tiêu sẽ gửi request lấy JWK từ URL của attacker để verify chữ ký.

**6. kid Parameter Injection:**
Tham số `kid` (Key ID) dùng để chỉ định khóa nào cần sử dụng.
- **Path lookup không an toàn**: Nếu server ghép `kid` vào đường dẫn, ký tự phân cách có thể thoát key namespace. Chỉ kiểm tra bằng opaque fixture ID và synthetic key directory; không đọc file hệ thống.
- **Query không an toàn**: Nếu server nối `kid` vào query, input có thể thay đổi phép chọn khóa. Lesson không phát hành chuỗi injection riêng; bản sửa map opaque `kid` sang key record do server quản lý bằng query tham số hóa.

**7. Token Replay:**
`jti` chỉ là định danh duy nhất của JWT; sự hiện diện của claim này tự nó không chặn replay. Với thao tác được thiết kế dùng một lần, server phải ghi nhận `issuer` + `audience` + `jti` bằng thao tác nguyên tử và từ chối lần dùng sau cho tới khi token hết hạn. Access token thông thường có thể hợp lệ cho nhiều request, vì vậy chính sách chống replay phải khớp loại token và use case; thời gian sống ngắn chỉ giảm cửa sổ rủi ro. [S1]

## 9. Code dễ bị lỗi và code an toàn

```javascript
// === VULNERABLE CODE ===
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 1. Vulnerable to JWK/JKU Header Injection
function verifyJkuUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Fetching key from external JKU URL provided by user
    if (decoded.header.jku) {
        const jwks = fetchExternalKey(decoded.header.jku); // Simulated external fetch
        const key = jwks.find(k => k.kid === decoded.header.kid);
        return jwt.verify(token, key);
    }
    return null;
}

// 2. Vulnerable to Path Traversal via kid
function verifyKidPathUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Direct file path construction using unsanitized kid
    const keyPath = path.join(__dirname, 'keys', decoded.header.kid);
    const key = fs.readFileSync(keyPath);
    return jwt.verify(token, key);
}
```

```javascript
// === SECURE CODE ===
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    // SECURE: Hardcoded trusted JWKS URI
    jwksUri: 'https://identity.provider.lab.test/.well-known/jwks.json'
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function(err, key) {
        if (err) return callback(err);
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

function verifyTokenSafe(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            // SECURE: Whitelist only RS256, reject none/HS256
            algorithms: ['RS256'],
            issuer: 'https://identity.provider.lab.test',
            audience: 'my-secure-app'
        }, (err, decoded) => {
            if (err) return reject(err);

            // Enforce one-time use only for operations whose contract requires it.
            // consumeTokenIdOnce must atomically SET NX with TTL through decoded.exp.
            if (requiresOneTimeUse(decoded)) {
                if (typeof decoded.jti !== 'string' || decoded.jti.length === 0) {
                    return reject(new Error('Missing jti for one-time token'));
                }
                const firstUse = consumeTokenIdOnce({
                    issuer: decoded.iss,
                    audience: decoded.aud,
                    jti: decoded.jti,
                    expiresAt: decoded.exp
                });
                if (!firstUse) return reject(new Error('One-time token already used'));
            }

            resolve(decoded);
        });
    });
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Pin algorithm, issuer, audience, trusted key; validate header và enforce lifecycle server-side.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Bảo vệ JWT bằng thuật toán verify cố định, khóa đáng tin cậy, kiểm tra issuer/audience/thời hạn và chính sách vòng đời phù hợp từng loại token; `jti` chỉ hỗ trợ chống replay khi server lưu trạng thái nguyên tử.
- **Các bước chi tiết**:
  - **Whitelist algorithms**: Luôn chỉ định danh sách thuật toán được chấp nhận khi verify, **không bao giờ** để server tự chọn từ header.
  - **Strong secrets**: Sử dụng secret key tối thiểu 256-bit ngẫu nhiên cho HS256, hoặc RSA key ≥ 2048-bit cho RS256.
  - **Reject "none" algorithm**: Đảm bảo library JWT không chấp nhận `alg: none`.
  - **JWK/JKU Validation**: Chỉ cho phép nạp JWK từ các domain được whitelist nghiêm ngặt, hoặc cấm hoàn toàn việc nạp key từ client-side.
  - **Sanitize `kid`**: Validate `kid` không chứa ký tự lạ (như `/`, `\`, `'`, `"`) hoặc dùng SQL parameterized queries.
  - **Token Replay Defense**: Với token dùng một lần, tiêu thụ bộ khóa `issuer` + `audience` + `jti` bằng thao tác nguyên tử và giữ trạng thái đến `exp`. Với access token dùng nhiều lần, dùng thời gian sống ngắn, ràng buộc sender khi threat model yêu cầu và cơ chế thu hồi/phát hiện phù hợp; không coi `jti` riêng lẻ là biện pháp chống replay.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

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

- **JWT (JSON Web Token)**: Định dạng mã nguồn mở giúp truyền tải thông tin an toàn giữa các bên dưới dạng một đối tượng JSON, thường dùng để xác thực và phân quyền người dùng trong ứng dụng web.
- **HS256 (HMAC with SHA-256)**: Thuật toán ký số đối xứng, sử dụng duy nhất một khóa bí mật chung cho cả việc tạo chữ ký và xác minh tính toàn vẹn của token.
- **RS256 (RSA Signature with SHA-256)**: Thuật toán ký số bất đối xứng, sử dụng khóa bí mật (Private Key) để ký số và khóa công khai (Public Key) để kiểm tra chữ ký.
- **JWK (JSON Web Key)**: Cấu trúc dữ liệu JSON dùng để biểu diễn các khóa mật mã công khai được sử dụng trong hệ thống JWT.
- **JKU (JSON Web Key Set URL)**: Tham số trong header của JWT chứa liên kết URL trỏ tới danh sách các khóa công khai hợp lệ để máy chủ tải về phục vụ việc xác minh chữ ký.
- **kid (Key ID)**: Tham số định danh khóa, giúp máy chủ biết chính xác khóa nào trong cơ sở dữ liệu cần dùng để kiểm tra chữ ký của token này.
- **Token Replay (Tấn công gửi lại)**: Hình thức tấn công mà kẻ xấu chặn bắt được một token hợp lệ của nạn nhân rồi gửi lại yêu cầu đó lên máy chủ để giả mạo phiên làm việc của nạn nhân.

## 16. Bài liên quan và đọc thêm

- [Weak Session IDs](../weak-session-ids/README.md)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/jwt — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** Auth0. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/345.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** CWE-347. https://cwe.mitre.org/data/definitions/347.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** CWE-20. https://cwe.mitre.org/data/definitions/20.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S7]** PyJWT Usage — algorithm/key handling. https://pyjwt.readthedocs.io/en/stable/usage.html — phiên bản/trạng thái: PyJWT 2.10.x; truy cập: 2026-07-18.
