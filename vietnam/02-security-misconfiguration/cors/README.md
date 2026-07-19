---
schema_version: 1
id: WEB-A02-CORS
title: "Cross-Origin Resource Sharing"
slug: cors
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-942
content_status: technical-review
payload_status: none
last_verified: null
---

# Cross-Origin Resource Sharing

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Origin Resource Sharing bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Origin tuple, Same-Origin Policy và Fetch/CORS.

- Safelisted request, preflight và credential mode.

- Cache behavior với trường `Origin` và `Vary`.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang sống trong một khu chung cư cao cấp. Ban quản lý tòa nhà có một quy định an ninh cực kỳ nghiêm ngặt: "Người lạ ở bên ngoài không được phép tự ý vào căn hộ của cư dân để lục lọi đồ đạc hay đọc trộm thư từ". Quy định an toàn cơ bản này trong thế giới trình duyệt được gọi là **SOP** (Same-Origin Policy - Chính sách cùng nguồn gốc). Nó đảm bảo rằng một đoạn mã độc hại chạy trên trang web giải trí `callback.lab.test` không thể nào tự ý đọc tin nhắn Facebook hay dữ liệu tài khoản ngân hàng của bạn đang mở ở tab bên cạnh. Một "nguồn" (origin) ở đây được xác định chặt chẽ bằng sự kết hợp của: giao thức (http/https), tên miền (domain) và cổng kết nối (port). [S3]

Tuy nhiên, trong thực tế, các ứng dụng web hiện đại cần phải hợp tác với nhau. Ví dụ, trang web bán hàng (`shop.com`) cần gọi API tại `api.shop.com`. CORS quy định khi nào script ở một origin được đọc response của origin khác. Browser chỉ gửi preflight `OPTIONS` cho request không thuộc nhóm CORS-safelisted, chẳng hạn method/header không safelisted; “simple request” có thể được gửi ngay và CORS không thay thế CSRF protection. [S3]

```javascript
// Express.js middleware for safe CORS policy handling
const express = require('express');
const app = express();

// Whitelist of trusted origins allowed to access the API
const allowedOrigins = ['https://www.victim.lab.test', 'https://api.victim.lab.test'];

app.use((req, res, next) => {
    const origin = req.headers.origin;

    const isAllowed = allowedOrigins.includes(origin);
    if (origin && !isAllowed) {
        return res.status(403).json({ error: 'Origin is not allowed' });
    }

    if (isAllowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.append('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    // Answer only an allowed cross-origin preflight request here
    if (req.method === 'OPTIONS' && isAllowed) {
        return res.sendStatus(204);
    }

    next();
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng CORS (CORS Misconfiguration) xảy ra khi người bảo vệ đứng cửa (cấu hình CORS trên máy chủ API) quá lỏng lẻo, lười biếng hoặc thiết lập sai quy trình. [S3]

Sai lầm phổ biến nhất là phản ánh tùy ý `Origin` và đồng thời trả `Access-Control-Allow-Credentials: true`. Để đọc dữ liệu bằng cookie, script còn phải gửi request với chế độ credentials và cookie phải được phép gắn vào request theo `SameSite`, `Secure`, domain/path và ngữ cảnh site. ACAC không tự làm browser gửi cookie; nó là một điều kiện để browser cho script đọc credentialed response. CORS cũng không thay thế CSRF protection cho request có side effect. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** response API synthetic được bảo vệ bằng cookie/session.

- **Actor:** script trên attacker.lab.test trong Chromium; victim đã đăng nhập lab nếu kiểm tra credentialed CORS.

- **Trust boundary:** middleware CORS Express.js 4.x tạo Access-Control-Allow-* dựa trên Origin.

- **Điều kiện cần:** origin không tin cậy được allow và browser cho phép script đọc response; CSRF là threat riêng.

- **Môi trường:** attacker/api origin loopback, Chromium pin version, preflight/network log bật.

Request được gửi không đồng nghĩa CORS bị bypass; phải chứng minh JavaScript đọc được response nhạy cảm theo SOP/CORS. [S1]

## 6. Cơ chế tấn công

Browser gửi `Origin`; khi script yêu cầu credentialed fetch và policy cookie cho phép gắn cookie, middleware trả ACAO/ACAC sai có thể cho JavaScript attacker đọc response. Nếu cookie không được gửi, endpoint không dùng credential khác, hoặc response không chứa dữ liệu nhạy cảm, cùng cấu hình header chưa chứng minh tác động đó. [S1], [S3]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy attacker và API Express loopback, pin Chromium, seed session/data synthetic.
2. **Baseline:** origin allowlist đọc response; origin attacker bị chặn.
3. **Thao tác:** từ attacker origin gửi simple và preflight request, có/không credentials theo từng case.
4. **Expected result:** bản lỗi cho script đọc marker; bản sửa không cấp ACAO/ACAC sai và browser chặn đọc.
5. **Boundary:** thử Origin null, subdomain suffix, port khác và cache Vary: Origin.
6. **Cleanup:** xóa cookie/profile và dừng fixture.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Nhà phát triển tạm thời phản ánh origin CORS để gỡ lỗi rồi triển khai nhầm. Trong fixture, user đã đăng nhập, cookie được cấu hình cho phép credentialed cross-site request và script attacker dùng `credentials: 'include'`. Nếu API cũng phản ánh origin attacker và trả ACAC, browser cho script đọc marker số dư synthetic. Phải kiểm tra riêng cả cookie attachment và khả năng đọc response; không suy ra chúng chỉ từ header CORS. [S3]

## 9. Code dễ bị lỗi và code an toàn

```javascript
// Express.js safe CORS middleware using CORS module with strict whitelist
const express = require('express');
const cors = require('cors');
const app = express();

// === VULNERABLE CODE: reflects every Origin while allowing credentials ===
app.use('/vulnerable-api', cors({
  origin: true,
  credentials: true
}));

// === SECURE CODE (same Express.js/CORS use case) ===
const allowedOrigins = ['https://trusted.victim.lab.test', 'https://admin.victim.lab.test'];

const corsOptions = {
  origin: function (origin, callback) {
    // Requests without Origin are outside browser CORS; route auth still applies
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use('/api', cors(corsOptions));
```

## 10. Phát hiện

- Chạy request từ origin được phép và không được phép; kiểm tra browser có cho script đọc response hay không. [S3]

- Review logic phản chiếu `Origin`, credentials, preflight và `Vary: Origin`. [S3]

- Thu request/response CORS cùng browser console; phân biệt request được gửi với response được đọc.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- So khớp origin đã parse với allowlist chính xác; chỉ gửi ACAO cho origin được phép. [S3]

- Chỉ bật credentials khi cần và không kết hợp chúng với wildcard origin. [S3]

### Defense-in-depth

- Giữ authorization/CSRF control độc lập với CORS.

- Cache response theo `Origin` khi nội dung header thay đổi.

## 12. Retest

- **Positive:** origin allowlisted đọc được đúng response cần thiết.

- **Negative:** origin ngoài allowlist không đọc được response credentialed.

- **Boundary:** `null` origin, port khác, subdomain tương tự, preflight và cache.

- **Telemetry:** lưu Origin, ACAO/ACAC, credential mode và quyết định policy.

## 13. Sai lầm thường gặp

- Phản chiếu mọi giá trị `Origin`.

- Dùng substring hoặc suffix không kiểm tra label boundary.

- Coi preflight là cơ chế authorization.

- Chỉ kiểm tra request có được gửi, không kiểm tra browser cho đọc response.

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

- **Origin:** tuple scheme, host và port dùng trong same-origin checks. [S3]

- **CORS:** giao thức header cho phép server nới lỏng một số quyền đọc cross-origin của browser. [S3]

- **Preflight:** request `OPTIONS` mà browser gửi trước một số request không safelisted. [S3]

## 16. Bài liên quan và đọc thêm

- [Clickjacking](../clickjacking/) — Xem thêm bài học về Clickjacking.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** WHATWG Fetch Standard — CORS protocol and preflight fetch. https://fetch.spec.whatwg.org/ — phiên bản/trạng thái: Living Standard; truy cập: 2026-07-17.
