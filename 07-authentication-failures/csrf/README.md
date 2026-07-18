---
schema_version: 1
id: WEB-A07-CSRF
title: "Cross-Site Request Forgery"
slug: csrf
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-352
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site Request Forgery

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Site Request Forgery bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang đăng nhập vào tài khoản ngân hàng của mình trên trình duyệt để chuyển tiền. Sau khi giao dịch xong, bạn không đăng xuất mà mở một tab mới để đọc tin tức giải trí. Vô tình, bạn bấm vào một bài báo giật gân dẫn đến một trang web lạ độc hại.

Trang web độc hại này lập tức chạy một đoạn code ngầm để gửi một yêu cầu chuyển tiền từ tài khoản của bạn đến tài khoản của kẻ xấu. Vì bạn vẫn chưa đăng xuất khỏi trang ngân hàng, trình duyệt của bạn theo thói quen mặc định sẽ tự động đính kèm "chìa khóa phiên" (session cookie) của bạn vào yêu cầu đó và gửi đi. Ngân hàng nhận được yêu cầu kèm chìa khóa hợp lệ của bạn, nên lập tức chuyển tiền mà không hề biết rằng yêu cầu đó được gửi từ tab độc hại bên cạnh. Đây chính là cuộc tấn công **Giả mạo yêu cầu chéo trang (CSRF)**.

Để ngăn chặn trò lừa gạt này, các hệ thống sử dụng hai lớp khiên bảo vệ:
1. **SameSite Cookie**: Thuộc tính này hạn chế một số trường hợp trình duyệt gửi cookie trong ngữ cảnh cross-site. Hành vi khác nhau giữa `Strict`, `Lax` và `None`, đồng thời còn phụ thuộc loại navigation/request; đây là defense-in-depth chứ không thay thế token theo mọi threat model. [S3]
2. **Anti-CSRF Token**: Máy chủ phát một giá trị bí mật gắn với session hoặc request và xác minh nó trên thao tác thay đổi trạng thái. Token không bắt buộc phải dùng một lần cho từng form; yêu cầu cốt lõi là kẻ tấn công cross-site không thể đoán/đọc được và server kiểm tra đúng. [S3]

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const app = express();

const csrfSecret = process.env.CSRF_SECRET;
if (!csrfSecret || Buffer.byteLength(csrfSecret, 'utf8') < 32) {
    throw new Error('CSRF_SECRET must contain at least 32 UTF-8 bytes');
}

app.use(express.json());
app.use(cookieParser(csrfSecret));

// Initialize doubleCsrf helper configuration
const {
    generateToken,
    doubleCsrfProtection
} = doubleCsrf({
    getSecret: () => csrfSecret,
    cookieName: "x-csrf-token",
    cookieOptions: {
        sameSite: "lax", // Protects cookies from being sent in cross-site requests
        path: "/",
        secure: true,    // Requires HTTPS execution environment
        httpOnly: true   // Protects against client-side script access
    },
});

// Route to fetch CSRF token for the frontend form
app.get('/api/csrf-token', (req, res) => {
    const token = generateToken(req, res);
    res.json({ csrfToken: token });
});

// Secure API endpoint protected by CSRF verification middleware
app.post('/api/transfer-funds', doubleCsrfProtection, (req, res) => {
    // Process secure database transaction after successful verification
    res.json({ message: "Transaction completed successfully" });
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng CSRF (Cross-Site Request Forgery) xảy ra khi ứng dụng web tin tưởng một cách tuyệt đối vào các yêu cầu do trình duyệt gửi lên chỉ dựa vào việc có đính kèm cookie xác thực hay không.

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể lợi dụng phiên đăng nhập còn hiệu lực của nạn nhân để thực hiện các hành động phá hoại mà họ không hề hay biết, chẳng hạn như tự động đổi mật khẩu tài khoản, thay đổi email liên kết, hoặc thực hiện các giao dịch chuyển tiền trái phép chỉ bằng cách lừa nạn nhân truy cập vào một liên kết độc hại do chúng chuẩn bị sẵn.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** operation đổi email/transfer và session cookie.
- **Actor, xác thực và role:** origin untrusted khiến browser của role user đã đăng nhập gửi request.
- **Điều kiện khai thác:** server tin ambient cookie nhưng thiếu CSRF token hoặc custom header gắn origin.
- **Browser, proxy, framework và phiên bản:** Chromium và Express 4.x csrf-csrf được pin trên .lab.test; ghi trạng thái SameSite; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với csrf, server tin ambient cookie nhưng thiếu CSRF token hoặc custom header gắn origin. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium và Express 4.x csrf-csrf được pin trên .lab.test; ghi trạng thái SameSite; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case csrf; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “server tin ambient cookie nhưng thiếu CSRF token hoặc custom header gắn origin”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của csrf; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công nhận thấy rằng một ứng dụng cho phép tạo bài viết bằng các yêu cầu GET đơn giản. Hắn gửi cho nạn nhân một liên kết trỏ đến URL đăng bài viết với một payload tùy chỉnh. Khi nạn nhân nhấp vào liên kết trong khi đã đăng nhập, trình duyệt sẽ tự động truyền các cookie xác thực, tạo ra một bài đăng rác đóng vai trò như một sâu máy tính (worm).

### JSON CSRF via Content-Type
Nhiều framework bảo vệ CSRF bằng cách kiểm tra Content-Type. Tuy nhiên nếu endpoint chấp nhận cả `text/plain` và parse nội dung như JSON:

<!-- payload-id: WEB-A07-CSRF-001 -->
<!-- context: pinned Chromium submits a text/plain form cross-site to the Express fixture -->
<!-- prerequisites: Chromium fixture; synthetic account; endpoint intentionally accepts text/plain as JSON -->
<!-- encoding: UTF-8 HTML; browser serializes the crafted input as a text/plain form body and preserves the embedded JSON punctuation -->
<!-- expected-result: synthetic account email changes once and audit log records the cross-site request -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Malicious page: sends JSON data via form with text/plain enctype -->
<form action="https://victim.lab.test/api/update-email" method="POST"
      enctype="text/plain">
  <!-- text/plain is CORS-safelisted, so this form submission is not preflighted -->
  <input name='{"email":"fixture@untrusted.lab.test", "_dummy":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```
Đây không phải là “bypass CORS”: form tạo một simple request mà browser được phép gửi, trong khi SOP/CORS vẫn có thể ngăn trang tấn công đọc response. Với JSON-only API, từ chối simple content types giúp thu hẹp bề mặt; kiểm soát gốc vẫn là CSRF token hoặc custom header kèm CORS allowlist chặt, và `SameSite` là defense-in-depth theo threat model. [S3]

## 9. Code dễ bị lỗi và code an toàn

Hai handler sau dùng Express 4.x và `csrf-csrf` 4.x cho cùng endpoint thay đổi trạng thái. Cookie phiên được browser gửi tự động, nên route chỉ kiểm tra session mà không xác nhận request chủ ý của người dùng là dễ bị CSRF. Token do middleware kiểm tra là kiểm soát gốc trong ví dụ; `SameSite` là lớp bổ sung và phải phù hợp use case. [S3] [S4]

### Không an toàn (vulnerable): chỉ kiểm tra session

```javascript
app.post('/transfer', requireSession, (req, res) => {
  // Vulnerable: a valid session cookie is not proof of request intent
  transferStore.apply(req.user.id, req.body.recipient, req.body.amount);
  res.send('Transfer processed');
});
```

### An toàn (secure): xác minh CSRF token trước side effect

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();

const csrfSecret = process.env.CSRF_SECRET;
if (!csrfSecret || Buffer.byteLength(csrfSecret, 'utf8') < 32) {
  throw new Error('CSRF_SECRET must contain at least 32 UTF-8 bytes');
}

app.use(express.urlencoded({ extended: false }));
// sessionMiddleware is configured before cookie-parser as required by the package
app.use(sessionMiddleware);
app.use(cookieParser());

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => csrfSecret,
  getSessionIdentifier: (req) => req.session.id,
  cookieName: "__Host-psifi.x-csrf-token",
  cookieOptions: {
    sameSite: "strict",
    path: "/",
    secure: true,
  },
  // This server-rendered form sends the token in one explicit body field
  getCsrfTokenFromRequest: (req) => req.body._csrf,
});

app.get('/transfer-form', requireSession, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.render('transfer', { csrfToken });
});

app.post('/transfer', requireSession, doubleCsrfProtection, (req, res) => {
  // Secure: token validation completes before the state-changing operation
  transferStore.apply(req.user.id, req.body.recipient, req.body.amount);
  res.send('Transfer processed');
});
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Verify CSRF token gắn session hoặc custom header với strict CORS trên mọi state-changing route.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sử dụng các token chống CSRF duy nhất và an toàn về mặt mật mã, áp dụng thuộc tính cookie SameSite, và giới hạn các hành động thay đổi trạng thái trong các phương thức POST/PUT/DELETE.
- **Các bước chi tiết**:
  - Triển khai các token chống CSRF duy nhất và an toàn về mặt mật mã cho tất cả các hoạt động thay đổi trạng thái.
  - Chọn `SameSite=Lax` hoặc `Strict` theo luồng đăng nhập/navigation và kiểm thử trên browser được hỗ trợ; không coi SameSite là kiểm soát CSRF duy nhất.
  - Đảm bảo tất cả các hành động thay đổi trạng thái yêu cầu các phương thức HTTP như POST, PUT, hoặc DELETE, thay vì GET.
  - Sử dụng các thư viện hiện đại, được duy trì (như csrf-csrf cho mẫu Double Submit Cookie) để quản lý và xác thực các token chống CSRF.

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

- **SameSite Cookie**: Một thuộc tính của cookie cho phép lập trình viên kiểm soát việc cookie có được gửi kèm theo các yêu cầu từ trang web khác hay không, giúp chống lại việc lạm dụng cookie phiên trong tấn công CSRF.
- **Anti-CSRF Token**: Một chuỗi ký tự ngẫu nhiên, bí mật và duy nhất được máy chủ tạo ra cho mỗi phiên làm việc hoặc yêu cầu của người dùng, dùng để xác thực rằng yêu cầu đó thực sự bắt nguồn từ ứng dụng hợp pháp.
- **Same-Origin Policy (Chính sách đồng nguồn gốc)**: Cơ chế bảo mật quan trọng của trình duyệt ngăn cản các đoạn mã script ở một trang web truy cập vào dữ liệu của một trang web khác ở nguồn gốc (Domain/Port/Protocol) khác.
- **Cross-origin request credentials (Thông tin xác thực chéo nguồn)**: Các thông tin dùng để nhận diện người dùng (như cookie, header xác thực) được tự động gửi kèm theo các yêu cầu mạng hướng tới một tên miền khác với tên miền hiện tại của trang web.
- **Double Submit Cookie**: Kỹ thuật phòng thủ CSRF bằng cách gửi token chống CSRF ở cả cookie và tham số yêu cầu (hoặc header). Máy chủ sẽ so sánh hai giá trị này, nếu trùng khớp thì yêu cầu được chấp nhận.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-352. https://cwe.mitre.org/data/definitions/352.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** OWASP Cross-Site Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** csrf-csrf documentation. https://github.com/Psifi-Solutions/csrf-csrf — phiên bản/trạng thái: 4.x; truy cập: 2026-07-18.
