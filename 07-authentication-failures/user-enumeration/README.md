---
schema_version: 1
id: WEB-A07-USER-ENUMERATION
title: "User Enumeration"
slug: user-enumeration
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-204
  - CWE-200
content_status: technical-review
payload_status: none
last_verified: null
---

# User Enumeration

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích User Enumeration bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đến gõ cửa một văn phòng để tìm một người tên là "Nam".
- Nếu người bảo vệ kiểm tra danh sách và lập tức trả lời: "Ở đây không có ai tên Nam cả", bạn biết ngay người này không làm việc tại đây.
- Nhưng nếu có người tên Nam, người bảo vệ phải đi vào phòng trong, gọi Nam ra, xác nhận thông tin, mất khoảng 5 phút.

Tin tặc có thể khai thác sự khác biệt này thông qua một cuộc tấn công đo thời gian phản hồi (**Timing Attack**). Khi đăng nhập, nếu tài khoản tồn tại, máy chủ sẽ thực hiện một thuật toán băm mật khẩu rất phức tạp và chậm (như `bcrypt.compare`) để đối chiếu mật khẩu, mất khoảng vài trăm mili-giây. Nhưng nếu tài khoản không tồn tại, máy chủ lập tức báo lỗi ngay ở bước tìm kiếm mà không băm gì cả. Bằng cách đo thời gian phản hồi siêu nhỏ này, tin tặc sẽ biết chính xác email nào đã đăng ký trên hệ thống của bạn.

Để ngăn chặn, lập trình viên sử dụng kỹ thuật băm giả lập (**Dummy Hash**). Nếu không tìm thấy người dùng trong cơ sở dữ liệu, máy chủ sẽ không báo lỗi ngay mà tự động lôi một chuỗi mật mã giả ra để băm thử với mật khẩu người dùng nhập vào. Việc này làm máy chủ tiêu tốn khoảng thời gian giống hệt như khi đối chiếu với tài khoản thật. Kết quả là dù tài khoản có tồn tại hay không, thời gian trả về phản hồi đều như nhau, đồng thời máy chủ hiển thị một thông điệp chung chung giống hệt nhau (như "Email hoặc mật khẩu không đúng").

```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// A generic dummy hash conforming to bcrypt's standard format
const DUMMY_HASH = "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');

    // Always use a generic message to prevent authentication disclosure
    const genericMessage = "Invalid email or password.";

    try {
        const user = await db.findUserByEmail(email);

        // Determine whether a valid hash exists for the fetched user
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;

        // If user doesn't exist, use the DUMMY_HASH to prevent timing differences
        const passwordHash = hasValidHash ? user.passwordHash : DUMMY_HASH;

        // Always execute the hashing function (bcrypt.compare) to ensure equal timing
        const isMatch = await bcrypt.compare(passwordStr, passwordHash);

        if (!user || !hasValidHash || !isMatch) {
            return res.status(401).json({ success: false, message: genericMessage });
        }

        // Handle successful login and issue token
        const token = generateToken(user);
        return res.json({ success: true, token });
    } catch (error) {
        return res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Dò tìm tài khoản (User Enumeration) xảy ra khi ứng dụng vô tình để lộ việc một tên đăng nhập hoặc email có tồn tại trên hệ thống hay không thông qua các thông báo lỗi khác nhau hoặc qua độ trễ thời gian phản hồi của máy chủ.

Mối nguy hiểm của lỗ hổng này nằm ở chỗ nó giúp kẻ tấn công dễ dàng quét và lập ra một danh sách chứa toàn bộ các tài khoản có thực của khách hàng. Đây là bước đệm lý tưởng để chúng thực hiện các cuộc tấn công tiếp theo như dò mật khẩu hàng loạt (Brute-Force), tấn công lừa đảo đích danh (Phishing), hoặc tống tiền bằng cách đe dọa công bố danh tính người dùng của một dịch vụ nhạy cảm nào đó.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** sự tồn tại account tổng hợp và response auth/reset.
- **Actor, xác thực và role:** anonymous thử danh sách username fixture có giới hạn.
- **Điều kiện khai thác:** khác biệt body, status hoặc work factor tạo oracle ổn định.
- **Browser, proxy, framework và phiên bản:** Node.js 20, bcrypt cost và Express timing harness được pin; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với user enumeration, khác biệt body, status hoặc work factor tạo oracle ổn định. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Node.js 20, bcrypt cost và Express timing harness được pin; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case user enumeration; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “khác biệt body, status hoặc work factor tạo oracle ổn định”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của user enumeration; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công gửi danh sách email đăng nhập tới trang đăng nhập, đăng ký hoặc khôi phục mật khẩu của ứng dụng. Nếu trang đăng nhập báo "Tài khoản không tồn tại" thay vì một thông báo chung "Thông tin đăng nhập không hợp lệ", kẻ tấn công sẽ biết ngay email đó có đăng ký hay chưa. Tương tự, nếu máy chủ băm mật khẩu bằng thuật toán chậm (như bcrypt) khi tìm thấy tài khoản nhưng lại bỏ qua băm khi tài khoản không tồn tại, kẻ tấn công có thể đo thời gian phản hồi (Timing Attack) để xác định sự hiện diện của người dùng.

## 9. Code dễ bị lỗi và code an toàn

Hai endpoint sau dùng Express 4.x và bcrypt 5.x cho cùng luồng login. Response khác nhau hoặc bỏ qua password hashing khi user không tồn tại có thể tạo oracle nội dung hoặc thời gian; bản an toàn dùng thông báo chung và vẫn chạy một phép so sánh bcrypt với hash giả hợp lệ. [S2]

### Không an toàn (vulnerable): phản hồi và control flow khác nhau

```javascript
app.post('/api/login', async (req, res) => {
    const user = await db.findUserByEmail(req.body.email);
    if (!user) {
        // Vulnerable: distinct response and early return disclose account existence
        return res.status(404).json({ message: 'Account does not exist' });
    }
    const match = await bcrypt.compare(String(req.body.password || ''), user.passwordHash);
    if (!match) return res.status(401).json({ message: 'Wrong password' });
    res.json({ success: true, token: generateToken(user) });
});
```

### An toàn (secure): response chung và bcrypt path nhất quán

```javascript
const bcrypt = require('bcrypt');

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const passwordStr = String(password || '');

    // Use a generic message for all authentication failures
    const genericMessage = "Invalid email or password.";

    try {
        const user = await db.findUserByEmail(email);
        const hasValidHash = user && typeof user.passwordHash === 'string' && user.passwordHash.length === 60;
        const passwordHash = hasValidHash ? user.passwordHash : "$2b$12$K3o8z1t.K4S8P9y2X6o2O.uK7zYVnU7g6r2gG.G.y8y2y2y2y2y2y";

        const match = await bcrypt.compare(passwordStr, passwordHash);

        if (!user || !hasValidHash || !match) {
            return res.status(401).json({ success: false, message: genericMessage });
        }

        // Successful authentication logic
        res.json({ success: true, token: generateToken(user) });
    } catch (error) {
        res.status(500).json({ success: false, message: "An unexpected error occurred." });
    }
});
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng status/body/work factor nhất quán và rate/detect enumeration.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Chống dò tìm tài khoản bằng cách sử dụng thông điệp phản hồi đồng nhất, đồng bộ hóa thời gian xử lý bằng dummy hash cho tài khoản không tồn tại, và triển khai giới hạn tần suất (rate limiting).
- **Các bước chi tiết**:
  - Trả về thông báo lỗi chung, giống hệt nhau (ví dụ: 'Email hoặc mật khẩu không hợp lệ' hoặc 'Nếu email tồn tại, link khôi phục đã được gửi') cho cả tài khoản tồn tại và không tồn tại.
  - Đảm bảo mọi luồng xử lý trên máy chủ có độ trễ thời gian tương đương nhau bằng cách sử dụng dummy hash có độ phức tạp (work factor) bằng với hash thật khi tài khoản không tồn tại.
  - Triển khai cơ chế rate limiting trên tất cả các endpoint liên quan đến xác thực để ngăn cản việc rà quét tự động hàng loạt.
  - Tránh trả về các mã trạng thái HTTP khác nhau (như 200 OK vs 404 Not Found) hoặc giao diện hiển thị khác nhau dựa trên sự tồn tại của người dùng.

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

- **User Enumeration (Dò tìm tài khoản)**: Lỗ hổng cho phép kẻ tấn công xác định xem một tài khoản người dùng hoặc email cụ thể có tồn tại trên hệ thống hay không bằng cách phân tích sự khác biệt trong phản hồi của ứng dụng.
- **Timing Attack (Tấn công đo thời gian)**: Phương pháp tấn công gián tiếp bằng cách đo lượng thời gian máy chủ cần để xử lý các yêu cầu khác nhau, từ đó suy đoán ra cấu trúc logic hoặc sự hiện diện của dữ liệu bên trong.
- **Dummy Hash (Băm giả định)**: Kỹ thuật chạy thuật toán băm với một khóa giả khi tài khoản không tồn tại, nhằm làm giả thời gian xử lý của máy chủ sao cho tương đương với trường hợp tài khoản có thật.
- **Rate Limiting (Giới hạn tần suất)**: Biện pháp kiểm soát số lượng yêu cầu mà một địa chỉ IP hoặc người dùng được phép thực hiện trong một đơn vị thời gian để ngăn chặn việc dò quét tự động.
- **Authentication Disclosure (Lộ lọt thông tin xác thực)**: Tình trạng ứng dụng cung cấp quá nhiều chi tiết về quá trình đăng nhập (như "mật khẩu sai" hoặc "tài khoản không tồn tại"), gián tiếp giúp tin tặc thu hẹp phạm vi tấn công.

## 16. Bài liên quan và đọc thêm

- [2FA/MFA Bypass](../2fa-mfa-bypass/README.md)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-204. https://cwe.mitre.org/data/definitions/204.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
