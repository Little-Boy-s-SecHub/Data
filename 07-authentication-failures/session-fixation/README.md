---
schema_version: 1
id: WEB-A07-SESSION-FIXATION
title: "Session Fixation"
slug: session-fixation
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-384
content_status: technical-review
payload_status: none
last_verified: null
---

# Session Fixation

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Session Fixation bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn bước vào một khách sạn. Thay vì để nhân viên lễ tân cấp cho bạn một chiếc chìa khóa phòng ngẫu nhiên và mới tinh sau khi bạn làm thủ tục nhận phòng (xác thực), bạn lại nhặt một chiếc chìa khóa cũ bị vứt ngay trước sảnh và đưa cho lễ tân: "Tôi muốn dùng chiếc chìa khóa này cho phòng của mình". Nếu lễ tân đồng ý lập tức liên kết căn phòng của bạn với chiếc chìa khóa đó mà không nghi ngờ, bạn đã rơi vào cái bẫy. Kẻ xấu đã cố tình vứt chiếc chìa khóa đó ở sảnh và đánh sẵn một chiếc bản sao giống hệt. Ngay khi bạn cất hành lý vào phòng, chúng chỉ việc dùng chiếc chìa khóa bản sao kia để vào dọn sạch đồ của bạn. Đây chính là lỗ hổng **Cố định phiên làm việc (Session Fixation)**.

Để quản lý an toàn hệ thống, nhà phát triển cần kiểm soát chặt chẽ **vòng đời của phiên làm việc và cookie (session and cookies lifecycle)**. Cookie giống như chiếc thẻ phòng được trình duyệt lưu giữ. Để thẻ này không bị đọc trộm, nó cần được cài đặt các thuộc tính bảo vệ nghiêm ngặt:
- **HttpOnly**: Khóa không cho các mã script (JavaScript) đọc nội dung thẻ (chống XSS).
- **Secure**: Chỉ cho phép truyền thẻ qua các kênh HTTPS được mã hóa.
- **SameSite**: Hạn chế việc gửi thẻ khi đi từ các trang web khác (chống CSRF).

Đặc biệt, quy tắc vàng trong **quản lý vòng đời phiên (session lifecycle management)** là: ngay khi người dùng đăng nhập thành công hoặc nâng đặc quyền, máy chủ bắt buộc phải **hủy bỏ chiếc thẻ cũ** và **cấp một chiếc thẻ mới hoàn toàn ngẫu nhiên**. Việc này sẽ cắt đứt hoàn toàn cơ hội của bất kỳ kẻ xấu nào muốn phục kích bằng chiếc khóa cũ đã biết trước. Ngoài ra, máy chủ cũng cần tự động thu hồi thẻ nếu người dùng không hoạt động sau một thời gian (idle timeout) để đảm bảo an toàn tối đa.

```javascript
const express = require('express');
const app = express();

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.authenticate(username, password);

    if (!user) {
        return res.status(401).send("Invalid credentials");
    }

    // Keep temporary session data before destroying the old session
    const tempCart = req.session.cart;

    // Regenerate session ID immediately on privilege elevation (login)
    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).send("Session regeneration failed");
        }

        // Populate the new session with authenticated user details
        req.session.userId = user.id;
        req.session.cart = tempCart;

        // Explicitly save the session to prevent write/read race conditions
        req.session.save((saveErr) => {
            if (saveErr) {
                return res.status(500).send("Failed to save secure session");
            }
            return res.json({ status: "Logged in and session regenerated successfully" });
        });
    });
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Cố định phiên (Session Fixation) xảy ra khi ứng dụng web cho phép người dùng sử dụng tiếp mã định danh phiên (Session ID) cũ sau khi họ đã đăng nhập thành công.

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể chủ động tạo ra một mã Session ID hợp lệ, tìm cách cài cắm mã này vào trình duyệt của nạn nhân (ví dụ qua một liên kết chứa tham số session ID). Khi nạn nhân bấm vào và đăng nhập thành công, máy chủ liên kết tài khoản của nạn nhân với mã ID đó. Do kẻ tấn công đã nắm giữ mã này từ trước, chúng có thể dễ dàng truy cập thẳng vào tài khoản của nạn nhân mà không cần biết tên đăng nhập hay mật khẩu.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** session identifier trước và sau authentication.
- **Actor, xác thực và role:** actor đặt trước ID; nạn nhân sau đó login với role user.
- **Điều kiện khai thác:** server giữ nguyên ID qua authentication boundary.
- **Browser, proxy, framework và phiên bản:** Flask/Express session store và hai Chromium context được pin trên .lab.test; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với session fixation, server giữ nguyên ID qua authentication boundary. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Flask/Express session store và hai Chromium context được pin trên .lab.test; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case session fixation; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “server giữ nguyên ID qua authentication boundary”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của session fixation; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công (Mal) truy cập trang web mục tiêu và nhận được một Session ID hợp lệ chưa đăng nhập (ví dụ: `SID=XYZ123`).
Bước 2: Mal gửi cho nạn nhân (Vic) một liên kết dẫn tới trang web mục tiêu có đính kèm mã Session ID này trong query string: `https://victim.lab.test/login?session_id=XYZ123`.
Bước 3: Vic click vào link và tiến hành đăng nhập bằng tài khoản của mình. Ứng dụng chấp nhận Session ID `XYZ123` có sẵn từ URL và liên kết phiên đăng nhập của Vic vào mã ID này.
Bước 4: Vì Mal đã biết trước mã ID `XYZ123`, Mal cấu hình trình duyệt của mình sử dụng cookie `SID=XYZ123` và truy cập trực tiếp vào hệ thống để chiếm quyền điều khiển tài khoản của Vic.

## 9. Code dễ bị lỗi và code an toàn

Hai handler sau dùng Express 4.x và `express-session` 1.18.x cho cùng luồng login. Gắn identity vào session hiện hữu giữ nguyên session ID trước xác thực; bản an toàn regenerate session rồi mới lưu identity và dữ liệu pre-login đã chọn rõ. [S2] [S3]

### Không an toàn (vulnerable): nâng quyền session hiện hữu

```javascript
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (!user) return res.status(401).send('Invalid credentials');

  // Vulnerable: the pre-authentication session ID remains authenticated
  req.session.userId = user.id;
  res.send('Logged in');
});
```

### An toàn (secure): regenerate session khi đổi mức xác thực

```javascript
// User login endpoint in Express
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (user) {
    const tempCart = req.session.cart;
    // Regenerate session ID to prevent Session Fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).send('Session error');
      req.session.userId = user.id;
      req.session.cart = tempCart;
      // Fix: Explicitly save session to prevent write/read race conditions
      req.session.save((err) => {
        if (err) return res.status(500).send('Session error');
        res.send('Logged in successfully');
      });
    });
  } else {
    res.status(401).send('Invalid credentials');
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

- Rotate session ID atomically khi login/đổi privilege và invalidate ID cũ.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Session fixation is an attack where a malicious user forces another user's session identifier to a predetermined value, allowing them to hijack the session after authentication. Mitigation requires generating a new session identifier immediately upon any privilege level change, specifically during login.
- **Các bước chi tiết**:
  - Always invalidate the existing session and generate a new session identifier (session ID) immediately upon successful user login.
  - Implement proper session timeout mechanisms (both idle timeout and absolute timeout).
  - Secure cookies containing session identifiers by setting attributes: HttpOnly (prevent JS access), Secure (force HTTPS), and SameSite=Strict or SameSite=Lax.
  - Ensure session IDs are random, cryptographically strong, and generated by the server's security framework rather than accepted from client input.

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

- **Session Fixation (Cố định phiên)**: Lớp lỗ hổng bảo mật xảy ra khi ứng dụng cho phép người dùng duy trì cùng một mã định danh phiên (Session ID) sau khi đăng nhập, tạo điều kiện cho tin tặc chiếm quyền điều khiển phiên bằng mã ID biết trước.
- **Session ID (Mã phiên)**: Một chuỗi ký tự ngẫu nhiên duy nhất được máy chủ tạo ra để nhận diện phiên làm việc hiện tại của một người dùng cụ thể trên ứng dụng web.
- **HttpOnly Cookie**: Thuộc tính bảo mật của cookie ngăn cản các mã script chạy trên trình duyệt (như JavaScript) truy cập vào giá trị của cookie, giúp giảm thiểu rủi ro bị đánh cắp cookie qua lỗ hổng XSS.
- **Secure Cookie**: Thuộc tính yêu cầu trình duyệt chỉ được phép truyền cookie này lên máy chủ thông qua kết nối HTTPS được mã hóa an toàn.
- **SameSite Cookie**: Thuộc tính kiểm soát việc cookie có được gửi kèm theo các yêu cầu từ trang web của bên thứ ba hay không, giúp ngăn chặn tấn công CSRF.
- **Session Lifecycle Management (Quản lý vòng đời phiên)**: Quy trình kiểm soát toàn bộ vòng đời của một phiên làm việc, từ lúc khởi tạo, gia hạn, cho đến khi hủy bỏ hoàn toàn khi người dùng đăng xuất hoặc phiên hết hạn.

## 16. Bài liên quan và đọc thêm

- [OAuth 2.0 Vulnerabilities](../oauth-vulnerabilities/README.md)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-384. https://cwe.mitre.org/data/definitions/384.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** Express session — Session.regenerate. https://github.com/expressjs/session#sessionregeneratecallback — phiên bản/trạng thái: express-session 1.18.x; truy cập: 2026-07-18.
