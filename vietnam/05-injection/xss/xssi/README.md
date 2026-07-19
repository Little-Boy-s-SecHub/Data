---
schema_version: 1
id: WEB-A05-XSS-XSSI
title: "Cross-Site Script Inclusion"
slug: xss-xssi
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-200
content_status: technical-review
payload_status: none
last_verified: null
---

# Cross-Site Script Inclusion

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Site Script Inclusion bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Cross-Site Script Inclusion và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Chính sách đồng nguồn gốc (SOP) hạn chế một origin đọc response của origin khác qua nhiều API. Tuy nhiên, cơ chế nạp script cho phép browser gửi request chéo origin và thực thi tài nguyên được phân loại là JavaScript; điều đó không tự động cho trang gọi đọc response bytes. XSSI chỉ hình thành khi tài nguyên động mang dữ liệu nhạy cảm tạo ra side effect quan sát được trong runtime cụ thể. [S3] [S4]

### Code ví dụ hoạt động bình thường (Secure JSON Response with Anti-XSSI)
```javascript
const express = require('express');
const app = express();

// Secure middleware setting HTTP headers to prevent MIME-sniffing
app.use((req, res, next) => {
    // Force browser to respect the declared Content-Type (prevents executing non-JS as JS)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// Secure API endpoint returning user profile details
app.get('/api/user-profile', (req, res) => {
    const userProfile = {
        username: "johndoe",
        email: "johndoe@victim.lab.test",
        role: "user"
    };

    // Return content type as application/json rather than application/javascript
    res.setHeader('Content-Type', 'application/json');

    // Optional compatibility measure for clients that explicitly strip this prefix.
    // It is defense-in-depth for specific legacy JSON-hijacking patterns.
    const antiXssiPrefix = ")]}',\n";
    res.send(antiXssiPrefix + JSON.stringify(userProfile));
});
```

## 4. Mô tả và nguyên nhân gốc

XSSI xảy ra khi một origin khác có thể nạp tài nguyên JavaScript động mang dữ liệu nhạy cảm và dữ liệu đó trở nên quan sát được qua side effect, biến toàn cục, callback hoặc kỹ thuật phù hợp với browser/runtime. Phần tử nạp script có thể gửi request chéo origin, nhưng khả năng đọc dữ liệu không tự động suy ra chỉ từ việc request thành công. Cookie còn phụ thuộc `SameSite` và ngữ cảnh request; phải chứng minh dữ liệu quan sát được trong browser fixture. [S3] [S4]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** profile động và cookie session API.
- **Actor, xác thực và role:** origin untrusted include resource khi role user có session tổng hợp.
- **Điều kiện khai thác:** dữ liệu nhạy cảm được trả dưới JavaScript quan sát được cross-origin hoặc JSON legacy yếu.
- **Browser, proxy, framework và phiên bản:** Chromium và Express 4.x được pin trên victim/untrusted .lab.test; ghi trạng thái SameSite; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với xssi, dữ liệu nhạy cảm được trả dưới JavaScript quan sát được cross-origin hoặc JSON legacy yếu. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium và Express 4.x được pin trên victim/untrusted .lab.test; ghi trạng thái SameSite; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case xssi; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “dữ liệu nhạy cảm được trả dưới JavaScript quan sát được cross-origin hoặc JSON legacy yếu”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của xssi; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Trong lab, trang `untrusted.lab.test` nạp `https://victim.lab.test/js/user-profile.js`. Chỉ ghi nhận lỗ hổng nếu browser trace cho thấy cookie thực sự được gửi theo cấu hình `SameSite` của fixture và script tạo ra một giá trị/side effect mà origin không tin cậy quan sát được; việc tải tài nguyên thành công đơn thuần chưa đủ.

## 9. Code dễ bị lỗi và code an toàn

Hai endpoint sau dùng Express 4.x cho cùng use case trả hồ sơ đã xác thực. Response JavaScript động tạo side effect toàn cục là thiết kế dễ bị XSSI; JSON không thực thi và `nosniff` làm giảm bề mặt này. Prefix chỉ là defense-in-depth cho client legacy, không thay thế content type và authorization. [S2] [S3] [S4]

### Không an toàn (vulnerable): trả dữ liệu nhạy cảm dưới dạng JavaScript động

```javascript
app.get('/api/user-profile.js', requireSession, (req, res) => {
    const profile = { name: req.user.name, email: req.user.email };
    // Vulnerable: cross-origin script loading can observe this global side effect
    res.type('application/javascript');
    res.send(`window.profile = ${JSON.stringify(profile)};`);
});
```

### An toàn (secure): trả JSON không thực thi

```javascript
app.use((req, res, next) => {
    // Prevent browsers from MIME-sniffing the response as script
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

app.get('/api/user-profile', requireSession, (req, res) => {
    const profile = { name: req.user.name, email: req.user.email };

    // Optional legacy defense for clients that explicitly strip this prefix
    res.type('application/json');
    res.send(")]}',\n" + JSON.stringify(profile));
});
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Cross-Site Script Inclusion, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Trả dữ liệu xác thực bằng JSON đúng MIME/nosniff, không bằng JavaScript thực thi.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Cross-Site Script Inclusion, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Không phát dữ liệu nhạy cảm dưới dạng JavaScript có thể include chéo origin; yêu cầu xác thực/ủy quyền phù hợp, dùng JSON với `application/json` và `nosniff`. Anti-XSSI prefix chỉ là defense-in-depth cho client và kiểu tấn công tương thích.
- **Các bước chi tiết**:
  - Tuyệt đối không nhúng các thông tin nhạy cảm, dữ liệu cá nhân của người dùng dưới dạng biến số trong các file kịch bản JavaScript tĩnh hoặc động.
  - Sử dụng định dạng dữ liệu JSON để truyền tải thông tin, và xác thực các yêu cầu API bằng token chống CSRF hoặc header Authorization thay vì chỉ dựa vào session cookie.
  - Có thể dùng tiền tố như `)]}',\n` khi mọi client chủ động loại bỏ nó và browser regression test xác nhận hiệu quả; không coi tiền tố này là kiểm soát phổ quát cho mọi dạng XSSI.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để bắt buộc trình duyệt không thực thi các tệp định dạng phi kịch bản (như JSON, CSV) dưới dạng script.
  - Cấu hình chính sách CORS để giới hạn các nguồn truy cập hợp lệ tới các endpoint nhạy cảm.

## 12. Retest

- **Positive case:** với Cross-Site Script Inclusion, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Cross-Site Script Inclusion mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

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

- **XSSI (Cross-Site Script Inclusion)**: Lỗ hổng cho phép trang web độc hại đọc dữ liệu nhạy cảm được nhúng trong file JavaScript động của trang web khác.
- **SOP (Same-Origin Policy)**: Cơ chế bảo mật chặn quyền truy cập chéo tài nguyên giữa các nguồn khác nhau.
- **Dynamic JavaScript**: File JavaScript được tạo ra động theo ngữ cảnh cụ thể của từng phiên người dùng.
- **MIME Sniffing**: Tính năng tự nhận diện định dạng file thực tế của trình duyệt bất chấp khai báo trên header.
- **Nosniff**: Giá trị cấu hình của tiêu đề X-Content-Type-Options ngăn cản MIME sniffing của trình duyệt.

## 16. Bài liên quan và đọc thêm

- [Reflected XSS](../reflected/) — Lỗ hổng phản xạ tập lệnh.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** WHATWG HTML Living Standard — The script element. https://html.spec.whatwg.org/multipage/scripting.html#the-script-element — phiên bản/trạng thái: Living Standard; truy cập: 2026-07-18.
- **[S4]** Fetch Living Standard — X-Content-Type-Options. https://fetch.spec.whatwg.org/#x-content-type-options-header — phiên bản/trạng thái: Living Standard; truy cập: 2026-07-18.
