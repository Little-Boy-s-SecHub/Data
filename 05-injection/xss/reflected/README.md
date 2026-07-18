---
schema_version: 1
id: WEB-A05-XSS-REFLECTED
title: "Reflected XSS"
slug: xss-reflected
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: none
last_verified: null
---

# Reflected XSS

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Reflected XSS bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng tham số truy vấn trên URL giống như một lời nhắn gửi kèm theo phong bì thư bạn gửi lên máy chủ (ví dụ: `?q=tin_tức`). Khi nhận được phong bì, máy chủ sẽ đọc lời nhắn này và dùng nó để tạo ra một trang phản hồi động (như trang kết quả tìm kiếm cho từ khóa "tin_tức") rồi gửi lại cho bạn. Tuy nhiên, nếu máy chủ này quá ngây thơ – nhận được lời nhắn thế nào liền in nguyên văn như thế lên trang phản hồi mà không thèm kiểm tra xem lời nhắn đó có chứa các ký tự nguy hiểm của ngôn ngữ HTML hay không – thì đó chính là nguồn cơn của lỗ hổng bảo mật.

### Code ví dụ hoạt động bình thường (Secure Server-Side Rendering)
```javascript
const express = require('express');
const app = express();

// Helper function to escape HTML characters and prevent XSS injection
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Express route handling search query parameters
app.get('/search', (req, res) => {
    // Retrieve parameter and ensure it is treated strictly as a string
    const rawQuery = typeof req.query.q === 'string' ? req.query.q : '';

    // Escape user input before interpolating it into server-side HTML rendering
    const safeQuery = escapeHtml(rawQuery);

    // Send response with safely encoded parameters
    res.setHeader('Content-Type', 'text/html');
    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: <strong>${safeQuery}</strong></p>
            </body>
        </html>
    `);
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Reflected XSS (XSS phản xạ) xảy ra khi máy chủ lấy dữ liệu từ yêu cầu gửi lên và "phản chiếu" ngay lập tức nó vào trang web trả về cho trình duyệt mà không qua bộ lọc an toàn. Kẻ tấn công sẽ tạo ra một đường dẫn URL chứa mã JavaScript độc hại ở phần tham số truy vấn rồi tìm cách lừa nạn nhân click vào đó. Khi nạn nhân bấm link, trình duyệt gửi yêu cầu lên máy chủ, máy chủ lập tức phản chiếu đoạn mã độc đó vào trang HTML trả về. Trình duyệt của nạn nhân nhận được trang web, tưởng đó là nội dung hợp lệ của hệ thống nên chạy mã độc ngay lập tức. Sự nguy hiểm của cuộc tấn công này nằm ở chỗ nó diễn ra tức thì và có thể dễ dàng giúp kẻ tấn công cướp quyền đăng nhập của người dùng chỉ qua một cú click chuột đơn giản.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** HTML response tức thời và session visitor.
- **Actor, xác thực và role:** actor gửi link; nạn nhân role user mở search public.
- **Điều kiện khai thác:** query input được phản chiếu vào HTML mà không contextual encoding.
- **Browser, proxy, framework và phiên bản:** Chromium và Express 4.x được pin trên .lab.test; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với reflected, query input được phản chiếu vào HTML mà không contextual encoding. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium và Express 4.x được pin trên .lab.test; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case reflected; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “query input được phản chiếu vào HTML mà không contextual encoding”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của reflected; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Trong browser lab, `https://victim.lab.test/search?q=banana` phản chiếu tham số tìm kiếm. Một giá trị thử nghiệm chèn script chỉ đặt `document.body.dataset.labExecuted='true'`; không truyền cookie hoặc dữ liệu ra mạng. Nếu marker xuất hiện ở vulnerable fixture nhưng được encode thành text ở secure fixture, lab đã chứng minh sink XSS trong đúng output context.

## 9. Code dễ bị lỗi và code an toàn

Hai handler sau dùng Express 4.x cho cùng route tìm kiếm. Khác biệt nằm ở việc dữ liệu không tin cậy được chèn trực tiếp hay được encode đúng HTML text context trước khi render. [S2] [S3] [S4]

### Không an toàn (vulnerable): nội suy input trực tiếp

```javascript
app.get('/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    // Vulnerable: user input is interpreted as part of the HTML response
    res.send(`<h1>Search results for: ${query}</h1>`);
});
```

### An toàn (secure): encode cho HTML text context

```javascript
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Example handler rendering search results
app.get('/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    const safeQuery = escapeHtml(query);
    // Secure for this HTML text context
    res.send(`<h1>Search results for: ${safeQuery}</h1>`);
});
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Render bằng template auto-escaping hoặc encode đúng context.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Phòng chống Reflected XSS bằng cách mã hóa dữ liệu đầu ra dựa theo ngữ cảnh hiển thị, kiểm tra kiểu dữ liệu đầu vào nghiêm ngặt và triển khai chính sách Content Security Policy (CSP).
- **Các bước chi tiết**:
  - Thực hiện mã hóa đầu ra tương thích với ngữ cảnh (HTML body, thuộc tính HTML, kịch bản JavaScript, hoặc tham số URL) cho tất cả các dữ liệu do người dùng cung cấp trước khi trả về.
  - Xác thực và lọc sạch tất cả các tham số đầu vào bằng cơ chế danh sách trắng (allowlist).
  - Triển khai chính sách bảo mật nội dung (CSP) nghiêm ngặt để cấm thực thi các tập lệnh inline không rõ nguồn gốc và giới hạn nguồn script được phép tải.
  - Sử dụng các framework hiện đại (React, Angular, Vue) có tích hợp sẵn cơ chế mã hóa đầu ra an toàn theo mặc định.
  - Thiết lập tiêu đề phản hồi `X-Content-Type-Options: nosniff` để ngăn chặn các cuộc tấn công khai thác MIME-sniffing.

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

- **Reflected XSS**: Lỗ hổng XSS phản xạ, mã độc được gửi qua request và trả về ngay lập tức trong response của server.
- **Query Parameter**: Tham số đi kèm trên đường dẫn URL để truyền tải dữ liệu.
- **Server-Side Rendering**: Phương pháp dựng toàn bộ giao diện HTML động ngay trên máy chủ trước khi gửi về client.
- **Payload**: Đoạn mã khai thác được kẻ tấn công chèn vào hệ thống.
- **HTML Entity**: Ký tự mã hóa đặc biệt đại diện cho các thẻ HTML giúp trình duyệt không hiểu nhầm thành lệnh thực thi.

## 16. Bài liên quan và đọc thêm

- [Stored XSS](../stored/) — Lỗ hổng XSS lưu trữ.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP WSTG — Testing for Reflected Cross Site Scripting. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting — phiên bản/trạng thái: latest; truy cập: 2026-07-18.
