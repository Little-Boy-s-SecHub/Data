---
schema_version: 1
id: WEB-A05-XSS-DOM-BASED
title: "DOM-based XSS"
slug: xss-dom-based
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
payload_status: static-verified
last_verified: null
---

# DOM-based XSS

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích DOM-based XSS bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Khi trình duyệt tải một trang web, nó sẽ dịch mã nguồn HTML thành một sơ đồ cấu trúc cây gọi là DOM (Document Object Model) để quản lý. Sau đó, JavaScript sẽ chạy để thay đổi động các nút trên cây DOM này (như đổi màu, thêm chữ). Trong quá trình này, JavaScript thường đọc dữ liệu từ các nguồn có sẵn trên trình duyệt (gọi là sources - ví dụ như phần đuôi URL sau dấu `#`) và đưa chúng vào các điểm tiếp nhận dữ liệu trên trang (gọi là sinks - ví dụ như thuộc tính `innerHTML`). Điểm mấu chốt ở đây là cách JavaScript đưa dữ liệu vào: nếu sử dụng `innerHTML`, trình duyệt sẽ cố gắng dịch dữ liệu đó thành mã lập trình thực thi; còn nếu dùng `textContent`, trình duyệt chỉ coi đó là chữ viết thô vô hại và không bao giờ chạy bất kỳ đoạn mã nào ẩn chứa bên trong.

### Code ví dụ hoạt động bình thường (Secure DOM Manipulation)
```javascript
// Secure JavaScript implementation for handling user input in DOM
window.addEventListener('DOMContentLoaded', () => {
    // Extract user profile name from URL query parameter safely
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get('username') || 'Guest';

    // Get DOM elements
    const welcomeTextNode = document.getElementById('welcome-message');
    const customContainer = document.getElementById('custom-content');

    // Safe Method 1: Using textContent to prevent DOM XSS
    // Browser treats the content strictly as text, not HTML/JS
    welcomeTextNode.textContent = `Welcome back, ${username}!`;

    // Safe Method 2: Creating elements programmatically to render structured markup
    const paragraphElement = document.createElement('p');
    paragraphElement.textContent = 'Your profile is loaded successfully.';
    customContainer.appendChild(paragraphElement);
});
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng DOM-based XSS xảy ra hoàn toàn bên trong trình duyệt của người dùng (phía client) mà không cần sự can thiệp trực tiếp của máy chủ. Nó xuất hiện khi các đoạn mã JavaScript của trang web lấy dữ liệu từ một nguồn không an sau (source) rồi đẩy thẳng vào một điểm tiếp nhận nhạy cảm (sink như innerHTML hoặc eval) mà quên không kiểm tra hay làm sạch. Kẻ tấn công có thể dụ nạn nhân bấm vào một liên kết có phần đuôi URL chứa mã độc. Khi trang web tải lên, JavaScript phía client tự động lấy đoạn mã độc này từ URL và ghi vào trang web thông qua `innerHTML`, khiến trình duyệt thực thi mã độc ngay lập tức. Lỗ hổng này cực kỳ phổ biến trong các ứng dụng hiện đại (Single Page Application) vốn sử dụng JavaScript rất nhiều để thay đổi giao diện động.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** DOM và dữ liệu client từ URL, storage hoặc message.
- **Actor, xác thực và role:** actor điều khiển source; nạn nhân role user mở fixture.
- **Điều kiện khai thác:** client source đi vào innerHTML, eval hoặc document.write.
- **Browser, proxy, framework và phiên bản:** Chromium được pin với fixture JavaScript tĩnh trên .lab.test; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với dom based, client source đi vào innerHTML, eval hoặc document.write. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium được pin với fixture JavaScript tĩnh trên .lab.test; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case dom based; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “client source đi vào innerHTML, eval hoặc document.write”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của dom based; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Fixture đọc fragment đã decode rồi gán trực tiếp vào `innerHTML`. Probe chỉ đặt
một marker DOM, không đọc cookie và không truyền dữ liệu ra ngoài. Kết quả chỉ
áp dụng cho đúng source/sink và chính sách browser của fixture; một fragment
xuất hiện trong URL chưa tự nó chứng minh DOM XSS. [S3]

<!-- payload-id: WEB-A05-DOM-XSS-001 -->
<!-- context: pinned Chromium; decoded location.hash is assigned to element.innerHTML on a synthetic origin -->
<!-- prerequisites: local browser fixture; fresh context; no cookies or sensitive data; outbound network disabled -->
<!-- encoding: UTF-8 HTML fragment percent-encoded once in the URL and decoded once before the sink -->
<!-- expected-result: vulnerable fixture sets document.body.dataset.labExecuted to true; textContent-based fixture displays literal markup -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```html
<img src="x" onerror="document.body.dataset.labExecuted='true'">
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// Unsafe sink example:
// element.innerHTML = location.hash; // Vulnerable to DOM XSS

// Secure approach 1: Use textContent for text data
const userInput = location.hash.substring(1);
const textElement = document.getElementById("user-display");
textElement.textContent = userInput; // Safe: content is not parsed as HTML/JS

// Secure approach 2: Sanitize HTML using DOMPurify when markup is needed
import DOMPurify from 'dompurify';

const handleHashChange = () => {
    const dirtyHtml = window.location.hash.substring(1);
    const cleanHtml = DOMPurify.sanitize(dirtyHtml);
    document.getElementById("html-display").innerHTML = cleanHtml;
};
window.addEventListener('hashchange', handleHashChange);
handleHashChange();
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng textContent/DOM construction và validate URL scheme trước navigation.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Ngăn chặn DOM-based XSS bằng cách hạn chế sử dụng innerHTML, ưu tiên dùng textContent, vệ sinh HTML bằng các thư viện mạnh như DOMPurify khi cần render markup, và áp dụng Trusted Types.
- **Các bước chi tiết**:
  - Tránh sử dụng các sink diễn giải chuỗi ký tự thành mã thực thi hoặc HTML (như `element.innerHTML`, `document.write`, `eval`, `setTimeout(string)`).
  - Sử dụng các API an toàn hơn chỉ xử lý văn bản thô (text content) thay vì phân tích cú pháp HTML, chẳng hạn như `element.textContent` hoặc `element.innerText`.
  - Khi bắt buộc phải hiển thị mã HTML từ dữ liệu ngoài, hãy sử dụng thư viện vệ sinh uy tín như `DOMPurify` để loại bỏ toàn bộ kịch bản độc hại.
  - Xây dựng chính sách bảo mật nội dung (CSP) chặt chẽ (ví dụ: cấm dùng `unsafe-inline`).
  - Cấu hình Trusted Types trong trình duyệt để cưỡng chế việc kiểm duyệt và vệ sinh dữ liệu trước khi chèn vào các sink.

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

- **DOM-based XSS**: Lỗ hổng XSS xảy ra hoàn toàn ở phía trình duyệt người dùng do lỗi xử lý dữ liệu trong JavaScript.
- **DOM (Document Object Model)**: Mô hình đối tượng tài liệu cấu trúc phân cấp thể hiện nội dung trang web.
- **Source**: Các nguồn dữ liệu đầu vào mà JavaScript có thể đọc được trên trình duyệt (như location.hash, document.referrer).
- **Sink**: Các điểm hàm hoặc thuộc tính JavaScript nhạy cảm có khả năng thực thi mã (như innerHTML, eval).
- **DOMPurify**: Thư viện lọc và làm sạch mã HTML phía client để ngăn chặn XSS.

## 16. Bài liên quan và đọc thêm

- [DOM Clobbering](../../dom-clobbering/) — Lỗ hổng thao túng DOM.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP DOM based XSS Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
