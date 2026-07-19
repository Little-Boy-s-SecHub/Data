---
schema_version: 1
id: WEB-A05-REGEX-INJECTION
title: "Regex Injection"
slug: regex-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1333
content_status: technical-review
payload_status: none
last_verified: null
---

# Regex Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Regex Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Regex Injection và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Biểu thức chính quy (Regex) giống như một tấm lưới lọc văn bản vô cùng thông minh giúp tìm kiếm các chuỗi ký tự theo một quy luật định sẵn. Khi lọc thông tin, các bộ máy Regex thường sử dụng cơ chế "quay lui" (backtracking) – tức là nếu thử một đường đi không khớp, nó sẽ quay lại ngã rẽ trước đó để thử đường đi khác. Tuy nhiên, nếu tấm lưới lọc này được thiết kế quá phức tạp (ví dụ chứa các vòng lặp lồng nhau) gặp đúng một chuỗi dữ liệu gần giống nhưng không khớp ở phút chót, bộ máy Regex sẽ phải thử hàng triệu triệu tổ hợp đường đi khác nhau. Hiện tượng này gọi là quay lui vô hạn (catastrophic backtracking), giống như một người bị lạc vào mê cung không lối thoát và kiệt sức vì cố tìm đường.

```javascript
// JavaScript normal operation of regex searching
function escapeRegex(inputString) {
    // Escapes special regex characters to treat them as literal characters
    return inputString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function searchUserContent(userInput, documentText) {
    // Escape the user input to prevent regex injection / catastrophic backtracking
    const safePattern = escapeRegex(userInput);

    // Create a regular expression safely using the escaped literal pattern
    const regex = new RegExp(safePattern, 'i');
    return regex.test(documentText);
}
```

## 4. Mô tả và nguyên nhân gốc

Regex Injection xảy ra khi actor kiểm soát toàn bộ hoặc một phần pattern và có thể làm thay đổi ngữ nghĩa so khớp. Với engine backtracking, một số pattern/input gây thời gian xử lý tăng rất nhanh và có thể dẫn đến ReDoS; mức CPU, thời gian và blast radius phụ thuộc engine, pattern, input, concurrency và timeout, không mặc định là “quay lui vô hạn” hay luôn đạt 100% CPU. [S2]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** CPU worker và kết quả validation bằng regex.
- **Actor, xác thực và role:** anonymous gọi search/validation.
- **Điều kiện khai thác:** regex tùy ý hoặc backtracking xấu làm thời gian tăng phi tuyến.
- **Browser, proxy, framework và phiên bản:** Node.js 20 trong container có timeout 200 ms, CPU/memory cap và giới hạn input; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với regex injection, regex tùy ý hoặc backtracking xấu làm thời gian tăng phi tuyến. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Node.js 20 trong container có timeout 200 ms, CPU/memory cap và giới hạn input; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case regex injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “regex tùy ý hoặc backtracking xấu làm thời gian tăng phi tuyến”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của regex injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công tìm thấy một tính năng tìm kiếm hoặc lọc dữ liệu sử dụng biểu thức chính quy (Regex) được xây dựng động từ chuỗi tìm kiếm đầu vào của người dùng.
Bước 2: Kẻ tấn công gửi một chuỗi đầu vào được thiết kế đặc biệt chứa các nhóm lặp lồng nhau (ví dụ: `(a+)+` hoặc `(a|a)+$`) cùng với một chuỗi không khớp ở cuối (như `aaaaaaaaaaaaaaaaaaaaaaaa!`).
Bước 3: Trình phân tích Regex của máy chủ thực hiện cơ chế quay lui (backtracking) qua hàng triệu khả năng để tìm kiếm sự trùng khớp.
Bước 4: Trong fixture có timeout và CPU cap, đo thời gian/CPU theo kích thước input; chỉ kết luận ReDoS khi độ phức tạp quan sát được tăng bất thường và làm cạn budget đã định, không chạy input không giới hạn. [S2]

## 9. Code dễ bị lỗi và code an toàn

```python
# ReDoS vulnerable pattern: catastrophic backtracking on (a+)+ type
import re, time

# Vulnerable: exponential backtracking
pattern = r'^(a+)+$'  # catastrophic for input like 'aaaaaaaaaaaaaaaaaX'
test_input = 'a' * 30 + 'X'

start = time.time()
try:
    re.match(pattern, test_input, timeout=5)
except re.error:
    pass
print(f'Time: {time.time() - start:.2f}s')  # can take seconds/minutes

# Secure: use atomic groups or rewrite pattern to avoid ambiguity
# Or use timeout mechanism
def safe_match(pattern, text, timeout=1.0):
    import signal
    def handler(signum, frame): raise TimeoutError
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(int(timeout))
    try:
        return re.match(pattern, text)
    finally:
        signal.alarm(0)
```

```javascript
function escapeRegExp(string) {
  // Escape special characters so they are treated as literal characters
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Secure construction using the escaped user string
const safeRegex = new RegExp(escapeRegExp(userInput), 'i');
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Regex Injection, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng pattern cố định hoặc engine tuyến tính, giới hạn độ dài và timeout.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Regex Injection, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Tiêm biểu thức chính quy (ReDoS) xảy ra khi dữ liệu đầu vào từ người dùng được dùng trực tiếp để xây dựng regex mà không qua làm sạch, hoặc khi bản thân regex có lỗi quay lui vô hạn. Biện pháp giảm thiểu bao gồm: escape dữ liệu đầu vào, dùng engine không quay lui, thiết lập timeout cho thao tác khớp mẫu, và tránh tạo regex động từ tham số người dùng.
- **Các bước chi tiết**:
  - Không tạo biểu thức chính quy động từ dữ liệu đầu vào chưa được escape.
  - Nếu bắt buộc phải tạo regex động, hãy escape toàn bộ ký tự đặc biệt của regex trước.
  - Viết biểu thức chính quy cẩn thận để tránh quay lui vô hạn (tránh các bộ định lượng lồng nhau, các lớp ký tự trùng lặp).
  - Triển khai kiểm soát timeout nghiêm ngặt cho quá trình thực thi regex, hoặc sử dụng engine an toàn (như RE2 của Google) đảm bảo độ phức tạp tuyến tính.

## 12. Retest

- **Positive case:** với Regex Injection, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Regex Injection mà không xác nhận side effect và log.
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

- **Regex / Regular Expression**: Biểu thức chính quy dùng để so khớp chuỗi theo mẫu.
- **Backtracking**: Cơ chế quay lại các bước trước đó trong bộ máy Regex để tìm kiếm mọi khả năng khớp.
- **ReDoS**: Cuộc tấn công từ chối dịch vụ bằng cách làm quá tải bộ máy xử lý Regex.
- **Catastrophic Backtracking**: Hiện tượng quay lui vô hạn gây tiêu tốn tài nguyên CPU ở mức tối đa.
- **Escape**: Hành động vô hiệu hóa ý nghĩa của các ký tự đặc biệt bằng cách chèn dấu gạch chéo ngược `\` phía trước.

## 16. Bài liên quan và đọc thêm

- [Command Execution](../command-execution/) — Thực thi lệnh thông qua xử lý không an toàn.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** CWE-1333. https://cwe.mitre.org/data/definitions/1333.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
