---
schema_version: 1
id: WEB-A05-XSS-STORED
title: "Cross-Site Scripting (Stored)"
slug: xss-stored
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

# Cross-Site Scripting (Stored)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Site Scripting (Stored) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Cross-Site Scripting (Stored) và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Trong thiết kế ứng dụng web, dữ liệu thường được lưu trữ theo hai cách: tạm thời (chỉ tồn tại trong một yêu cầu hoặc một phiên làm việc ngắn hạn) và vĩnh viễn (được ghi sâu vào cơ sở dữ liệu hoặc tệp tin trên máy chủ để dùng lại lâu dài). Các dữ liệu vĩnh viễn như lời bình luận dưới bài viết hay thông tin cá nhân của bạn sẽ luôn ở đó, sẵn sàng hiển thị cho bất kỳ ai truy cập vào trang web sau này. Đây chính là mảnh đất màu mỡ cho các cuộc tấn công lưu trữ nếu không được quản lý an toàn.

```python
import nh3

# Mock database representing persistent storage
class CommentDatabase:
    def __init__(self):
        self.storage = []

    def save_comment(self, user_id, raw_content):
        # Store the raw text content in persistent storage.
        # It is a best practice to store data in raw form and handle safety during rendering.
        self.storage.append({"user_id": user_id, "content": raw_content})

    def get_comments(self):
        return self.storage

# Initialize secure database instance
db = CommentDatabase()
db.save_comment(101, "This is a normal comment.")
db.save_comment(102, "Hello world, <b>great post</b>!")

# Render comments securely using nh3 to sanitize HTML at output time
def render_comments_to_html():
    comments = db.get_comments()
    rendered_list = []
    for comment in comments:
        # nh3.clean blocks scripts and allows only secure, white-listed formatting tags
        safe_content = nh3.clean(comment["content"], tags={'b', 'i', 'strong', 'em', 'p'})
        rendered_list.append(f"<div class='comment'>User {comment['user_id']}: {safe_content}</div>")
    return "\n".join(rendered_list)
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Stored XSS (XSS lưu trữ hay XSS vĩnh viễn) xảy ra khi ứng dụng web cho phép người dùng nhập dữ liệu chứa mã độc, rồi ngây thơ lưu thẳng dữ liệu thô này vào cơ sở dữ liệu mà không hề làm sạch. Sự nguy hiểm thực sự nằm ở chỗ: vì đoạn mã độc này đã được lưu trữ vĩnh viễn, nên cứ mỗi khi có bất kỳ người dùng nào truy cập vào trang web đó, máy chủ sẽ tự động lôi dữ liệu độc hại từ database ra và hiển thị lên trình duyệt của họ, kích hoạt mã độc chạy ngay lập tức. Đây là loại XSS nguy hiểm nhất vì kẻ tấn công không cần phải gửi đường link dụ dỗ từng người; mã độc sẽ tự động lây lan và tấn công hàng loạt khách hàng truy cập trang web một cách hoàn toàn âm thầm.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** nội dung database và DOM của người xem sau.
- **Actor, xác thực và role:** role user tạo content; user/moderator khác xem.
- **Điều kiện khai thác:** input đã lưu được render vào browser sink có thể thực thi.
- **Browser, proxy, framework và phiên bản:** Chromium, Express/Flask và PostgreSQL 16 được pin với dữ liệu tổng hợp; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với stored, input đã lưu được render vào browser sink có thể thực thi. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium, Express/Flask và PostgreSQL 16 được pin với dữ liệu tổng hợp; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case stored; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input đã lưu được render vào browser sink có thể thực thi”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của stored; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Các biến thể tấn công Stored XSS nâng cao bao gồm:

*   **XSS via SVG Upload**: Kẻ tấn công tải lên tệp đồ họa vector (SVG) chứa mã JavaScript độc hại. SVG thực chất là một tài liệu XML, do đó trình duyệt có thể thực thi script bên trong nó khi tệp được hiển thị trực tiếp.
    *   *Payload SVG độc hại*:
<!-- payload-id: WEB-A05-XSS-STORED-001 -->
<!-- context: Chromium 126 opens an uploaded SVG inline from the same-origin Flask/SQLite fixture -->
<!-- prerequisites: synthetic blog and browser profile; SVG route is deliberately inline; no session secret or network callback; one author and one viewer -->
<!-- encoding: SVG is UTF-8 XML uploaded as multipart/form-data; the harness generates the multipart boundary once -->
<!-- expected-result: vulnerable inline viewer sets documentElement.dataset.storedXss to svg; secure route serves attachment from an isolated origin or rejects active SVG -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <?xml version="1.0" standalone="no"?>
        <svg xmlns="http://www.w3.org/2000/svg" onload="document.documentElement.dataset.storedXss='svg'">
          <circle cx="50" cy="50" r="40" fill="blue" />
        </svg>
        ```
*   **Mutation XSS (mXSS)**: Xảy ra do sự không đồng nhất trong cách xử lý HTML giữa thư viện làm sạch (sanitizer) và trình duyệt web. Kẻ tấn công gửi một payload trông có vẻ vô hại với thư viện vệ sinh HTML, nhưng khi trình duyệt phân tích cú pháp và ghi lại vào DOM (thông qua `innerHTML`), nó sẽ tự động biến đổi (mutate) cấu trúc và kích hoạt thực thi JavaScript.
    *   *Payload mXSS ví dụ*:
<!-- payload-id: WEB-A05-XSS-STORED-002 -->
<!-- context: Chromium 126 reparses stored HTML through a deliberately flawed lab sanitizer and then innerHTML; this is not a claim about current DOMPurify/nh3 -->
<!-- prerequisites: synthetic comment only; broken image remains local; one author/viewer; no cookie access; exact sanitizer fixture is pinned with the evidence -->
<!-- encoding: UTF-8 form body; angle brackets/quotes are percent-encoded once by the client and decoded before the single innerHTML assignment -->
<!-- expected-result: vulnerable reparse sets documentElement.dataset.storedXss to mxss once; context-aware escaping or the pinned secure sanitizer prevents creation of the img element -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```html
        <noscript><p title="</noscript><img src=x onerror="document.documentElement.dataset.storedXss='mxss'">"></noscript>
        ```
        Bộ lọc HTML thấy thẻ `noscript` an toàn và bỏ qua thuộc tính `title` bọc trong nháy kép. Nhưng khi gán vào `innerHTML`, trình duyệt tự động đóng thẻ `noscript` sớm do sự biến đổi cú pháp, khiến thẻ `<img>` lộ ra ngoài và thực thi.
*   **Polyglot Payloads**: Là một chuỗi payload được thiết kế tinh vi để có thể thực thi JavaScript thành công trong nhiều ngữ cảnh HTML khác nhau (nằm ngoài thẻ, nằm trong thuộc tính nháy đơn, nháy kép, hoặc trong thẻ script).
    *   *Payload Polyglot điển hình*:
<!-- payload-id: WEB-A05-XSS-STORED-003 -->
<!-- context: Flask/SQLite comment fixture stores an HTML polyglot fragment opened in Chromium 126 body context -->
<!-- prerequisites: synthetic origin without sensitive cookies; no outbound network; one author/viewer -->
<!-- encoding: UTF-8 SVG/HTML fragment is form-encoded once and parsed in the recorded body context -->
<!-- expected-result: vulnerable SVG branch sets documentElement.dataset.storedXss to polyglot; secure renderer outputs text or removes active SVG content -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```html
        javascript:"/*'/*`/*--></noscript></title></style></textarea></script></xmp><svg/onload="document.documentElement.dataset.storedXss='polyglot'">
        ```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE (Python Flask) ===
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def add_comment():
    content = request.form.get('content')
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    # Stores the raw content including potential SVG payloads or polyglots
    cursor.execute("INSERT INTO comments (content) VALUES (?)", (content,))
    conn.commit()
    return "Comment added!"

@app.route('/view')
def view_comments():
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM comments")
    comments = cursor.fetchall()

    # DANGER: Directly rendering unsanitized HTML from database leads to Stored XSS
    html = "<ul>"
    for c in comments:
        html += f"<li>{c[0]}</li>"
    html += "</ul>"
    return html

# === SECURE CODE (Python Flask using nh3) ===
import nh3

@app.route('/secure-view')
def view_comments_secure():
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM comments")
    comments = cursor.fetchall()

    html = "<ul>"
    for c in comments:
        # SECURE: Sanitize rich text using nh3 before rendering, removing dangerous scripts/tags
        safe_content = nh3.clean(c[0], tags={'b', 'i', 'strong', 'em', 'p', 'br'})
        html += f"<li>{safe_content}</li>"
    html += "</ul>"
    return html
```

```javascript
// === SECURE CLIENT-SIDE RENDERING (JavaScript) ===
// Safe DOM manipulation using textContent to prevent mXSS
function displayCommentSecure(rawCommentText) {
    const commentElement = document.createElement('div');
    commentElement.className = 'comment-box';

    // SECURE: textContent automatically treats input as plaintext, preventing XSS and mXSS
    commentElement.textContent = rawCommentText;

    document.getElementById('comments-container').appendChild(commentElement);
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Cross-Site Scripting (Stored), kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Encode tại output; nếu cần HTML, sanitize allowlist ngay trước render.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Cross-Site Scripting (Stored), các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sử dụng các thư viện lọc HTML chuyên dụng (như DOMPurify ở client, nh3 ở server), mã hóa đầu ra theo ngữ cảnh, cấu hình CSP và thiết lập cookie HttpOnly.
- **Các bước chi tiết**:
  - Không bao giờ tin cậy dữ liệu từ cơ sở dữ liệu; hãy thực hiện mã hóa HTML đầu ra trước khi render.
  - Sử dụng thư viện an toàn `nh3` (Python) hoặc `DOMPurify` (JavaScript) để làm sạch HTML đối với các trường cho phép nhập văn bản định dạng (Rich Text).
  - Đối với tệp tải lên (như SVG): Cấu hình máy chủ để trả về tiêu đề `Content-Disposition: attachment` hoặc phục vụ các tệp này từ một domain riêng biệt (sandboxed domain) để tránh đánh cắp cookie của domain chính.
  - Triển khai chính sách Content Security Policy (CSP) mạnh để ngăn thực thi inline scripts.

## 12. Retest

- **Positive case:** với Cross-Site Scripting (Stored), luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Cross-Site Scripting (Stored) mà không xác nhận side effect và log.
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

- **Stored XSS**: Lỗ hổng XSS lưu trữ, mã độc nằm vĩnh viễn trong database và kích hoạt khi người dùng xem trang chứa dữ liệu đó.
- **Persistent Storage**: Cơ chế lưu trữ dữ liệu lâu dài không bị biến mất khi tắt ứng dụng.
- **Sanitize**: Làm sạch dữ liệu đầu vào bằng cách lọc bỏ các thành phần nguy hại.
- **Session Hijacking**: Hành vi đánh cắp session token để cướp phiên làm việc của người dùng hợp lệ.
- **Malware**: Phần mềm độc hại dùng để gây tổn hại đến hệ thống hoặc người dùng.

## 16. Bài liên quan và đọc thêm

- [Session Hijacking](../../../07-authentication-failures/session-hijacking/) — Đánh cắp phiên làm việc của người dùng là một trong những mục tiêu phổ biến nhất của kẻ tấn công khi khai thác thành công lỗ hổng Stored XSS.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/cross-site-scripting/stored — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/79.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
