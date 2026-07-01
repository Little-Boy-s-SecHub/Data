# Cross-Site Scripting (Stored)

> **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: Cross-Site Scripting

## Kiến thức Nền tảng

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

## Mô tả lỗ hổng

Lỗ hổng Stored XSS (XSS lưu trữ hay XSS vĩnh viễn) xảy ra khi ứng dụng web cho phép người dùng nhập dữ liệu chứa mã độc, rồi ngây thơ lưu thẳng dữ liệu thô này vào cơ sở dữ liệu mà không hề làm sạch. Sự nguy hiểm thực sự nằm ở chỗ: vì đoạn mã độc này đã được lưu trữ vĩnh viễn, nên cứ mỗi khi có bất kỳ người dùng nào truy cập vào trang web đó, máy chủ sẽ tự động lôi dữ liệu độc hại từ database ra và hiển thị lên trình duyệt của họ, kích hoạt mã độc chạy ngay lập tức. Đây là loại XSS nguy hiểm nhất vì kẻ tấn công không cần phải gửi đường link dụ dỗ từng người; mã độc sẽ tự động lây lan và tấn công hàng loạt khách hàng truy cập trang web một cách hoàn toàn âm thầm.

## Cơ chế tấn công

Các biến thể tấn công Stored XSS nâng cao bao gồm:

*   **XSS via SVG Upload**: Kẻ tấn công tải lên tệp đồ họa vector (SVG) chứa mã JavaScript độc hại. SVG thực chất là một tài liệu XML, do đó trình duyệt có thể thực thi script bên trong nó khi tệp được hiển thị trực tiếp.
    *   *Payload SVG độc hại*:
        ```xml
        <?xml version="1.0" standalone="no"?>
        <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
          <circle cx="50" cy="50" r="40" fill="blue" />
        </svg>
        ```
*   **Mutation XSS (mXSS)**: Xảy ra do sự không đồng nhất trong cách xử lý HTML giữa thư viện làm sạch (sanitizer) và trình duyệt web. Kẻ tấn công gửi một payload trông có vẻ vô hại với thư viện vệ sinh HTML, nhưng khi trình duyệt phân tích cú pháp và ghi lại vào DOM (thông qua `innerHTML`), nó sẽ tự động biến đổi (mutate) cấu trúc và kích hoạt thực thi JavaScript.
    *   *Payload mXSS ví dụ*:
        ```html
        <noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>
        ```
        Bộ lọc HTML thấy thẻ `noscript` an toàn và bỏ qua thuộc tính `title` bọc trong nháy kép. Nhưng khi gán vào `innerHTML`, trình duyệt tự động đóng thẻ `noscript` sớm do sự biến đổi cú pháp, khiến thẻ `<img>` lộ ra ngoài và thực thi.
*   **Polyglot Payloads**: Là một chuỗi payload được thiết kế tinh vi để có thể thực thi JavaScript thành công trong nhiều ngữ cảnh HTML khác nhau (nằm ngoài thẻ, nằm trong thuộc tính nháy đơn, nháy kép, hoặc trong thẻ script).
    *   *Payload Polyglot điển hình*:
        ```javascript
        javascript:"/*'/*`/*--></noscript></title></style></textarea></script></xmp><svg/onload=alert(1)>
        ```

## Biện pháp phòng thủ

- **Tóm tắt**: Sử dụng các thư viện lọc HTML chuyên dụng (như DOMPurify ở client, nh3 ở server), mã hóa đầu ra theo ngữ cảnh, cấu hình CSP và thiết lập cookie HttpOnly.
- **Các bước chi tiết**:
  - Không bao giờ tin cậy dữ liệu từ cơ sở dữ liệu; hãy thực hiện mã hóa HTML đầu ra trước khi render.
  - Sử dụng thư viện an toàn `nh3` (Python) hoặc `DOMPurify` (JavaScript) để làm sạch HTML đối với các trường cho phép nhập văn bản định dạng (Rich Text).
  - Đối với tệp tải lên (như SVG): Cấu hình máy chủ để trả về tiêu đề `Content-Disposition: attachment` hoặc phục vụ các tệp này từ một domain riêng biệt (sandboxed domain) để tránh đánh cắp cookie của domain chính.
  - Triển khai chính sách Content Security Policy (CSP) mạnh để ngăn thực thi inline scripts.

## Code Example

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

## Xem thêm

- [Session Hijacking](../../../07-authentication-failures/session-hijacking/) — Đánh cắp phiên làm việc của người dùng là một trong những mục tiêu phổ biến nhất của kẻ tấn công khi khai thác thành công lỗ hổng Stored XSS.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/cross-site-scripting/stored
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE: https://cwe.mitre.org/data/definitions/79.html

## Giải thích thuật ngữ

- **Stored XSS**: Lỗ hổng XSS lưu trữ, mã độc nằm vĩnh viễn trong database và kích hoạt khi người dùng xem trang chứa dữ liệu đó.
- **Persistent Storage**: Cơ chế lưu trữ dữ liệu lâu dài không bị biến mất khi tắt ứng dụng.
- **Sanitize**: Làm sạch dữ liệu đầu vào bằng cách lọc bỏ các thành phần nguy hại.
- **Session Hijacking**: Hành vi đánh cắp session token để cướp phiên làm việc của người dùng hợp lệ.
- **Malware**: Phần mềm độc hại dùng để gây tổn hại đến hệ thống hoặc người dùng.
