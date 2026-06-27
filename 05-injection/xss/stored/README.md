# Cross-Site Scripting

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation) | **Phân loại**: XSS

## 🧱 Kiến thức Nền tảng
Lỗ hổng bảo mật ứng dụng web thường phân biệt rõ ràng giữa hai loại lưu trữ: lưu trữ vĩnh viễn (persistent storage) và lưu trữ tạm thời (transient storage). Lưu trữ tạm thời liên quan đến các dữ liệu chỉ tồn tại ngắn hạn trong phạm vi một yêu cầu đơn lẻ hoặc trong một phiên làm việc cục bộ của một người dùng. Ngược lại, lưu trữ vĩnh viễn là nơi lưu giữ dữ liệu lâu dài trong cơ sở dữ liệu hoặc hệ thống tệp tin trên máy chủ, sẵn sàng cung cấp cho bất kỳ người dùng nào truy cập sau đó.

Lỗ hổng Stored XSS (XSS lưu trữ) phát sinh trực tiếp từ sự tương tác thiếu an toàn với lưu trữ vĩnh viễn. Khi người dùng nhập dữ liệu chứa mã độc và ứng dụng lưu thẳng dữ liệu thô này vào persistent storage. Vấn đề nguy hiểm xảy ra khi máy chủ lấy dữ liệu này ra từ bộ lưu trữ vĩnh viễn để hiển thị cho các thành viên khác.

Do dữ liệu mang tính vĩnh viễn, mã độc sẽ tự động thực thi trên trình duyệt của bất kỳ ai tải trang chứa thông tin đó. Để phòng thủ triệt để, ứng dụng cần thực thi việc làm sạch và mã hóa dữ liệu tại thời điểm hiển thị (render time), hoặc sử dụng các thư viện lọc định dạng văn bản giàu chuyên dụng như `nh3` trước khi render ra trình duyệt.

### Code ví dụ hoạt động bình thường (Secure Data Storing and Rendering)
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

## 🔍 Mô tả lỗ hổng
Stored XSS (XSS lưu trữ / Persistent XSS) xảy ra khi dữ liệu đầu vào chứa mã độc của người dùng được máy chủ lưu trữ trực tiếp vào cơ sở dữ liệu (ví dụ bình luận, hồ sơ cá nhân). Khi những người dùng khác truy cập trang web hiển thị dữ liệu này, đoạn mã độc sẽ được tải lên từ database và tự động thực thi trên trình duyệt của họ. Lỗ hổng này cực kỳ nguy hại vì nó không yêu cầu nạn nhân phải click vào một liên kết độc hại riêng biệt mà hoạt động hoàn toàn tự động.

## ⚔️ Cơ chế tấn công
Kẻ tấn công gửi một bài đăng hoặc bình luận chứa mã JavaScript (ví dụ: `<script>alert('hack')</script>`). Ứng dụng lưu bài viết này nguyên vẹn vào cơ sở dữ liệu. Khi Vic truy cập vào trang để đọc bình luận, máy chủ lấy dữ liệu này từ database, chèn nguyên văn vào trang HTML và gửi về cho trình duyệt của Vic. Trình duyệt của Vic tự động biên dịch thẻ `<script>` và chạy kịch bản độc hại, có thể đánh cắp phiên đăng nhập hoặc thực hiện các thao tác thay đổi dữ liệu danh nghĩa Vic.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn Stored XSS bằng cách kiểm duyệt đầu vào, lưu trữ dữ liệu thô, thực hiện mã hóa đầu ra theo mặc định (Jinja2 auto-escape), sử dụng các thư viện vệ sinh an toàn (như nh3) cho nội dung rich text.
- **Các bước chi tiết**:
  - Vệ sinh và lọc sạch dữ liệu đầu vào trước khi lưu vào cơ sở dữ liệu để loại bỏ các thẻ HTML nguy hại (chỉ áp dụng đối với nội dung cho phép định dạng HTML).
  - Áp dụng cơ chế tự động mã hóa đầu ra dựa theo ngữ cảnh của các template engine hiện đại (ví dụ tính năng tự động escape của Jinja2).
  - Khi cho phép hiển thị các định dạng văn bản giàu (rich text), hãy định nghĩa bộ lọc vệ sinh đầu ra bằng các thư viện an toàn ở thời điểm render thay vì lúc lưu vào DB.
  - Cấu hình tiêu đề cookie `HttpOnly` để ngăn chặn kịch bản phía client đánh cắp cookie phiên làm việc.
  - Thiết lập chính sách Content Security Policy (CSP) chặt chẽ cho phép kiểm soát tài nguyên kịch bản.

## 💻 Code Example
```python
import nh3

def save_comment(raw_content):
    # Store raw content in the database.
    # Sanitization/escaping should ideally be done at render/output time.
    db.save(raw_content)

# 1. Option A: Outputting plain text (highly recommended)
# In Jinja2 templates, standard interpolation automatically HTML-escapes everything:
# {{ comment.content }}  <- Safe: all HTML tags are rendered as plaintext literals

# 2. Option B: Render simple rich formatting tags using nh3 at output time:
# First, define a custom template filter in Flask/Jinja2:
# @app.template_filter('sanitize_html')
# def sanitize_html(text):
#     if text is None or text == '':
#         return ''
#     return nh3.clean(str(text), tags={'b', 'i', 'strong', 'em', 'p'})
#
# Then render in the Jinja2 template using the filter and safe flag:
# {{ comment.content | sanitize_html | safe }}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã thay thế khuyến nghị sử dụng thư viện `bleach` (Python) đã bị Mozilla ngừng bảo trì từ năm 2023 bằng thư viện an toàn `nh3` (viết bằng Rust). Đồng thời khắc phục lỗi trong hàm lọc tự chế `sanitize_html` khi câu lệnh `if not text` lọc nhầm các giá trị falsy hợp lệ như số `0` hoặc boolean `False`, chuyển sang kiểm tra đúng kiểu rỗng `if text is None or text == ''`.
- **Nguồn tham khảo**: OWASP XSS Cheat Sheet, PortSwigger
