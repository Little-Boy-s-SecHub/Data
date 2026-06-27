# SQL Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) | **Phân loại**: Injection

## 🧱 Kiến thức Nền tảng
SQL (Structured Query Language) là ngôn ngữ chuẩn để quản lý cơ sở dữ liệu quan hệ. Nó sử dụng các câu lệnh cơ bản như `SELECT` (truy xuất dữ liệu), `INSERT` (thêm dữ liệu mới), `UPDATE` (cập nhật dữ liệu hiện có), và `DELETE` (xóa dữ liệu). Mệnh đề `WHERE` được dùng để lọc bản ghi thỏa mãn điều kiện nhất định. Trong SQL, dấu nháy đơn `'` đóng vai trò bao bọc một giá trị chuỗi (quote literal), giúp hệ quản trị cơ sở dữ liệu (DBMS) phân biệt giữa cú pháp lệnh và dữ liệu văn bản. Dấu hai gạch ngang `--` (hoặc `#` trong MySQL) biểu thị phần chú thích (comment), toàn bộ nội dung phía sau nó trên cùng dòng sẽ bị DBMS bỏ qua khi thực thi.

Tấn công SQL Injection (SQLi) xảy ra khi dữ liệu nhập từ người dùng không được kiểm soát mà nối trực tiếp vào câu lệnh SQL. Dấu nháy đơn `'` do kẻ tấn công nhập vào có thể kết thúc chuỗi dữ liệu sớm và mở ra cơ hội chèn thêm cú pháp SQL độc hại, trong khi dấu `--` được dùng để vô hiệu hóa phần kiểm tra logic phía sau (ví dụ: bỏ qua kiểm tra mật khẩu). Để phòng chống SQLi, kỹ thuật parameterized query (truy vấn tham số hóa) hay prepared statement là giải pháp cốt lõi. Khi sử dụng kỹ thuật này, DBMS sẽ phân tách cấu trúc lệnh SQL và dữ liệu đầu vào. Đầu vào của người dùng luôn được xử lý như một chuỗi hằng (literal value) thay vì mã thực thi, khiến dấu nháy đơn hay chú thích `--` không thể thay đổi logic của truy vấn.

```python
import sqlite3

def get_user_by_email(email):
    # Establish connection to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Normal operation using parameterized query (prepared statement)
    # The database engine compiles the SQL query structure first,
    # then binds the email parameter as a literal value, preventing SQL injection.
    query = "SELECT id, username, email FROM users WHERE email = ?"
    cursor.execute(query, (email,))
    
    user = cursor.fetchone()
    conn.close()
    return user
```

## 🔍 Mô tả lỗ hổng
SQL Injection xảy ra khi dữ liệu đầu vào do người dùng kiểm soát được nối trực tiếp vào chuỗi truy vấn cơ sở dữ liệu mà không qua xử lý. Điều này cho phép kẻ tấn công thay đổi cấu trúc câu lệnh truy vấn và thực thi các lệnh SQL tùy ý. Lỗ hổng này có thể dẫn đến rò rỉ dữ liệu nhạy cảm, phá hoại database hoặc chiếm đoạt tài khoản quản trị.

## ⚔️ Cơ chế tấn công
Kẻ tấn công nhập các ký tự đặc biệt (như dấu nháy đơn `'`) hoặc các cú pháp SQL đặc trưng vào các biểu mẫu đầu vào (ví dụ trường email đăng nhập). Dấu nháy đơn kết thúc chuỗi truy vấn sớm hơn dự kiến, và kẻ tấn công có thể chèn thêm các mệnh đề logic luôn đúng (như `' or 1=1--`). Ký tự `--` chỉ định cơ sở dữ liệu bỏ qua phần còn lại của truy vấn (kiểm tra mật khẩu), dẫn đến việc kẻ tấn công được đăng nhập thành công vào hệ thống mà không cần mật khẩu.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Sử dụng các câu lệnh truy vấn tham số hóa (parameterized queries / prepared statements), thủ tục lưu sẵn (stored procedures), các framework ORM và kiểm tra dữ liệu đầu vào nghiêm ngặt.
- **Các bước chi tiết**:
  - Sử dụng truy vấn tham số hóa (prepared statements) cho tất cả các thao tác cơ sở dữ liệu để đảm bảo dữ liệu đầu vào luôn được xử lý dưới dạng tham số thay vì mã thực thi.
  - Sử dụng các framework ORM (Object-Relational Mapping) mặc định sử dụng truy vấn tham số hóa.
  - Kiểm tra và làm sạch tất cả các biến đầu vào tại ranh giới ứng dụng bằng cách ép kiểu dữ liệu nghiêm ngặt (như cast sang integer, so khớp mẫu RegExp).
  - Áp dụng nguyên tắc đặc quyền tối thiểu cho tài khoản kết nối cơ sở dữ liệu, giới hạn quyền ghi/đọc chỉ trên những bảng cần thiết.

## 💻 Code Example
Ví dụ mã nguồn phòng thủ trong Python (sqlite3):
```python
import sqlite3

def get_user_profile(user_email):
    conn = sqlite3.connect('database.db')
    try:
        cursor = conn.cursor()
        # SECURE: Use placeholder '?' to separate query structure from user input
        cursor.execute("SELECT name, bio FROM users WHERE email = ?", (user_email,))
        return cursor.fetchone()
    finally:
        conn.close()
```

Ví dụ mã nguồn phòng thủ trong Node.js (pg client sử dụng parameterized query):
```javascript
const { Client } = require('pg');

async function getUser(email) {
  const client = new Client();
  await client.connect();
  try {
    // SECURE: Parameterized query using placeholders
    const query = {
      text: 'SELECT name, bio FROM users WHERE email = $1',
      values: [email],
    };
    const res = await client.query(query);
    return res.rows[0];
  } finally {
    await client.end();
  }
}
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Mã nguồn ví dụ phòng thủ trong Python đã được cập nhật bọc trong cấu trúc `try-finally` để đảm bảo đóng kết nối sqlite3 một cách an sau khi truy vấn, tránh rò rỉ kết nối (connection leak).
- **Nguồn tham khảo**: OWASP A03:2021, CWE-89, PortSwigger
