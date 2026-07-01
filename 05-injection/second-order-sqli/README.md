# Second-Order SQL Injection

> **CWE**: CWE-89 | **Phân loại**: Injection

## Kiến thức Nền tảng

Trong các cuộc tấn công SQL Injection truyền thống (first-order), kẻ xấu chèn mã độc vào và nó sẽ phát nổ ngay lập tức trong cùng một yêu cầu gửi lên. Để đối phó, các ứng dụng ngày nay đã bảo vệ cửa ngõ đầu vào rất tốt bằng cách sử dụng các truy vấn tham số hóa (parameterized queries). Tuy nhiên, kẻ tấn công vẫn có một chiêu thức thâm hiểm hơn gọi là SQL Injection bậc hai (Second-Order SQL Injection). Với chiêu này, kẻ xấu sẽ gửi một chuỗi mã độc trông có vẻ vô hại ở bước đầu tiên để ứng dụng lưu trữ an toàn vào cơ sở dữ liệu. Sau đó, ở một bước thứ hai, khi ứng dụng đọc dữ liệu này ra từ cơ sở dữ liệu để thực hiện một truy vấn khác, mã độc mới thực sự phát nổ. Điểm mấu chốt ở đây là nơi nhập mã độc và nơi mã độc thực thi là hoàn toàn khác nhau.

```python
# Step 1: User registration — stores username safely with parameterized query
def register(username, password):
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hash_password(password))
    )
    # Username is stored AS-IS in the database — including special characters

# Step 2: Password change — retrieves username from session
def change_password(session_user, new_password):
    # The username is read from database, assumed "safe"
    cursor.execute(
        "UPDATE users SET password=%s WHERE username=%s",
        (hash_password(new_password), session_user)
    )
```

Quy trình trên an toàn vì **cả hai bước đều dùng parameterized query**. Vấn đề phát sinh khi bước thứ hai sử dụng string concatenation.

## Mô tả lỗ hổng

Lỗ hổng Second-Order SQLi xảy ra do lập trình viên mắc phải một sai lầm phổ biến về ranh giới tin cậy: họ cho rằng dữ liệu một khi đã nằm yên vị bên trong cơ sở dữ liệu của mình thì mặc định là an toàn và có thể thoải mái lôi ra sử dụng bằng cách cộng chuỗi trực tiếp. Kẻ tấn công lợi dụng điều này bằng cách đặt một tên đăng nhập độc hại (ví dụ: `admin' --`). Bước đăng ký tài khoản diễn ra suôn sẻ và tên này được lưu vào database. Đến khi nạn nhân thực hiện thao tác đổi mật khẩu, ứng dụng lấy tên này ra và ghép nối trực tiếp vào câu lệnh SQL cập nhật mật khẩu, vô tình biến đổi câu lệnh thành "đổi mật khẩu của người dùng admin". Lỗ hổng này cực kỳ nguy hiểm vì nó ẩn mình rất kỹ, vượt qua các công cụ quét tự động thông thường và có thể âm thầm gây họa sau nhiều ngày lưu trữ.

## Cơ chế tấn công

**Kịch bản kinh điển: Thay đổi mật khẩu admin**

```python
# Step 1: Attacker registers with malicious username
# Registration uses parameterized query — payload stored safely
register_username = "admin'--"
register_password = "anything"
# INSERT INTO users (username, password) VALUES ('admin''--', 'hashed')
# The username admin'-- is now stored in the database

# Step 2: Attacker changes their own password
# But the vulnerable code builds SQL via concatenation
def change_password_vulnerable(session_user, new_password):
    hashed = hash_password(new_password)
    # DANGER: Username from DB used in string concatenation
    query = f"UPDATE users SET password='{hashed}' WHERE username='{session_user}'"
    cursor.execute(query)

# When session_user = "admin'--", the query becomes:
# UPDATE users SET password='new_hash' WHERE username='admin'--'
# The -- comments out the rest — admin's password is changed!
```

**Kịch bản data exfiltration qua profile page**:

```python
# Attacker sets their "company" field to: ' UNION SELECT password FROM users--
# Later, a report query uses this value unsafely:
company = get_user_company(user_id)  # Returns the malicious string
query = f"SELECT * FROM employees WHERE company='{company}'"
# Results in UNION-based data extraction
```

## Biện pháp phòng thủ

- **Tóm tắt**: Sử dụng truy vấn tham số hóa ở mọi nơi dữ liệu được sử dụng, không tin cậy dữ liệu được truy xuất từ cơ sở dữ liệu.
- **Các bước chi tiết**:
  - Parameterized queries EVERYWHERE: Không chỉ tại input point mà tại mọi nơi dữ liệu được sử dụng trong SQL — kể cả dữ liệu lấy từ database.
  - Zero trust cho stored data: Coi dữ liệu từ database cũng là untrusted input, áp dụng cùng mức độ sanitization.
  - Input validation tại registration: Validate username chỉ chứa ký tự hợp lệ (alphanumeric, underscore).
  - Code review cross-module: Trace data flow từ input → storage → retrieval → usage để phát hiện second-order vulnerability.
  - ORM framework: Sử dụng ORM (SQLAlchemy, Django ORM) giúp tự động parameterize mọi truy vấn.

## Code Example

```python
# === VULNERABLE CODE ===
def change_password_vulnerable(user_id, new_password):
    # Fetch username from database — developer assumes it's safe
    cursor.execute("SELECT username FROM users WHERE id=%s", (user_id,))
    username = cursor.fetchone()[0]

    hashed = hash_password(new_password)
    # DANGER: Username from DB concatenated into SQL
    query = f"UPDATE users SET password='{hashed}' WHERE username='{username}'"
    cursor.execute(query)


# === SECURE CODE ===
def change_password_secure(user_id, new_password):
    hashed = hash_password(new_password)
    # Use parameterized query — even for data retrieved from database
    # Update by user ID instead of username to avoid injection entirely
    cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed, user_id)
    )
    # No string concatenation, no injection possible
    # Using ID (integer) instead of username further reduces attack surface
```

## Xem thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng SQL Injection cơ bản sử dụng đầu vào trực tiếp từ người dùng trong cùng một vòng đời yêu cầu.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/sql-injection#second-order-sql-injection
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE: https://cwe.mitre.org/data/definitions/89.html

## Giải thích thuật ngữ

- **Second-Order SQLi**: Lỗ hổng SQL Injection xảy ra khi mã độc được lưu vào database trước rồi mới thực thi ở một truy vấn sau đó.
- **Trust Boundary**: Ranh giới tin cậy phân biệt giữa dữ liệu đã kiểm duyệt và dữ liệu chưa được kiểm duyệt.
- **Parameterized Query**: Kỹ thuật truyền tham số riêng biệt giúp triệt tiêu hoàn toàn khả năng chèn câu lệnh SQL trái phép.
- **String Concatenation**: Hành động ghép nối các chuỗi chữ lại với nhau, thường gây ra các lỗi injection.
- **First-Order SQLi**: Lỗ hổng SQL Injection truyền thống thực thi ngay lập tức trong yêu cầu gửi lên.
