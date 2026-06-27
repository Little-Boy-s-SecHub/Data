# Second-Order SQL Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-89 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Trong SQL Injection truyền thống (first-order), payload được inject và thực thi **ngay lập tức** trong cùng một request. Tuy nhiên, nhiều ứng dụng hiện đại đã áp dụng parameterized queries tại điểm nhập liệu (input point), khiến attacker không thể khai thác trực tiếp.

**Second-Order SQL Injection** (hay Stored SQL Injection) là kỹ thuật mà payload được **lưu trữ an toàn** vào database trong bước đầu tiên, sau đó được **đọc ra và sử dụng không an toàn** trong một truy vấn SQL khác ở bước thứ hai. Điểm mấu chốt: **injection point ≠ execution point**.

Ví dụ luồng hoạt động bình thường của hệ thống đổi mật khẩu:

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

## 🔍 Mô tả lỗ hổng

Second-Order SQLi xảy ra khi developer tin rằng dữ liệu đã nằm trong database thì "đáng tin cậy" và sử dụng trực tiếp trong câu SQL bằng cách nối chuỗi. Đây là sai lầm về **trust boundary** — dữ liệu từ database không nhất thiết an toàn nếu nguồn gốc của nó là user input chưa được xử lý đúng ngữ cảnh.

Lỗ hổng này đặc biệt khó phát hiện vì:
- Automated scanner thường chỉ test first-order injection
- Payload và execution xảy ra ở **hai request khác nhau**, có thể cách nhau hàng giờ hoặc hàng ngày
- Code review phải trace data flow xuyên suốt nhiều module

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Parameterized queries EVERYWHERE**: Không chỉ tại input point mà tại **mọi nơi** dữ liệu được sử dụng trong SQL — kể cả dữ liệu từ database.
2. **Zero trust cho stored data**: Coi dữ liệu từ database cũng là untrusted input, áp dụng cùng mức độ sanitization.
3. **Input validation tại registration**: Validate username chỉ chứa ký tự hợp lệ (alphanumeric, underscore).
4. **Code review cross-module**: Trace data flow từ input → storage → retrieval → usage để phát hiện second-order vulnerability.
5. **ORM framework**: Sử dụng ORM (SQLAlchemy, Django ORM) giúp tự động parameterize mọi truy vấn.

## 💻 Code Example

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

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/sql-injection#second-order-sql-injection
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE: https://cwe.mitre.org/data/definitions/89.html
