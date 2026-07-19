---
schema_version: 1
id: WEB-A11-GRAPHQL-VULNERABILITIES
title: "GraphQL Vulnerabilities"
slug: graphql-vulnerabilities
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - API1:2023
  - API3:2023
  - API4:2023
  - API8:2023
cwe:
  - CWE-200
  - CWE-400
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# GraphQL Vulnerabilities

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích GraphQL Vulnerabilities bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống GraphQL Vulnerabilities và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

Phản hồi JSON hợp lệ chỉ chứa các field đã yêu cầu:

```json
{
  "data": {
    "user": {
      "name": "Alice",
      "email": "alice@victim.lab.test",
      "orders": [
        { "id": "o1", "total": 99.99 }
      ]
    }
  }
}
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **GraphQL Vulnerabilities (Các lỗ hổng đặc thù trong GraphQL)** nảy sinh từ việc nhà phát triển quá chú trọng vào tính linh hoạt mà quên mất việc đặt ra các quy tắc bảo vệ.

Kẻ tấn công có thể lợi dụng những tính năng ưu việt của GraphQL để phản công lại chính hệ thống:
- **Introspection bị lộ ngoài chủ đích**: Introspection là tính năng hợp lệ để mô tả GraphQL schema, không tự nó tạo ra authorization bypass. Tuy nhiên, schema disclosure có thể hỗ trợ reconnaissance nếu production không cần công khai schema. [S7]
- **Truy vấn lồng nhau gây DoS (Nested Query DoS)**: Hắn gửi một câu hỏi lặp vòng vô hạn, ví dụ: "Tìm bạn của tôi, rồi tìm bạn của bạn tôi, rồi lại tìm bạn của người bạn đó..." (truy vấn lồng nhau theo cấp số nhân). Hệ thống sẽ bị nghẽn mạch cơ sở dữ liệu, vắt kiệt RAM của máy chủ và sập nguồn.
- **Tấn công vét cạn qua Batch Query (Gộp truy vấn)**: Thay vì gửi 1.000 yêu cầu đăng nhập riêng lẻ để dò mật khẩu (hành vi dễ bị tường lửa phát hiện và chặn), kẻ tấn công nén cả 1.000 truy vấn này vào làm một. Tường lửa chỉ đếm là 1 yêu cầu hợp lệ, nhưng máy chủ phía sau lại âm thầm thực hiện 1.000 lần kiểm tra mật khẩu.
- **Vượt qua kiểm tra quyền hạn cấp trường (Authorization Bypass)**: Hệ thống chỉ kiểm tra xem người dùng có quyền vào thư viện hay không, chứ không kiểm tra xem họ có được phép đọc các trang tài liệu tuyệt mật hay không (thiếu field-level authorization).
- **Lỗi chèn mã độc (Injection)**: Lạm dụng các biến số đầu vào của GraphQL để chèn các câu lệnh SQL độc hại hoặc mã hệ thống.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S6], [S7].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** dữ liệu ở cấp object/field, mutation budget và CPU/DB cost của resolver; schema metadata không tự động là lỗ hổng.
- **Trust boundary:** GraphQL document/variables đi qua parse, validation, authorization/cost rules rồi vào resolver.
- **Actor:** user thường, admin và client chưa đăng nhập được seed riêng; mỗi case dùng token tổng hợp đúng role.
- **Điều kiện cần:** resolver thiếu object/field authorization, hoặc depth/alias/batch/cost/rate accounting không giới hạn đúng operation.
- **Điều kiện môi trường:** Node.js 20 và Apollo Server 4 local; schema, resolver counter và policy version được pin trong fixture.

Introspection bật chỉ là tín hiệu cấu hình/phơi bày schema; phải chứng minh truy cập dữ liệu trái quyền hoặc resource amplification mới kết luận finding tương ứng. [S1]

## 6. Cơ chế tấn công

Alias, nesting và batching có thể biến một HTTP request thành nhiều resolver/DB call; resolver chỉ kiểm tra auth ở root query có thể trả field/object trái quyền. Evidence phải nối operation tới resolver counter, policy decision và object owner, không chỉ dựa vào response 200 kèm GraphQL errors. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy Apollo Server 4/Node 20 local; seed hai user và một admin, bật resolver/cost/policy log và giới hạn tối đa 20 resolver calls.
2. **Input:** baseline query dữ liệu của chính user; sau đó dùng query object khác owner, field admin, alias/nesting/batch bị giới hạn.
3. **Thao tác:** thay một đặc tính mỗi lượt; ghi document/variables, GraphQL errors, resolver count, DB calls và authorization decision.
4. **Expected result:** bản sửa từ chối object/field trái quyền, tính đủ aliases/batch vào quota và chặn query trước khi vượt cost/depth limit.
5. **Cleanup:** xóa token/dữ liệu giả, reset counter và dừng server/database fixture.
6. **Giới hạn an toàn:** không chạy query recursive/unbounded; không dùng production endpoint, schema hoặc credential thật.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Introspection — Khám phá toàn bộ API schema:**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-001 -->
<!-- context: Apollo Server 4.x on Node.js 20; GraphQL October 2021 semantics; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-001 -->
<!-- prerequisites: seed the bounded schema, two synthetic users and OTP counters; cap depth, aliases and resolver time; capture GraphQL and authorization telemetry -->
<!-- encoding: UTF-8 GraphQL operation text; the harness wraps it once in a JSON POST body and preserves aliases, arguments and quoted scalar escapes -->
<!-- expected-result: the authorized fixture returns schema metadata; exposure alone is recorded as configuration evidence and not labeled a vulnerability -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```graphql
# Introspection query returns schema metadata exposed to this actor
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
      name
      description
    }
  }
}
```

**2. Nested Query DoS — Exponential resource consumption:**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-002 -->
<!-- context: Apollo Server 4.x on Node.js 20; GraphQL October 2021 semantics; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-002 -->
<!-- prerequisites: seed the bounded schema, two synthetic users and OTP counters; cap depth, aliases and resolver time; capture GraphQL and authorization telemetry -->
<!-- encoding: UTF-8 GraphQL operation text; the harness wraps it once in a JSON POST body and preserves aliases, arguments and quoted scalar escapes -->
<!-- expected-result: the bounded query returns at most the seeded nodes and resolver telemetry records its cost; the fixed cost/depth gate rejects requests over policy -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```graphql
# Bounded nested-query probe; actual resolver cost is implementation-dependent
query NestedCostProbe {
  users(first: 2) {
    friends(first: 2) {
      friends(first: 2) {
        friends(first: 2) {
          name
        }
      }
    }
  }
}
```

**3. Batch Query — Brute force OTP/password trong một request:**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-003 -->
<!-- context: Apollo Server 4.x on Node.js 20; GraphQL October 2021 semantics; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-003 -->
<!-- prerequisites: seed the bounded schema, two synthetic users and OTP counters; cap depth, aliases and resolver time; capture GraphQL and authorization telemetry -->
<!-- encoding: UTF-8 JSON without comments; the request/JWK document is parsed exactly once and string escapes are preserved -->
<!-- expected-result: exactly the listed synthetic OTP operations reach the resolver and every attempt is counted by the shared rate-limit policy -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```json
[
  {"query": "mutation { verifyOtp(code: \"000000\") { accepted } }"},
  {"query": "mutation { verifyOtp(code: \"000001\") { accepted } }"}
]
```

**4. Alias-based batching (khi array batching bị chặn):**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-004 -->
<!-- context: Apollo Server 4.x on Node.js 20; GraphQL October 2021 semantics; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-004 -->
<!-- prerequisites: seed the bounded schema, two synthetic users and OTP counters; cap depth, aliases and resolver time; capture GraphQL and authorization telemetry -->
<!-- encoding: UTF-8 GraphQL operation text; the harness wraps it once in a JSON POST body and preserves aliases, arguments and quoted scalar escapes -->
<!-- expected-result: both aliases are counted as separate synthetic OTP attempts; the fixed policy rejects the operation when the per-request attempt cap is exceeded -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```graphql
# Aliases can invoke the same mutation field more than once in one operation
mutation {
  attempt1: verifyOtp(code: "000000") { accepted }
  attempt2: verifyOtp(code: "000001") { accepted }
}
```

**5. Authorization bypass — Accessing fields without proper checks:**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-005 -->
<!-- context: Apollo Server 4.x on Node.js 20; GraphQL October 2021 semantics; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-005 -->
<!-- prerequisites: seed the bounded schema, two synthetic users and OTP counters; cap depth, aliases and resolver time; capture GraphQL and authorization telemetry -->
<!-- encoding: UTF-8 GraphQL operation text; the harness wraps it once in a JSON POST body and preserves aliases, arguments and quoted scalar escapes -->
<!-- expected-result: the regular actor receives only authorized fields for its own object; requests for another user return null or a policy error without sensitive values -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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

**6. Field suggestion qua error message:**

<!-- payload-id: WEB-A11-GRAPHQL-VULNERABILITIES-006 -->
<!-- context: Apollo Server 4.x on Node.js 20; local schema at 127.0.0.1:18080/graphql; case: WEB-A11-GRAPHQL-VULNERABILITIES-006 -->
<!-- prerequisites: seed bounded schema; debug stack traces are disabled; capture GraphQL validation errors without sensitive values -->
<!-- encoding: UTF-8 GraphQL operation text; misspelled field is submitted once -->
<!-- expected-result: vulnerable fixture returns a suggestion such as `Did you mean "email"?`; hardened fixture returns a generic validation error without schema hints for unauthorized actors -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S7 -->
<!-- last-verified: 2026-07-18 -->
```graphql
query FieldSuggestionProbe {
  user(id: "self") {
    emali
  }
}
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// === VULNERABLE: No depth limit, no auth checks, introspection enabled ===
const vulnerableResolvers = {
  Query: {
    user: (_, { id }) => db.users.findById(id),  // No authorization check!
  },
  User: {
    friends: (user) => db.users.findFriendsByUserId(user.id), // Schema permits repeated nesting without a separate depth/cost rule
    ssn: (user) => user.ssn,  // Sensitive field with no access control
  },
};

// === SECURE: Depth-limited, authorized, introspection disabled ===
const secureResolvers = {
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

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến GraphQL Vulnerabilities, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Áp dụng kiểm soát ở cấp đối tượng, thuộc tính, chức năng và mức tiêu thụ tài nguyên của API.
- Kiểm tra object/field authorization trong resolver và áp depth/cost/alias/batch cùng rate accounting theo operation; tắt introspection chỉ là hardening tùy mô hình.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Với GraphQL Vulnerabilities, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

```javascript
// Apollo Server — disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Only in dev
});
```
Apollo Server không tự áp một ngưỡng depth/cost phù hợp cho mọi schema. Chọn validation rule tương thích đúng Apollo/GraphQL version, pin dependency, và regression-test với fragments, aliases, lists cùng introspection; không dùng riêng depth làm đại diện cho resolver/DB cost. [S7]
Rate accounting phải chạy sau parse/validation và tính số operation trong array batching, alias gọi field nhạy cảm, cùng resolver/cost thực tế. Đếm riêng số phần tử HTTP body sẽ bỏ sót alias và nested resolver work. [S7]

- **Tóm tắt**: Bảo mật GraphQL bằng cách tắt tính năng Introspection trên production, giới hạn query depth/complexity và triển khai rate limit theo operation.
- **Các bước chi tiết**:
  - **Tắt introspection trong production**: tắt theo môi trường hoặc role khi production không cần công khai schema; vẫn giữ authorization và cost controls vì introspection không phải bản sửa root-cause.
  - **Giới hạn query depth và complexity**: dùng validation rule/cost estimator theo schema, tính fragments, aliases và list multipliers rồi từ chối trước resolver khi vượt policy.
  - **Rate limit theo operation**: đếm từng operation, alias, mutation nhạy cảm và batch item theo principal/object/action thay vì chỉ đếm một HTTP request.
  - **Field-level authorization** — kiểm tra quyền truy cập cho từng field nhạy cảm.
  - **Disable query batching** nếu không cần thiết.

## 12. Retest

- **Positive case:** với GraphQL Vulnerabilities, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của GraphQL Vulnerabilities mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

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

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/graphql — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S7]** OWASP GraphQL Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
