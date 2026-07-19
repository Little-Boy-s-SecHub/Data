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
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain GraphQL Vulnerabilities by root cause instead of just describing the consequences. 
- Identify trust boundaries, assets, actors, and the necessary conditions for the flaw to be exploitable. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in GraphQL Vulnerabilities scenarios and how to apply input handling across trust boundaries.
- Distinguish authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework shown in the example.
- Have a local lab isolated, with synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you walk into a large library to find a book. In a traditional library (equivalent to REST API), whenever you want to get information, the librarian would give you an entire stack of thick books (loading all the resources), even though you only need to read a single page. To solve this waste, the library upgrades to the **GraphQL** model. Now, you just need to write a small note specifying exactly: "I want page 5, line 10 of book X." The librarian will only cut out that exact line and give it to you. The exchange happens extremely quickly and efficiently. GraphQL channels all your requests through a single window (endpoint `/graphql`) and performs three main actions: reading information (Query), writing/updating information (Mutation), and real-time tracking (Subscription).

To serve better, the library has a detailed handbook (called **Introspection**). This book clearly states: what shelves the library has, what chapters each book contains, and how to search for them. Although this is a useful guide for library staff, if it falls into the hands of a bad person, they will know the exact arrangement of the entire library.

In addition, because the library only serves at a single counter, the older methods of limiting queue lines (rate limit based on URL) are completely ineffective. Customers can also submit an entire stack of request papers at once during a single meeting with the librarian (batch query technique - **Batch Queries**), causing the librarian to work to exhaustion.

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
Valid JSON response only contains the requested fields:

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

## 4. Description and Root Cause

The **GraphQL Vulnerabilities (Specific vulnerabilities in GraphQL)** arise from developers focusing too much on flexibility while forgetting to set up protective rules.

An attacker can exploit the advanced features of GraphQL to counterattack the system itself:
- **Unintended Introspection Exposure**: Introspection is a legitimate feature used to describe the GraphQL schema and does not by itself create an authorization bypass. However, schema disclosure can aid reconnaissance if the schema does not need to be public in production. [S7]
- **Nested Queries Causing DoS (Nested Query DoS)**: The attacker sends a query that loops infinitely, for example: "Find my friends, then find my friends' friends, then find friends of those friends..." (nested queries in a geometric progression). The system's database will become congested, exhausting the server's RAM and causing it to crash.
- **Exhaustion Attack via Batch Query**: Instead of sending 1,000 individual login requests to guess passwords (behavior easily detected and blocked by firewalls), the attacker compresses all 1,000 queries into one. The firewall counts it as a single valid request, but the backend server quietly performs 1,000 password checks.
- **Bypassing Field-Level Authorization**: The system only checks whether the user has access to the library, not whether they are allowed to read highly confidential documents (missing field-level authorization).
- **Injection Vulnerability**: Abusing GraphQL input variables to inject malicious SQL statements or system code.

> **References:** Technical claims in the lesson are marked with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4], [S6], [S7].

## 5. Threat Model and Exploitation Conditions

- **Assets:** data at the object/field level, mutation budget, and CPU/DB resolver costs; schema metadata is not automatically a vulnerability.  
- **Trust boundary:** GraphQL documents/variables go through parsing, validation, authorization/cost rules, and then into the resolver.  
- **Actor:** regular user, admin, and unauthenticated client each have a separate seed; each case uses a token corresponding to the proper role.  
- **Necessary condition:** resolver lacks object/field authorization, or depth/alias/batch/cost/rate accounting does not correctly limit the operation.  
- **Environmental condition:** Node.js 20 and Apollo Server 4 locally; schema, resolver counter, and policy version are pinned in the fixture.

Introspection is just a signal for configuration/schema exposure; it is necessary to prove unauthorized data access or resource amplification before concluding the corresponding finding. [S1]

## 6. Attack Mechanism

Alias, nesting, and batching can turn a HTTP request into multiple resolver/DB calls; a resolver that only checks auth at the root query can return fields/objects without proper permission. Evidence must link the operation to the resolver counter, policy decision, and object owner, not just rely on a 200 response with GraphQL errors. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run Apollo Server 4/Node 20 locally; seed two users and one admin, enable resolver/cost/policy log, and limit to a maximum of 20 resolver calls.
2. **Input:** baseline query for the user's own data; then use a query for objects with a different owner, admin fields, alias/nesting/batch are limited.
3. **Actions:** change one feature at a time; record document/variables, GraphQL errors, resolver count, DB calls, and authorization decision.
4. **Expected result:** fix denial of unauthorized object/field, count aliases/batch in the quota, and block query before exceeding cost/depth limit.
5. **Cleanup:** delete token/synthetic data, reset counters, and stop server/database fixture.
6. **Safety limits:** do not run recursive/unbounded queries; do not use production endpoint, schema, or real credentials.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Introspection — Explore the entire API schema:**

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
**3. Batch Query — Brute force OTP/password in a single request:**

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
**4. Alias-based batching (when array batching is blocked):**

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

## 9. Vulnerable Code and Secure Code

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

## 10. Detection

- Log actor/session, route or operation, object/resource related to GraphQL vulnerabilities, policy results, and correlation ID; do not log secrets or entire tokens.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chain, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to verify whether the request reached the sink and whether it had any impact.  
- Scanner or WAF alerts are just investigation signals; they are not sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Apply control at the level of objects, attributes, functions, and resource consumption of API. 
- Check object/field authorization in the resolver and apply depth/cost/alias/batch along with rate accounting per operation; disabling introspection is just hardening depending on the model. 
- Use the same policy for all equivalent routes/operations; do not just fix the endpoint that appears in the PoC.

### Defense-in-depth

With GraphQL Vulnerabilities, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

```javascript
// Apollo Server — disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production', // Only in dev
});
```
Apollo Server does not automatically enforce a depth/cost threshold suitable for every schema. Choose a validation rule compatible with the correct Apollo/GraphQL version, pin dependencies, and regression-test with fragments, aliases, lists, as well as introspection; do not use depth alone as a proxy for resolver/DB cost. [S7]
Rate accounting must run after parse/validation and calculate the number of operations in array batching, sensitive field alias calls, along with actual resolver/cost. Counting only the number of elements HTTP body will miss aliases and nested resolver work. [S7]

- **Summary**: Secure GraphQL by disabling Introspection in production, limiting query depth/complexity, and implementing rate limiting per operation. 
- **Detailed steps**:
  - **Disable introspection in production**: disable based on environment or role when production does not need to expose the schema; still maintain authorization and cost controls since introspection is not a root-cause fix.
  - **Limit query depth and complexity**: use validation rules/cost estimator according to the schema, considering fragments, aliases, and list multipliers, then reject before the resolver if it exceeds policy.
  - **Rate limit per operation**: count each operation, alias, sensitive mutation, and batch item per principal/object/action instead of just counting a single HTTP request.
  - **Field-level authorization** — check access permissions for each sensitive field.
  - **Disable query batching** if not required.

## 12. Retest

- **Positive case:** with GraphQL Vulnerabilities, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** same input/resource but unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effect match correlation ID.  
- **Retest:** save a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of GraphQL vulnerabilities without verifying side effects and logs.  
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another original control.  
- Only fix one route while the same sink/policy is used in another route.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **GraphQL**: A data query language for API designed so that clients can request exactly the data they need, avoiding bandwidth wastage. 
- **Schema**: A technical design document describing the data structure, data types, and all available queries of a GraphQL system API. 
- **Introspection**: A special feature of GraphQL that allows users to query the system to get detailed information about the current schema. 
- **Resolver**: Code snippets or functions in GraphQL responsible for fetching the actual data for each requested field. 
- **Query**: An operation to read data from the system. 
- **Mutation**: An operation that changes the state of data (such as creating, updating, or deleting data). 
- **Batch Queries**: A technique to package multiple GraphQL queries into a single network request to reduce the number of connections. 
- **Query Depth**: The level of nesting between entities in a query, indicating the hierarchy of the requested data. 
- **Field-level Authorization**: A mechanism that grants permissions down to specific fields of an object, preventing unauthorized access to information. 
- **Alias**: A technique for assigning custom names to returned fields in GraphQL, which can be misused to merge multiple identically named queries into a single request.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/graphql — version/status: current version; accessed: 2026-07-18. 
- **[S2]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/ — version/status: current version; accessed: 2026-07-18. 
- **[S3]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — version/status: current version; accessed: 2026-07-18. 
- **[S4]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — version/status: current version; accessed: 2026-07-18. 
- **[S6]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S7]** OWASP GraphQL Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.