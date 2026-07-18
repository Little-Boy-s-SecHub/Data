# 9. Server-Side Template Injection (SSTI)

> [!CAUTION]
> Chỉ kiểm thử template fixture local được ủy quyền. Không dùng payload mở shell, đọc secret hoặc gọi mạng.

> **Phạm vi kiểm chứng:** Các probe dưới đây chỉ nhận diện việc biểu thức được đánh giá trong engine đã pin. `static-verified` không chứng minh RCE; các gadget phụ thuộc subclass index/callable/version đã bị loại.

SSTI xảy ra khi dữ liệu do actor kiểm soát trở thành template source thay vì chỉ là dữ liệu được render. Bắt đầu bằng probe số học/chuỗi không có side effect và so sánh với phản chiếu literal.

### 9.1. Jinja2 3.1

<!-- payload-id: CHEAT-09-001 -->
<!-- context: Jinja2 3.1 fixture; actor input is passed either to Template(source) or as a value in a fixed template -->
<!-- prerequisites: run one disposable Python 3.12 process; expose no Flask config/secret objects and block process/network/filesystem capabilities -->
<!-- encoding: UTF-8 Jinja template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-JINJA; the fixed value-rendering path displays the expressions literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```jinja
{{ 7 * 7 }}
{{ ['SECHUB', 'JINJA'] | join('-') }}
```

### 9.2. Twig 3.10

<!-- payload-id: CHEAT-09-002 -->
<!-- context: Twig 3.10 fixture with no user-defined callable filters; actor input is compared as template source versus a bound variable -->
<!-- prerequisites: run PHP 8.2 in a disposable container; disable filesystem/network access and capture rendered output only -->
<!-- encoding: UTF-8 Twig template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-TWIG; the fixed path renders literal text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```twig
{{ 7 * 7 }}
{{ ['SECHUB', 'TWIG'] | join('-') }}
```

### 9.3. FreeMarker 2.3.33

<!-- payload-id: CHEAT-09-003 -->
<!-- context: FreeMarker 2.3.33 fixture with restricted object wrapper and no Execute utility exposed -->
<!-- prerequisites: run Java 17 in a disposable container; expose only synthetic scalar values and block outbound network -->
<!-- encoding: UTF-8 FreeMarker template text -->
<!-- expected-result: the vulnerable source-template path renders 49 and SECHUB-FREEMARKER; the fixed path renders input as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```ftl
${7 * 7}
${['SECHUB', 'FREEMARKER']?join('-')}
```

### 9.4. Velocity 2.3

<!-- payload-id: CHEAT-09-004 -->
<!-- context: Apache Velocity 2.3 fixture exposing only synthetic scalar/list values; no ClassTool or runtime object -->
<!-- prerequisites: run Java 17 in a disposable container; compare evaluated template source with a fixed-template value binding -->
<!-- encoding: UTF-8 Velocity template text -->
<!-- expected-result: the vulnerable source-template path renders the arithmetic/list marker; the fixed path renders the bytes literally -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```velocity
#set($value = 7 * 7)$value
#set($marker = "SECHUB-VELOCITY")$marker
```

## Tài liệu tham khảo

- **[S1]** PortSwigger Web Security Academy — Server-side template injection. https://portswigger.net/web-security/server-side-template-injection — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** Jinja Documentation — Template Designer Documentation. https://jinja.palletsprojects.com/en/stable/templates/ — bản hiện hành; truy cập: 2026-07-18.
