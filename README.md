# 🛡️ Cẩm nang Bảo mật Ứng dụng Web — SecStudy

> **76 bài học** bảo mật web từ cơ bản đến nâng cao, tổ chức theo **OWASP Top 10:2025**
> 
> Tài liệu này được tổng hợp từ: Hacksplaining, PortSwigger Web Security Academy, HackTricks, OWASP WSTG, CWE Top 25

---

## 📋 Mục lục

### A01:2025 — Broken Access Control (Kiểm soát Truy cập Bị lỗi)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 1 | Broken Access Control | CWE-285 | [→](./01-broken-access-control/broken-access-control/) |
| 2 | Privilege Escalation | CWE-269 | [→](./01-broken-access-control/privilege-escalation/) |
| 3 | Directory Traversal | CWE-22 | [→](./01-broken-access-control/directory-traversal/) |
| 4 | Server-Side Request Forgery (SSRF) | CWE-918 | [→](./01-broken-access-control/ssrf/) |
| 5 | Open Redirects | CWE-601 | [→](./01-broken-access-control/open-redirects/) |
| 6 | **Insecure Direct Object Reference (IDOR)** | CWE-639 | [→](./01-broken-access-control/idor/) |
| 7 | **Broken Function Level Authorization (BFLA)** | CWE-285 | [→](./01-broken-access-control/bfla/) |

---

### A02:2025 — Security Misconfiguration (Sai sót Cấu hình Bảo mật)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 8 | Clickjacking | CWE-1021 | [→](./02-security-misconfiguration/clickjacking/) |
| 9 | Cross-Origin Resource Sharing (CORS) | CWE-942 | [→](./02-security-misconfiguration/cors/) |
| 10 | Lax Security Settings | CWE-16 | [→](./02-security-misconfiguration/lax-security-settings/) |
| 11 | Host Header Poisoning | CWE-644 | [→](./02-security-misconfiguration/host-header-poisoning/) |
| 12 | **Content Security Policy (CSP) Bypass** | CWE-693 | [→](./02-security-misconfiguration/csp-bypass/) |
| 13 | **Subdomain Takeover** | CWE-284 | [→](./02-security-misconfiguration/subdomain-takeover/) |

---

### A03:2025 — Software Supply Chain Failures (Lỗi Chuỗi Cung ứng)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 14 | Toxic Dependencies | CWE-1395 | [→](./03-supply-chain/toxic-dependencies/) |
| 15 | Subdomain Squatting | CWE-284 | [→](./03-supply-chain/subdomain-squatting/) |
| 16 | Malvertising | CWE-829 | [→](./03-supply-chain/malvertising/) |
| 17 | **Supply Chain Attacks (CI/CD)** | CWE-829 | [→](./03-supply-chain/supply-chain-attacks/) |

---

### A04:2025 — Cryptographic Failures (Lỗi Mã hóa)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 18 | Downgrade Attacks | CWE-757 | [→](./04-cryptographic-failures/downgrade-attacks/) |
| 19 | SSL Stripping | CWE-319 | [→](./04-cryptographic-failures/ssl-stripping/) |
| 20 | Unencrypted Communication | CWE-319 | [→](./04-cryptographic-failures/unencrypted-communication/) |
| 21 | DNS Poisoning | CWE-350 | [→](./04-cryptographic-failures/dns-poisoning/) |
| 22 | **Insecure Randomness** | CWE-330 | [→](./04-cryptographic-failures/insecure-randomness/) |

---

### A05:2025 — Injection (Chèn mã)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 23 | SQL Injection | CWE-89 | [→](./05-injection/sql-injection/) |
| 24 | Command Execution | CWE-78 | [→](./05-injection/command-execution/) |
| 25 | Regex Injection (ReDoS) | CWE-1333 | [→](./05-injection/regex-injection/) |
| 26 | CSS Injection | CWE-79 | [→](./05-injection/css-injection/) |
| 27 | XML External Entities (XXE) | CWE-611 | [→](./05-injection/xxe/) |
| 28 | DOM-based XSS | CWE-79 | [→](./05-injection/xss/dom-based/) |
| 29 | Reflected XSS | CWE-79 | [→](./05-injection/xss/reflected/) |
| 30 | Stored XSS | CWE-79 | [→](./05-injection/xss/stored/) |
| 31 | Cross-Site Script Inclusion (XSSI) | CWE-79 | [→](./05-injection/xss/xssi/) |
| 32 | **Server-Side Template Injection (SSTI)** | CWE-1336 | [→](./05-injection/ssti/) |
| 33 | **NoSQL Injection** | CWE-943 | [→](./05-injection/nosql-injection/) |
| 34 | **LDAP Injection** | CWE-90 | [→](./05-injection/ldap-injection/) |
| 35 | **CRLF Injection** | CWE-93 | [→](./05-injection/crlf-injection/) |
| 36 | **XPath Injection** | CWE-643 | [→](./05-injection/xpath-injection/) |
| 37 | **Code Injection** | CWE-94 | [→](./05-injection/code-injection/) |
| 38 | **Second-Order SQL Injection** | CWE-89 | [→](./05-injection/second-order-sqli/) |
| 39 | **Local/Remote File Inclusion** | CWE-98 | [→](./05-injection/lfi-rfi/) |
| 40 | **DOM Clobbering** | CWE-79 | [→](./05-injection/dom-clobbering/) |
| 41 | **PostMessage Exploitation** | CWE-345 | [→](./05-injection/postmessage-exploitation/) |
| 42 | **WebSocket Hijacking (CSWSH)** | CWE-1385 | [→](./05-injection/websocket-hijacking/) |
| 43 | **Server-Side Include (SSI) Injection** | CWE-97 | [→](./05-injection/ssi-injection/) |
| 44 | **CSV/Formula Injection** | CWE-1236 | [→](./05-injection/csv-formula-injection/) |
| 45 | **HTTP Parameter Pollution** | CWE-235 | [→](./05-injection/http-parameter-pollution/) |

---

### A06:2025 — Insecure Design (Thiết kế Không an toàn)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 46 | Insecure Design | CWE-840 | [→](./06-insecure-design/insecure-design/) |
| 47 | Information Leakage | CWE-200 | [→](./06-insecure-design/information-leakage/) |
| 48 | File Upload Vulnerabilities | CWE-434 | [→](./06-insecure-design/file-upload/) |
| 49 | Mass Assignment | CWE-915 | [→](./06-insecure-design/mass-assignment/) |
| 50 | **Race Conditions (TOCTOU)** | CWE-362 | [→](./06-insecure-design/race-conditions/) |
| 51 | **Business Logic Vulnerabilities** | CWE-840 | [→](./06-insecure-design/business-logic-vulnerabilities/) |
| 52 | **Error Handling & Exception Mismanagement** | CWE-755 | [→](./06-insecure-design/error-handling/) |

---

### A07:2025 — Authentication Failures (Lỗi Xác thực)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 53 | Password Mismanagement | CWE-521 | [→](./07-authentication-failures/password-mismanagement/) |
| 54 | User Enumeration | CWE-204 | [→](./07-authentication-failures/user-enumeration/) |
| 55 | Weak Session IDs | CWE-330 | [→](./07-authentication-failures/weak-session-ids/) |
| 56 | Session Fixation | CWE-384 | [→](./07-authentication-failures/session-fixation/) |
| 57 | Cross-Site Request Forgery (CSRF) | CWE-352 | [→](./07-authentication-failures/csrf/) |
| 58 | Email Spoofing | CWE-290 | [→](./07-authentication-failures/email-spoofing/) |
| 59 | **JWT Attacks** | CWE-345 | [→](./07-authentication-failures/jwt-attacks/) |
| 60 | **OAuth 2.0 Vulnerabilities** | CWE-601 | [→](./07-authentication-failures/oauth-vulnerabilities/) |
| 61 | **2FA/MFA Bypass** | CWE-308 | [→](./07-authentication-failures/2fa-mfa-bypass/) |
| 62 | **Credential Stuffing & Brute Force** | CWE-307 | [→](./07-authentication-failures/credential-stuffing/) |
| 63 | **Session Hijacking** | CWE-384 | [→](./07-authentication-failures/session-hijacking/) |

---

### A08:2025 — Software/Data Integrity Failures (Lỗi Toàn vẹn Dữ liệu)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 64 | Prototype Pollution | CWE-1321 | [→](./08-data-integrity-failures/prototype-pollution/) |
| 65 | **Insecure Deserialization** | CWE-502 | [→](./08-data-integrity-failures/insecure-deserialization/) |
| 66 | **HTTP Request Smuggling** | CWE-444 | [→](./08-data-integrity-failures/http-request-smuggling/) |
| 67 | **Web Cache Poisoning** | CWE-349 | [→](./08-data-integrity-failures/web-cache-poisoning/) |
| 68 | **Web Cache Deception** | CWE-524 | [→](./08-data-integrity-failures/web-cache-deception/) |

---

### A09:2025 — Logging & Alerting Failures (Lỗi Ghi nhật ký)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 69 | Logging and Monitoring | CWE-778 | [→](./09-logging-alerting/logging-and-monitoring/) |

---

### A10:2025 — Mishandling of Exceptional Conditions (Xử lý Ngoại lệ)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 70 | Buffer Overflows | CWE-120 | [→](./10-exceptional-conditions/buffer-overflows/) |
| 71 | Denial of Service Attacks | CWE-400 | [→](./10-exceptional-conditions/denial-of-service/) |
| 72 | XML Bombs | CWE-776 | [→](./10-exceptional-conditions/xml-bombs/) |
| 73 | Remote Code Execution | CWE-94 | [→](./10-exceptional-conditions/remote-code-execution/) |

---

### API Security (Bảo mật API)
| # | Lỗ hổng | CWE | Link |
|---|---|---|---|
| 74 | **GraphQL Vulnerabilities** | CWE-200 | [→](./11-api-security/graphql-vulnerabilities/) |
| 75 | **API Rate Limiting & Resource Abuse** | CWE-770 | [→](./11-api-security/api-rate-limiting/) |
| 76 | **Shadow APIs & Improper Inventory** | CWE-1059 | [→](./11-api-security/shadow-apis/) |

---

## 📊 Thống kê

| Metric | Giá trị |
|---|---|
| Tổng số bài | **76** |
| Bài gốc (Hacksplaining) | 41 |
| Bài bổ sung (OWASP/PortSwigger/HackTricks) | **35** |
| OWASP Top 10:2025 categories | 10/10 ✅ |
| API Security | 3 bài |
| Ngôn ngữ | Tiếng Việt (code comment: English) |

## 🏗️ Cấu trúc thư mục

```
├── 01-broken-access-control/     (7 bài)
├── 02-security-misconfiguration/ (6 bài)
├── 03-supply-chain/              (4 bài)
├── 04-cryptographic-failures/    (5 bài)
├── 05-injection/                 (23 bài, bao gồm nhóm XSS)
├── 06-insecure-design/           (7 bài)
├── 07-authentication-failures/   (11 bài)
├── 08-data-integrity-failures/   (5 bài)
├── 09-logging-alerting/          (1 bài)
├── 10-exceptional-conditions/    (4 bài)
└── 11-api-security/              (3 bài)
```

## 📚 Nguồn tham khảo chính

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [CWE Top 25 (2024)](https://cwe.mitre.org/top25/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Hacksplaining](https://www.hacksplaining.com/)

## 📝 License

Tài liệu này được tổng hợp cho mục đích giáo dục. Nội dung gốc từ Hacksplaining thuộc bản quyền của Hacksplaining.com.
