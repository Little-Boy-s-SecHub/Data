# Cross-Site Scripting (XSS)

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-79

## Tổng quan

Cross-Site Scripting (XSS) là nhóm lỗ hổng bảo mật cho phép kẻ tấn công chèn mã JavaScript độc hại vào các trang web được hiển thị cho người dùng khác. XSS là một trong những lỗ hổng phổ biến nhất trên web và được chia thành 4 loại chính:

| Loại | Mô tả | Link |
|---|---|---|
| **DOM-based XSS** | Mã độc thực thi thông qua thao tác DOM phía client | [→ dom-based/](./dom-based/) |
| **Reflected XSS** | Mã độc được "phản xạ" từ server qua URL/parameter | [→ reflected/](./reflected/) |
| **Stored XSS** | Mã độc được lưu trữ trong database, hiển thị cho mọi user | [→ stored/](./stored/) |
| **XSSI** | Cross-Site Script Inclusion — đánh cắp dữ liệu qua script tag | [→ xssi/](./xssi/) |

## Nguyên tắc phòng thủ chung

1. **Output Encoding** — Encode tất cả user input trước khi render vào HTML
2. **Content Security Policy (CSP)** — Giới hạn nguồn script được phép thực thi
3. **Input Validation** — Whitelist các ký tự hợp lệ
4. **HttpOnly Cookies** — Ngăn JavaScript truy cập session cookies
5. **Sanitization Libraries** — Sử dụng DOMPurify, bleach (Python), hoặc tương đương
