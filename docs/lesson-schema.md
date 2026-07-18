# Lesson contract schema v1

Mọi `README.md` bài học phải có YAML frontmatter và đúng 17 heading dưới đây. Validator không chấp nhận đổi tên hoặc đổi thứ tự.

```yaml
---
schema_version: 1
id: WEB-A01-IDOR
title: Insecure Direct Object Reference
slug: idor
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
owasp:
  - A01:2025
cwe:
  - CWE-639
content_status: technical-review
payload_status: static-verified
last_verified: null
---
```

## Giá trị

- `level`: `beginner`, `intermediate`, `advanced`.
- `content_status`: `draft`, `technical-review`, `verified`.
- `payload_status`: `none`, `static-verified`, `lab-verified`.
- `last_verified`: `null` cho bài chưa verified; ngày ISO `YYYY-MM-DD` sau review.
- `cwe`: có thể là `[]` khi chủ đề rộng không có mapping root-cause chính xác; không gán CWE theo hậu quả.

## Heading bắt buộc

1. `## 1. Mục tiêu học tập`
2. `## 2. Kiến thức cần có`
3. `## 3. Kiến thức nền tảng`
4. `## 4. Mô tả và nguyên nhân gốc`
5. `## 5. Mô hình đe dọa và điều kiện khai thác`
6. `## 6. Cơ chế tấn công`
7. `## 7. Kiểm thử trong lab được ủy quyền`
8. `## 8. Payload và phạm vi áp dụng`
9. `## 9. Code dễ bị lỗi và code an toàn`
10. `## 10. Phát hiện`
11. `## 11. Phòng thủ`
12. `## 12. Retest`
13. `## 13. Sai lầm thường gặp`
14. `## 14. Tóm tắt và checklist`
15. `## 15. Giải thích thuật ngữ`
16. `## 16. Bài liên quan và đọc thêm`
17. `## 17. Tài liệu tham khảo`

## Payload annotation

Annotation đứng liền trước opening fence:

```markdown
<!-- payload-id: SQLI-MYSQL-BOOLEAN-001 -->
<!-- context: MySQL 8.x; string value inside WHERE clause -->
<!-- prerequisites: error hidden; response difference observable -->
<!-- encoding: UTF-8; URL-encode once when placed in query string -->
<!-- expected-result: true/false response differs only at the tested predicate -->
<!-- risk: non-destructive -->
<!-- runnable: true -->
<!-- validation: lab-verified -->
<!-- evidence: tests/test_sqli_mysql.py::test_boolean_string_context -->
<!-- sources: S2,S4 -->
<!-- last-verified: 2026-07-17 -->
```

`static-verified` chỉ dành cho block đã kiểm tra cú pháp, context, ngữ nghĩa, tính hiện hành và safety bằng gate tĩnh phù hợp. `lab-verified` phải có fixture pin version và evidence/regression test. `runnable: false` nói rõ block là fragment/minh họa và không được đưa thẳng vào runtime harness.

## Source format

Trong nội dung chỉ dùng `[S1]`. Link đầy đủ nằm ở mục 17:

```markdown
- **[S1]** Tên tài liệu. https://example.invalid/spec — phiên bản/ngày: 1.0; truy cập: 2026-07-17.
```
