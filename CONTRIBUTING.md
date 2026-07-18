# Đóng góp nội dung

## Quy trình bắt buộc

1. Sửa bài theo [lesson contract](docs/lesson-schema.md), không đổi thứ tự 17 mục.
2. Tách root cause, hậu quả, exploit mechanism và defense-in-depth.
3. Gắn source marker ngay tại claim; chỉ đặt link ở mục 16–17.
4. Với payload, ghi đủ annotation và chỉ nâng `lab-verified` khi có regression evidence trên fixture pin version.
5. Chạy đầy đủ PR gates trước khi đề nghị review.
6. Technical review và language review phải là hai lượt độc lập.

## Nguồn

Ưu tiên RFC/standard, NIST, MITRE CWE/CAPEC, tài liệu vendor/framework chính thức; tiếp theo là OWASP và nghiên cứu gốc. Community source chỉ hỗ trợ discovery và cần bằng chứng độc lập. Không copy nguyên văn quá phạm vi giấy phép cho phép.

## Code và payload

- Nội dung tiếng Việt có dấu; code comment bằng tiếng Anh.
- Vulnerable/secure code phải cùng framework, phiên bản và use case.
- Không thêm callback Internet, secret, target thật hoặc payload phá hủy không có fixture cô lập.
- `runnable: true` yêu cầu syntax/runtime test; `lab-verified` yêu cầu evidence hoặc regression test.

## Lệnh kiểm tra

```bash
python3 scripts/build_audit_artifacts.py
python3 scripts/validate_content.py
python3 scripts/check_baseline_manifest.py
python3 scripts/check_markdown_render.py
python3 scripts/check_code_comments.py
python3 scripts/check_terminology.py
python3 scripts/scan_sensitive_data.py
python3 scripts/check_payload_safety.py
python3 scripts/check_training_endpoints.py
python3 scripts/check_runnable_blocks.py
```
