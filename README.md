# SecHub/Data — Web & Application Security Curriculum

Kho học liệu tiếng Việt từ beginner đến intermediate về Web/Application Security. Repository ưu tiên root cause, kiểm thử có ủy quyền, bản sửa có thể retest và nguồn kỹ thuật truy vết được.

> [!WARNING]
> Nhánh `fix/learning-readiness-v1` đang trong giai đoạn chuẩn hóa. Không coi nội dung là public-release-ready khi `python3 scripts/validate_content.py --release` chưa đạt. Trạng thái `technical-review` hoặc payload chỉ qua gate tĩnh không phải bằng chứng lab.

## Phạm vi v1

- 77 bài học thuộc 11 nhóm Web/AppSec.
- 15 chương cheatsheet đã tách từ file nguyên khối.
- Không mở rộng thành curriculum full cybersecurity trong v1.
- Obsidian, CTF write-up, HackTricks và PayloadsAllTheThings chỉ dùng để tìm nguồn/ý tưởng; không phải nguồn chân lý.

## Bắt đầu

1. Đọc [chính sách sử dụng có ủy quyền](AUTHORIZED_USE.md).
2. Chọn bài theo thư mục `01-...` đến `11-...`.
3. Dùng bài theo thứ tự mục tiêu → nền tảng → root cause → lab → phòng thủ → retest.
4. Chỉ chạy payload khớp context/phiên bản trong fixture local.

## Quality gates

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_content.py
python3 scripts/check_baseline_manifest.py
python3 scripts/check_markdown_render.py
python3 scripts/check_code_comments.py
python3 scripts/check_terminology.py
python3 scripts/check_duplicate_prose.py
python3 scripts/scan_sensitive_data.py
python3 scripts/check_payload_safety.py
python3 scripts/check_training_endpoints.py
python3 scripts/check_runnable_blocks.py
python3 scripts/validate_content.py --release
```

Gate cuối cố ý thất bại nếu còn bài chưa `verified`, claim thiếu nguồn, payload thiếu evidence hoặc quyết định license chưa hoàn tất.

## Governance

- [Cấu trúc bài học](docs/lesson-schema.md)
- [Checklist technical/language review](docs/review-checklist.md)
- [Hướng dẫn đóng góp](CONTRIBUTING.md)
- [Provenance](CONTENT_PROVENANCE.md)
- [Chỉ mục nguồn gợi ý từ Obsidian](audit/obsidian-source-index.tsv)
- [Quyết định quyền sử dụng](audit/provenance-decision.yml)
- [Trạng thái sẵn sàng phát hành](audit/release-readiness.md)
- [Trạng thái giấy phép](LICENSE-STATUS.md)
- [Báo lỗi bảo mật/nội dung](SECURITY.md)
