# Checklist review học liệu

Checklist này áp dụng cho từng bài hoặc một batch được liệt kê rõ. Technical review và language review phải do hai lượt độc lập thực hiện; CI không thay thế phê duyệt của reviewer.

## Technical review

- [ ] Root cause, điều kiện khai thác, hậu quả và kỹ thuật tấn công được tách đúng.
- [ ] Claim về protocol/browser/framework/version/mitigation có marker nguồn phù hợp.
- [ ] CWE là weakness hiện hành và khớp root cause; chủ đề rộng dùng danh sách rỗng khi không có mapping chính xác.
- [ ] Code vulnerable/secure cùng framework, version và use case.
- [ ] Kiểm soát gốc không bị thay bằng UUID, rate limit, WAF, CSP hoặc input validation không đúng ngữ cảnh.
- [ ] Lab ghi setup, input, thao tác, expected result, cleanup và giới hạn an toàn.
- [ ] Mọi payload đã kiểm tra syntax, context, semantics, version và safety; trạng thái validation không bị nâng quá evidence.
- [ ] Retest có positive, negative, boundary case và telemetry cần xác nhận.

Reviewer: `________________`  Ngày: `YYYY-MM-DD`  Phạm vi: `________________`

## Language review

- [ ] Văn xuôi tiếng Việt có dấu, không mojibake và thuật ngữ nhất quán.
- [ ] Code comment dùng tiếng Anh.
- [ ] Không còn diễn đạt tuyệt đối, suy diễn hoặc khẳng định vượt quá nguồn/evidence.
- [ ] Thuật ngữ chỉ giải thích khái niệm thực sự dùng trong bài.
- [ ] Link đọc thêm và tài liệu tham khảo chỉ ở mục 16–17.

Reviewer: `________________`  Ngày: `YYYY-MM-DD`  Phạm vi: `________________`

Chỉ đổi `content_status: verified` sau khi cả hai phần được ký và mọi blocker của phạm vi đã đóng.
