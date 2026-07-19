# SecHub/Data — Web & Application Security Curriculum

Kho học liệu tiếng Việt từ beginner đến intermediate về Web/Application Security. Repository ưu tiên root cause, kiểm thử có ủy quyền, bản sửa có thể retest và nguồn kỹ thuật truy vết được.

> [!WARNING]
> Chỉ thực hành payload trong lab local hoặc hệ thống có ủy quyền rõ ràng. Luôn đối chiếu context, phiên bản và điều kiện an toàn ghi trong từng bài.

## Phạm vi v1

- 83 bài học thuộc 11 nhóm Web/AppSec.
- Một file cheatsheet tổng hợp tại `security_cheatsheet.md`.
- Không mở rộng thành curriculum full cybersecurity trong v1.
- Obsidian, CTF write-up, HackTricks và PayloadsAllTheThings chỉ dùng để tìm nguồn/ý tưởng; không phải nguồn chân lý.

## Bắt đầu

1. Đọc [chính sách sử dụng có ủy quyền](AUTHORIZED_USE.md).
2. Chọn bài theo thư mục `01-...` đến `11-...`.
3. Dùng bài theo thứ tự mục tiêu → nền tảng → root cause → lab → phòng thủ → retest.
4. Chỉ chạy payload khớp context/phiên bản trong fixture local.

## Chất lượng nội dung

- Mỗi bài tách rõ root cause, cơ chế tấn công, điều kiện lab và kiểm soát phòng thủ.
- Claim kỹ thuật được gắn nguồn tham khảo và gom link ở mục cuối bài.
- Payload phải ghi context, điều kiện, encoding, expected result và mức rủi ro trước khi dùng trong lab.
