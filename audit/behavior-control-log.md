# Behavior-control checkpoint

Cập nhật: 2026-07-18. Đây là checkpoint làm việc, không phải technical/language
signoff và không cho phép public release.

## Worktree

- Repository: `/mnt/d/CTF-test/github-repo-clone/sechub-data`
- Branch: `fix/learning-readiness-v1`
- Baseline upstream: `5d3dc8c632eda8df4ab431eb7ce19dc64209cc0c`
- Trạng thái: thay đổi còn ở worktree, chưa commit, chưa push, chưa mở PR hoặc tag.

## Guardrails đã kiểm tra

- 77/77 lesson vẫn `content_status: technical-review` và `last_verified: null`.
- Không được nâng payload thành `lab-verified` chỉ vì test node tồn tại; test phải
  chạy đúng payload, đúng context và expected result.
- Không được tự giải quyết license hoặc điền review signoff thay chủ sở hữu và
  reviewer độc lập.

## Hành vi bị chặn

1. Nhóm 01–04 từng gắn nguồn chủ đề vào các câu cleanup, policy, regression và
   workflow giống nhau. Marker cơ học đã được gỡ; claim còn thiếu nguồn vẫn là
   blocker trung thực.
2. Nhóm 05 từng thêm `S99` hàng loạt, sau đó thay bằng `S1` trên các câu
   correlation/scanner template. Cách source-dumping này bị từ chối; batch repair
   chưa được controller chấp nhận.
3. Có 161 access-date trong 06–11 và cheatsheets bị đổi cơ học sang 2026-07-18
   mà không mở lại từng nguồn. Các dòng này phải được reverify trước signoff.
4. Một writer concurrent ngoài ba phạm vi hiện tại đã sửa 10 code-pair lesson:
   `06/insecure-design`, `06/mass-assignment`, `07/csrf`, `07/email-spoofing`,
   `07/password-mismanagement`, `07/session-fixation`, `07/user-enumeration`,
   `07/weak-session-ids`, `09/logging-and-monitoring`, `10/xml-bombs`. Mọi thay
   đổi này phải được review như input không tin cậy.
5. Behavior-controller đã dừng do lỗi policy sau khi ghi các phát hiện trên;
   không được coi auxiliary gate PASS là verdict thay thế.

## Gate và runtime evidence gần nhất

- PR structural validator: PASS trước batch repair hiện tại; phải chạy lại sau
  khi worktree ổn định.
- Duplicate-prose gate mới: 21 nhóm paragraph lặp vượt ngưỡng; FAIL.
- Python payload harness: 3/3 PASS cho HTTP framing, JWT `alg=none` fixture và
  XML entity fixture có giới hạn.
- Playwright local harness: 5/5 PASS, gồm CORS/CSRF/CSP, payload DOM XSS và form
  CSRF `text/plain` trên loopback fixture.
- Payload safety/Markdown/code-comment/training-endpoint gate được agent 05 báo
  PASS, nhưng phải được root chạy lại trước bàn giao.

## Blocker còn lại

- Nội dung lặp/generic và evidence theo claim chưa hoàn tất trên đủ 77 lesson.
- 06–11 và 15 cheatsheet chưa qua implementer + review độc lập hoàn chỉnh.
- Audit artifacts cần regenerate sau khi agent dừng ghi file.
- Baseline license vẫn `pending-owner-decision`.
- Chưa có technical review và language review độc lập trên đúng 77 lesson và
  15 cheatsheet.
