# Chính sách sử dụng có ủy quyền

Nội dung và payload chỉ dành cho:

- hệ thống do người học sở hữu;
- lab local/disposable;
- CTF/sandbox được phép;
- hệ thống có văn bản ủy quyền và phạm vi kiểm thử rõ ràng.

Không dùng repository để truy cập trái phép, làm gián đoạn dịch vụ, thu thập dữ liệu thật, né kiểm soát ngoài phạm vi hoặc gửi callback đến hạ tầng bên thứ ba.

## Quy tắc lab

- Dùng dữ liệu giả, snapshot có thể phục hồi và network egress mặc định bị chặn.
- Payload `destructive`, `dos` hoặc `oob` phải chạy trong container có timeout, CPU/memory cap; OOB dùng callback local.
- Không copy secret, credential, target, log khách hàng hoặc artefact engagement vào bài học/evidence.
- Dừng test nếu quan sát thấy tác động ngoài fixture dự kiến.
- Cleanup state, callback, file và container sau mỗi lượt.

Ủy quyền là điều kiện bắt buộc; cảnh báo trong repository không thay thế pháp luật, hợp đồng hoặc rules of engagement.

