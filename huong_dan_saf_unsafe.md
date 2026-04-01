# Hướng dẫn tạo trường hợp SAFE và UNSAFE cho SIEM AI

## 1. Giới thiệu tổng quan
Mục tiêu: xây dựng bộ test rõ ràng để đánh giá mô hình phát hiện "phiên không an toàn" (unsafe session) trong hệ thống SIEM. 

- SAFE: phiên hoạt động bình thường, không có dấu hiệu bất thường
- UNSAFE: phiên có một hoặc nhiều yếu tố rủi ro cao như kết nối tới cổng nhạy cảm, dữ liệu tải lớn, thời gian dài, hành vi login bất thường.

## 2. Các thành phần chính cần lưu ý

1. `event_type`:
   - Mô tả loại sự kiện (login, access, network, process, ...).
   - SAFE nếu kiểu sự kiện mang tính bình thường như `device_change`, `resource_access`.
   - UNSAFE nếu là `network`, `process`, `access`, `login` (những loại này dễ liên quan truy cập tài nguyên nhạy cảm, mã độc, tấn công).

2. `duration` (thời lượng phiên):
   - Phản ánh thời gian kết nối truy vấn.
   - SAFE khi < 2500s.
   - UNSAFE khi > 2500s (protocol, exfiltration, lạm dụng cố định lâu dài).

3. `bytes` (lượng dữ liệu chuyển):
   - SAFE khi < 500000 (hoạt động bình thường).
   - UNSAFE khi > 500000 (dữ liệu lớn tiềm ẩn rò rỉ).

4. `src_port` / `dst_port`:
   - Các cổng nhạy cảm: 22, 23, 3389, 445.
   - Chọn cổng đó thì khả năng high-risk (SSH/RDP/Telnet/SMB) => UNSAFE.

5. `user`:
   - `unknown`, `service_account` tăng rủi ro vì không chắc danh tính.
   - Người dùng định danh tốt như `admin`/`user1` vẫn cần quan sát nếu có pattern bất thường.

## 3. Quy tắc kết hợp để tạo trường hợp

### SAFE
- `event_type` không thuộc nhóm rủi ro (e.g. `device_change`)
- `duration` và `bytes` đều nhỏ
- cổng không nhạy cảm
- user có nguồn gốc rõ ràng

### UNSAFE
- ít nhất một trong bộ điều kiện sau:
  - `duration > 2500` và `bytes > 500000` (exfiltration/long-run)
  - `event_type` in [network, process, access, login]
  - `src_port` hoặc `dst_port` trong [22, 23, 3389, 445]
  - `event_type == login` + port nhạy cảm

## 4. Ý nghĩa của các quan hệ giữa phần tử
- `event_type` + `port` có thể biểu thị cuộc tấn công truy cập từ xa: nếu login qua 22/3389 thì rất nguy hiểm.
- `duration` x `bytes`: phiên dài + lượng dữ liệu lớn thường là dấu hiệu exfiltration (rò rỉ dữ liệu) hoặc người dùng bị điều khiển.
- `user` + `source`: nếu nguồn là `network_logs` + `user=unknown` dễ liên tưởng truy cập bất thường.

Khi nhiều yếu tố kết hợp:
- Giảm false-negative (tăng độ nhạy): nếu bạn có 1 yếu tố nhỏ, vẫn có thể gọi unsafe khi có thêm yếu tố khác.
- Giảm false-positive: cần giữ safe khi không có yếu tố rủi ro mới.

## 5. Cách tạo test case mẫu

### Safe mẫu
1) event_type=access, duration=1200, bytes=100000, src_port=50000, dst_port=443, user=user1
2) event_type=device_change, duration=900, bytes=120000, src_port=56000, dst_port=80

### Unsafe mẫu
1) event_type=network, duration=3000, bytes=600000, dst_port=443
2) event_type=login, src_port=40000, dst_port=22, duration=1000, bytes=200000

## 6. Kết luận
- SAFE/UNSAFE được xác định bằng tích hợp các chỉ số: hành vi, thời lượng, lưu lượng, cổng mạng.
- Khi thiết kế bộ test, hãy cân nhắc cả điều kiện đơn lẻ và multi-factor để phản ánh kịch bản tấn công thực tế.
- Luôn đánh giá thêm lý do (`Why this classification`) để giải thích rõ ràng từng yếu tố đã kích hoạt cảnh báo.
