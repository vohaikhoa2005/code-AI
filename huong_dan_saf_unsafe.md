# Hướng Dẫn Dễ Hiểu: Tạo Trường Hợp SAFE và UNSAFE Cho SIEM AI

## Mục Tiêu
Chúng ta cần tạo bộ dữ liệu test để kiểm tra mô hình AI phát hiện "phiên không an toàn" (unsafe session) trong hệ thống SIEM.

- **SAFE**: Phiên hoạt động bình thường, không có dấu hiệu lạ.
- **UNSAFE**: Phiên có yếu tố rủi ro cao, như kết nối cổng nhạy cảm, tải dữ liệu lớn, thời gian dài, hoặc hành vi login bất thường.

## Các Yếu Tố Chính Để Xem Xét

### 1. Loại Sự Kiện (event_type)
- **SAFE**: Sự kiện bình thường như `device_change` (thay đổi thiết bị) hoặc `resource_access` (truy cập tài nguyên).
- **UNSAFE**: Sự kiện dễ liên quan rủi ro như `network` (mạng), `process` (tiến trình), `access` (truy cập), `login` (đăng nhập).

### 2. Thời Lượng Phiên (duration)
- **SAFE**: Dưới 2500 giây (khoảng 40 phút).
- **UNSAFE**: Trên 2500 giây (có thể là kết nối lâu để tải dữ liệu hoặc tấn công).

### 3. Lượng Dữ Liệu Chuyển (bytes)
- **SAFE**: Dưới 500.000 bytes (hoạt động bình thường).
- **UNSAFE**: Trên 500.000 bytes (có thể rò rỉ dữ liệu).

### 4. Cổng Nguồn/Người Nhận (src_port / dst_port)
- Cổng nhạy cảm: 22 (SSH), 23 (Telnet), 3389 (RDP), 445 (SMB).
- **SAFE**: Không dùng cổng nhạy cảm.
- **UNSAFE**: Dùng cổng nhạy cảm (dễ bị tấn công từ xa).

### 5. Người Dùng (user)
- **SAFE**: Người dùng rõ ràng như `admin` hoặc `user1`.
- **UNSAFE**: Người dùng không rõ như `unknown` hoặc `service_account` (có thể giả mạo).

## Quy Tắc Kết Hợp Để Phân Loại

### Trường Hợp SAFE
- Loại sự kiện không rủi ro.
- Thời lượng và dữ liệu nhỏ.
- Không dùng cổng nhạy cảm.
- Người dùng rõ ràng.

### Trường Hợp UNSAFE
- Ít nhất một yếu tố sau:
  - Thời lượng > 2500 VÀ dữ liệu > 500.000 (kết nối lâu + tải lớn).
  - Loại sự kiện là network, process, access, hoặc login.
  - Cổng nguồn hoặc đích là 22, 23, 3389, hoặc 445.
  - Sự kiện login VÀ dùng cổng nhạy cảm.

## Ví Dụ Mẫu

### Ví Dụ SAFE
1. event_type=access, duration=1200, bytes=100000, src_port=50000, dst_port=443, user=user1  
   *(Truy cập bình thường, thời gian ngắn, dữ liệu ít, cổng không nhạy cảm.)*

2. event_type=device_change, duration=900, bytes=120000, src_port=56000, dst_port=80, user=admin  
   *(Thay đổi thiết bị, ngắn gọn.)*

### Ví Dụ UNSAFE
1. event_type=network, duration=3000, bytes=600000, dst_port=443  
   *(Mạng, lâu, tải nhiều.)*

2. event_type=login, src_port=40000, dst_port=22, duration=1000, bytes=200000  
   *(Đăng nhập qua SSH, cổng nhạy cảm.)*

## Ý Nghĩa Khi Kết Hợp Yếu Tố
- **Loại sự kiện + Cổng**: Đăng nhập qua cổng nhạy cảm rất nguy hiểm (tấn công từ xa).
- **Thời lượng + Dữ liệu**: Phiên lâu + tải lớn có thể là rò rỉ dữ liệu hoặc bị hack.
- **Người dùng + Nguồn**: Nếu nguồn là `network_logs` và user `unknown`, có thể truy cập bất hợp pháp.

Khi nhiều yếu tố cùng xuất hiện:
- Giảm bỏ sót (false-negative): Nếu có 1 yếu tố nhỏ, vẫn coi unsafe nếu có thêm yếu tố khác.
- Giảm báo sai (false-positive): Chỉ coi safe khi thực sự không có rủi ro.

## Kết Luận
- SAFE/UNSAFE dựa trên sự kết hợp của hành vi, thời gian, dữ liệu, cổng, và người dùng.
- Khi tạo bộ test, cân nhắc cả yếu tố đơn lẻ và kết hợp để mô phỏng tấn công thực tế.
- Luôn giải thích lý do phân loại (ví dụ: "Tại sao unsafe? Vì dùng cổng 22 và thời lượng dài.") để dễ hiểu và cải thiện mô hình.
