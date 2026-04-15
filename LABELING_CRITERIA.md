# 🏷️ TIÊU CHÍ GẮN NHÃN SAFE/UNSAFE - Advanced SIEM Dataset

## 📋 Tổng Quan

File `advanced_siem_dataset_with_labels.csv` chứa nhãn (label) phân loại các phiên mạng thành **SAFE (0)** hoặc **UNSAFE (1)** dựa trên các tiêu chí bảo mật xác định.

- **SAFE (0)**: Phiên hoạt động bình thường, không có dấu hiệu rủi ro
- **UNSAFE (1)**: Phiên có yếu tố rủi ro cao, có khả năng bị tấn công hoặc rò rỉ dữ liệu

---

## ⏱️ Duration (seconds)

**Giải thích về đơn vị và số thập phân:**

- **Đơn vị:** Giây (seconds) - đơn vị chuẩn để đo thời lượng phiên kết nối trong hệ thống SIEM.
- **Số thập phân:** Duration được biểu diễn dưới dạng số thập phân để đảm bảo độ chính xác cao, vì thời gian gốc từ log hệ thống thường được ghi bằng mili giây (ms) hoặc micro giây (μs).
- **Quy đổi đơn vị:**
  - Từ mili giây (ms) sang giây: `duration_seconds = duration_ms / 1000`
  - Từ micro giây (μs) sang giây: `duration_seconds = duration_μs / 1,000,000`
- **Ví dụ:**
  - Thời gian gốc: 1500 ms → Duration: 1.5 giây 
  - Thời gian gốc: 2,500,000 μs → Duration: 2.5 giây
- **Lý do sử dụng số thập phân:** Trong phân tích bảo mật, thời gian chính xác đến phần trăm giây giúp phát hiện các phiên kết nối bất thường, như các cuộc tấn công nhanh hoặc rò rỉ dữ liệu chậm nhưng kéo dài.

---

## 🔍 CÁC TIÊU CHÍ GẮN NHÃN

### Tiêu Chí 1: Thời Lượng + Lượng Dữ Liệu (Duration × Bytes)
```
Điều kiện: duration > 10 AND bytes > 500.000
Nhãn: UNSAFE (1)
```

**Giải thích:**
- **Duration > 10 giây**: Phiên kết nối lâu bất thường (điều chỉnh cho phù hợp với test cases thực tế)
- **Bytes > 500.000**: Lượng dữ liệu transfer lớn
- **Kết hợp cả hai**: Cảnh báo về khả năng rò rỉ dữ liệu hoặc đang bực chặn dữ liệu từ máy chủ

**Ví dụ:**
- ✅ SAFE: duration=5, bytes=300.000
- ❌ UNSAFE: duration=15, bytes=600.000
- ❌ UNSAFE: duration=20, bytes=1.000.000

---

### Tiêu Chí 2: Loại Sự Kiện (Event Type)
```
Điều kiện: event_type IN ['network', 'process', 'access', 'login']
Nhãn: UNSAFE (1)
```

**Giải thích:**
Các loại sự kiện sau được coi là nguy hiểm vì liên quan đến hành động đe dọa:

| Event Type | Nguy Hiểm | Lý Do |
|-----------|----------|------|
| **network** | 🔴 Rất cao | Mạng bất thường, có thể DDoS, port scan, hoặc data exfiltration |
| **process** | 🔴 Rất cao | Tiến trình nghi ngờ, malware, hoặc privilege escalation |
| **access** | 🟠 Cao | Truy cập file/tài nguyên bất hợp pháp |
| **login** | 🟠 Cao | Đăng nhập bất thường, có thể là brute force hoặc account takeover |

**Ví dụ:**
- ✅ SAFE: event_type='device_change'
- ❌ UNSAFE: event_type='network'
- ❌ UNSAFE: event_type='login'

---

### Tiêu Chí 3: Cổng Nhạy Cảm (Sensitive Ports)
```
Điều kiện: src_port IN [22, 23, 3389, 445] OR dst_port IN [22, 23, 3389, 445]
Nhãn: UNSAFE (1)
```

**Giải thích:**
Các cổng sau là mục tiêu tấn công chính:

| Cổng | Dịch Vụ | Nguy Hiểm | Ghi Chú |
|------|---------|----------|--------|
| **22** | SSH | 🔴 Rất cao | Được tấn công brute force, remote code execution |
| **23** | Telnet | 🔴 Rất cao | Lỗi thời nhưng vẫn được sử dụng, truyền mật khẩu clear text |
| **3389** | RDP | 🔴 Rất cao | Mục tiêu yêu thích của ransomware, lateral movement |
| **445** | SMB | 🔴 Rất cao | EternalBlue, WannaCry, chia sẻ file bất hợp pháp |

**Ví dụ:**
- ✅ SAFE: src_port=50000, dst_port=443 (HTTPS)
- ❌ UNSAFE: dst_port=22 (SSH)
- ❌ UNSAFE: src_port=445 (SMB)

---

### Tiêu Chí 4: Đăng nhập Qua Cổng Nhạy Cảm (Login + Sensitive Port)
```
Điều kiện: event_type = 'login' AND (src_port IN [22,23,3389,445] OR dst_port IN [22,23,3389,445])
Nhãn: UNSAFE (1)
```

**Giải thích:**
Kết hợp của sự kiện đăng nhập + cổng nhạy cảm là **dấu hiệu cảnh báo cao nhất**:
- Cố gắng đăng nhập từ xa qua SSH (port 22)
- Đăng nhập RDP bất thường (port 3389)
- Kết nối SMB/Telnet bất hợp pháp

**Ví dụ:**
- ✅ SAFE: event_type='login', dst_port=80
- ❌ UNSAFE: event_type='login', dst_port=22
- ❌ UNSAFE: event_type='login', src_port=3389

---

### Tiêu Chí 5: Dịch Vụ Đám Mây Không Xác Định (Unknown Cloud Service)
```
Điều kiện: event_type = 'unknown_cloud_service'
Nhãn: UNSAFE (1)
```

**Giải thích:**
- **Dựa trên:** Các best practices trong cloud security từ các framework như NIST Cybersecurity Framework, CIS Controls, và AWS/Azure security guidelines. Các dịch vụ đám mây không được phê duyệt hoặc không xác định (unknown) thường là dấu hiệu của "shadow IT" hoặc truy cập trái phép.
- **Lý do nguy hiểm:** 
  - **Shadow IT:** Nhân viên sử dụng dịch vụ đám mây không được tổ chức phê duyệt, dẫn đến rủi ro bảo mật như thiếu giám sát, không tuân thủ chính sách, và dễ bị tấn công.
  - **Truy cập trái phép:** Attacker có thể sử dụng dịch vụ đám mây không xác định để exfiltrate dữ liệu, inject malware, hoặc thực hiện lateral movement.
  - **Vi phạm compliance:** Không tuân thủ các quy định như GDPR, HIPAA, dẫn đến phạt và rủi ro pháp lý.
- **Ví dụ thực tế:** Trong SIEM logs, nếu có kết nối đến một IP hoặc domain đám mây không nằm trong whitelist (ví dụ, unknown AWS S3 bucket hoặc Google Cloud service), đây là cảnh báo cao.

**Ví dụ:**
- ✅ SAFE: event_type='cloud_access' (dịch vụ đã phê duyệt)
- ❌ UNSAFE: event_type='unknown_cloud_service'

---

## 📊 QUY TẮC KẾT HỢP

### Phân Loại UNSAFE
Một phiên được gắn nhãn **UNSAFE (1)** nếu **MỘT TRONG CÁC** điều kiện sau đúng:

```
UNSAFE = Điều kiện 1 OR Điều kiện 2 OR Điều kiện 3 OR Điều kiện 4 OR Điều kiện 5
```

### Phân Loại SAFE
Một phiên được gắn nhãn **SAFE (0)** nếu **KHÔNG CÓ** các điều kiện UNSAFE nào đúng

**Ví dụ:**
- ✅ SAFE: access event, duration=1000, bytes=50.000, user=admin, dst_port=443
- ❌ UNSAFE: network event (thoả tiêu chí 2)
- ❌ UNSAFE: login event + dst_port=22 (thoả tiêu chí 4)
- ❌ UNSAFE: duration=3000 + bytes=600.000 (thoả tiêu chí 1)

---

## 🔐 MỨC ĐỘ NGUY HIỂM

### Mức 1 - SAFE (Xanh)
- Không có dấu hiệu rủi ro
- Hoạt động bình thường
- Cần thiết nhưng ít nguy hiểm

**Đặc điểm:**
- Event type: device_change, resource_access
- Duration < 2500 giây
- Bytes < 500.000
- Không dùng cổng nhạy cảm

### Mức 2 - UNSAFE (Đỏ)
- Có dấu hiệu rủi ro
- Cần xem xét kỹ lưỡng
- Có thể là tấn công

**Đặc điểm:**
- Event type: network, process, access, login
- Duration > 2500 + bytes > 500.000
- Dùng cổng 22, 23, 3389, 445
- Login qua cổng nhạy cảm

---

## 💡 VÍ DỤ CHI TIẾT

### Ví Dụ 1: SAFE - Truy cập file bình thường
```
event_type: access
duration: 1200 (< 2500)
bytes: 100.000 (< 500.000)
src_port: 50000
dst_port: 443 (HTTPS - an toàn)
user: user1
label: 0 ✅
```
**Lý do SAFE:** Không thoả bất kỳ tiêu chí UNSAFE nào

---

### Ví Dụ 2: UNSAFE - Mạng bất thường với tải dữ liệu lớn
```
event_type: network ❌ (Tiêu chí 2)
duration: 3000 (> 2500) ⚠️
bytes: 600.000 (> 500.000) ⚠️
src_port: 50000
dst_port: 443
user: unknown
label: 1 🚨
```
**Lý do UNSAFE:**
- Thoả tiêu chí 2: event_type='network'
- Thoả tiêu chí 1: duration > 2500 AND bytes > 500.000 (kết hợp)

---

### Ví Dụ 3: UNSAFE - Đăng nhập qua SSH
```
event_type: login ❌ (Tiêu chí 4)
duration: 150
bytes: 5.000
src_port: 40000
dst_port: 22 ❌ (SSH - cổng nhạy cảm)
user: admin
label: 1 🚨
```
**Lý do UNSAFE:**
- Thoả tiêu chí 4: event_type='login' AND dst_port=22 (cổng nhạy cảm)
- Thoả tiêu chí 3: dst_port=22 (cổng nhạy cảm)

---

### Ví Dụ 4: UNSAFE - Truy cập qua RDP
```
event_type: access
duration: 800
bytes: 200.000
src_port: 45000
dst_port: 3389 ❌ (RDP - cổng nhạy cảm)
user: admin
label: 1 🚨
```
**Lý do UNSAFE:**
- Thoả tiêu chí 3: dst_port=3389 (cổng nhạy cảm)

---

## 🎯 MÔ HÌNH HÓA TẬP HỢP

```
┌────────────────────────────────────────────────────┐
│              TỔNG THỂ DỮ LIỆU                      │
└────────────────────────────────────────────────────┘
         ⬇️
         ┌─────────────────────────┐
         │   Tất cả sự kiện        │
         │   (advanced_siem_      │
         │   dataset.csv)          │
         └─────────────────────────┘
                 ⬇️

    ┌──────────────────────────────────────────┐
    │  Áp dụng 4 tiêu chí gắn nhãn            │
    └──────────────────────────────────────────┘
         ⬇️                         ⬇️
    ┌──────────────────┐    ┌──────────────────┐
    │  UNSAFE (Label=1)│    │  SAFE (Label=0)  │
    │  - Event: unsafe │    │  - Event: safe   │
    │  - Port: risky   │    │  - Port: normal  │
    │  - Combo: bad    │    │  - Combo: clean  │
    └──────────────────┘    └──────────────────┘
```

---

## 📈 PHÂN TÍCH PHÂN PHỐI NHÃN

Trong file `advanced_siem_dataset_with_labels.csv`:

```
Label Distribution (Ví dụ):
- SAFE (0): 7,500 mẫu (75%)
- UNSAFE (1): 2,500 mẫu (25%)
```

**Nhận xét:**
- ✅ Dữ liệu không quá không cân bằng
- ✅ Đủ mẫu UNSAFE để model học
- ⚠️ Nhiều SAFE hơn UNSAFE (trong thực tế cũng vậy)

---

## 🛡️ ỨNG DỤNG TRONG THỰC TẾ

### 1. Phát Hiện Tấn Công
- **Network events**: Có thể là port scan, DDoS, botnet
- **Process events**: Có thể là malware, lateral movement
- **SSH access**: Brute force attack, exploitation

### 2. Điều Tra Sự Cố
- Khi có cảnh báo UNSAFE, kiểm tra:
  - Ai (user)?
  - Từ đâu (src_ip)?
  - Đến đâu (dst_ip)?
  - Làm gì (action)?

### 3. Đòi Hỏi Chính Sách
- Chặn login SSH từ ngoài
- Giới hạn tải dữ liệu lớn
- Whitelist cổng cho phép

---

## 📝 CÔNG THỨC TOÁN HỌC

```
UNSAFE = Condition1 ∨ Condition2 ∨ Condition3 ∨ Condition4

WHERE:
  Condition1 = (duration > 2500) ∧ (bytes > 500,000)
  Condition2 = event_type ∈ {network, process, access, login}
  Condition3 = (src_port ∈ {22,23,3389,445}) ∨ (dst_port ∈ {22,23,3389,445})
  Condition4 = (event_type = 'login') ∧ ((src_port ∈ {22,23,3389,445}) ∨ (dst_port ∈ {22,23,3389,445}))

SAFE = ¬UNSAFE
```

---

## ✅ CHECKLIST GẮN NHÃN

Khi muốn xác định một phiên, hãy kiểm tra theo thứ tự:

- [ ] **Event type có phải network/process/access/login không?** 
  - Yes → **UNSAFE** ✋
  - No → Tiếp tục

- [ ] **Duration > 2500 VÀ bytes > 500.000?**
  - Yes → **UNSAFE** ✋
  - No → Tiếp tục

- [ ] **Port dùng 22, 23, 3389, 445?**
  - Yes → **UNSAFE** ✋
  - No → Tiếp tục

- [ ] **Login event QUA cổng nhạy cảm (22/23/3389/445)?**
  - Yes → **UNSAFE** ✋
  - No → Tiếp tục

- [ ] Không thoả bất kỳ tiêu chí nào?
  - → **SAFE** ✅

---

## 🔗 LIÊN KẾT TỆPROGRAM

- **add_labels.py**: Script tự động gắn nhãn
- **huong_dan_saf_unsafe.md**: Hướng dẫn tạo test case
- **test_cases_detailed.md**: Ví dụ cụ thể chi tiết
- **advanced_siem_dataset_with_labels.csv**: Dữ liệu đã gắn nhãn

---

## 📚 THAM KHẢO

[OWASP - Common Ports](https://owasp.org/www-community/attacks/Port_scanning)
[NIST - Security Events](https://nvlpubs.nist.gov/)
[CIS Benchmark - Security Baselines](https://www.cisecurity.org/)

---

**Cập nhật lần cuối:** 09/04/2026
**Phiên bản:** 1.0
