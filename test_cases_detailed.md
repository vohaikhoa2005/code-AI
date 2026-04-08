# Ví Dụ Chi Tiết Để Test SAFE và UNSAFE

Dưới đây là một số trường hợp mẫu với giá trị cụ thể cho từng cột (ô) trong dataset.
Bạn có thể copy-paste vào CSV hoặc dùng để test model.

## SAFE Cases (Label = 0)

### SAFE Case 1: Truy cập bình thường
- event_type: access
- source: web_server
- user: user1
- action: read
- object: file.txt
- process_id: 1234
- parent_process: explorer.exe
- device_type: laptop
- device_id: LAP001
- firmware_version: 1.0.0
- src_ip: 192.168.1.10
- dst_ip: 10.0.0.1
- cloud_service: aws
- resource_id: s3-bucket-1
- protocol: http
- method: GET
- mac_address: 00:11:22:33:44:55
- duration: 1200
- bytes: 100000
- src_port: 50000
- dst_port: 443
- label: 0

### SAFE Case 2: Đăng nhập hợp lệ
- event_type: login
- source: application
- user: admin
- action: authenticate
- object: user_session
- process_id: 5678
- parent_process: svchost.exe
- device_type: desktop
- device_id: DESK002
- firmware_version: 2.1.0
- src_ip: 192.168.1.20
- dst_ip: 10.0.0.2
- cloud_service: azure
- resource_id: vm-instance-1
- protocol: tcp
- method: POST
- mac_address: 11:22:33:44:55:66
- duration: 500
- bytes: 50000
- src_port: 40000
- dst_port: 80
- label: 0

### SAFE Case 3: Giám sát thiết bị
- event_type: device_change
- source: monitoring
- user: system
- action: update
- object: firmware
- process_id: 9999
- parent_process: system
- device_type: iot
- device_id: IOT003
- firmware_version: 3.0.1
- src_ip: 192.168.1.30
- dst_ip: 10.0.0.3
- cloud_service: gcp
- resource_id: iot-device-1
- protocol: udp
- method: PUT
- mac_address: 22:33:44:55:66:77
- duration: 300
- bytes: 20000
- src_port: 60000
- dst_port: 53
- label: 0

## UNSAFE Cases (Label = 1)

### UNSAFE Case 1: Mạng bất thường + dữ liệu lớn
- event_type: network
- source: firewall
- user: unknown
- action: block
- object: suspicious_traffic
- process_id: 1111
- parent_process: unknown
- device_type: server
- device_id: SRV001
- firmware_version: 1.5.0
- src_ip: 192.168.1.100
- dst_ip: 10.0.0.10
- cloud_service: unknown
- resource_id: unknown
- protocol: tcp
- method: unknown
- mac_address: 33:44:55:66:77:88
- duration: 3000
- bytes: 600000
- src_port: 50000
- dst_port: 443
- label: 1

### UNSAFE Case 2: Đăng nhập qua SSH nhạy cảm
- event_type: login
- source: ssh_server
- user: hacker
- action: brute_force
- object: root_access
- process_id: 2222
- parent_process: sshd
- device_type: server
- device_id: SRV002
- firmware_version: 2.0.0
- src_ip: 192.168.1.200
- dst_ip: 10.0.0.20
- cloud_service: unknown
- resource_id: unknown
- protocol: tcp
- method: CONNECT
- mac_address: 44:55:66:77:88:99
- duration: 1500
- bytes: 100000
- src_port: 40000
- dst_port: 22
- label: 1

### UNSAFE Case 3: Quá trình nghi ngờ + cổng nhạy cảm
- event_type: process
- source: endpoint
- user: service_account
- action: execute
- object: malware.exe
- process_id: 3333
- parent_process: cmd.exe
- device_type: workstation
- device_id: WS001
- firmware_version: 1.2.0
- src_ip: 192.168.1.50
- dst_ip: 10.0.0.5
- cloud_service: unknown
- resource_id: unknown
- protocol: tcp
- method: EXEC
- mac_address: 55:66:77:88:99:AA
- duration: 2500
- bytes: 500000
- src_port: 30000
- dst_port: 445
- label: 1

## Cách Sử Dụng
- Copy từng case vào file CSV hoặc dùng để test predict_sample().
- Model sẽ học pattern từ các cột này (không dùng duration/bytes/src_port/dst_port/event_type trực tiếp như rule).
- Nếu cần thêm case, cho tôi biết!