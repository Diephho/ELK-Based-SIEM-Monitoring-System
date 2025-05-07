# Deployment Guide

Hướng dẫn triển khai giải pháp SIEM dựa trên ELK Stack kết hợp pfSense, Snort, ModSecurity và Windows Client.

---

## 1. Giới thiệu

Mục tiêu tài liệu này là cung cấp các bước chi tiết để cài đặt và cấu hình ELK Stack (Elasticsearch, Logstash, Kibana) cùng các thành phần thu thập log:
- **pfSense Firewall**
- **Snort IDS**
- **ModSecurity WAF** trên Web Server
- **Windows Client** với Winlogbeat

Sau khi hoàn thành, hệ thống sẽ thu thập, parse, lưu trữ và trực quan hóa log, đồng thời thiết lập cảnh báo theo rule.

---

## 2. Yêu cầu cơ bản
- Hệ điều hành: Ubuntu 20.04 LTS (hoặc bản tương tự)
- Đủ tài nguyên: 4 CPU, 8 GB RAM, 50 GB ổ đĩa   

---

## 3. Chuẩn bị môi trường

### 3.1 Cập nhật hệ thống
```bash
sudo apt update && sudo apt upgrade -y
```

### 3.2 Cài đặt Java
```bash
sudo apt install openjdk-11-jdk -y
java -version
```

## 4. Triển khai ELK Stack

### 4.1 Elasticsearch
```bash
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.0-amd64.deb
sudo dpkg -i elasticsearch-7.17.0-amd64.deb
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
```
- File cấu hình nằm ở `/etc/elasticsearch/elasticsearch.yml`

### 4.2 Logstash
```bash
wget https://artifacts.elastic.co/downloads/logstash/logstash-7.17.0.deb
sudo dpkg -i logstash-7.17.0.deb
sudo systemctl enable logstash.service
```
- Tạo file pipeline: `/etc/logstash/conf.d/logstash.conf` (tham khảo `[configs/logstash/logstash.conf](configs/logstash/logstash.conf)`
- Khởi động Logstash:
```bash
sudo systemctl start logstash.service
```

### 4.3 Kibana
```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.17.0-amd64.deb
sudo dpkg -i kibana-7.17.0-amd64.deb
sudo systemctl enable kibana.service
sudo systemctl start kibana.service
```
- File cấu hình nằm ở `/etc/kibana/kibana.yml`

## 5. Cấu hình thu thập log

### 5.1 pfSense
- Vào **Status --> System Logs --> Settings**
- Đặt:
  - Remote Logging Server: `<Logstash-IP>:<port input Logstash>`
  - Chọn các facility cần gửi
### 5.2 Snort
- Cài đặt Snort host-based:
```bash
sudo apt install snort -y
```
- Chỉnh `/etc/snort/snort.conf` để xuất JSON hoặc sử dụng các json có sẵn:
```conf
output alert_json: /var/log/snort/alert.json
```
- Dùng Filebeat để forward `alert.json` về Logstash

### 5.3 ModSecurity (Web Server)

- Hướng dẫn cài đặt, tham khảo: https://github.com/khangtictoc/DVWA_ModSecurity_Deployment
- Trong `modsecurity.conf`:
```bash
SecAuditEngine On
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.log
```
- Dùng Filebeat hoặc syslog forward log audit

### 5.4 Windows Client

- Cài **Winlogbeat** (cần cài đặt cùng version với Logstash)
- Chỉnh `winlogbeat.yml` để gửi đến Logstash.
- Cài và chạy dịch vụ
```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

### 5.5 ELK Stack

- Tham khảo các file cáu hình:
  - [elasticsearch.yml](configs/elasticsearch/elasticsearch.yml)
  - [logstash.yml](configs/logstash/logstash.yml)
  - [kibana.yml](configs/kibana/kibana.yml)
- Để hiển thị Index Pattern lên Kibana Discover, vào Home > Management > Stack Management > Add Index Pattern, nhập Index Pattern muốn hiển thị, nếu có nó sẽ xuất hiện, chọn trường @timestamp.

### 5.6 Filebeat

- Cài Filebeat trên Linux (Ví dụ máy ELK, máy Ubuntu Snort, máy Ubuntu Web Server...)
```bash
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.0-amd64.deb
sudo dpkg -i filebeat-7.17.0-amd64.deb
sudo systemctl enable filebeat
```

- Cấu hình `filebeat.yml`: [filebeat.yml](configs/filebeat/filebeat.yml)

- Khởi động Filebeat:
```bash
sudo systemctl start filebeat
```

## 6 Kiểm thử cơ bản
- Gửi log mẫu (ping, web request, tấn công thử)
- Mở **Kibana --> Discover**, kiếm tra các index pattern (pfsense-*, snort-*, modsec-*, winlog-*)
- Thử truy vấn KQL, ví dụ: `event.dataset: "snort.alert"`

## 7 Thiết lập cảnh báo & Rules

- Snort: thêm rule vào `snort.rules`
- Elastic Security: Tạo alert thông qua KDL pattern, nếu log xuất hiện giống với rule đã tạo, nó sẽ được lưu trữ riêng và phát cảnh báo
