# Deployment Guide

Hướng dẫn triển khai giải pháp SIEM dựa trên ELK Stack kết hợp pfSense, Snort, ModSecurity và Windows Client.
Mở rộng triển khai phản hồi qua TheHive + Cortex 

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
- Mở **Kibana --> Discover**, kiếm tra các index pattern (`pfsense-*`, `snort-*`, `modsec-*`, `winlog-*`)
- Thử truy vấn KQL, ví dụ: `event.dataset: "snort.alert"`

## 7 Thiết lập cảnh báo & Rules

- Snort: thêm rule vào `snort.rules`
- Elastic Security: Tạo alert thông qua KDL pattern, nếu log xuất hiện giống với rule đã tạo, nó sẽ được lưu trữ riêng và phát cảnh báo

## 8 Tích hợp phản hồi tự động (TheHive + Cortex + ElastAlert)

Hệ thống được mở rộng với khả năng phân tích và phản hồi các cảnh báo bằng Thehive và Cortex:
- **ElastAlert**: theo dõi các log trong Elasticsearch và gửi alert đến TheHive.
Note: Có thể sử dụng trực tiếp tính năng **Elastic Security** trên ELK (truy cập trên giao diện Kibana để tạo ra các rule, cấu hình Connectors... để gửi alert đến TheHive). Tuy nhiên, phần Connectors yêu cầu License, có thể request để lấy Trial License và làm trực tiếp trên này nhé. Ở đây mình sẽ hướng dẫn đối với trường hợp không dùng các License bằng cách thay thế bằng ElastAlert.
- **TheHive:** quản lý cảnh báo (alert), tạo các case management, điều tra sự cố (case), điều phối hoạt động phản hồi.
- **Cortex:** thực thi các analyzer (phân tích) và responder (phản hồi) như truy vấn IP với VirusTotal hoặc chặn IP bằng pfSense.

### 8.1 Cài đặt ElastAlert 2

[Github/ElastAlert2](https://github.com/jertel/elastalert2)

```bash
git clone https://github.com/jertel/elastalert2.git
cd elastalert2
pip3 install -r requirements.txt
cp config.yaml.example config.yaml
```

Cấu hình `config.yaml`

Tạo thư mục `rules/` và một file rule mẫu [modsec_sqli_xss_alert.yaml](detection_rules/elastalert/sqli_xss_rule.yaml)

```yaml
name: Detect SQLi and XSS Attacks from ModSecurity
type: any

index: modsec-logs-*

filter:
  - query:
      query_string:
        query: >
          message:("SELECT" AND "FROM") OR
          message:("UNION SELECT") OR
          message:("<script>") OR
          message:(" OR " AND "1=1") OR
          message:("XSS") OR
          message:("SQL Injection") OR
          modsec_fields.msg:("SQL Injection" OR "XSS")

alert: hivealerter

hive_connection:
  hive_host: http://192.168.142.129
  hive_port: 9000
  hive_apikey: Xa5ji679eq9cAKpIHZEom/hEWN2O51dh
  hive_proxies:
    http: ''
    https: ''

hive_alert_config:
  title: 'SQLi/XSS Attack from {}'
  title_args: [ host.hostname ]
  description: '{0} : {1}'
  description_args: [ source.ip, message ]
  severity: 2
  status: 'New'
  source: 'waf-{}'
  source_args: [ host.hostname ]
  type: 'modsec-attack'
  tlp: 2
  pap: 2
  follow: True
  tags: ['modsecurity', 'waf', 'sqli', 'xss']
  customFields:
    - name: attack_type
      type: string
      value: 'SQLi/XSS'

hive_observable_data_mapping:
  - ip: source.ip
    tlp: 2
    tags: ['source-ip']
    message: 'Source IP of attacker'
  - domain: host.hostname
    tlp: 1
    tags: ['host']
    message: 'Host where WAF is running'
```

Khởi chạy ElastAlert

### 8.2 Cài đặt gói REST API cho pfSense

Truy cập vào pfsense (trực tiếp/ ssh)

```bash
pkg-static add https://github.com/jaredhendrickson13/pfsense-api/releases/download/v2.3.5/pfSense-2.7.2-pkg-RESTAPI.pkg
```

Tham khảo thêm tại: [pfrest.org](https://pfrest.org/INSTALL_AND_CONFIG/)

Sau khi cài đặt xong, pfSense webConfigurator nằm tại `System` > `REST API`

### 8.3 Cài đặt TheHive

Tham khảo hướng dẫn tại đây (file install.sh để cài đặt tự động TheHive + Cortex): https://docs.strangebee.com/cortex/installation-and-configuration/#installation-guide

Hướng dẫn cài đặt: [Step-by-Step Guide/TheHive](https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/)

Khởi chạy TheHive

```bash
sudo systemctl enable thehive
sudo systemctl start thehive
```

- Truy cập TheHive tại http://<IP>:9000
- Tạo user, API key dùng trong ElastAlert
- Cấu hình TheHive tại `/etc/thehive/application.conf`

Lưu ý: tài khoản Admin của TheHive được sử dụng để tạo user và phân quyền các tác vụ. Để có thể tạo tài khoản user để thực hiện analysis..., tham khảo phần Cortex bên dưới

### 8.4 Cài đặt Cortex

Cài đặt Cortex và các module analyzers, responders

```bash
sudo apt install cortex
cd /opt/cortex
git clone https://github.com/TheHive-Project/Cortex-Analyzers.git
cd Cortex-Analyzers
for i in analyzers/*/*/requirements.txt; do pip3 install -r $i; done
```
Trong phần `/etc/cortex/application.conf`, thêm urls:
```conf
analyzer {
  urls = ["/opt/Cortex-Analyzers/analyzers"]
}
responder {
  urls = ["/opt/Cortex-Analyzers/responders"]
}
```


Hoặc

https://docs.strangebee.com/cortex/installation-and-configuration/step-by-step-guide/#docker

Khởi động Cortex:

```bash
sudo systemctl enable cortex
sudo systemctl start cortex
```

Sau đó, để tạo User và thiết lập cortex as observer và analyzer, có thể tham khảo tại nguồn này: https://www.youtube.com/watch?v=C6tIpWSxdB0

- Truy cập: `http://<IP>:9001`
- Tạo một Organization trên Cortex > Tạo User trên Cortex > Chọn Rule cho User (read/analyzer/orgadmin) và đặt mật khẩu cho user > Tạo API Key User
- Đăng nhập vào TheHive bằng tài khoản User và enable một vài analyzer (VirusTotal)
- Tạo Connector trên TheHive: Platform Management > Connector > nhập Server url là url của Cortex > lấy API Key đã tạo của User khi nãy đưa vào trường API Key (mục đích ở đây là TheHive gọi responder thông qua User có quyền trên Cortex) > Tiến hành Test và Add this server để hoàn tất thiết lập Connector

Sau khi hoàn tất thiết lập xong, ta có thể tự tạo một Case Management và thiết lập thủ công Analyzer một số observables để kiểm tra: tạo case với IP 8.8.8.8, chọn `...` để mở rộng > chọn Run Analyzer > chọn Analyzer (ví dụ VirusTotal).

### 8.5 Tạo Custom Responder (Block IP via REST API pfSense)

a. Trên pfSense: đã cài đặt gói REST API, vì REST API của pfSense có thể xác thực thông qua Basic Auth (chuỗi "username:password" mã hóa base64) hoặc dùng "X-API-KEY: xxxxxxxxxxxxxxxx".

b. Tạo responder Block Ip via REST API pfSense

Cần 3 file:
- File json cấu trúc để Cortex có thể nhận diện được các field của responder
- File python chứa chương trình thực hiện gọi REST API để block IP.
- File Requirement.txt chứa các gói cài đặt cần thiết

Tạo trực tiếp vào /opt/Cortex-Analyzers/responders/
Cấp quyền cho file python
```bash
sudo chown -R cortex:cortex /opt/cortex/Cortex-Analyzers
sudo chmod +x /opt/cortex/Cortex-Analyzers/analyzers/*/*/*.py
```

Có thể tham khảo:

- [BlockIPOnPfsenseViaAPI.json](Cortex-Analyzers/responders/BlockIPOnPfsenseViaAPI/BlockIPOnPfSenseViaAPI.json)

- [BlockIPOnPfsenseViaAPI.py](Cortex-Analyzers/responders/BlockIPOnPfsenseViaAPI/BlockIPOnPfSenseViaAPI.py)

- [requirement.txt](Cortex-Analyzers/responders/BlockIPOnPfsenseViaAPI/requirement.txt)

### 8.6 Quá trình phân tích và chặn IP độc hại

1. ElastAlert phát hiện log tấn công dựa trên pattern, sau đó gửi về TheHive các field đã đăng ký trong rule
2. TheHive tạo case, artifact IP > chạy analyzer VirusTotal
3. Nếu IP có độ nguy hiểm cao > chạy responder chặn IP qua pfSense REST API
