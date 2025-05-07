# ELK-Based SIEM Monitoring System
## Mục tiêu
Xây dựng hệ thống SIEM để dễ dàng quản lý log trong một hệ thống mạng nội bộ gồm các thiết bị an toàn mạng, web server và client. Mục tiêu chính là thu thập, xử lý, phân tích và giám sát nhật ký từ tường lửa pfSense, hệ thống IDS Snort, web server có ModSecurity WAF và máy Windows, nhằm phát hiện kịp thời các sự kiện bảo mật và trực quan hóa thông tin trong thời gian thực.

## Tổng quan về ELK Stack
![Overview](media/overview.png)

**1. Elasticsearch:**
  - Công cụ tìm kiếm và phân tích: Lưu trữ dữ liệu dưới dạng JSON trong các index, cho phép truy vấn full-text, hỗ trợ phân tích số liệu

**2. Logstash:**
  - Trạm trung chuyển dữ liệu: Nhận dữ liệu từ nhiều nguồn (file log, syslog, FileBeat, database...), xử lý và chuyển tiếp dữ liệu.
  - Pipeline: Gồm 3 giai đoạn - input (nhận dữ liệu đầu vào), filter (parse, gắn thẻ...) và output (đẩy dữ liệu tới Elasticsearch hoặc nơi khác)

**3. Kibana:**
  - Giao diện trực quan: Cho phép xây dựng dashboard, biểu đồ (line, bar, pie, maps...) và report dựa trên dữ liệu trong Elasticsearch
  - Khám phá dữ liệu: Tìm kiếm, lọc và phân tích log/event theo thời gian thực
  - Quản lý và mở rộng: tạo index patterns, visualization, cài đặt alerting...

## Phạm vi (các modules triển khai)
- Log Collection: File cấu hình và script đẩy log từ từng thiết bị và endpoint vào Logstash
- Log Ingestion & Parsing: Pipeline Logstash để chuẩn hóa, enrich sự kiện trước khi lưu vào Elasticsearch.
- Searching & Investigation: Truy vấn KQL và thiết lập index mapping hỗ trợ truy vấn, săn tìm mối đe dọa
- Detection & Alerting: Bộ quy tắc Snort và cấu hình ELK Security để phát hiện SQLi, XSS, DDoS...
- Visualization & Reporting: Trực quan hóa bằng dashboard
- Documentations: Sơ đồ kiến trúc, hướng dẫn triển khai từng thành phần và báo cáo tổng kết kết quả, bài học kinh nghiệm, định hướng phát triển

## Tech stack & Kiến trúc tổng quan

**Tech stack**
![techstack](media/tech_stack.png)

![Archtecture](media/network_topology.png)
Chi tiết kiến trúc hệ thống tại [Sơ đồ kiến trúc và mô tả chi tiết](docs/architecture.md).

## Deployment

## Demo Videos

Xem các video minh họa hoạt động của hệ thống: https://drive.google.com/drive/folders/11oPinABcN_RSF0s3mgBEs7_I8LKQiLiN?usp=sharing

| Feature    | Demo                                                         |
|--------------|--------------------------------------------------------------|
| Log Collection     | [![pfSense demo](demos/pfsense-demo-thumb.png)](demos/pfsense-demo.mp4) |
| Log Ingestion & Parsing    | [![Snort demo](demos/snort-demo-thumb.png)](demos/snort-demo.mp4)       |
| Searching & Investigation  | [![WAF demo](demos/waf-demo-thumb.png)](demos/waf-demo.mp4)             |
| Detection & Alerting | [![Client demo](demos/client-demo-thumb.png)](demos/client-demo.mp4)   |
| Visualization & Dashboard | [![Client demo](demos/client-demo-thumb.png)](demos/client-demo.mp4)   |


