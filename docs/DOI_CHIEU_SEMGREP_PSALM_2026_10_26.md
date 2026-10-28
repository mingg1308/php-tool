# Đối chiếu Semgrep và Psalm với PHP Deserialization SAST

## Thiết lập và giới hạn

- Công cụ hiện tại: JSON trong `reports/evaluation/project-by-project-scope-2026-10-26/`, dùng cấu hình và phiên bản PHP theo `scripts/retest_case_studies.py`.
- Semgrep 1.180.0: bốn luật ở `semgrep_php_deserialization.yml` của workspace, không phải toàn bộ bộ luật chính thức của Semgrep. Chạy offline với `--metrics=off --no-git-ignore --x-ignore-semgrepignore-files --max-target-bytes 0 --timeout 60 --jobs 2`; JSON gốc, log, lệnh và thời gian ở `reports/evaluation/semgrep-full-2026-10-26/`. Lượt dùng bộ lọc mặc định được lưu riêng ở `reports/evaluation/semgrep-reference-2026-10-26/`.
- Psalm: chạy trong Docker trên XVWA và Saloon với `--taint-analysis`; JSON, cấu hình, log, chẩn đoán và trạng thái ở `reports/evaluation/psalm-check-2026-10-26/`.
- So sánh vị trí dùng `tệp tương đối:dòng`. Quy tắc review cú pháp, taint từ request, PHAR path review và ứng viên POP là **các loại bằng chứng khác nhau**. Tổng finding giữa hai engine không phải precision hoặc recall.

## Kết quả Semgrep trên phạm vi mở rộng

| Mẫu | Tệp của công cụ / Semgrep | Finding của công cụ / Semgrep | Sink `unserialize` cùng vị trí | Taint request → `unserialize` của công cụ / Semgrep | Lỗi Semgrep |
|---|---:|---:|---:|---:|---:|
| XVWA | 304 / 304 | 36 / 38 | 3 / 3 | 1 / 1 | 0 |
| Saloon 3.0.0 | 332 / 332 | 1 / 21 | 1 / 1 | 0 / 0 | 0 |
| Monolog mới | 228 / 228 | 6 / 92 | 5 / 5 | 0 / 0 | 0 |
| Monolog 1.23.0 | 167 / 167 | 29 / 38 | 0 / 0 | 0 / 0 | 0 |
| Monolog 1.23.0, `src` sâu | 88 / 88 | 11 / 9 | 0 / 0 | 0 / 0 | 0 |
| TCPDF 6.2.22 | 227 / 227 | 103 / 87 | 0 / 0 | 0 / 0 | 2 |
| Laravel 5.6.29 | 1.174 / 1.174 | 123 / 122 | 39 / 39 | 0 / 0 | 0 |
| WordPress 5.8.2 | 1.212 / 1.212 | 571 / 612 | 14 / 14 | 2 / 0 | 0 |
| Drupal 8.6.9 | 8.855 / 8.465 | 832 / 795 | 159 / 159 | 0 / 0; công cụ thêm 3 trace framework | 4 |

Các vị trí sink cùng nằm trong tệp Semgrep đã quét khớp **221/221**; đây chỉ là sự đồng thuận về lời gọi `unserialize`, không phải 221 lỗ hổng. Ở lượt Semgrep mặc định, số tệp quét thấp hơn đáng kể vì bỏ qua test/vendor; ví dụ Saloon 145/332 và Drupal 4.136/8.855. Cờ bỏ qua `.semgrepignore` sửa phần lớn chênh lệch. Drupal còn ít hơn 390 tệp trong lượt mở rộng, chủ yếu vì các phần mở rộng Drupal như `.module`, `.install`, `.inc` không được chọn như PHP. Bốn cảnh báo parse của Drupal gồm `core/modules/rest/src/RequestHandler.php`; hai cảnh báo TCPDF gồm `tcpdf.php` và `tcpdf_parser.php`. Các tệp được liệt kê là "scanned" vẫn có thể bị phân tích một phần.

## Đối chiếu các vị trí quan trọng

| Mẫu | Công cụ hiện tại | Semgrep | Psalm nếu đã chạy | Diễn giải |
|---|---|---|---|---|
| XVWA `home.php:38` | Request → sink; có liên kết ứng viên `__wakeup → eval` | `php-request-to-unserialize` và review sink | `TaintedUnserialize` cùng dòng | Ba công cụ đồng thuận về nguồn → sink trực tiếp. Semgrep bốn luật không phân tích gadget; runtime chưa được xác nhận. |
| Saloon `AccessTokenAuthenticator.php:105` | HIGH ở cấp cú pháp sink, không có request caller | Review sink, không có request taint | Không có `TaintedUnserialize` | Đồng thuận về sink; không suy ra ứng dụng tích hợp có đường khai thác. |
| Laravel `Encrypter.php:149` | Review sink, không có request trace | Review sink, không có request taint | Chưa chạy lại trong lượt này | Định vị sink chính xác; MAC, `APP_KEY` và cờ `$unserialize` vẫn chưa được chứng minh. |
| WordPress `upgrade.php:1616` | Review sink | Review sink | Chưa chạy lại trong lượt này | Cả hai chỉ xác định vị trí; chưa nối option DB, multisite và kích hoạt upgrade. Hai trace request khác của công cụ hiện tại đều HIGH/LOW với guard chưa chứng minh; Semgrep không xác nhận chúng. |
| Drupal `MapItem.php:67`, `LinkItem.php:194` | Hai HIGH/LOW `unresolved_return_flow`; còn một HIGH ở test module | Review sink tại hai vị trí production; không có taint request | Chưa chạy lại trong lượt này | Mô hình REST/HAL của công cụ đưa ra đường có điều kiện; Semgrep không chứng minh hoặc phủ định CVE-2019-6340. Parser Semgrep còn cảnh báo trong `RequestHandler.php`. |
| Monolog | POP ứng viên, quét sâu giữ chuỗi `SyslogUdpHandler → BufferHandler` | Bốn luật không có phân tích POP | Chưa chạy lại trong lượt này | Không thể dùng 0 taint Semgrep để kết luận gadget không tồn tại. |
| TCPDF 6.2.22 | Không có HIGH/MEDIUM ở chế độ mặc định | 87 PHAR-path review, 2 lỗi parse | Chưa chạy lại trong lượt này | Cảnh báo review path không xác nhận CVE; lỗi parse ở tệp lõi khiến kết quả âm tính Semgrep không đầy đủ. |

Psalm tạo JSON hợp lệ cho cả hai mẫu, nhưng có 954 chẩn đoán ở XVWA và 2.496 ở Saloon, phần lớn không phải vấn đề taint và có lỗi thiếu dependency. Chỉ lọc `TaintedUnserialize` mới cho một vị trí XVWA và không có vị trí Saloon. Không dùng tổng chẩn đoán Psalm làm tổng lỗ hổng.

## Đánh giá

1. **Đạt:** định vị sink trực tiếp chính xác trên phạm vi giao nhau; XVWA được Semgrep và Psalm xác nhận nguồn request tới sink. Công cụ hiện tại cung cấp thêm liên kết gadget ứng viên và nhãn phạm vi test/example/vendor.
2. **Chưa đạt:** Drupal, Laravel và WordPress chưa có xác nhận khai thác độc lập. Trace Drupal là mô hình có điều kiện, còn đường WordPress `upgrade.php:1616` và Laravel `Encrypter.php:149` mới ở cấp review sink trong cả công cụ hiện tại và Semgrep.
3. **Giới hạn của đối chứng:** luật Semgrep được lấy từ cùng workspace và có mô hình PHAR đơn giản, chưa áp điều kiện PHP runtime; Psalm mới chỉ chạy hai mẫu và thiếu dependency. Không tính precision/recall thực tế từ số finding hoặc từ sự đồng thuận vị trí sink.
