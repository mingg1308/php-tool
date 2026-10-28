# Đánh giá kiểm thử lại các testcase sau nâng cấp

Đợt quét bắt đầu ngày 24/10/2026 và hoàn tất ngày 25/10/2026. Chạy `py -3.12 scripts/retest_case_studies.py` trên cả tám thư mục trong `testcase`; Monolog 1.23.0 có thêm lượt quét sâu riêng `src/Monolog`. `--severity INFO` được dùng để lưu toàn bộ tín hiệu. Cấu hình PHP và cờ side effects nằm trong [runs.json](../reports/evaluation/retest-2026-10-24/runs.json); SHA-256 mã engine nằm trong [source_manifest.json](../reports/evaluation/retest-2026-10-24/source_manifest.json). Lượt Monolog mới ban đầu chạm giới hạn 10.000 đường gadget, nên đã được chạy lại với 100.000 đường và 500.000 cạnh; JSON `monolog.json` cùng `runs.json` là kết quả hoàn chỉnh. Không dùng lượt bị giới hạn để kết luận.

## Kết quả

| Mẫu | Tệp quét | Finding C/H/M/L/I | Gadget | Thời gian | Lỗi/giới hạn |
|---|---:|---:|---:|---:|---:|
| XVWA toàn project | 304 | 1/1/2/1/31 | 1 | 4,63 s | 0 |
| Saloon 3.0.0 | 332 | 0/1/0/0/0 | 0 | 3,09 s | 0 |
| Monolog bản mới (`testcase/monolog`) | 228 | 0/0/5/1/0 | 128 | 14,81 s | 0 |
| Monolog 1.23.0 toàn project | 167 | 0/0/0/1/28 | 148 | 4,86 s | 0 |
| Monolog 1.23.0 chỉ `src`, depth 10 | 88 | 0/0/0/1/10 | 173 | 11,57 s | 0 |
| TCPDF 6.2.22 | 227 | 0/0/0/1/102 | 5 | 38,01 s | 0 |
| Laravel 5.6.29 | 1.174 | 0/0/39/1/83 | 181 | 21,00 s | 0 |
| WordPress 5.8.2 | 1.212 | 1/53/28/3/486 | 7 | 102,21 s | 0 |
| Drupal 8.6.9 | 8.855 | 0/3/156/2/671 | 3 | 170,76 s | 0 |

`C/H/M/L/I` lần lượt là CRITICAL/HIGH/MEDIUM/LOW/INFO. Đây là số tín hiệu của công cụ, không phải số lỗ hổng đã xác nhận. Các JSON đầy đủ nằm trong [thư mục retest](../reports/evaluation/retest-2026-10-24/runs.json).

## Đối chiếu độ chính xác

- **Ca nhỏ có nhãn:** [108/108 ca đạt](../reports/evaluation/retest-2026-10-24/small/summary.json), gồm 64 ca dương và 44 ca âm theo mô hình của bộ fixture, không có lỗi quét. Precision/recall bằng 1,0 **chỉ trên bộ fixture này**; không suy ra cho dự án thực tế.
- **XVWA:** Giữ đúng nguồn `$_REQUEST['r'] → unserialize()` ở `php_object_injection/home.php:38` (CRITICAL/HIGH confidence) và chuỗi `__wakeup → eval` ở dòng 30 (LOW). Hai finding vẫn chưa được nối thành một chứng minh RCE tự động.
- **Saloon:** Giữ HIGH tại `AccessTokenAuthenticator.php:105` cho `allowed_classes => true`, đúng vị trí sink được công bố. Chưa có caller ứng dụng chứng minh chuỗi token do kẻ tấn công kiểm soát.
- **Monolog 1.23.0:** Lượt quét sâu nay có chuỗi tham chiếu `SyslogUdpHandler::close → BufferHandler::close → flush → AbstractHandler::handleBatch → BufferHandler::handle → call_user_func`, ID `c47409495791`. Số gadget toàn project tăng **35 → 148**, lượt sâu **39 → 173**; số finding và vị trí finding không đổi. Các chuỗi vẫn là ứng viên, chưa chứng minh thuộc tính, callback hoặc payload khả thi. Với bản Monolog mới, năm MEDIUM đều là luật rà soát `unserialize` trong `tests/`, không phải năm lỗ hổng production.
- **TCPDF 6.2.22:** Không có HIGH/MEDIUM ở chế độ mặc định, phù hợp bản đã vá cho CVE-2018-17057. 102 INFO là API cần rà soát, không chứng minh khai thác PHAR.
- **Laravel 5.6.29:** 123 finding không đổi; sink `Encrypter.php:149` vẫn chỉ được nhận ở cấp cú pháp. Công cụ chưa chứng minh đường header/cookie, ranh giới MAC và APP_KEY của CVE-2018-15133.
- **WordPress 5.8.2:** 571 finding và mọi vị trí giữ nguyên; gadget **6 → 7**. Cảnh báo CRITICAL tại `functions.php:624` vẫn còn. Trace hiện ghi `is_serialized_string()` ở caller `template.php:625`, nhưng engine chưa chứng minh guard loại trừ object theo từng route. Không được diễn giải CRITICAL này như object injection đã xác nhận. Tín hiệu CVE-2022-21663 ở `upgrade.php:1616` vẫn chưa có luồng nguồn DB hoàn chỉnh.
- **Drupal 8.6.9:** 832 finding và mọi vị trí giữ nguyên; gadget **2 → 3**, 0 lỗi. Ba HIGH ở `MapItem.php:67`, `LinkItem.php:194`, `TestObjectItem.php:56` đều LOW confidence và `unresolved_return_flow`. Chưa dựng được trace REST/HAL đầy đủ cho CVE-2019-6340; `TestObjectItem` còn thuộc mã kiểm thử.

Với bảy mẫu có mốc trước cùng cấu hình (XVWA, Saloon, Monolog 1.23.0, TCPDF, Laravel, WordPress, Drupal), đối chiếu `(rule_id, tệp, dòng, severity)` cho **0 vị trí thêm và 0 vị trí mất**. Vì vậy nâng cấp vừa qua cải thiện khả năng lưu/giải thích đường gadget và guard, nhưng chưa cải thiện độ chính xác phân loại ở các điểm khó của WordPress, Laravel và Drupal. Thời gian quét chỉ là quan sát của từng lượt, không phải benchmark ngang hàng giữa các dự án.

## Ưu tiên tiếp theo

1. Tách route theo caller và guard, chứng minh ngữ nghĩa helper trước khi thay đổi mức WordPress CRITICAL; giảm các guard không liên quan do dùng chung biến mảng.
2. Liên kết sink giải tuần tự hóa với gadget và tiền điều kiện thuộc tính/callback; tránh coi số gadget tăng là số lỗ hổng tăng.
3. Bổ sung mô hình ciphertext/MAC/APP_KEY cho Laravel và đường REST/HAL có điều kiện cho Drupal; kiểm thử đối chứng bản vá và bản lỗi với cùng cấu hình.
