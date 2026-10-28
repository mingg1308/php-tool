# Kiểm thử WordPress 5.8.2

> **Cập nhật sau sửa engine:** [`after-guard-upgrade.json`](../reports/evaluation/wordpress-5.8.2/after-guard-upgrade.json)
> quét 1.212 tệp trong 99,40 giây, 571 findings, 0 lỗi. Đường CRITICAL tại
> `functions.php:624` nay ghi thêm điều kiện `is_serialized_string()` ở
> `template.php:625`; trước đây bước phân tích coi phép gán chứa lời gọi là
> một write đi trước và làm mất guard. Mức CRITICAL vẫn còn vì engine chưa
> chứng minh ngữ nghĩa loại trừ object của helper này, và báo cáo gộp 783
> đường nguồn vào một sink. Đây vẫn là điểm cần khắc phục, không được coi là
> lỗ hổng object injection đã xác nhận.

## Phạm vi và cách chạy

- Mẫu: `testcase/wordpress-5.8.2`, commit `489b33c97a8942e43c92f3d4a5efe069fecccb32`.
- Lượt quét hoàn chỉnh: `py -3.12 -m php_deserial_sast.cli scan testcase/wordpress-5.8.2 --php-version 7.3 --severity INFO -f json -o reports/evaluation/wordpress-5.8.2/default-php73.json`.
- [JSON gốc](../reports/evaluation/wordpress-5.8.2/default-php73.json), [log](../reports/evaluation/wordpress-5.8.2/default-php73.log). Một lượt thử bật `--experimental-side-effects` được dừng sau khi chạy quá lâu mà chưa tạo JSON; nó không được dùng để đánh giá độ chính xác.

| Chỉ số | Kết quả |
|---|---:|
| Tệp quét / lỗi | 1.212 / 0 |
| Dòng quét | 495.902 |
| Thời gian | 105,29 giây |
| Tổng cảnh báo | 571 |
| CRITICAL / HIGH / MEDIUM / LOW / INFO | 1 / 53 / 28 / 3 / 486 |
| Ứng viên gadget | 6 |
| Sink kiểm kê | 580 |

Trong 571 cảnh báo có 486 mẫu API đường dẫn PHAR mức INFO, 68 cảnh báo PHAR theo giả định luồng, 12 mẫu `unserialize` theo cú pháp, 3 ứng viên POP và 2 cảnh báo taint tới `unserialize`. Đây là các nhóm ứng viên, không phải 571 lỗ hổng đã xác nhận. Phân tích summary hội tụ nhưng có `summary_evidence_truncated=true`, 1.533 scope CFG dùng fallback và 11.867 typed dynamic call chưa giải được; các giới hạn này ảnh hưởng độ đầy đủ của đường liên hàm.

## Chuẩn đối chiếu: CVE-2022-21663

[Công bố WordPress 5.8.3](https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/) xác nhận bản vá object injection ở một số cài đặt multisite. [Phân tích của SonarSource, nhóm phát hiện](https://www.sonarsource.com/blog/wordpress-object-injection-vulnerability/) mô tả đường liên quan đến `upgrade_280()` và cách vượt qua việc double serialization: chuỗi PHP custom serialized object bắt đầu bằng `C` không được `is_serialized()` cũ nhận diện, nên có thể đi vào option mà không bị tuần tự hóa thêm. Khi admin có quyền phù hợp thay đổi `db_version` để kích hoạt script nâng cấp, lệnh `unserialize` trực tiếp lại nhận diện chuỗi đó. Điều kiện kiểu đối tượng đặc biệt này áp dụng với PHP trước 7.4, vì vậy lượt chính đặt PHP mục tiêu 7.3. Việc khai thác còn phụ thuộc multisite, quyền super admin, kích hoạt nâng cấp và gadget phù hợp.

Trong mẫu 5.8.2, `wp-admin/includes/upgrade.php:1616` gọi `@unserialize($value)` sau khi `upgrade_280()` đọc `$row->option_value` từ bảng options trong nhánh `is_multisite()`. [Bản vá WordPress](https://github.com/WordPress/WordPress/commit/638ef7815ec29318434365ffde1d3cef7437b948) thay lệnh trực tiếp bằng `maybe_unserialize($row->option_value)` và thay điều kiện xử lý tiếp theo. Ở mẫu còn một lệnh `@unserialize` trong `upgrade_network()` tại dòng 2285; lượt này chưa phân loại khả năng khai thác của đường đó.

## Đánh giá công cụ

- Công cụ tìm thấy sink CVE tại `upgrade.php:1616` nhưng chỉ bằng luật `php-unserialize-review`, mức MEDIUM, confidence MEDIUM, `evidence_level=syntactic_review`. `sink_inventory` ghi `no_tracked_source`; không có trace từ option/database, `db_version` và nhánh multisite tới sink. **Đây là phát hiện đúng vị trí nhưng chưa phát hiện được CVE ở cấp đường khai thác.**
- Cảnh báo CRITICAL duy nhất nằm tại `wp-includes/functions.php:624`, từ `$_POST['meta'][...]['value']` qua `_list_meta_row()` đến `maybe_unserialize()`. Tại `wp-admin/includes/template.php:624–633`, nhánh gọi `maybe_unserialize` chỉ chạy nếu `is_serialized_string()` đúng; nhánh serialized object/array bị trả về sớm. `is_serialized_string()` yêu cầu ký tự đầu `s`. Do đó trace này không chứng minh object payload tới sink, và không phải đường CVE-2022-21663. Mức CRITICAL/HIGH confidence là quá cao cho kết luận object injection ở đường này.
- Cảnh báo taint HIGH còn lại tại `class-wp-customize-widgets.php:1452` có kiểm tra `hash_equals(get_instance_hash_key($decoded), instance_hash_key)` trước `unserialize`. Công cụ đánh dấu guard chưa nhận diện, nên chưa chứng minh dữ liệu POST tự do đi qua kiểm tra hash. Nó cũng không phải đường CVE đang đối chiếu.
- Các cảnh báo PHAR và POP phải được xem từng đường; tổng số hoặc severity trong JSON không thể thay cho chứng minh nguồn kiểm soát, điều kiện runtime và gadget khả thi.

**Kết luận:** trên WordPress 5.8.2, công cụ quét hoàn tất nhưng chưa đạt tiêu chí phát hiện chính xác CVE-2022-21663. Nó ưu tiên một cảnh báo CRITICAL ở nhánh khác trong khi sink CVE chỉ được nêu mức rà soát cú pháp.

## Hướng khắc phục để kiểm thử hồi quy

1. Mô hình hóa dữ liệu `wpdb->get_results()` từ bảng options và chuỗi ghi/đọc option, kèm điều kiện quyền và cơ chế kích hoạt `db_version`.
2. Theo dõi ràng buộc `is_multisite()` và các predicate của nhánh nâng cấp; hỗ trợ đối chiếu sự khác biệt giữa `is_serialized()` và native `unserialize` cho token `C` trên PHP trước 7.4.
3. Hạ hoặc loại cảnh báo object injection khi có guard `is_serialized_string()` chỉ cho phép chuỗi; nhận diện kiểm tra MAC/hash trước `unserialize` trong nhánh widget.
4. Quét đối chứng WordPress 5.8.3 cùng cấu hình và xác nhận đường CVE biến mất do bản vá, thay vì chỉ đếm tổng số sink.
