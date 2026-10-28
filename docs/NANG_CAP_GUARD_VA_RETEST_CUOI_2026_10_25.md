# Kết quả nâng cấp guard và quét lại testcase

## Sửa đổi

- Engine lưu định danh route theo nguồn, caller và guard; gộp kết quả từ các file trước khi thống kê. JSON phân biệt `alternative_flow_count` (đường thô), `distinct_route_count` (nhóm route khác nhau), `route_callers` và `route_totals`.
- Thêm mô hình hẹp cho `is_serialized_string()`. Engine chỉ loại object route khi **mã nguồn helper** có một nhánh trả `true` sau kiểm tra token đầu `s`, các nhánh khác trả `false`, lời gọi nằm trong nhánh dương trên đúng đối số và không có câu lệnh xen giữa guard với sink. Helper cùng tên nhưng triển khai khác, điều kiện `OR`, nhánh `else` hoặc ghi đè dữ liệu không được coi là an toàn.
- Những route được loại được ghi trong `analysis.object_payload_exclusion` và, nếu sink còn finding, trong `metadata.object_excluded_callers`. Route khác cùng sink vẫn được báo cáo.

## Kết quả kiểm thử

- **131/131 unit test đạt**; [108/108 ca nhỏ có nhãn đạt](../reports/evaluation/retest-2026-10-25-final-guard/small/summary.json). Các tỷ lệ này chỉ thuộc bộ fixture, không ước lượng độ chính xác trên toàn bộ dự án thật.
- [Chín lượt quét](../reports/evaluation/retest-2026-10-25-final-guard/runs.json) trên tám thư mục testcase và Monolog 1.23.0 quét sâu đều quét đủ tệp, **0 lỗi/giới hạn**. [Source manifest](../reports/evaluation/retest-2026-10-25-final-guard/source_manifest.json) lưu hash mã engine dùng trong đợt quét.
- So với [lượt trước](../reports/evaluation/retest-2026-10-25-route-attribution/runs.json), chỉ một finding đổi severity: `wp-includes/functions.php:624` từ CRITICAL sang HIGH. Không thêm hoặc mất vị trí finding khác.

| Mẫu | Tệp | Finding | CRITICAL/HIGH | Gadget | Kết quả chính |
|---|---:|---:|---:|---:|---|
| XVWA | 304 | 36 | 1/1 | 1 | Đường request đến `unserialize` vẫn là CRITICAL. |
| Saloon 3.0.0 | 332 | 1 | 0/1 | 0 | Giữ sink `allowed_classes => true` dòng 105. |
| Monolog bản mới | 228 | 6 | 0/0 | 128 | POP vẫn là ứng viên; MEDIUM thuộc mã test. |
| Monolog 1.23.0 | 167 | 29 | 0/0 | 148 | Lượt sâu `src`: 88 tệp, 11 finding, 173 gadget; giữ chuỗi tham chiếu. |
| TCPDF 6.2.22 | 227 | 103 | 0/0 | 5 | Không báo HIGH/MEDIUM trên bản đã vá ở chế độ mặc định. |
| Laravel 5.6.29 | 1.174 | 123 | 0/0 | 181 | Sink giữ nguyên; xem library mode bên dưới. |
| WordPress 5.8.2 | 1.212 | 571 | **0/54** | 7 | CRITICAL không còn; route chưa rõ vẫn là HIGH/LOW confidence. |
| Drupal 8.6.9 | 8.855 | 832 | 0/3 | 3 | Ba HIGH vẫn LOW confidence, `unresolved_return_flow`. |

### WordPress 5.8.2

[Finding mới tại `functions.php:624`](../reports/evaluation/retest-2026-10-25-final-guard/wordpress-5.8.2.json) có mức **HIGH, confidence LOW**. Engine ghi **2 route bị loại** qua `_list_meta_row()` ở `template.php:627`: helper đã được kiểm tra chỉ cho token serialized string đi qua. Còn **260 nhóm route** từ `option.php:225` đều `uncertain` và vẫn được giữ. Việc hạ CRITICAL vì thế không khẳng định `option.php` an toàn; nó loại riêng đường có bằng chứng không thể phục hồi object. `alternative_flow_count` vẫn là 783 đường thô, còn `distinct_route_count` của các đường giữ lại là 260.

### Laravel 5.6.29

[Library mode trên cùng bản engine](../reports/evaluation/retest-2026-10-25-final-guard/laravel-library.json) có 162 finding, 0 lỗi. Tại `Encrypter.php:149` còn **2 route** từ `$payload['value']`, so với 16 trước khi sửa mô hình `openssl_decrypt`. Điều kiện MAC/`APP_KEY` và caller HTTP thực tế chưa được chứng minh.

## Chưa đạt

- Route `option.php:225` của WordPress còn lan truyền không chắc chắn; chưa thể xác nhận khả năng khai thác.
- Drupal chưa có trace REST/HAL đầy đủ cho CVE-2019-6340. Monolog/XVWA chưa tự động chứng minh thuộc tính và callback gadget do payload điều khiển.
- Phân tích WordPress mất 143,8 giây và Drupal 202,0 giây ở lượt này. Đây là thời gian quan sát, chưa phải benchmark chuẩn; metadata route cần được theo dõi thêm về chi phí trên dự án lớn.
