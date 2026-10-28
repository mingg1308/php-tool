# Khắc phục phân tích Drupal 8.6.9

## Thay đổi đã thực hiện

- Sửa việc đọc `use Trait` trong thân lớp; nối phương thức trait, trait lồng nhau và kế thừa theo thứ tự lớp → trait → lớp cha. Không đoán đích khi có adaptation chưa hỗ trợ hoặc phương thức mơ hồ.
- Bổ sung hợp đồng dispatch Drupal serializer: request → entity normalizer → field normalizer → field item normalizer → lớp field kế thừa FieldItemBase. Chỉ nối tới phương thức thực sự có trong tập mã; không tạo nguồn hoặc sink theo tên CVE.
- Kiểm tra receiver lấy từ `context['target_instance']` trước khi áp dụng hợp đồng setValue. Có thể tắt bằng `--no-framework-models`.
- Luồng đi qua hợp đồng được đánh dấu không chắc chắn; JSON lưu `framework_dispatch_assumptions` và `runtime_configuration_verified=false`. Việc một lớp field có trong mã không chứng minh module đó đang bật hoặc REST endpoint khai thác được.
- Đồng nhất sink inventory với luồng tìm thấy tại các tệp gọi khác; bổ sung kiểm thử hồi quy liên tệp.
- Mở rộng dependency coverage qua các đích của hợp đồng; không coi các intrinsic PHP như isset/empty là hàm bên ngoài bị thiếu.
- Tái sử dụng vị trí AST khi dựng trace để giảm chi phí tạo đối tượng lặp lại.
- Bộ đối chiếu không lấy nhầm commit Git của thư mục cha làm phiên bản CodeQL; wrapper Progpilot ghi thêm stack trace khi lỗi.

## Kiểm chứng

Bộ unittest: **116 test đạt**. Các ca mới bao gồm trait lồng nhau, override, adaptation chưa hỗ trợ, dữ liệu hằng, namespace không liên quan, sai context, allowed_classes=false và đối chiếu sink liên tệp.

Quét toàn bộ Drupal bằng cấu hình mặc định, PHP 7.4, severity INFO:

| Chỉ tiêu | Trước | Sau |
|---|---:|---:|
| Tệp được quét | 8855 | 8855 |
| Thời gian nội bộ (giây) | 134.85 | 169.06 |
| Finding từ taint engine | 0 | 3 |
| Tổng finding, gồm INFO | 832 | 832 |

Ba finding HIGH, confidence LOW:

1. `core/modules/link/src/Plugin/Field/FieldType/LinkItem.php:194`.
2. `core/lib/Drupal/Core/Field/Plugin/Field/FieldType/MapItem.php:67`.
3. `core/modules/field/tests/modules/field_test/src/Plugin/Field/FieldType/TestObjectItem.php:56` — mã kiểm thử Drupal, không mặc nhiên là điểm khai thác production.

Nguồn được lưu trong trace là RequestHandler/getContent. Hai finding đầu khắc phục việc chỉ định vị sink mà không nối được nguồn request trong kết quả trước. Đây là kết quả có điều kiện theo mô hình framework, chưa xác nhận RCE hoặc khả năng khai thác CVE trên một website chạy thật.

Tập mã Drupal nhỏ khi bật mô hình tìm được hai sink LinkItem/MapItem; khi tắt mô hình có **0 finding taint**. Điều này xác nhận tác động của hợp đồng; không thay thế tập ground truth độc lập. Không suy ra precision/recall toàn dự án từ ba finding này.

Lần chạy đầu sau sửa mất 255.76 giây; lần xác nhận cuối mất 169.06 giây. Khác biệt điều kiện máy/cache và mã khiến hai lần này không đủ để khẳng định tỷ lệ tăng tốc. So với baseline trước nâng cấp, lần cuối vẫn chậm hơn.

## Các giới hạn còn lại

- Chế độ experimental side effects từng vượt 900 giây. Profile xác định bind/call_effects và số luồng trung gian lớn, có lần bind xử lý 3.087 flows trong FormBuilder. Cache vị trí trace chưa giải quyết gốc tăng trưởng này; chưa xác nhận chế độ đó hoàn tất trên toàn Drupal.
- Quét cuối ghi lỗi coverage `call_graph_limit`: bỏ 3.955 cạnh ứng viên, nên POP coverage chưa đầy đủ. Taint summaries đã hội tụ không đồng nghĩa toàn bộ engine hoàn chỉnh.
- Trait alias/insteadof chưa được phân giải đầy đủ; được giữ là không xác định.
- Framework dispatch hiện chỉ có hợp đồng Drupal nêu trên. Chưa giải quyết dispatch động chung cho mọi framework hoặc cấu hình service lúc chạy.
- Hàm validation không được coi là sanitizer chỉ vì tên gọi. Việc đánh giá đầy đủ bản vá Drupal cần thêm mô hình schema và kiểm thử bản đã vá.
- Psalm thiếu dependency của Drupal, Progpilot gặp lỗi nội bộ; hai kết quả tham chiếu toàn dự án chưa được chạy lại thành công. Không dùng lỗi/crash làm bằng chứng không có lỗ hổng. CodeQL hiện không có PHP extractor phù hợp trong bộ công cụ này.

## Tệp kết quả

- `reports/evaluation/drupal-fixes/full-final.json`: kết quả toàn dự án, bản xác nhận cuối.
- `reports/evaluation/drupal-fixes/comparison.json`: đối chiếu trước/sau.
- `reports/evaluation/drupal-fixes/slice.json` và `slice-models-off.json`: đối chứng trên tập mã nhỏ.
- `reports/evaluation/drupal-fixes/before-summary.log`: profile chẩn đoán side effects.

Mã Drupal gốc không được sửa. Không commit/push trong đợt này.


## Cập nhật tiếp theo

Side effects theo nhu cầu đã giúp lần quét Drupal có POP hoàn tất trong 169,37 giây. Xem [báo cáo kiểm chứng side effects](KHAC_PHUC_SIDE_EFFECTS_DRUPAL.md). Mô tả chưa hoàn tất phía trên phản ánh lần đánh giá trước.
