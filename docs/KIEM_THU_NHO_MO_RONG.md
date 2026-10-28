# Kiểm thử PHP nhỏ mở rộng và sửa lỗi

> Cập nhật tiếp theo: [sửa guard và đường dẫn](SUA_LOI_GUARD_DUONG_DAN.md).
> Quy tắc tự hạ severity do guard mô tả trong đợt dưới đây đã được thay thế sau
> khi phát hiện hồi quy trên XVWA. Số liệu giữ theo đúng đợt kiểm thử lịch sử.

## Phạm vi

Đợt kiểm tra này mở rộng từ 34 lên **64 mẫu PHP nhỏ**, gồm 40 mẫu cần có taint
finding theo mô hình và 24 mẫu không cần có finding loại này. Mục tiêu là dữ liệu
không tin cậy đi tới `unserialize` có thể tái tạo object; không đồng nhất việc
phát hiện luồng với chứng minh khai thác thành công.

Mỗi mẫu được scanner quét **độc lập qua toàn bộ pipeline**, bật parser, symbol,
summary, taint, luật YAML và gadget analysis. Kết quả kiểm tra lọc finding của
taint engine tại `unserialize`; cảnh báo cú pháp được giữ riêng trong JSON.

## Lỗi tái hiện và cách sửa

| Ca lỗi trước sửa | Nguyên nhân | Xử lý |
|---|---|---|
| Options đặt trong biến chứa `allowed_classes=false` | Chỉ nhận dạng array literal ngay tại lời gọi | Đọc phép gán literal chi phối; từ chối kết luận an toàn nếu có ghi đè, alias hoặc sử dụng trung gian không rõ |
| `['allowed_classes'=>false, ...$unknown]` | Bỏ qua unpack, giữ nhầm giá trị false | Unpack hoặc key động làm mất giá trị chắc chắn; áp dụng quy tắc key cuối ghi đè |
| Nhánh `ctype_digit($s)` vẫn báo POI | Chưa thu hẹp miền giá trị theo predicate | Nhận dạng nhánh đúng của một số builtin số/boolean; kiểm tra shadowing và sử dụng/ghi lại sau kiểm tra |
| Constructor có `readonly protected/public` | Hạn chế thứ tự modifier của grammar | Bỏ riêng token readonly trong bản đầu vào parser, giữ vị trí visibility/type/parameter và bytes gốc |
| Hàm legacy tên `readonly` | Grammar xem tên như keyword | Placeholder cùng độ dài chỉ trong bản parse; tên symbol/snippet vẫn lấy từ mã gốc |

Lượt đầu của bộ ca mới có **5 ca thất bại** tương ứng năm dòng trên. Sau sửa,
64/64 mẫu có kết quả mong đợi và không có lỗi phân tích trong pipeline.

Việc chuẩn hóa parser chỉ áp dụng khi cây ban đầu có lỗi; tránh vùng string,
comment, heredoc và text. Đây là tương thích cho phân tích tĩnh, không xác nhận
rằng mã hợp lệ với mọi phiên bản PHP hoặc mô phỏng đầy đủ ngữ nghĩa readonly.

## Điều kiện bảo vệ và các ca chống báo nhầm

Các nhánh có predicate liên quan dữ liệu hoặc kiểm tra trả về sớm được lưu vào
`metadata.review_conditions`. Finding có trạng thái `guarded_flow_review`, mức
MEDIUM/LOW, nếu trace được chọn còn phụ thuộc vào các điều kiện cần xác minh.
Không xóa finding chỉ vì nhìn thấy `hash_equals`, tên hàm `is_*` hoặc một chữ ký.

Các test bổ sung kiểm tra:

- `hash_equals` với hai đầu vào attacker kiểm soát vẫn có finding.
- Kiểm tra HMAC rồi return khi sai giữ evidence để rà soát, không tự xác nhận an toàn.
- Predicate truyền qua hàm wrapper vẫn xuất hiện trong evidence.
- Một đường gọi không có guard vẫn được ưu tiên hiển thị nếu cùng sink có đường guarded.
- Gán dữ liệu mới sau guard không thừa hưởng guard của dữ liệu cũ.
- `ctype_digit` bị shadow bằng hàm người dùng không được coi là builtin sanitizer.
- Nhánh `else`, phép OR, ghi đè hoặc lời gọi có thể thay đổi biến không được hưởng
  loại trừ taint từ điều kiện `ctype_digit` trước đó.

`guarded_flow_review` chỉ là yêu cầu đánh giá điều kiện, không chứng minh guard
mạnh hoặc lỗ hổng ít tác động. Không dùng nó như kết luận “an toàn”. Đây là bước
cải thiện việc trình bày hai trace WordPress của lượt trước; chưa xây dựng solver
đầy đủ cho HMAC/secret, mọi predicate người dùng và tính khả thi của đường đi.

## Phạm vi kiểm thử bổ sung

Ngoài 64 mẫu có bảng kết quả, suite có **16 test methods**, bao gồm subtest về:

- Luồng liên tệp với caller an toàn/không an toàn; vị trí finding phải ở sink trong thư viện.
- Phar: cùng lời gọi filesystem ở PHP 7.4 và 8.1; đường dẫn có tiền tố local cố định.
- Chuỗi 40 hàm, augmented assignment, array field riêng biệt và weak write bằng key động.
- Named arguments, namespace/function import, method có kiểu và request model của framework.
- Allowed classes rỗng, false, allowlist không rỗng, key trùng, key động và alias mutation.
- NUL trong chuỗi, bảo toàn vị trí source, readonly trong comment/string, target không tồn tại.
- POP entry kế thừa và ranh giới closure trong luật `pattern-inside`.

**16/16 test methods đạt.** Bốn tệp thật từng có lỗi parser được kiểm tra lại trực tiếp:

| Tệp | `root.has_error` sau sửa |
|---|---|
| Saloon `src/Http/BaseResource.php` | false |
| Saloon `tests/Fixtures/Authenticators/CustomOAuthAuthenticator.php` | false |
| Saloon `tests/Fixtures/Requests/QueryParameterRequest.php` | false |
| WordPress `wp-includes/general-template.php` | false |

Đợt này tập trung vào các ca nhỏ và bốn tệp parser; không thay số liệu của tám
dự án trong báo cáo cũ bằng kết quả chưa chạy lại.

## Đối chiếu Progpilot/Psalm

Hai công cụ được chạy lại trên bộ 64 fixture, PHP target 8.1, image
`php-sast-references:local`, timeout 180 giây. Progpilot hoàn tất khoảng 18,8 giây;
Psalm khoảng 27,0 giây. Progpilot báo 31 vị trí fixture có `unserialize` taint;
Psalm báo 43; scanner hiện tại báo 40 theo kỳ vọng của bộ test.

**Các con số trên không phải thứ hạng độ chính xác.** Psalm còn có diagnostic về
hàm/class chưa định nghĩa. Cả hai công cụ tham chiếu có thể cảnh báo deserialize
trong ca `allowed_classes=false`, còn mục tiêu kỳ vọng ở đây tập trung vào POI.
Các hàm không resolve và nguồn framework cũng dùng giả định khác nhau.

Scanner được đánh giá từng fixture độc lập. Hai công cụ tham chiếu quét một tập
fixture chung; tên helper/namespace được đổi để giảm xung đột. Khác biệt môi
trường phân tích này phải được giữ khi diễn giải kết quả, không tính recall trên
dự án thực tế từ sự đồng thuận giữa các scanner.

## Artifact và tái lập

- [Test mở rộng](../php_deserial_sast/tests/test_small_cases.py).
- [Script chạy độc lập từng ca](../scripts/evaluate_small_cases.py).
- [Kết quả và đối chiếu từng ca](../reports/evaluation/small-expanded/own/summary.json).
- [Hash mã nguồn](../reports/evaluation/small-expanded/own/source_manifest.json).
- [Progpilot run](../reports/evaluation/small-expanded/progpilot-runs.json).
- [Psalm run](../reports/evaluation/small-expanded/psalm-runs.json).

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -v
py -3.12 scripts/evaluate_external.py --label small-expanded --image php-sast-references:local --fixtures-only --timeout 180
py -3.12 scripts/evaluate_small_cases.py
```

Các artifact trong `reports` là dữ liệu cục bộ bị Git ignore. Bộ test cải thiện
độ tin cậy của những hành vi đã kiểm tra; không bảo đảm chính xác tuyệt đối với
mọi mã PHP. Heap/alias tổng quát, callback/closure động, CFG đầy đủ và candidate
caps của call graph vẫn là giới hạn. Không có finding không chứng minh an toàn.
