# Sửa lỗi guard và đường dẫn sau đánh giá project thực tế

## Thay đổi

### 1. Guard không tự động làm giảm severity

`isset`, `empty`, kiểm tra kiểu và kiểm tra file tồn tại không chứng minh dữ liệu
an toàn để deserialize. Các builtin này không còn được dùng làm evidence của
guard bảo vệ. Predicate khác vẫn có thể xuất hiện trong `review_conditions`,
nhưng sự có mặt của predicate **không tự hạ severity/confidence**.

`guarded_flow_review` có nghĩa điều kiện cần rà soát, không có nghĩa mức nguy hiểm
thấp hơn. `is_serialized` kiểm tra định dạng chứ không loại trừ object.
`hash_equals` chưa chứng minh nguồn khóa hoặc hai vế so sánh đáng tin cậy.

### 2. TCPDF: wrapper và kết quả trả về của validator

Bộ nhận diện hỗ trợ dấu ngoặc quanh các so sánh HTTP/HTTPS và trường hợp vòng
lặp nằm trong nhánh `strpos($filename, '://') > 0`. Guard được gắn với nhánh bao
ngoài chỉ khi cấu trúc này khớp; nhánh điều khiển tùy ý không được coi tương đương.

Một hàm chỉ được suy ra quan hệ “trả về giá trị truthy thì tham số không còn là
Phar” khi bộ lọc wrapper đã nhận diện nằm đầu thân hàm, các nhánh từ chối trả
`false`, và tham số chưa bị ghi lại trước/trong bộ lọc. Caller phải kiểm tra
`!validator($path)` và chấm dứt nhánh lỗi; gọi validator rồi bỏ qua kết quả không
bảo vệ sink. Định nghĩa shadow các builtin cũng không được nhận làm bộ lọc chuẩn.

Guard phải cùng phạm vi hàm với use-site. Ghi lại biến sau kiểm tra không được
thừa hưởng bảo vệ cũ. Phép gán biến vòng lặp `foreach` được đặt trước thân vòng
lặp, cho phép áp dụng đúng guard bên trong mỗi lượt. Phân tích alias/by-reference
tổng quát vẫn chưa đầy đủ.

### 3. Hằng đường dẫn: tách bằng chứng và mặc định cấu hình

- `define` duy nhất, vô điều kiện, cùng tệp và đứng trước use có thể cung cấp
  tiền tố local chắc chắn; khi đủ bằng chứng, loại route Phar không phù hợp.
- Định nghĩa ở bootstrap/hàm/tệp khác chỉ cho biết giá trị mặc định của project.
  Scanner giữ finding và gắn `configured_local_path_review`, MEDIUM/LOW,
  `path_prefix_assumptions` chứa vị trí định nghĩa. Cần kiểm tra thứ tự bootstrap
  và cấu hình ghi đè ngoài project.
- Không hardcode tên `WP_PLUGIN_DIR`. Chuỗi hằng được suy luận từ các định nghĩa
  `define` tìm thấy. Nếu có định nghĩa động hoặc không chứng minh được local,
  không áp dụng giả định tiền tố local.

## Kiểm thử

29 test methods đạt, gồm bộ ca cũ và các regression mới tại
[`test_real_project_regressions.py`](../php_deserial_sast/tests/test_real_project_regressions.py).
Các ca đối chứng giữ finding khi: wrapper không trả về sớm, cho phép `phar`,
nguồn danh sách wrapper giả, builtin bị shadow, ghi lại biến, bỏ qua kết quả
validator, validator trả thành công trước khi kiểm tra, hoặc guard ở hàm khác.

Ba project XVWA, TCPDF 6.2.22 và WordPress 5.8.2 được quét lại với cùng cấu hình
độ sâu 10, tối đa 20.000 sink paths và 500.000 expansions như `deep-current`.
Không sửa các JSON cũ; kết quả xác nhận mới nằm tại `reports/evaluation/fixes-validated`.

- [JSON so sánh trước/sau](../reports/evaluation/fixes-validated/comparison.json).
- [Command, thời gian và lỗi từng lượt](../reports/evaluation/fixes-validated/runs.json).
- [Hash snapshot mã nguồn](../reports/evaluation/fixes-validated/source_manifest.json).

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -v
py -3.12 scripts/evaluate_scanner.py fixes-validated --snapshot --timeout 1200 --max-depth 10 --max-gadget-paths 20000 --max-gadget-expansions 500000 --projects xvwa tcpdf-6.2.22 wordpress-5.8.2
py -3.12 scripts/compare_guard_fixes.py
```

Các thay đổi không loại bỏ giới hạn call graph, không chứng minh exploitability
và không thay thế kiểm tra thủ công đối với runtime/configuration chưa biết.

## Kết quả xác nhận

| Project | Tổng finding trước → sau | Taint finding trước → sau | Thay đổi chính |
|---|---:|---:|---|
| XVWA | 25 → 25 | 2 → 2 | POI dòng 38 trở lại CRITICAL/HIGH, `source_to_sink`; `isset` không làm giảm mức |
| TCPDF 6.2.22 | 37 → 37 | 3 → 0 | Ba taint finding Phar qua bộ lọc wrapper không còn; giữ 36 nhận xét cú pháp INFO và một ứng viên POP LOW |
| WordPress 5.8.2 | 419 → 419 | 70 → 70 | 16 finding có `configured_local_path_review`; không tự giảm severity chỉ vì có predicate |

WordPress tại `plugin-editor.php:108` có MEDIUM/LOW cùng evidence của hằng đường
dẫn thay vì HIGH/HIGH. Hai sink unserialize vẫn cần kiểm tra: `functions.php:624`
có CRITICAL/HIGH và `class-wp-customize-widgets.php:1452` có HIGH/LOW; cả hai giữ
`guarded_flow_review`. Severity thể hiện tác động tiềm năng của luồng, không phải
kết luận đã vượt được predicate, kiểm tra chữ ký hoặc xác thực ứng dụng.

Không có lỗi parse hoặc timeout trong ba lượt. XVWA và WordPress vẫn báo
`call_graph_limit`. Giữ nguyên tổng finding không có nghĩa bản sửa không tác
dụng: các taint finding bị loại có thể để lộ nhận xét cú pháp INFO tại cùng sink.
