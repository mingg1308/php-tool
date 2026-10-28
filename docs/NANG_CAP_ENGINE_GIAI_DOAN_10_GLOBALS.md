# Giai đoạn 10: global, effect ở lối thoát và chi phí duyệt AST

## Thay đổi

### Summary tác động ghi

Trước đây, mọi ghi taint vào tham số tham chiếu đều có thể xuất hiện trong
summary, kể cả khi giá trị được ghi đè an toàn trước khi hàm kết thúc.
`ScopeCFG.effect_can_escape` kiểm tra còn đường từ ghi đến lối thoát mà
không đi qua phép ghi đè chắc chắn cùng vùng lưu trữ hay không.

Một nhánh ghi đè an toàn không đủ để xóa tác động ở nhánh còn lại.
Return sớm được giữ; throw cũng giữ tác động vì caller có thể bắt exception
và đọc dữ liệu đã bị thay đổi. Scope exception/finally hoặc CFG fallback
không dùng phép lọc này. Lời gọi hàm vẫn không được coi là phép xóa taint
chắc chắn ở caller.

### Global

- Lập chỉ mục khai báo `global $name` theo scope và vị trí.
- Dùng luồng symbolic global để bind giá trị tại caller.
- Xuất summary ghi global và truyền qua hàm trung gian.
- Phân biệt local trùng tên với global.
- Xử lý chuỗi hàm ghi rồi hàm đọc global, kể cả khi hàm trung gian không
  khai báo global của riêng nó.
- Áp dụng guard như `ctype_digit()` cho symbolic global; giữ thông tin
  chặn Phar và đường đi khi bind về caller.

Luồng global được đánh dấu không chắc chắn khi bind; đây là mô hình bảo thủ.
Chưa mô hình hóa đầy đủ `$GLOBALS`, tên biến động, alias global, khai báo
global có điều kiện, include/bootstrap order, heap và mọi tác động do exception.

### Duyệt thân phương thức

Profile toàn pipeline ghi nhận chi phí lớn ở
`ASTVisitor._analyze_method_body`. Đổi stack danh sách `named_children` sang
iterator dựa trên TreeCursor; bỏ qua nội dung literal không có biểu thức.
Vẫn bỏ qua scope hàm/class lồng bên trong như trước và giữ thứ tự thu thập.
Thay đổi không giới hạn số node hay cắt bớt cảnh báo.

## Kiểm thử đã xác nhận

- 71 unittest method đạt sau các thay đổi trên. Ca mới gồm global đọc/ghi,
  local trùng tên, wrapper, tham số vào global, return, throw, ghi đè ở một/
  cả hai nhánh và guard global.
- `upgrade-globals-small`: 64/64 ca, bật foreach thử nghiệm, trước bản sửa guard.
- `upgrade-globals-guards-small`: 64/64 ca, cấu hình mặc định, sau bản sửa guard
  và trước tối ưu duyệt AST.
- `upgrade-globals-guards`: bốn dự án Monolog 1.23.0, Saloon, TCPDF và XVWA.
  Đối chiếu rule/tệp/dòng/cột/severity với `upgrade-effects-validated`:
  không thêm hoặc mất finding. Đây là snapshot trước tối ưu duyệt AST.
- Kết quả đối chiếu có thể đọc trong
  `reports/evaluation/upgrade-globals-guards/comparison.json`.

## Các lượt chưa đạt và chẩn đoán

`upgrade-globals` hoàn tất sáu dự án nhưng Drupal và WordPress timeout.
Lượt WordPress ghi thời gian wall bất thường 17.275,415 giây dù cấu hình
timeout 600 giây; không sử dụng số này để kết luận tốc độ engine.
Không coi bộ này là kiểm thử đủ tám dự án đạt.

Profile trong `upgrade-globals-guards`:

- `drupal-summary.prof` và `drupal-diagnostic.log`: đo dựng summary.
- `drupal-whole.prof` và `drupal-whole.log`: đo toàn pipeline.

Lượt profile bị ngắt theo ngân sách là dữ liệu chẩn đoán, không phải một
báo cáo quét hoàn tất. `scripts/diagnose_flow.py --whole-scan` được bổ sung
để giới hạn đo toàn pipeline, tránh chờ vô hạn trước giai đoạn summary.

## Hồi quy sau tối ưu

`upgrade-globals-cursor` vẫn timeout ở Drupal và WordPress. Chỉ tối ưu
duyệt AST chưa khắc phục được vấn đề. Sáu dự án còn lại hoàn tất.

Profile summary dài hơn (`drupal-summary-long.prof`) chỉ ra chi phí gộp
luồng tăng lớn khi bind. Đã đổi `bind` từ gộp lại toàn bộ tuple sau mỗi
luồng sang cập nhật bảng theo khóa, vẫn giữ đại diện có trace ngắn nhất.
CFG cũng dùng bitset theo điểm xuất phát cho reachability/dominance,
thay vì duyệt lại đồ thị cho từng cặp definition/use.

Đồng thời sửa wildcard AST ở chỉ số mảng: `$_GET[...]` nay nhận chỉ số
literal hoặc biểu thức mà không nhầm với `$_POST`.

Bản có các sửa đổi này đạt 71 unittest và 64/64 ca nhỏ:
`reports/evaluation/upgrade-globals-batched-small`.
Các bài unittest cần quyền ghi thư mục tạm; một lượt chạy trong sandbox
bị mắc ở tempfile, còn lượt ngoài sandbox hoàn tất bình thường.

Snapshot hồi quy mới: `reports/evaluation/upgrade-globals-batched`.
Lượt này vẫn timeout ở Drupal (600,604 giây) và WordPress (600,121 giây),
sáu dự án còn lại hoàn tất. Chưa chứng minh tối ưu gộp luồng giải quyết
được khả năng mở rộng của mô hình effects.

## Tách mô hình effects sang tùy chọn thử nghiệm

Tham số CLI `--experimental-side-effects` và cấu hình cùng tên (dạng
snake_case) mặc định false. Khi tắt, công cụ vẫn phân tích return/sink liên
hàm như trước nhưng không áp dụng summary ghi qua reference/global mới.
JSON có `analysis.interprocedural_side_effects` ghi trạng thái và giới hạn;
không dùng việc tắt mô hình để tuyên bố quét đầy đủ hoặc mã nguồn an toàn.

72 unittest đạt, gồm test tích hợp cả hai chế độ. Helper của các ca kiểm
thử tác động hàm bật tùy chọn để tiếp tục kiểm tra tính năng thực nghiệm.

Hai nhóm `upgrade-effects-default-a` và `upgrade-effects-default-b` dùng
cùng snapshot, tắt side effects và vẫn bật foreach thử nghiệm. Chỉ được
gộp audit nếu manifest trùng nhau. Đây là phép cô lập hồi quy, không phải
kiểm chứng khả năng mở rộng khi bật effects.

Audit hai nhóm ghi nhận 7 báo cáo hợp lệ, không thay đổi mã nguồn so với
snapshot, nhưng chưa đạt toàn bộ do WordPress timeout. Drupal hoàn tất
222,008 giây, 832 finding, summary hội tụ; lỗi còn ghi nhận là
`call_graph_limit`. So với nền giai đoạn 8, Drupal không mất finding và thêm
178 INFO rà soát API Phar cùng 159 MEDIUM rà soát unserialize. Đây là mở rộng
đối sánh cú pháp, không phải 337 lỗ hổng mới đã chứng minh.

`upgrade-default-wordpress` tắt cả foreach và effects vẫn timeout 600 giây.
Như vậy tách effects chưa giải quyết toàn bộ hiệu năng WordPress. Profile
`wordpress-whole.prof` của thư mục này ghi nhận chi phí dựng summary và bind.
Lượt `upgrade-default-wordpress-extended` dùng giới hạn 1.200 giây để kiểm
chứng thêm; chỉ kết luận hoàn tất khi có JSON và audit hợp lệ.

Lượt mở rộng vẫn timeout 1.200,257 giây. Chẩn đoán stack tiếp theo xác định
điểm nóng tại `rest_sanitize_value_from_schema()` trong
`wp-includes/rest-api.php:2644`: bind các summary đệ quy tạo rồi loại bỏ
nhiều đối tượng flow/trace trùng. Đã bổ sung kiểm tra khóa flow và độ dài
trace trước khi tạo đối tượng mới, giữ nguyên quy tắc chọn trace ngắn nhất.
72 unittest đạt sau sửa đổi. Hai bộ snapshot kiểm chứng sửa đổi cuối này:
`upgrade-bind-dedup-wordpress` và `upgrade-bind-dedup-seven`.

### Kết quả cuối đợt, 21/10/2026

| Dự án | Finding | Giây | Trạng thái |
|---|---:|---:|---|
| Drupal 8.6.9 | 832 | 212,431 | Hoàn tất; call_graph_limit |
| Laravel 5.6.29 | 122 | 40,453 | Hoàn tất; call_graph_limit |
| Monolog mới | 6 | 12,494 | Hoàn tất; call_graph_limit, gadget_limit |
| Monolog 1.23.0 | 29 | 4,917 | Hoàn tất; call_graph_limit |
| Saloon 3.0.0 | 1 | 3,662 | Hoàn tất |
| TCPDF 6.2.22 | 103 | 48,007 | Hoàn tất |
| XVWA | 36 | 4,946 | Hoàn tất; call_graph_limit |
| WordPress 5.8.2 | Chưa có JSON hoàn chỉnh | 600,323 | Timeout |

Bảy dự án hoàn tất bật foreach thử nghiệm và tắt side effects. WordPress
tắt cả hai. Đây là thời gian từng lượt chạy, không phải benchmark thống kê.
Đối chiếu với hai nhóm `upgrade-effects-default-a/b` không thêm hoặc mất
finding theo rule, tệp, dòng, cột, severity. Audit xác nhận 7 báo cáo hợp lệ,
không có lỗi vận hành trong 7 báo cáo này và `changed_source_files=0`.
Audit toàn bộ vẫn **không đạt** vì thiếu báo cáo hoàn tất của WordPress.

72 unittest đạt; `upgrade-bind-dedup-small` đạt 64/64 ca end-to-end trên
bản mã cuối. Kết quả audit và đối chiếu nằm trong thư mục
`reports/evaluation/upgrade-bind-dedup-seven`.

Chưa khắc phục xong độ phức tạp summary đệ quy của WordPress. Tối ưu tránh
flow trùng giữ được kết quả ở bảy dự án nhưng chưa đủ để WordPress hoàn tất
trong 600 giây. Không coi việc tách tính năng thử nghiệm hoặc tăng timeout
là đã giải quyết vấn đề này.

Hai bộ ca nhỏ cuối cùng đều đạt 64/64:
`upgrade-effects-default-small` dùng cấu hình mặc định;
`upgrade-effects-optin-small` bật cả hai tùy chọn thử nghiệm.

## Phần còn lại

Heap/property identity, tham chiếu foreach và tác động qua backedge chưa đầy đủ.
POP vẫn cần chứng minh entry, property control và class loading.
Coverage từng finding và nhãn ground truth cho các dự án lớn vẫn còn cần
hoàn thiện. Các bài kiểm thử hiện có không chứng nhận phát hiện mọi lỗ hổng.

Rà soát POP ghi nhận thêm hai việc cần xử lý ở giai đoạn sau:

- `_chain_quality` còn ưu tiên các tên `processrecord`, `flush` và setter
  của thuộc tính dùng trong `close`. Đây là heuristic gắn với hình dạng
  thư viện cụ thể, chưa phải chứng minh điều khiển thuộc tính. Cần đánh giá
  lại thứ tự duyệt theo bằng chứng khi ngân sách đường đi bị giới hạn.
- Metadata của finding POP hiện chỉ ghi `candidate_call_chain`, cơ sở
  call-graph reachability và `exploitability_verified=false`. Chưa có liên
  kết được kiểm chứng giữa entry deserialization, lớp được phép khôi phục,
  thuộc tính được điều khiển và đối số sink. Không nâng confidence thành
  chứng nhận khai thác chỉ dựa trên một đường gọi hàm.
