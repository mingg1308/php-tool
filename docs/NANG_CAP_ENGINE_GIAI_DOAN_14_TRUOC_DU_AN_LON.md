# Giai đoạn 14 — nâng cấp trước khi kiểm thử dự án lớn

Ngày kiểm chứng: 23/10/2026.

## 1. Thay đổi mã nguồn

### Luồng thuộc tính liên hàm

Module mới `core/object_effects.py` mô hình hóa may-write lên thuộc tính literal
của `$this` và tham số đối tượng. Summary được gắn vào đối tượng thực tế tại
nơi gọi, bao gồm tham số có tên. Getter và sink trong phương thức có thể đọc
thuộc tính do caller hoặc setter trước đó ghi vào. Hàm bao ngoài tiếp tục
truyền effect. Phép ghi chắc chắn đè lên giá trị trong callee và phép ghi local
sau lời gọi được xét theo mô hình CFG hiện có.

Các allocation khác nhau vẫn được tách trong scope thẳng. Alias biến đối tượng
được dùng để phân giải phương thức; khi có gán lại hoặc kiểu không xác định,
công cụ không dùng lại kiểu tham số cũ. Tên thuộc tính giữ nguyên hoa/thường,
khoảng trắng quanh `->` không tạo storage khác nhau.

Chỉ mục `scope_writes` tránh duyệt mọi phép ghi của cả file cho từng function.
Việc phân giải chuỗi alias có giới hạn 32 bước; khi không xác định được thì
không chọn tùy tiện một lớp.

### `$GLOBALS`

Hỗ trợ key literal hợp lệ, ví dụ `$GLOBALS['payload']`, gồm trường mảng con,
đọc/ghi qua hàm và wrapper. Storage global được tách khỏi biến local cùng tên;
ở top-level hoặc sau `global $payload`, hai dạng truy cập được nối đúng.
Key động và các dạng alias global phức tạp chưa được giải đầy đủ.

Các mô hình trên thuộc cờ `--experimental-side-effects`; mặc định vẫn tắt.
JSON ghi danh sách mô hình đang bật trong `analysis.interprocedural_side_effects`.
Các luồng thuộc tính mới được đánh dấu uncertain vì chưa chứng minh đầy đủ
kiểu runtime, magic property và trạng thái heap.

### CFG và finally

Sửa lỗi đã tái hiện: các block chết sau `return`/`throw` trong `try` bị tính là
lối thoát bình thường, khiến luồng giả tiếp tục sau `finally`. Chỉ các lối thoát
thực sự reachable mới cho phép nối vào luồng bình thường sau finally.
Ca có nhánh sống vẫn giữ cảnh báo. Đây không phải mô hình exception hoàn chỉnh:
các kiểu exception và completion qua finally vẫn được gộp bảo thủ.

### Coverage và chất lượng kết luận

`dependency_coverage` thêm số lượng và danh sách lời gọi không phân giải được
trong các scope phụ thuộc. Phân biệt lời gọi hàm ngoài/thiếu mã với dispatch
chưa xác định; không liệt kê các builtin đã có mô hình. Chỉ xét lời gọi reachable,
hiển thị tối đa 32 mục nhưng giữ tổng số và cờ truncated. Assessment bổ sung
`dependency_calls_unresolved`. Scope không liên quan không bị gắn vào finding.

Đây vẫn là dependency graph từ trace giữ lại và các callee phân giải được,
không phải chứng nhận đã phân tích đầy đủ mọi đường chạy.

### POP và luật AST

Ưu tiên tìm POP theo khoảng cách đã biết tới sink, thay cho heuristic ưu tiên
tên `close` hoặc callback của một số thư viện. Budget vẫn có thể làm thiếu
candidate; thay đổi thứ tự có thể thay đổi tập candidate khi hết budget.

Matcher dùng AST thêm cho phép gán, truy cập mảng/thuộc tính, biểu thức nhị phân
và tạo đối tượng. Candidate trong rule engine và chỉ mục AST được cập nhật để
không bỏ qua biểu thức lồng nhau. Ca âm kiểm tra code giả nằm trong chuỗi,
biến/thuộc tính khác hoa thường và metavariable lặp lại.
Chưa tương đương toàn bộ cú pháp/ngữ nghĩa của Semgrep.

## 2. Kiểm chứng trên mã hiện tại

| Bộ kiểm thử | Kết quả |
| --- | --- |
| Unittest | 103 method đạt |
| Ca nhỏ toàn pipeline, demand | 108/108 |
| Ca nhỏ toàn pipeline, eager | 108/108 |
| Ca constructor/thư viện, eager và demand | 24/24 |

Mỗi bộ 108 ca gồm 64 ca dương, 44 ca âm; 30 ca mới kiểm tra object/global
side effects. Cấu hình theo từng ca được lưu trong summary, không nên hiểu
mọi ca đều bật cùng một tập cờ. Các ca effects mới bật tùy chọn side effects.

Các artifact:

- `reports/evaluation/upgrade-prelarge-demand-small/`
- `reports/evaluation/upgrade-prelarge-eager-small/`
- `reports/evaluation/upgrade-prelarge-library-small/`

Mỗi thư mục có fixture PHP, kết quả JSON, summary và source manifest.
`upgrade-prelarge-demand-small/verification.json` xác nhận cả ba manifest khớp
mã package hiện tại. Không dùng LLM, không chạy lại công cụ ngoài trong đợt này.
Các số tham chiếu Progpilot/Psalm nếu có trong summary là dữ liệu lịch sử;
các ca mới không được gán kết quả tham chiếu giả.

## 3. Phạm vi chưa hoàn thiện

- Heap liên hàm chưa bao phủ constructor trong mọi ngữ cảnh ứng dụng, clone,
  alias theo nhánh, dynamic property và private property trùng tên qua kế thừa.
- Effect hiện là may-write; chưa có strong kill an toàn cho mọi setter/callee.
  Tham số bị gán lại/alias phức tạp có thể không xuất được property effect.
- CFG chưa giải đầy đủ exception type và từng completion qua finally;
  foreach CFG vẫn tùy chọn thử nghiệm.
- POP vẫn là candidate, chưa chứng minh runtime class loading, quyền kiểm soát
  thuộc tính hay khả năng kích hoạt sink từ payload thực tế.
- Coverage chưa bao phủ đầy đủ dynamic dispatch và trace bị lược bỏ; matcher
  chưa có toàn bộ ngữ nghĩa Semgrep.
- Chưa có đánh giá độ chính xác trên ground truth độc lập mới hoặc đo hiệu năng
  dự án lớn cho phiên bản này.

Vì vậy, đã hoàn thành các thay đổi và kiểm thử nhỏ được mô tả trong đợt này;
chưa thể tuyên bố toàn bộ công cụ đã hoàn thiện. **Chưa quét dự án lớn** theo
thứ tự công việc yêu cầu. Các báo cáo tám dự án trước đây thuộc snapshot cũ.

## 4. Tái lập

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -q
py -3.12 scripts/evaluate_small_cases.py --include-upgrade-cases --include-object-global-cases --output reports/evaluation/recheck-prelarge-demand
py -3.12 scripts/evaluate_small_cases.py --include-upgrade-cases --include-object-global-cases --eager-summaries --output reports/evaluation/recheck-prelarge-eager
py -3.12 scripts/evaluate_library_cases.py --output reports/evaluation/recheck-prelarge-library
```
