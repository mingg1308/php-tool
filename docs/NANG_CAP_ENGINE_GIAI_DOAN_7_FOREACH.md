# CFG cho foreach theo giá trị

Ngày: 19/10/2026.

Lịch sử giai đoạn 7. Kết quả sửa tiếp ngày 20/10 và lượt TCPDF đã hoàn tất
khi bật foreach nằm tại [giai đoạn 8](NANG_CAP_ENGINE_GIAI_DOAN_8_SUMMARY.md).

**Trạng thái: thử nghiệm, tắt mặc định.** Bật bằng
`--experimental-foreach-cfg`, hoặc `ScannerConfig(experimental_foreach_cfg=True)`.
Chưa đạt hồi quy hiệu năng TCPDF; không coi tính năng này là đã hoàn thiện.
Chế độ mặc định tiếp tục dùng taint foreach cũ, ghi `foreach_cfg_disabled`.

## Phạm vi và cơ chế

Hỗ trợ `foreach ($items as $value)` với biến đơn nhận giá trị. Iterable được
đánh giá tại điểm vào vòng, trước khi ghi biến binding. CFG có block kiểm tra
phần tử tiếp theo, block binding và block thoát. Mỗi lần đi vào thân thực hiện
GEN/KILL cho binding; continue quay về kiểm tra phần tử, break đi ra ngoài.

Đường không chạy thân được giữ để không mất giá trị có trước vòng khi iterable
rỗng. Dữ liệu gán trong thân có thể truyền đến lần lặp tiếp theo. Đổi biến
iterable trong thân không làm thay đổi dữ liệu đã chụp tại điểm vào vòng theo
mô hình duyệt theo giá trị. Không mô phỏng heap, Iterator tùy biến hay số lượng
phần tử chính xác.

Key/value, by-reference, destructuring và binding không phải biến đơn vẫn
fallback toàn scope với `foreach_binding`. Phân tích taint cũ của các binding
này vẫn được giữ; fallback không có nghĩa đã phân tích CFG đầy đủ.

Trường `analysis.control_flow.loop_dataflow` đổi thành
`while_do_for_foreach_value_variables`. Comment giữa các thành phần foreach
không còn làm lệch lựa chọn iterable hoặc binding.

## Hồi quy guard được sửa

Bật CFG foreach khiến quy tắc cũ bỏ guard cho mọi scope có vòng lặp được áp
dụng rộng hơn. Ba test Phar đã phát hiện cảnh báo thừa ở bộ lọc wrapper và
validator bên trong foreach.

Đã giữ guard cho biến không có phép ghi trong scope, hoặc biến chỉ được ghi
bởi một binding foreach và đang được đọc bên trong thân của vòng đó. Các
điều kiện nhận diện guard, thứ tự và dominance cũ vẫn phải thỏa mãn. Biến có
phép ghi khác tiếp tục được xử lý bảo thủ, không suy ra an toàn xuyên lần lặp.
Đây là chứng minh trong mô hình phép ghi hiện có, chưa bao phủ alias/reference
hoặc tác động phụ chưa được mô hình hóa.

## Kiểm thử chức năng

- 59 unittest method đạt, gồm 18 tình huống foreach mới, hai dạng fallback
  binding, test giữ finding khi vượt budget CFG và khi tắt CFG foreach.
  Helper unittest bật chế độ thử nghiệm để thực sự kiểm tra CFG mới.
- Test bao gồm source, hằng an toàn, ghi đè, khả năng 0 lần lặp, dữ liệu qua
  backedge, break/continue lồng nhau, thay đổi iterable trong thân, cùng tên
  iterable/binding, comment và truyền nguồn qua summary liên hàm.
- Các test hồi quy wrapper filter, validator và tình huống ghi đè sau guard
  đều đạt lại sau sửa.
- 64/64 ca nhỏ qua pipeline mặc định, lưu tại `reports/evaluation/upgrade-foreach-small`.

## Hồi quy hiệu năng và biện pháp giới hạn

Các lượt `upgrade-foreach-validated`, `upgrade-foreach-cached` và
`upgrade-foreach-final` đều timeout ở TCPDF (180, 240 và 180 giây).
Không dùng các lượt này làm bằng chứng quét TCPDF thành công.

Đã thêm cache cho kết quả fixed point đã hội tụ, xóa khi xây dựng lại summary.
Cache này qua test nhưng chưa đủ để xử lý timeout. CPU profiler có giới hạn
thời gian chỉ ra chi phí lớn ở dựng CFG; đây là profile bị ngắt, không phải
báo cáo quét hoàn tất. Log stack bằng faulthandler trước đó không đủ dữ liệu.

CFG không còn lưu location cho từng literal không có đọc/ghi hoặc điều khiển.
Tuy vậy, riêng thay đổi này vẫn chưa đưa TCPDF về dưới timeout. Đã bổ sung
giới hạn node duyệt cho mỗi scope; thử nghiệm 50.000 node trong
`upgrade-foreach-budgeted` vẫn timeout TCPDF ở 180 giây. Ngưỡng hiện tại là
5.000 node; scope vượt ngưỡng fallback toàn bộ
và ghi `cfg_node_budget`. Không dùng đồ thị xây dở để loại luồng. Giới hạn này
đổi độ chi tiết CFG lấy khả năng hoàn tất; không phải hỗ trợ đầy đủ scope lớn.

Ngưỡng 5.000 node (`upgrade-foreach-bounded`) vẫn timeout TCPDF. Thử giới
hạn riêng scope foreach 256 node (`upgrade-foreach-safe`) cũng timeout ở
180 giây. Vì vậy không kết luận các budget này đã giải quyết điểm nghẽn.
Giữ ngưỡng 256 trong chế độ thử nghiệm với `foreach_cfg_budget`, và tắt
CFG foreach mặc định. Cần profile sâu hơn sau giai đoạn dựng CFG trước khi
cân nhắc bật lại mặc định. Các thử nghiệm thất bại được giữ nguyên để đối chiếu.

## Kết quả cuối ở chế độ mặc định

Snapshot và JSON: `reports/evaluation/upgrade-foreach-default`. Đã kiểm tra
hash snapshot với manifest và mã nguồn hiện tại: không khác. Các JSON đọc
lại hợp lệ qua schema `ScanResult`.

| Dự án | Finding | Giây subprocess | Lỗi/giới hạn |
|---|---:|---:|---|
| monolog-1.23.0 | 23 | 4,363 | call_graph_limit |
| saloon-3.0.0 | 1 | 2,884 | Không ghi nhận |
| tcpdf-6.2.22 | 37 | 36,381 | Không ghi nhận |
| xvwa | 25 | 3,609 | call_graph_limit |

Không thêm/mất finding khi so sánh multiset rule, vị trí và severity với
`upgrade-for-validated`. Không có lỗi parser, summary hay loop solver.
PHP mục tiêu: Saloon 8.1, các dự án còn lại 7.4; application mode, POP depth
10, tối đa 20.000 path và 500.000 expansion; không dùng LLM.

Thời gian này là một lượt đo, không chứng minh tốc độ tăng bao nhiêu do riêng
cache hoặc cắt literal. Cấu hình mặc định tắt tính năng mới; **kết quả đạt
này không chứng minh chế độ thử nghiệm đã hết timeout**. Riêng TCPDF có 11
scope ghi `cfg_node_budget`, cùng các lý do fallback khác. Chưa quét lại bốn
dự án còn lại trong bộ tám dự án.

## Giới hạn còn lại

Chưa hỗ trợ CFG binding key/value, by-reference, destructuring; switch và
exception/finally vẫn fallback. Chưa giải đầy đủ alias/heap, side effect
liên hàm hoặc xác minh khả năng khai thác của chuỗi POP.
