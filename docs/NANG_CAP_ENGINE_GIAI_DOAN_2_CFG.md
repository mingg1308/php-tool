# Giai đoạn 2: CFG reachability và dominance có giới hạn

## Thay đổi

`core/control_flow.py` bổ sung đồ thị lệnh trong từng lexical scope, entry,
cạnh nhánh và lệnh kết thúc. Mỗi lệnh giữ liên kết tới AST qua node ID. Đây là
lớp statement CFG, chưa phải bộ IR chuẩn hóa biểu thức đầy đủ.

`FileFlow` dùng đồ thị để:

- Loại sink và return không thể tới trong scope hỗ trợ.
- Không truyền định nghĩa ở nhánh đã return/throw tới điểm hợp nhánh phía sau.
- Chứng minh dominance của phép gán độc lập: mọi đường tới use phải đi qua
  block của phép gán. Khi một nhánh kết thúc và nhánh còn lại gán hằng, định
  nghĩa taint cũ có thể được loại đúng.
- Giữ phép gán trong short-circuit là có điều kiện. Test mới phát hiện lỗi cũ
  với `$flag && ($x='safe')`: ghi đè đó không được làm mất taint của `$x` trên
  mọi đường đi. Đã thêm ngữ cảnh cho `&&`, `||`, `and`, `or`, `??`.

CFG không đánh giá giá trị predicate và không loại nhánh chỉ vì tên hàm có vẻ
là validator. Lời gọi bên trong biểu thức return/throw vẫn được kiểm tra.
Hàm lồng nhau có entry riêng; chưa chứng minh việc khai báo động đó reachable.

## Fallback và báo cáo

Scope có loop, switch, try/catch/finally, goto, break/continue, yield hoặc ERROR
không dùng CFG pruning. Trường hợp nesting vượt recursion limit cũng fallback.
Đây là duy trì mô hình cũ, không bảo đảm mô hình cũ đầy đủ cho các cấu trúc đó.

`analysis.control_flow` ghi mode, số scope/block, số scope được hỗ trợ và lý do
fallback. Finding taint được ghi `cfg_partial_project_coverage` nếu dự án còn
scope fallback; cách gắn giới hạn này bảo thủ ở cấp dự án, chưa theo dependency
của từng finding. Inventory giữ sink không reachable với disposition riêng.

## Kiểm thử

41 unittest method qua, gồm các subcase:

- Sink sau return/throw; sink bên trong return/throw.
- Caller chết, return summary chết.
- If/elseif/else đều kết thúc và nhánh còn đường sống.
- Phép gán tainted ở nhánh kết thúc; ghi đè hằng ở nhánh sống sót.
- Ghi đè có điều kiện trong short-circuit/ternary không che taint cũ.
- Scope loop/try/goto/switch giữ fallback; hàm lồng nhau có scope riêng.
- Inventory phân biệt unreachable với chưa tìm được source.

Hai lượt thực tế lưu tại `reports/evaluation/upgrade-cfg-xvwa.json` và
`reports/evaluation/upgrade-cfg-saloon.json`. XVWA dùng PHP 7.4; Saloon dùng PHP
8.1 và library mode. Không thực thi payload hoặc bật LLM.

## Phần chưa triển khai

Chưa có reaching definitions fixed-point trên loop, exception edges/finally,
alias/heap, side-effect summary hay xác minh dữ liệu xuyên chuỗi POP. CFG hiện
chỉ bổ sung kiểm tra reachability/dominance cho dataflow cũ. Không gọi trạng thái
này là đã hoàn thành thay thế toàn bộ engine bằng CFG.
