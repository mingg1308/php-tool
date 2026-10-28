# CFG cho break/continue

Ngày: 19/10/2026.

## Thay đổi

`core/control_flow.py` duy trì stack đích của các vòng while/do đang xây dựng.
Mỗi vòng có block thoát riêng. `break` đi tới block thoát; `continue` đi tới
điều kiện. Cả hai kết thúc đường tuần tự hiện tại, nên lệnh phía sau không
được coi là luôn có thể chạy. Với do/while, break bỏ qua điều kiện còn continue
vẫn đánh giá điều kiện.

Các cấp như `break 2`, `continue 2` chọn đích của vòng ngoài từ stack. Chỉ
chấp nhận số thập phân dương không có số 0 đầu. Định dạng khác, cấp vượt độ
sâu, hoặc bước nhảy ngoài vòng làm toàn scope dùng phân tích dự phòng, ghi
`unsupported_loop_jump`; không cắt đường bằng đồ thị thiếu đích.

Reaching definitions và solver taint dùng các cạnh này. Nhờ vậy nguồn chỉ được
gán sau break không truyền ra ngoài; nguồn gán trước continue có thể truyền
đến lần lặp sau; break không tạo đường quay lại giả.

## Kiểm thử

- 54 unittest method đạt. Test mới có 14 tình huống luồng nhảy và bốn tình
  huống fallback, kiểm tra cả cảnh báo cần có và cảnh báo cần loại.
- 64/64 ca nhỏ qua pipeline; JSON tại `reports/evaluation/upgrade-jumps-small`.
- Snapshot và JSON dự án tại `reports/evaluation/upgrade-jumps-validated`.
  PHP mục tiêu: Saloon 8.1, hai dự án còn lại 7.4; application mode, POP depth
  10, tối đa 20.000 path và 500.000 expansion, timeout 120 giây mỗi dự án.

| Dự án | Finding | Giây subprocess | Scope CFG hỗ trợ trước → sau | Lỗi/giới hạn |
|---|---:|---:|---:|---|
| monolog-1.23.0 | 23 | 7,930 | 1.162 → 1.163 | call_graph_limit |
| saloon-3.0.0 | 1 | 7,230 | 1.623 → 1.623 | Không ghi nhận |
| xvwa | 25 | 9,454 | 1.299 → 1.307 | call_graph_limit |

Đối chiếu với `upgrade-loops-validated` và bản XVWA trong
`upgrade-loop-tail-diagnosis`: không khác tập rule, vị trí và severity.
Không ghi nhận lỗi parser, summary hoặc loop solver trong ba lượt mới.
Lượt thăm dò `upgrade-jumps` dùng budget POP mặc định khác, không dùng để
so sánh bảng trên. Không sử dụng LLM hoặc thực thi mã PHP mục tiêu.

## Giới hạn

For/foreach, switch và try/finally vẫn làm scope fallback. Vì switch có ngữ
nghĩa bước nhảy riêng, không áp dụng stack vòng lặp cho scope chứa switch.
Chưa giải giá trị predicate, alias/heap hoặc side effect liên hàm tổng quát.
Ba dự án hồi quy không thay thế việc quét lại toàn bộ tám dự án; chưa tuyên
bố độ bao phủ PHP đầy đủ hay xác nhận khả năng khai thác của các finding.
