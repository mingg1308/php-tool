# Nâng cấp CFG cho vòng for

Ngày: 19/10/2026.

## Cơ chế

Vòng for được tách thành các khối theo thứ tự thực thi PHP:

1. Khởi tạo chạy một lần khi vào vòng.
2. Đánh giá điều kiện trước mỗi lần chạy thân.
3. Thân kết thúc bình thường hoặc continue thì chạy cập nhật.
4. Cập nhật xong quay lại điều kiện. Break đi thẳng đến khối thoát.

Điều kiện bỏ trống không tạo cạnh thoát; một vòng `for (;;)` chỉ có đường
ra khi có break hoặc cơ chế kết thúc được mô hình hóa. Điều kiện hiện diện
vẫn được xem có cả khả năng đúng và sai, chưa giải giá trị biểu thức.
Stack vòng lặp giữ đúng đích cho `continue 2` hoặc `break 2` khi lồng for
với while/do.

Các biểu thức phân cách bằng dấu phẩy trong header có block riêng theo thứ
tự trái sang phải. Phép gán biến đơn ở cấp ngoài cùng của biểu thức header
tham gia GEN/KILL; phép gán lồng trong biểu thức điều kiện vẫn dùng fallback
cho biến đó. Không coi phép gán short-circuit là ghi đè vô điều kiện.

Trường `analysis.control_flow.loop_dataflow` hiện là
`while_do_for_standalone_variables`. For không còn làm toàn scope fallback.

## Kiểm thử chức năng

55 unittest method đạt. Method mới có 16 tình huống: nguồn ở khởi tạo,
ghi đè an toàn, nguồn ở cập nhật, break bỏ cập nhật, continue đi qua cập nhật,
vòng có thể chạy 0 lần, vòng không có điều kiện, sink trong cập nhật, thứ tự
phép gán dấu phẩy, nguồn trong điều kiện và bước nhảy qua vòng lồng nhau.

64/64 ca nhỏ qua pipeline; báo cáo trong
`reports/evaluation/upgrade-for-small`.

## Hồi quy trên dự án thật

Snapshot và JSON nằm tại `reports/evaluation/upgrade-for-validated`.
Hash các tệp trong snapshot khớp manifest và mã nguồn tại thời điểm kiểm tra.
Các JSON được đọc lại qua schema `ScanResult` trước khi đối chiếu.

| Dự án | Finding | Giây subprocess | Scope CFG hỗ trợ trước → sau | Lỗi/giới hạn |
|---|---:|---:|---:|---|
| monolog-1.23.0 | 23 | 8,192 | 1.163 → 1.165 | call_graph_limit |
| saloon-3.0.0 | 1 | 5,872 | 1.623 → 1.623 | Không ghi nhận |
| tcpdf-6.2.22 | 37 | 72,548 | 563 → 648 | Không ghi nhận |
| xvwa | 25 | 7,061 | 1.307 → 1.318 | call_graph_limit |

Không có finding thêm hoặc mất khi so sánh bộ rule, vị trí và severity,
tính cả số lần xuất hiện. Không có lỗi parser, summary hoặc loop solver.
Ba dự án so với `upgrade-jumps-validated`; riêng TCPDF so với
`upgrade-loops-validated`, nên mức tăng scope của TCPDF gồm cả hỗ trợ bước
nhảy đã bổ sung ở giai đoạn trước.

Application mode, Saloon dùng PHP 8.1; ba dự án còn lại PHP 7.4. Giới hạn
POP giữ như baseline: depth 10, 20.000 path, 500.000 expansion. Timeout
180 giây mỗi dự án. Không sử dụng LLM hoặc chạy mã PHP mục tiêu. Chưa chạy
lại bốn dự án còn lại của bộ tám dự án trong vòng nâng cấp này.

## Phạm vi còn thiếu

Foreach, switch, try/catch/finally và goto vẫn fallback. Chưa mô hình hóa đầy
đủ alias, heap, side effect liên hàm hoặc chứng minh khả năng khai thác POP.
Hỗ trợ CFG for không đồng nghĩa giải chính xác số lần lặp hay giá trị chỉ số.
