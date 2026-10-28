# Luồng dữ liệu vòng lặp và kiểm thử toàn dự án

Ngày cập nhật: 19/10/2026.

## Mã nguồn đã thay đổi

- CFG bổ sung cạnh quay lại cho `while` và `do…while`, phân biệt khả năng chạy
  0 lần của while với chạy thân ít nhất một lần của do…while. Điều kiện không
  được giải giá trị cụ thể; cả khả năng tiếp tục và thoát đều được giữ.
- Reaching definitions cho phép định nghĩa ở cuối thân lặp đến lần sử dụng
  trong lần lặp sau, thay vì loại chỉ vì byte offset nằm sau use.
- Đánh giá taint dùng trạng thái vòng tính trước khi gặp chu trình. So sánh
  tập khóa flow để hội tụ; trace không tạo vòng tăng vô hạn. Chỉ biểu thức
  trong scope có vòng lặp được hỗ trợ mới bật cơ chế này.
- Guard suy ra bằng thứ tự AST không được dùng để chứng minh giá trị đã sạch
  xuyên các lần lặp. Điều này có thể tăng review finding nhưng tránh loại sai.
- Sau 128 vòng chưa ổn định, ghi `loop_fixed_point` và giữ kết quả là chưa đầy
  đủ. Không có lỗi không đồng nghĩa hỗ trợ mọi hành vi PHP.

## Hồi quy phát hiện trên dự án thật

Lượt `upgrade-loops-full` phát hiện lỗi `maximum recursion depth exceeded`
trong taint summary. Một chu trình như `$x .= 'suffix'` làm `read()` gọi lại
chính nó khi reaching definitions chứa phép gán từ lần lặp trước.

Đã bổ sung chốt chu trình cho phép đọc: dùng trạng thái vòng tính trước, tương
tự chốt của biểu thức. Test mới bao gồm `.=` với nguồn request, chỉ hằng và
sink đứng trước phép nối để kiểm tra ảnh hưởng của lần lặp sau.

Không dùng lượt lỗi đó làm kết quả chấp nhận. Giữ nguyên snapshot và log để
đối chiếu; bộ chấp nhận kết hợp `upgrade-loops-validated` với
`upgrade-loop-tail-diagnosis`. Hai bộ có manifest mã nguồn giống nhau.
Lượt WordPress đầu tiên tạo JSON rỗng; runner trước đó dừng khi đọc JSON này.
Đã sửa runner để lưu `report_error` và tiếp tục dự án kế tiếp. Lượt chạy lại
WordPress và XVWA hoàn tất. Chưa xác định chắc chắn nguyên nhân tiến trình
WordPress đầu tiên tạo tệp rỗng.

## Các lớp kiểm thử

1. 52 unittest method qua, có nhiều subcase cho while/do, taint đi qua nhiều
   lần lặp, vòng không có source, ghi đè, return và summary liên hàm; thêm
   kiểm tra xuất JSON nguyên tử và giữ route có guard khi gộp nhiều caller.
2. 64/64 ca nhỏ qua toàn pipeline, lưu tại
   `reports/evaluation/upgrade-release-small`. Oracle chỉ đánh giá
   taint tới unserialize theo mô hình; không phải precision 100% ngoài thực tế.
3. Tám dự án được quét ở application mode, PHP mục tiêu theo dự án, depth POP
   10, tối đa 20.000 path và 500.000 expansion. Mỗi subprocess tối đa 600 giây.
4. Saloon chạy thêm library mode trong `upgrade-loops-library` để kiểm tra
   API exposure; kết quả này không gộp với cảnh báo request của application mode.
5. `scripts/audit_upgrade.py` kiểm tra schema, số finding, các lỗi vận hành,
   đủ danh sách dự án và hash source khớp snapshot. Giới hạn POP vẫn được giữ
   nguyên trong audit; không bị đổi tên thành thành công đầy đủ.

## Kết quả quét dự án thật

Audit: `reports/evaluation/upgrade-loops-validated/audit.json`, dùng bổ sung
`upgrade-loop-tail-diagnosis`. Thời gian là thời gian subprocess, tính bằng giây.

| Dự án | Tệp | Finding | Giây | Giới hạn còn ghi nhận |
|---|---:|---:|---:|---|
| drupal-8.6.9 | 8.855 | 495 | 233,567 | Call graph |
| laravel-5.6.29 | 1.174 | 35 | 29,737 | Call graph |
| monolog | 228 | 1 | 15,542 | Call graph, gadget budget |
| monolog-1.23.0 | 167 | 23 | 5,822 | Call graph |
| saloon-3.0.0 | 332 | 1 | 4,376 | Không ghi nhận lỗi |
| tcpdf-6.2.22 | 227 | 37 | 71,379 | Không ghi nhận lỗi |
| wordpress-5.8.2 | 1.212 | 419 | 398,391 | Call graph |
| xvwa | 304 | 25 | 4,993 | Call graph |

Tổng: 12.499 tệp, 1.036 finding. Finding gồm cảnh báo cú pháp, taint và
candidate POP; **không phải 1.036 lỗ hổng được xác nhận**. Bộ chấp nhận không
còn lỗi parser, taint summary hoặc loop fixed point. Những scope fallback
và cạnh POP bị giới hạn vẫn có thể gây bỏ sót. Không sử dụng LLM trong lượt này.

WordPress vẫn chậm: riêng pha graph và summaries khoảng 323,49 giây, trên
tổng scan khoảng 388,78 giây. Đây là vùng cần tối ưu tiếp; chưa có bằng chứng
để kết luận vòng nâng cấp này cải thiện tốc độ quét.

## Kích thước và độ an toàn của báo cáo

- JSON ghi dần vào tệp tạm cùng thư mục và thay thế đích sau khi hoàn tất.
  Test lỗi ghi xác nhận báo cáo cũ được giữ và tệp tạm được dọn. Tiến trình
  bị hệ điều hành dừng đột ngột vẫn có thể để lại tệp tạm.
- Chỉ xuất tối đa 32 route đại diện mỗi finding, ưu tiên khác biệt về nguồn,
  uncertainty, guard và giả định. Taint vẫn xét toàn bộ route trước bước này.
  Cờ truncation và limitation báo rõ bằng chứng hiển thị chưa đầy đủ.
- `scripts/compact_report.py` tái xuất báo cáo WordPress thành
  `reports/evaluation/wordpress-upgrade-compact.json`: từ 247.970.791 xuống
  12.369.651 byte, giữ nguyên 419 finding, ID, vị trí và severity.
  Đây là **tái xuất, không phải quét lại**; metadata lưu hash đầu vào.
- Snapshot quét tám dự án có trước thay đổi xuất JSON và giới hạn evidence.
  Mã sau thay đổi này được kiểm tra bằng 52 unittest và 64 ca nhỏ. Audit
  ghi rõ các tệp khác snapshot, kể cả tệp mới; không coi các phiên bản là một.

## Ma trận hoàn thiện hiện tại

| Thành phần | Đã có | Phần còn thiếu |
|---|---|---|
| Evidence | Route, guard, assumptions, assessment, JSON/SARIF | Coverage chính xác theo dependency từng finding |
| CFG | Tuần tự, nhánh, return/throw, while/do | For/foreach, break/continue, switch, exception/finally, goto |
| Reaching definitions | Biến đơn ghi độc lập, hợp nhánh và backedge | Field/heap tổng quát, alias/reference |
| Liên hàm | Return/sink summary bằng worklist | Side effect trên thuộc tính/global/reference tổng quát |
| Luật | Search subset, kiểm tra schema và lỗi rõ ràng | Matcher cấu trúc đầy đủ, model registry thống nhất |
| POP | Candidate chain, budget và coverage | Chứng minh property control, liên kết với điểm deserialize |
| LLM | Đánh giá bổ sung tùy chọn | Không dùng làm bằng chứng xác nhận khai thác |

Vì các mục ở cột cuối còn tồn tại, không được gọi bản này là hoàn thành mọi
nâng cấp của project. Kết quả test và scan chỉ xác minh phạm vi đã triển khai.
