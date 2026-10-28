# Giai đoạn 11: lập lịch summary theo thành phần liên thông mạnh

Đợt kiểm chứng: 21–22/10/2026.

## Vấn đề và thay đổi

Bộ lập lịch trước đây dùng một hàng đợi chung cho toàn bộ hàm. Khi summary
của một hàm đệ quy thay đổi, các hàm gọi nó được đưa lại vào hàng đợi dù nhóm
đệ quy chưa hội tụ. Do đó cùng một caller có thể phải tính lại nhiều lần.

`core/dataflow.py` bổ sung `summary_components()`, dùng thuật toán Kosaraju
với stack tường minh. Thuật toán phân nhóm các hàm gọi vòng lẫn nhau thành
SCC, sắp nhóm được gọi trước nhóm gọi. Không dùng đệ quy Python khi duyệt
đồ thị. `FlowProject.build()` xử lý từng SCC; thay đổi summary chỉ đưa lại
caller trong cùng SCC vào hàng đợi. Caller ngoài SCC được xử lý sau khi
nhóm phụ thuộc hội tụ.

Bản sửa giữ nguyên miền Flow, giới hạn chiều sâu trường, quy tắc guard,
binding đối số, sink và side effect. Không loại bớt fact để giảm thời gian.
Ngân sách tổng số lần đánh giá vẫn được giữ; nếu hết ngân sách và còn nhóm
hoặc phần tử hàng đợi chưa xử lý thì `converged=False`.

## Kiểm thử hồi quy

- 77 unittest method đạt.
- 64/64 ca nhỏ đạt, gồm 40 ca dương tính kỳ vọng; cấu hình mặc định.
- Đồ thị chuỗi 3.001 đỉnh được phân nhóm mà không chạm giới hạn đệ quy Python.
- Chuỗi PHP gồm 101 hàm chỉ cần 101 lượt tính summary, thay vì 201 lượt.
- Ca mô phỏng schema đệ quy có ba nhánh `anyOf`, `oneOf`, `items`, trường
  `default` và 30 wrapper giảm từ 186 xuống 36 lượt tính summary.
- So sánh trực tiếp với lịch cũ (ép toàn bộ hàm vào một nhóm): tập fact
  return và sink bằng nhau; đầu vào từ request vẫn được phát hiện, chuỗi
  hằng với schema rỗng không bị báo, request trong trường schema lồng nhau
  vẫn được phát hiện. Tổng fact return ở ca mô phỏng là 2.108 ở cả hai lịch.
- Ca đệ quy tương hỗ có sink và tham số tham chiếu giữ nguyên tập fact effect.

Các phép so sánh tập fact không so sánh toàn bộ nội dung trace và không
chứng minh tính chính xác với mọi chương trình PHP.

## Quét dự án thực tế

Artifact: `reports/evaluation/upgrade-scc-seven/` và
`reports/evaluation/upgrade-scc-wordpress/`. Mỗi thư mục có snapshot và
manifest mã nguồn; audit ghi nhận `changed_source_files=0`.

| Dự án | Finding | Thời gian (giây) | Trạng thái |
| --- | ---: | ---: | --- |
| Drupal 8.6.9 | 832 | 170,770 | Hoàn tất, giới hạn call graph |
| Laravel 5.6.29 | 122 | 21,161 | Hoàn tất, giới hạn call graph |
| Monolog (thư mục `monolog`) | 6 | 5,576 | Hoàn tất, giới hạn call graph |
| Monolog 1.23.0 | 29 | 3,683 | Hoàn tất, giới hạn call graph |
| Saloon 3.0.0 | 1 | 2,950 | Hoàn tất |
| TCPDF 6.2.22 | 103 | 43,727 | Hoàn tất |
| XVWA | 36 | 6,409 | Hoàn tất, giới hạn call graph |
| WordPress 5.8.2 | — | 600,375 | Timeout, không có báo cáo quét hoàn chỉnh |

Bảy dự án bật `--experimental-foreach-cfg`, tắt side effect thử nghiệm.
WordPress tắt cả hai tùy chọn. Không sử dụng LLM. Ngân sách POP lượt này là
depth 6, 10.000 paths, 250.000 expansions; baseline `upgrade-bind-dedup-seven`
dùng depth 10, 20.000 paths, 500.000 expansions. Vì cấu hình POP khác nhau
và có lượt chạy đồng thời, không dùng bảng thời gian này để kết luận mức
tăng tốc của riêng thay đổi SCC.

`comparison.json` ghi nhận cả bảy dự án không thêm hoặc mất cảnh báo theo
khóa rule/file/line/column/severity. Đây là kiểm tra ổn định tập cảnh báo,
không phải đối chiếu với ground truth. Trạng thái coverage, đường POP và
trace có thể khác. Audit xác thực bảy báo cáo, nhưng toàn bộ bộ tám dự án
vẫn **không đạt** vì WordPress timeout.

## Giới hạn và phần việc còn lại

SCC giảm việc tính lại caller, nhưng không hạn chế được độ lớn tập fact và
chi phí binding bên trong một nhóm đệ quy. WordPress vẫn timeout: chưa thể
coi vấn đề quét dự án lớn đã được giải quyết. Cần tiếp tục phân tích profile,
đặc biệt chi phí tổng hợp trường lồng nhau, trước khi thay đổi miền dữ liệu
hoặc đưa thêm cơ chế phân tích theo nhu cầu. Không hạ số finding bằng cách
cắt bỏ fact rồi coi đó là cải thiện độ chính xác.

Profile bổ sung (`upgrade-scc-wordpress/summary.prof`, `diagnostic.log`)
dừng có chủ đích sau ngân sách 90 giây phân tích summary. Stack tại thời
điểm dừng vẫn nằm trong `rest_sanitize_value_from_schema()` ở
`wp-includes/rest-api.php:2644`: một lần `bind` nhận 487 flow, và một lần
binding phía ngoài đã tích lũy 954 kết quả. Profile ghi nhận gần 12 triệu
lượt tính độ dài trace trong vòng lặp binding. Điều này củng cố rằng việc
kết hợp fact bên trong nhóm đệ quy vẫn là điểm nóng; tối ưu lịch caller
chưa đủ. Profile bị ngắt chủ đích không phải báo cáo quét hoàn chỉnh và
không được tính là một dự án đã kiểm thử thành công.

Các giới hạn heap, dispatch động, coverage theo từng finding và xác minh
chuỗi POP vẫn còn như ở giai đoạn trước.
