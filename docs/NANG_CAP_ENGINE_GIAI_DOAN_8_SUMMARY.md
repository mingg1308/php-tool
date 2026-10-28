# Khắc phục hồi quy hiệu năng và guard khi bật foreach CFG

Ngày: 20/10/2026.

## Chẩn đoán có đo lường

Lượt chẩn đoán mới tách thời gian khởi tạo mỗi FileFlow khỏi CPU profile của
summary. Khởi tạo FileFlow cho tcpdf.php khoảng 0,8 giây trong một lượt đo;
không đủ cơ sở quy toàn bộ timeout cho dựng CFG như giả thuyết ban đầu.

Profile summary 30 giây cho thấy `review_conditions()` chiếm khoảng 25,4 giây
với gần 27.000 lần gọi. Sau cache, chi phí guard giảm nhưng số lần bind tăng
lên hơn 440.000 trong một profile 30 giây khác. Nhiều hàm chứa 1.072 biến thể
sink summary chỉ cho bốn định danh luồng taint, khác chủ yếu ở tổ hợp guard.
Các profile bị ngắt có thời gian và trạng thái khác nhau; không dùng chúng
để tính phần trăm tăng tốc toàn chương trình.

## Thay đổi

### Cache điều kiện và giới hạn biến thể bằng chứng

- Cache `review_conditions` theo cặp AST node của biểu thức và điểm sử dụng.
  Kết quả phụ thuộc AST, phép ghi và phân giải lời gọi tĩnh; không phụ thuộc
  giá trị taint của vòng summary hiện tại. Cache sống cùng FileFlow.
- Không duyệt lời gọi trong điều kiện nếu không còn biến liên quan.
- Chuẩn hóa định danh tập guard để không coi thứ tự liệt kê khác nhau là
  luồng taint mới.
- Mỗi định danh luồng giữ tối đa 16 biến thể guard. Nguồn, tham số, trường,
  trạng thái blocked_phar/uncertain, sink và giả định đường dẫn vẫn chia nhóm
  riêng. Không gộp các nguồn khác nhau thành một nguồn. Đường không guard
  được ưu tiên; sau đó chọn theo số guard và thứ tự ổn định.
- Khi vượt giới hạn, JSON có `analysis.summary_evidence_truncated`, metadata
  finding và limitation `summary_guard_alternatives_truncated`. Đây là rút
  gọn bằng chứng mô tả, không phải xác nhận các guard an toàn. Kết quả được
  đánh dấu limited để người đọc biết không có mọi biến thể bằng chứng.

### Guard và phép ghi ngoài vòng lặp

Lượt `upgrade-summary-guards` đã hết timeout nhưng tạo hai cảnh báo HIGH ở
tcpdf_static.php:1844 và 1848. Nguyên nhân: `_guard` bỏ guard khi biến có bất
kỳ phép ghi nào trong scope có vòng lặp, kể cả phép ghi nằm sau vòng lặp.

Trong `TCPDF_STATIC::file_exists`, vòng duyệt wrapper loại phar trước khi
gọi filesystem. Phép đổi dấu cách bằng str_replace xảy ra sau vòng này,
không thể truyền quanh backedge của nó. Đã thu hẹp quy tắc bỏ guard cho
phép ghi thực sự nằm trong vòng lặp; kiểm tra thứ tự định nghĩa/guard cũ vẫn
áp dụng. Test đối chứng thay phép đổi dấu cách bằng dữ liệu POST vẫn phải
giữ cảnh báo cho sink sau phép ghi mới.

Đây là suy luận trong mô hình hiện có, chưa xử lý đầy đủ alias/reference và
side effect chưa biết. Không suy ra khả năng khai thác chỉ từ taint.

## Kiểm thử và kết quả cuối

- 61 unittest method đạt. Test mới kiểm tra 40 nhánh guard không làm mất
  nguồn thứ hai hoặc đường không guard; thêm cặp test hồi quy TCPDF và phép
  ghi không an toàn sau guard.
- 64/64 ca nhỏ đạt khi bật foreach CFG trên bản cuối:
  `reports/evaluation/upgrade-summary-final-small`.
- Bộ 64 ca mặc định cũng đạt ở bản trước sửa guard cuối, tại
  `upgrade-summary-default-small`; không gắn nhãn đây là cùng snapshot cuối.
- Snapshot và JSON bốn dự án cuối: `reports/evaluation/upgrade-summary-validated`.
  Đã kiểm tra hash snapshot khớp manifest và mã hiện tại, đọc lại JSON bằng
  schema ScanResult và đối chiếu multiset rule, vị trí, severity với baseline
  `upgrade-foreach-default`.

| Dự án | Finding | Giây subprocess | Scope CFG hỗ trợ / fallback | Giới hạn còn lại |
|---|---:|---:|---:|---|
| monolog-1.23.0 | 23 | 7,222 | 1.217 / 41 | call_graph_limit |
| saloon-3.0.0 | 1 | 4,477 | 1.636 / 28 | Không có lỗi được ghi nhận |
| tcpdf-6.2.22 | 37 | 57,228 | 669 / 150 | Không có lỗi được ghi nhận |
| xvwa | 25 | 6,819 | 1.363 / 79 | call_graph_limit |

Không thay đổi rule/vị trí/severity ở bốn dự án; không lỗi parser, summary
hoặc loop solver. Tất cả summary hội tụ và **không chạm giới hạn 16 biến thể
guard** trong lượt cuối. TCPDF giữ cảnh báo cú pháp và candidate POP như
baseline; không còn hai taint finding thừa ở lượt trung gian.

Lượt này bật `--experimental-foreach-cfg`, application mode, Saloon PHP 8.1,
các dự án còn lại PHP 7.4; POP depth 10, 20.000 path và 500.000 expansion,
timeout 180 giây. Không dùng LLM hay chạy PHP mục tiêu. TCPDF từng timeout
180–240 giây khi bật foreach; bản cuối hoàn tất 57,2 giây. Không so con số
này như phép đo tăng tốc tương đương với baseline tắt foreach.

## Phạm vi chưa hoàn tất

Foreach CFG vẫn là tùy chọn thử nghiệm, tắt mặc định; giới hạn scope foreach
256 node và CFG chung 5.000 node vẫn giữ. Chưa quét lại Drupal, WordPress,
Laravel và Monolog phiên bản mới trong vòng này. Key/value, by-reference,
destructuring, exception flow, alias/heap và xác minh POP còn chưa đầy đủ.
