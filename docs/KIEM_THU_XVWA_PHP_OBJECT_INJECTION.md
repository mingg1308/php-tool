# Kiểm thử XVWA: PHP Object Injection

## Phạm vi và cấu hình

- Mẫu chính: `testcase/xvwa/vulnerabilities/php_object_injection`, commit project `fb30fa517d288e618b521d252f61107ef6a24797`.
- Lượt đối chứng: toàn bộ `testcase/xvwa`, cùng PHP mục tiêu 7.4 và ngưỡng `INFO`.
- JSON: [`scoped.json`](../reports/evaluation/xvwa-php-object-injection/scoped.json) và [`full-xvwa.json`](../reports/evaluation/xvwa-php-object-injection/full-xvwa.json).

| Chỉ số | Thư mục chỉ định | Toàn bộ XVWA |
|---|---:|---:|
| Tệp quét / lỗi | 2 / 0 | 304 / 0 |
| Thời gian | 0,015 giây | 3,673 giây |
| Tổng cảnh báo | 2 | 36 |
| Cảnh báo tại `php_object_injection/home.php` | 2 | 2 |
| Sink có nguồn request được quan sát tại `home.php:38` | Có | Có |
| Gadget `PHPObjectInjection::__wakeup → eval` | Có | Có |

## Chuẩn đối chiếu từ mã nguồn

`index.php:49` nạp `home.php`. Trong `home.php`, lớp `PHPObjectInjection` được khai báo trước lời gọi `unserialize`; thuộc tính `$inject` là `public`. `__wakeup()` tại dòng 30–34 kiểm tra `isset($this->inject)` rồi gọi `eval($this->inject)` ở dòng 32. Khi có `$_REQUEST['r']`, dòng 38 gọi thẳng `unserialize($_REQUEST['r'])`; `isset` ở dòng 36 chỉ kiểm tra tham số tồn tại, không kiểm tra cấu trúc serialized object hoặc vô hiệu hóa việc tạo lớp.

Vì lớp đã được nạp, một chuỗi serialized object hợp lệ của `PHPObjectInjection` chứa thuộc tính công khai `inject` có thể kích hoạt `__wakeup` và chuyển nội dung thuộc tính tới `eval`. Đây là đường PHP Object Injection dẫn đến thực thi mã theo phân tích tĩnh của test case. Lượt này không chạy payload trên PHP runtime, nên báo cáo không ghi là đã kiểm chứng thực thi động.

## Kết quả và độ chính xác của công cụ

- Cảnh báo `php-unserialize-tainted-input` ở `home.php:38` có mức CRITICAL, confidence HIGH. Dấu vết gồm đúng hai bước `$_REQUEST['r'] → unserialize($_REQUEST['r'])`, `source_kind=request`, `sink_inventory=observed_request`. Đây là **true positive** cho đường nguồn tới sink, không cần suy luận gián tiếp.
- Cảnh báo `php-pop-gadget-chain` ở `home.php:30` tìm đúng `PHPObjectInjection::__wakeup → eval($this->inject)` và ghi `sink_type=RCE`. Công cụ cho riêng ứng viên này mức LOW, mặc dù trong ca cụ thể thuộc tính là public, lớp được nạp trước sink và input serialized do request kiểm soát.
- Hai lượt quét cho cùng kết quả ở test case, vì toàn bộ đường nguồn, sink và lớp gadget đều nằm trong `home.php`. Quét rộng hơn thêm cảnh báo của các module XVWA khác nhưng không làm mất hoặc đổi mức cảnh báo mục tiêu.
- Báo cáo hiện xuất hai phát hiện riêng; `dataflow_trace` của cảnh báo CRITICAL không nối tiếp sang `gadget_chain`, và chuỗi gadget vẫn ghi chung rằng chưa xác minh điểm giải tuần tự hóa hay quyền điều khiển thuộc tính. Với test case này, liên kết đó có thể được chứng minh ngay trong cùng tệp.

**Kết luận:** công cụ phát hiện đúng test case PHP Object Injection của XVWA ở cả phạm vi hẹp và toàn project. Hạn chế là chưa hợp nhất bằng chứng nguồn request, đối tượng giải tuần tự hóa, thuộc tính `inject` và `eval` thành một kết luận RCE có thể giải thích trọn vẹn.

## Hướng cải thiện kiểm thử hồi quy

1. Nối `unserialize` với các magic method của lớp có thể được tạo từ serialized input, rồi theo dõi thuộc tính public tới sink trong magic method.
2. Phân biệt guard `isset` chỉ kiểm tra sự tồn tại với kiểm tra tính an toàn của dữ liệu.
3. Giữ hai cấp báo cáo: source-to-sink đã chứng minh và chuỗi gadget; khi cùng một case thỏa cả hai, tạo bằng chứng tổng hợp với tiền điều kiện cụ thể, thay vì tự động nâng mọi ứng viên gadget thành RCE.
