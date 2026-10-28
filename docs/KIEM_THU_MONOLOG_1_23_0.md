# Kiểm thử Monolog 1.23.0

> **Cập nhật sau nâng cấp:** Lượt quét gadget mới trên `src/Monolog` lưu tại
> [`after-gadget-upgrade.json`](../reports/evaluation/monolog-1.23.0/after-gadget-upgrade.json)
> đã giữ được chuỗi `SyslogUdpHandler::__destruct → SyslogUdpHandler::close →
> BufferHandler::close → BufferHandler::flush → AbstractHandler::handleBatch →
> BufferHandler::handle → call_user_func` (ID `c47409495791`). Lượt này quét
> 88 tệp, 8,88 giây, 173 chuỗi, không có lỗi hoặc giới hạn. Kết luận false
> negative bên dưới mô tả **bản quét cũ**; nguyên nhân thực tế là bước gộp
> chuỗi theo tên sink quá rộng, không phải đồ thị thiếu cạnh. Chuỗi vẫn là ứng
> viên tĩnh; điều kiện thuộc tính và callback chưa được xác minh bằng runtime.

## Mẫu và cấu hình

- Mẫu: `testcase/monolog-1.23.0`, gói `monolog/monolog`, commit `fd8c787753b3a2ad11bc60c063cff1358a32a3b4`.
- Quét bằng `php_deserial_sast.cli`, `--php-version 5.6 --experimental-side-effects --severity INFO`. Lượt thứ hai thêm `--library-mode`. Lượt thứ ba quét riêng `src/Monolog` với `--max-depth 10 --max-gadget-paths 100000 --max-gadget-expansions 500000`.
- JSON: [`default.json`](../reports/evaluation/monolog-1.23.0/default.json), [`library-mode.json`](../reports/evaluation/monolog-1.23.0/library-mode.json), [`src-deep.json`](../reports/evaluation/monolog-1.23.0/src-deep.json). Lượt thử trung gian [`deep-gadgets.json`](../reports/evaluation/monolog-1.23.0/deep-gadgets.json) chạm giới hạn 20.000 đường và **không** được dùng làm kết quả hoàn chỉnh.

| Chỉ số | Toàn bộ, mặc định | Toàn bộ, library mode | Chỉ `src`, quét sâu |
|---|---:|---:|---:|
| Tệp quét / lỗi | 167 / 0 | 167 / 0 | 88 / 0 |
| Thời gian | 3,41 giây | 4,19 giây | 11,44 giây |
| Cảnh báo HIGH / MEDIUM / LOW / INFO | 0 / 0 / 1 / 28 | 0 / 9 / 1 / 28 | 0 / 0 / 1 / 10 |
| Chuỗi gadget ứng viên trong JSON | 35 | 35 | 39 |
| Chạm giới hạn gadget | Không | Không | Không |

Không có lời gọi `unserialize` trong `src/Monolog`. Monolog là thư viện gadget: một ứng dụng khác phải đưa đối tượng có lớp Monolog vào quá trình giải tuần tự hóa thì magic method mới có thể được kích hoạt. Do đó không nên diễn giải 0 cảnh báo taint từ `unserialize` là kiểm chứng Monolog không thể tham gia khai thác, hoặc diễn giải chuỗi gadget ứng viên là một lỗ hổng độc lập trong Monolog.

## Đối chiếu chuỗi gadget đã công bố

[PHPGGC Monolog/RCE1](https://github.com/ambionics/phpggc/blob/master/gadgetchains/Monolog/RCE/1/chain.php) liệt kê phiên bản 1.17.2–2.7.0+, bao gồm 1.23.0, và dùng `SyslogUdpHandler` chứa `BufferHandler` tự tham chiếu. Đường gọi tương ứng trong mã nguồn:

1. `AbstractHandler::__destruct()` gọi `close()` trên đối tượng `SyslogUdpHandler`.
2. `SyslogUdpHandler::close()` gọi `$this->socket->close()`, với `socket` được thay bằng `BufferHandler` trong đối tượng đã giải tuần tự hóa.
3. `BufferHandler::close()` gọi `flush()`; `flush()` gọi `$this->handler->handleBatch($this->buffer)`, với `handler` trỏ về chính `BufferHandler`.
4. `AbstractHandler::handleBatch()` gọi `$this->handle($record)`; phép gọi ảo phải chọn `BufferHandler::handle()`.
5. `BufferHandler::handle()` gọi `call_user_func($processor, $record)`. Tính khả thi của callback và dữ liệu phụ thuộc cấu trúc đối tượng được tạo, các ràng buộc nhánh và môi trường chạy.

Đường này được đối chiếu tĩnh bằng mã nguồn và định nghĩa của PHPGGC; chưa chạy payload hoặc xác minh hành vi trên PHP runtime trong môi trường kiểm thử.

## Đánh giá kết quả công cụ

- Lượt quét mặc định tạo 35 chuỗi ứng viên trong `gadget_chains`, nhưng chỉ đưa 1 cảnh báo POP mức LOW ra `findings`: `FingersCrossedHandler::__destruct → array_filter`. Tại `FingersCrossedHandler.php:135`, đối số callback của `array_filter` là closure viết cố định trong mã, nên đường này **không chứng minh** khả năng gọi hàm tùy ý. Ngoài ra, điều kiện `passthruLevel` và dữ liệu `buffer` chưa được xác minh.
- Có ứng viên `SyslogUdpHandler::__destruct → FingersCrossedHandler::close → GroupHandler::handleBatch → call_user_func`, nhưng đây không phải chuỗi Monolog/RCE1 nói trên. Không có bằng chứng nguồn giải tuần tự hóa hoặc thuộc tính điều khiển được; không thể gán nhãn lỗ hổng xác nhận.
- `--library-mode` thêm 9 cảnh báo MEDIUM độ tin cậy LOW ở API tệp (`file_exists`, `file`, `fopen`, `is_writable`, `unlink`, `is_dir`) với giả định tham số API bên ngoài có thể kiểm soát. Chúng không chứng minh đầu vào `phar://` đến từ request hoặc metadata PHAR bị giải tuần tự hóa trong một ứng dụng cụ thể. 28 cảnh báo INFO là mẫu rà soát API đường dẫn, gồm 18 trong `tests`.
- Lượt `src` độ sâu 10 đã xét 38.628 đường, 125.042 cạnh, không chạm giới hạn và tìm 39 ứng viên, nhưng **không có** chuỗi `SyslogUdpHandler → BufferHandler → BufferHandler::handle → call_user_func`. Đây là false negative đối với chuỗi tham chiếu PHPGGC, không phải do ngân sách của lượt quét này. Dấu hiệu chính là đồ thị chưa nối đủ phép gọi ảo `handleBatch` kế thừa và cạnh tự tham chiếu của `BufferHandler`.

**Kết luận:** công cụ nhận ra nhiều thành phần magic method và sink động, nhưng chưa tái dựng chính xác chuỗi gadget đã công bố cho Monolog 1.23.0. Cần kiểm tra điều kiện thuộc tính và callback trước khi nâng mức tin cậy của các ứng viên hiện có.

## Hướng kiểm thử và cải thiện kế tiếp

1. Tạo fixture tối giản với `SyslogUdpHandler`, `BufferHandler` tự tham chiếu và callback vô hại để kiểm tra riêng `inherited handleBatch → virtual handle`; đối chiếu kết quả đồ thị với đường PHPGGC.
2. Theo dõi kiểu receiver qua thuộc tính được giải tuần tự hóa và qua lời gọi trên đối tượng tự tham chiếu, đồng thời giới hạn nhánh ảo theo kiểu receiver thực tế.
3. Phân biệt callable cố định (closure trong `array_filter`) với callable lấy từ thuộc tính có thể điều khiển. Chỉ báo cáo chuỗi khả thi khi điều kiện nhánh, thuộc tính và điểm giải tuần tự hóa được kiểm tra.
4. Hiển thị rõ tỷ lệ chuỗi trong `gadget_chains` được đưa ra `findings` và lý do lọc, để người dùng không bỏ qua ứng viên đáng xem xét.
