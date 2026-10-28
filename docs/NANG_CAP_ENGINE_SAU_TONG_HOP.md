# Nâng cấp engine sau đối chiếu các case study

## Thay đổi đã thực hiện

1. **Giữ chuỗi gadget theo vị trí sink.** Bước gộp cũ chỉ dùng lớp entry, magic method và tên hàm sink. Hai lời gọi `call_user_func` trong các handler khác nhau vì thế bị xem như một kết quả. Bước mới phân biệt cả lớp và phương thức chứa sink, giữ tối đa hai đường gọi khác nhau cho mỗi vị trí. Finding POP ở cùng vị trí entry vẫn được gộp để tránh lặp cảnh báo; metadata `alternative_gadget_chain_ids` cho phép truy ngược các chuỗi trong `gadget_chains`.
2. **Ghi nhận guard khi lời gọi nằm trong phép gán.** Phép gán chứa chính lời gọi được phân tích trước đây bị tính nhầm là một write xảy ra giữa điều kiện và lời gọi. Kiểm tra mới yêu cầu write hoàn tất trước vị trí use. Nhờ đó guard ở hàm gọi được truyền vào bằng chứng sink ở hàm đích.
3. **Giữ nguyên mức cảnh báo cho guard chưa rõ nghĩa.** Bộ kiểm thử chỉ ra `is_serialized()` và các helper tùy ý có thể vẫn cho payload object đi qua. Engine ghi điều kiện cần rà soát nhưng không tự hạ severity dựa trên tên hoặc sự hiện diện của guard.

## Kết quả xác minh

| Ca | Kết quả sau sửa | Giới hạn |
|---|---|---|
| Monolog 1.23.0, chỉ `src/Monolog`, gadget depth 10 | 88 tệp, 8,88 giây, 173 chuỗi, 0 lỗi. Chuỗi `SyslogUdpHandler::close → BufferHandler::close → flush → AbstractHandler::handleBatch → BufferHandler::handle → call_user_func` có ID `c47409495791`. | Đây là đường gọi ứng viên; chưa chứng minh thuộc tính và callback khả dụng từ một payload. Số chuỗi tăng vì giữ nhiều vị trí sink và tối đa hai biến thể cho mỗi vị trí. |
| XVWA PHP Object Injection | Giữ CRITICAL `$_REQUEST['r'] → unserialize` dòng 38 và LOW `__wakeup → eval` dòng 30; 0 lỗi. | Hai bằng chứng chưa thành một chứng minh khả năng khai thác tự động. |
| Saloon 3.0.0 | Giữ một HIGH tại `AccessTokenAuthenticator.php:105` với `allowed_classes => true`; 0 lỗi. | Cần caller thực tế để chứng minh dữ liệu không tin cậy đi đến API. |
| WordPress 5.8.2, PHP 7.3 | 1.212 tệp, 99,40 giây, 571 findings, 0 lỗi. Trace CRITICAL ở `functions.php:624` nay có thêm `is_serialized_string()` tại `template.php:625`. | CRITICAL chưa được giải quyết; finding gộp 783 route. Chưa chứng minh ngữ nghĩa helper trên từng route và chưa tách các caller có guard khác nhau. |
| Unit suite | 126 bài kiểm thử đạt. | Không thay cho đối chiếu runtime và các phiên bản PHP khác. |

JSON: [Monolog](../reports/evaluation/monolog-1.23.0/after-gadget-upgrade.json), [XVWA](../reports/evaluation/xvwa-php-object-injection/after-upgrade.json), [Saloon](../reports/evaluation/saloon-3.0.0/after-upgrade.json), [WordPress](../reports/evaluation/wordpress-5.8.2/after-guard-upgrade.json).

## Việc còn lại

1. Tách bằng chứng theo caller/guard và chứng minh tác động của helper `is_serialized_string` trước khi hạ cảnh báo WordPress. Không suy ra an toàn chỉ từ tên hàm.
2. Kiểm tra thuộc tính, điều kiện nhánh, callback và class loading trên chuỗi Monolog; liên kết nguồn giải tuần tự hóa với gadget XVWA theo cấu trúc lớp, tránh nối dựa riêng vào cùng file.
3. Mô hình hóa luồng `openssl_decrypt` theo ciphertext, điều kiện APP_KEY/MAC của Laravel; hoàn thiện runtime/framework dispatch cho Drupal. Sau đó quét lại các mẫu lớn với cùng cấu hình để so sánh.
