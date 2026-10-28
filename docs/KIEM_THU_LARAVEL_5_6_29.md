# Kiểm thử Laravel Framework 5.6.29

## Phạm vi và cách chạy

- Mẫu: `testcase/laravel-5.6.29`, gói `laravel/framework`, commit `acc6b5c54ab196d3358f60acc5f55d9ebaaccc02`; đây là mã framework, không có ứng dụng cụ thể hoặc `vendor`.
- Công cụ: `python -m php_deserial_sast.cli scan` với PHP 7.2, `--experimental-side-effects`, ngưỡng `INFO`. Quét lần hai thêm `--library-mode`.
- Kết quả đầy đủ: [`default.json`](../reports/evaluation/laravel-5.6.29/default.json) và [`library-mode.json`](../reports/evaluation/laravel-5.6.29/library-mode.json).

| Chỉ số | Mặc định | Chế độ thư viện |
|---|---:|---:|
| Tệp quét / lỗi tệp | 1.174 / 0 | 1.174 / 0 |
| Thời gian | 21,13 giây | 20,00 giây |
| Tổng cảnh báo | 123 | 162 |
| HIGH / MEDIUM / LOW / INFO | 0 / 39 / 1 / 83 | 0 / 78 / 1 / 83 |
| Mẫu `unserialize` theo cú pháp | 39 | 39 |
| Cảnh báo API thư viện có điều kiện | 0 | 39 |
| Sink `Encrypter.php:149` | Có | Có |
| Đường dữ liệu từ HTTP cookie / `X-XSRF-TOKEN` đến sink | Không | Không |

Trong 39 mẫu `unserialize`, 11 nằm dưới `src` và 28 nằm dưới `tests`. 83 cảnh báo INFO là rà soát API đường dẫn PHAR, không phải 83 lỗ hổng đã xác nhận. Cảnh báo POP duy nhất là ứng viên chuỗi, có điểm đầu là lớp trong test kế thừa `Model::__wakeup`; báo cáo không chứng minh được nguồn giải tuần tự hóa, điều khiển thuộc tính hay khả năng khai thác thực tế.

## Đối chiếu với lỗi đã được Laravel sửa

Phần `X-XSRF-TOKEN` tương ứng với [CVE-2018-15133](https://github.com/advisories/GHSA-qvqm-h22r-4cp9), ảnh hưởng Laravel 5.6.0–5.6.29. Hướng dẫn của Laravel 5.6.30 còn mô tả thay đổi đối với giải tuần tự hóa cookie. Hai đường đầu vào cần được đánh giá riêng, dù cùng đi qua `Encrypter::decrypt`.

Trong 5.6.29, `EncryptCookies::decryptCookie` (`src/Illuminate/Cookie/Middleware/EncryptCookies.php:95`) và `decryptArray` (dòng 110) gọi `Encrypter::decrypt` mà không truyền tham số thứ hai. `VerifyCsrfToken::getTokenFromRequest` nhận header `X-XSRF-TOKEN` (dòng 140) rồi cũng gọi `decrypt($header)` (dòng 141). `Encrypter::decrypt` mặc định `$unserialize = true` (dòng 132) và gọi `unserialize($decrypted)` (dòng 149). Đây là những vị trí cần đối chiếu, không phải chỉ riêng lời gọi `unserialize`.

`getJsonPayload` kiểm tra cấu trúc payload và MAC trước khi giải mã. Laravel công bố điều kiện khai thác là kẻ tấn công có `APP_KEY`; việc người dùng gửi cookie hoặc header tùy ý tự nó chưa đủ. Bản 5.6.30 đặt mặc định không serialize cookie và truyền cờ `static::serialized(...)` vào các lệnh gọi `decrypt` của middleware; đường `X-XSRF-TOKEN` cũng truyền cờ này. Hàm `Encrypter::decrypt` vẫn giữ nhánh `unserialize` cho trường hợp được yêu cầu tường minh. Vì vậy, kết luận chỉ dựa vào sự hiện diện của sink sẽ sai khi đánh giá bản đã vá.

Nguồn đối chiếu: [hướng dẫn nâng cấp Laravel 5.6.30](https://laravel.com/framework/docs/5.6/upgrade#upgrade-5.6.30), [EncryptCookies 5.6.30](https://github.com/laravel/framework/blob/v5.6.30/src/Illuminate/Cookie/Middleware/EncryptCookies.php), [VerifyCsrfToken 5.6.30](https://github.com/laravel/framework/blob/v5.6.30/src/Illuminate/Foundation/Http/Middleware/VerifyCsrfToken.php).

## Đánh giá công cụ

Lượt mặc định đánh dấu đúng sink `Encrypter.php:149` bằng `php-unserialize-review` mức MEDIUM, nhưng chỉ là khớp cú pháp (`syntactic_rule_match`). `sink_inventory` ghi `no_tracked_source`; không có bằng chứng đi từ request đến sink.

Chế độ thư viện bổ sung `php-library-api-exposure` mức MEDIUM, độ tin cậy LOW cho cùng sink. Một số dấu vết bắt đầu từ tham số `$payload` của API `decrypt`, nhưng tất cả chỉ giả định người gọi API có thể kiểm soát tham số. Các dấu vết khác bắt đầu từ `$key` hoặc `$cipher` của hàm khởi tạo và truyền qua `openssl_decrypt` vì hàm này chưa có mô hình ngữ nghĩa; đây không phải bằng chứng người gửi HTTP kiểm soát bản rõ được giải mã. Báo cáo cũng chưa thể hiện điều kiện MAC hợp lệ và `APP_KEY` bị lộ.

**Kết luận:** công cụ tìm được vị trí giải tuần tự hóa liên quan đến lỗi thực tế, nhưng chưa phát hiện chính xác đường khai thác, tiền điều kiện hay ranh giới bản vá. Không thể tính kết quả này là true positive hoàn chỉnh cho lỗ hổng Laravel. Mẫu hiện tại cũng thiếu ứng dụng, cấu hình và phụ thuộc để kiểm chứng bằng chạy thực tế.

## Hướng xử lý tiếp theo

1. Mô hình hóa `openssl_decrypt` theo đúng tham số dữ liệu và điều kiện giải mã, tránh lan truyền taint từ `$cipher`/`$key` như thể là bản rõ do người gửi cung cấp.
2. Nối luồng HTTP cookie và `X-XSRF-TOKEN` qua middleware, interface `Encrypter` và lời gọi phương thức của đối tượng được tiêm vào.
3. Theo dõi giá trị mặc định `$unserialize = true`, đối số `false`/`static::serialized`, và điều kiện xác thực MAC/`APP_KEY` trong kết luận; kiểm thử hồi quy trên cả 5.6.29 lẫn 5.6.30 để tránh báo cùng một lỗi ở bản vá.
4. Tách cảnh báo API giả định và mẫu cú pháp khỏi các đường dữ liệu được chứng minh, đồng thời lọc `tests` khi đánh giá lỗ hổng trong mã sản phẩm.
