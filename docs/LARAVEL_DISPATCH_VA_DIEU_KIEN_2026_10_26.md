# Cải thiện đường Laravel 5.6.29 và kiểm thử hồi quy

## Sửa đổi

- Mô hình hóa nguồn `Request::$cookies` khi tham số có kiểu `Symfony\\Component\\HttpFoundation\\Request` trong `EncryptCookies::decrypt`.
- Mô hình hóa header `X-XSRF-TOKEN` trong `VerifyCsrfToken::getTokenFromRequest`; sửa phép gán ở điều kiện `if` để giá trị có thể đi tới thân nhánh đúng, không lan sang `else`.
- Nối có điều kiện lời gọi trên `$this->encrypter` của hai middleware với `Illuminate\\Encryption\\Encrypter::decrypt`. Cạnh được bỏ khi đối số `$unserialize` được chứng minh là literal `false`, gồm đối số có tên.
- Nếu mã `getJsonPayload` của Encrypter chứa cả kiểm tra cấu trúc, MAC và nhánh ném exception, finding ghi điều kiện đó là **cần kiểm chứng**, không coi dữ liệu header/cookie tự do vượt MAC.

## Kết quả

JSON cuối: `reports/evaluation/conditional-assignment-full-2026-10-26/laravel-5.6.29.json`. Bản trước: `reports/evaluation/project-by-project-scope-2026-10-26/laravel-5.6.29.json`.

| Chỉ số | Trước | Sau |
|---|---:|---:|
| Tệp quét / lỗi | 1.174 / 0 | 1.174 / 0 |
| Tổng finding | 123 | 123 |
| Finding ở `Encrypter.php:149` | MEDIUM, chỉ khớp cú pháp | HIGH/LOW confidence, `guarded_flow_review` |
| Nhóm route request có điều kiện | 0 | 3: cookie thường, cookie mảng, `X-XSRF-TOKEN` |
| Điều kiện MAC và `APP_KEY` | Không nằm trong finding | Được ghi rõ là chưa xác minh |

Finding mới **không xác nhận khả năng khai thác CVE-2018-15133**: mã framework không cung cấp ứng dụng triển khai hoặc `APP_KEY`; chưa chứng minh payload có MAC hợp lệ, lớp gadget được nạp hoặc chuỗi đối tượng có thể tái tạo. Cạnh tới Encrypter là mô hình service contract có điều kiện và có thể tắt bằng `--no-framework-models`.

## Hồi quy

- 146/146 unit test và 108/108 ca nhỏ có nhãn đạt.
- Chín lượt quét trong `reports/evaluation/conditional-assignment-full-2026-10-26/` đều hoàn tất, 0 lỗi quét.
- Vị trí finding ở XVWA, Saloon, Monolog, TCPDF, WordPress và Drupal không đổi. Drupal giữ 832 finding và ba HIGH/LOW `unresolved_return_flow`. Laravel thay một finding cú pháp tại dòng 149 bằng finding taint tại cùng sink.
