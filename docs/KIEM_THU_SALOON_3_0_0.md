# Kiểm thử Saloon 3.0.0

## Phạm vi

- Mẫu `testcase/saloon-3.0.0`, gói `saloonphp/saloon`, commit `b36be6b45e2170e1325cf034bc378e31318afe11`. Mẫu không có `vendor` hoặc ứng dụng tích hợp Saloon.
- Quét với PHP mục tiêu 8.1, `--experimental-side-effects --severity INFO`; chạy mặc định và thêm `--library-mode`.
- Kết quả gốc: [`default.json`](../reports/evaluation/saloon-3.0.0/default.json) và [`library-mode.json`](../reports/evaluation/saloon-3.0.0/library-mode.json).

| Chỉ số | Mặc định | Chế độ thư viện |
|---|---:|---:|
| Tệp quét / lỗi | 332 / 0 | 332 / 0 |
| Thời gian | 2,18 giây | 2,11 giây |
| Cảnh báo HIGH / MEDIUM | 1 / 0 | 1 / 1 |
| Chuỗi gadget ứng viên | 0 | 0 |
| Sink `AccessTokenAuthenticator.php:105` | Có | Có |

## Đối chiếu lỗ hổng công bố

[Advisory do dự án Saloon công bố, GHSA-rf88-776r-rcq9 / CVE-2026-33942](https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9) xác nhận các phiên bản dưới 4.0.0 bị ảnh hưởng. `AccessTokenAuthenticator::unserialize()` dùng `unserialize($string, ['allowed_classes' => true])` để phục hồi token OAuth. Khi kẻ tấn công kiểm soát chuỗi đã lưu hoặc được đưa vào phương thức này, PHP có thể tạo đối tượng gadget và chạy magic method. Dự án đã xóa cách tuần tự hóa PHP khỏi lớp này ở [v4.0.0](https://github.com/saloonphp/saloon/blob/v4.0.0/src/Http/Auth/AccessTokenAuthenticator.php).

Trong mã 3.0.0, hàm nhận `string $string` ở dòng 103 và gọi `unserialize` ở dòng 105. Mã `src` không gọi `AccessTokenAuthenticator::unserialize()`; lời gọi duy nhất trong mẫu nằm ở unit test `tests/Unit/Oauth2/AccessTokenAuthenticatorTest.php:23`, với dữ liệu được tạo từ `serialize()` trên đối tượng thử nghiệm. Vì vậy mẫu không cho thấy đường từ request hay kho lưu trữ của một ứng dụng cụ thể. Không có thư mục `vendor`, nên không thể xác nhận chuỗi gadget từ dependency như Monolog trong lượt này.

## Đánh giá công cụ

- Lượt mặc định báo `php-unserialize-allows-all-classes` tại đúng dòng 105, mức HIGH và confidence HIGH. Đây là **true positive ở cấp vị trí và cấu hình sink** so với advisory. `sink_inventory` vẫn ghi `no_tracked_source`, `flow_evidence` rỗng và `evidence_level` là `syntactic_review`; confidence của luật không phải bằng chứng kẻ tấn công đã kiểm soát dữ liệu.
- `--library-mode` bổ sung `php-library-api-exposure` mức MEDIUM, confidence LOW: tham số API công khai `$string` đi trực tiếp tới sink. Báo cáo ghi rõ quyền kiểm soát của bên ngoài là giả định và không có caller từ request. Đây là triage hợp lý cho thư viện, nhưng vẫn chưa xác nhận đường khai thác trong ứng dụng.
- Cả hai lượt đều có 0 chuỗi gadget. Kết quả này phù hợp với phạm vi mã nguồn Saloon riêng lẻ và không bác bỏ khả năng RCE khi được tích hợp cùng những dependency có gadget.
- Mục tiêu PHP 8.1 khiến các API tệp liên quan `phar://` không bị diễn giải thành kích hoạt giải tuần tự hóa metadata PHAR ngầm. Đây là đánh giá riêng với sink `unserialize` trực tiếp.

**Kết luận:** công cụ phát hiện đúng lỗi nền tảng mà Saloon công bố tại phiên bản 3.0.0, nhưng mới ở cấp sink và API công khai. Để xác nhận khả năng khai thác của một ứng dụng, cần quét cùng mã tích hợp, nơi lưu token và tập dependency, rồi kiểm tra quyền ghi/đưa dữ liệu vào chuỗi token.
