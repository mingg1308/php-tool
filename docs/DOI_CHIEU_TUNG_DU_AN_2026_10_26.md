# Đối chiếu từng dự án sau khi sửa liên kết POP và phân loại phạm vi

## Cách kiểm chứng

Lượt quét dùng cùng bộ cấu hình trong `scripts/retest_case_studies.py`; JSON và manifest mã engine nằm ở `reports/evaluation/project-by-project-scope-2026-10-26/`. Chín lượt quét đều hoàn tất, không có lỗi quét. 136 unit test và 108/108 ca nhỏ có nhãn đạt. Các ca nhỏ chỉ đo những mô hình đã đặt nhãn, không đo độ chính xác trên mọi dự án thực.

`finding_scope_counts` phân loại vị trí của finding theo đường dẫn tương đối trong project. Phân loại này không thay đổi severity và không khẳng định một tệp `production` được triển khai hoặc tiếp xúc với Internet. Tổng số finding ở tất cả mẫu không đổi so với lượt `retest-2026-10-25-final-guard`.

| Dự án | Finding; phạm vi | Bằng chứng hiện có | Điều kiện còn thiếu |
|---|---|---|---|
| XVWA | 36; production 5, tests 12, vendor 19 | `home.php:38` có request → `unserialize`; gadget `PHPObjectInjection::__wakeup → eval` được nối với sink cùng tệp. Lớp khai báo ở cấp tệp trước sink; `inject` là thuộc tính public được sink dùng. | Nhánh thực thi và tác động runtime chưa được thử bằng payload vô hại; kết quả vẫn là ứng viên tĩnh, `exploitability_verified=false`. |
| Saloon 3.0.0 | 1; production 1 | `AccessTokenAuthenticator.php:105` cho phép mọi lớp khi `unserialize`; luật xác nhận cú pháp sink. | Bản thư viện thiếu caller ứng dụng, dữ liệu token và dependency; chưa có nguồn request quan sát được hoặc gadget trong project này. |
| Monolog mới | 6; production 1, tests 5 | Có các chuỗi gadget ứng viên; không có nguồn giải tuần tự hóa của ứng dụng tích hợp. | Cấu trúc đối tượng được khôi phục, callback có thể điều khiển và sink nhập đối tượng phải được xác minh trong ứng dụng sử dụng Monolog. |
| Monolog 1.23.0 | 29; production 11, tests 18. Quét sâu `src`: 11 production | Quét sâu giữ được chuỗi `SyslogUdpHandler → BufferHandler → call_user_func`; không chạm giới hạn. | Alias/tự tham chiếu, giá trị callback, nhánh thực thi và điểm giải tuần tự hóa ở ứng dụng bên ngoài chưa được chứng minh bằng runtime. |
| TCPDF 6.2.22 | 103; production 35, examples 68 | Không có HIGH/MEDIUM trong quét mặc định; phiên bản đích PHP 7.2; đường wrapper ảnh đã vá có helper chặn `phar://`. | Các API nhận path từ ứng dụng vẫn cần caller và wrapper thực tế. Chưa có mẫu 6.2.19 trong `testcase` để đối chứng trước/sau vá. |
| Laravel 5.6.29 | 123; production 82, tests 41 | Có sink `Encrypter.php:149`; dữ liệu đầu ra `openssl_decrypt` chỉ phụ thuộc ciphertext theo mô hình hiện tại. | Mã framework không có ứng dụng/cấu hình `APP_KEY`. Cần xác minh MAC, cờ `$unserialize`, cookie/header tới `decrypt` và dependency runtime. |
| WordPress 5.8.2 | 571; production 571; 54 HIGH/CRITICAL | Tìm thấy sink `upgrade.php:1616`; route qua `is_serialized_string()` đã bị loại khỏi kết luận object payload CRITICAL. | Chưa nối option DB, multisite, quyền và kích hoạt nâng cấp cho CVE-2022-21663. Nhiều HIGH là đường PHAR hoặc return flow chưa giải; không thể coi 54 là 54 lỗ hổng. |
| Drupal 8.6.9 | 832; production 361, tests 471; 3 HIGH/LOW | REST `RequestHandler` → serializer/field → `unserialize` có trace mô hình hóa. Hai HIGH nằm trong `MapItem.php` và `LinkItem.php`; HIGH thứ ba ở `TestObjectItem.php` thuộc tests. `decode()` nay chỉ lan truyền request body. | `serializer->decode` thiếu triển khai dependency; lựa chọn normalizer/field và REST resource là runtime. `rest.resource.entity.node.yml` nằm trong `config/optional`, không chứng minh đã cài. Ba HIGH vẫn `unresolved_return_flow`; CVE-2019-6340 chưa được xác nhận bằng runtime. |

## Kết luận kỹ thuật

1. **Đã sửa được từ mã nguồn:** nguồn dữ liệu của Drupal `decode`, liên kết sink và gadget đơn giản cùng tệp ở XVWA, và phân loại finding trong mã sản phẩm/test/example/vendor. Các kết quả này có ca hồi quy và JSON mới.
2. **Chưa thể tự động xác nhận từ bản snapshot:** cấu hình và dependency được triển khai, khóa bí mật, quyền truy cập, loader/autoload, giá trị thuộc tính serialized, callback và điều kiện nhánh lúc chạy. Scanner giữ `exploitability_verified=false` khi thiếu bằng chứng.
3. **Bước xử lý tiếp theo theo mẫu:** Drupal cần bản cài có REST/HAL config và dependency; Laravel cần ứng dụng cùng cấu hình khóa và đường cookie/header; WordPress cần dữ liệu option và trạng thái multisite/upgrade; Saloon/Monolog/TCPDF cần mã ứng dụng tích hợp; XVWA có thể dùng thử nghiệm runtime vô hại để xác nhận nhánh `__wakeup`.

Không suy ra khả năng khai thác chỉ từ số tệp đã quét, số finding, hoặc sự có mặt của một gadget trong cùng repository.
