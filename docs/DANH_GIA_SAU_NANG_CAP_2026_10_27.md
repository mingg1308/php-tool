# Đánh giá sau khi nâng cấp scanner (27/10/2026)

## Thay đổi đã kiểm tra

- Tự bật giả định đầu vào API công khai khi `composer.json` gốc khai báo `type: library`; CLI cho phép ghi đè bằng `--library-mode` hoặc `--application-mode`.
- Phân biệt closure cố định với callback động, nhận diện thuộc tính được dùng làm callback trong vòng `foreach`, và phân loại `array_map('unlink', ...)` là thao tác xóa tệp.
- Giữ ứng viên POP theo loại sink, ưu tiên đường đi chứa callback động và ghi các thuộc tính có thể cần kiểm soát. Các thuộc tính này là ứng viên, chưa được chứng minh đến từ dữ liệu deserialize.
- Gắn ngữ cảnh phiên bản/advisory ngoại tuyến cho Saloon và TCPDF; gắn tham chiếu PHPGGC Monolog/RCE7 khi bằng chứng cấu trúc phù hợp. Tham chiếu này không tự xác minh khai thác.
- Gộp cảnh báo Phar INFO cùng vị trí với finding luồng API đã có, tránh báo trùng.

## Kiểm thử

`py -3.12 -B -m unittest discover -s php_deserial_sast/tests -q`: **163/163 đạt**. Bộ 108 ca nhỏ: **108/108 đạt**, gồm 64 ca dương tính mong đợi. `verify-rules`: **11 luật YAML hợp lệ**. Cả 9 lượt quét dự án đều hoàn tất, không có lỗi phân tích và số tệp được quét bằng số tệp được phát hiện.

| Dự án | Tệp quét | Finding | High | Medium | Low | Info | Thời gian (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| XVWA | 304 | 36 | 1 | 2 | 1 | 31 | 4,6 |
| Saloon 3.0.0 | 332 | 2 | 0 | 2 | 0 | 0 | 3,0 |
| Monolog (bộ testcase) | 228 | 10 | 0 | 5 | 5 | 0 | 10,0 |
| Monolog 1.23.0 | 167 | 33 | 0 | 9 | 5 | 19 | 4,4 |
| Monolog 1.23.0, chỉ `src/Monolog`, quét sâu | 88 | 15 | 0 | 0 | 5 | 10 | 9,7 |
| TCPDF 6.2.22 | 227 | 103 | 0 | 16 | 1 | 86 | 36,6 |
| Laravel 5.6.29 | 1174 | 122 | 1 | 38 | 0 | 83 | 19,9 |
| WordPress 5.8.2 | 1212 | 572 | 54 | 28 | 4 | 486 | 97,4 |
| Drupal 8.6.9 | 8855 | 832 | 3 | 156 | 2 | 671 | 145,9 |

Báo cáo JSON, log và manifest mã nguồn của từng lượt quét: `reports/evaluation/retest-2026-10-27-integrated-final/`. Bộ ca nhỏ: `reports/evaluation/retest-2026-10-27-integrated-small/`. Mốc đối chiếu trước thay đổi: `reports/evaluation/retest-2026-10-27-cache-cleared/`.

## Đối chiếu ba thư viện trọng tâm

**Saloon 3.0.0:** scanner chỉ đúng `AccessTokenAuthenticator.php:105`, lời gọi `unserialize($string, ['allowed_classes' => true])`, và luồng từ tham số của API công khai. Finding luồng ở mức Medium, có điều kiện vì không có caller ứng dụng gửi dữ liệu độc hại. Advisory [CVE-2026-33942](https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9) được gắn vào finding cú pháp; phiên bản 3.0.0 suy ra từ tên thư mục, nên cần kiểm tra lại nguồn phát hành.

**Monolog 1.23.0:** scanner giữ một ứng viên POP từ `FingersCrossedHandler` tới `call_user_func`, với thuộc tính callback `processors`; finding mang tham chiếu [PHPGGC Monolog/RCE7](https://github.com/ambionics/phpggc/tree/master/gadgetchains/Monolog/RCE/7). Đây là khớp cấu trúc cần rà soát, mức Low; chưa chứng minh caller deserialize, điều khiển thuộc tính, điều kiện thực thi của chuỗi, hoặc payload RCE. `array_filter` với closure cố định không còn bị xếp thành sink gọi động.

**TCPDF 6.2.22:** scanner ghi 16 luồng API Phar có điều kiện và một ứng viên POP tới `array_map('unlink', ...)` với tác động xóa tệp. Không có bằng chứng để nâng chúng thành khai thác object injection. Phiên bản 6.2.22 nằm ngoài phạm vi ảnh hưởng của [CVE-2018-17057](https://github.com/advisories/GHSA-5hw4-m7f3-hhx8); advisory được ghi trong ngữ cảnh gói, không gắn vào finding.

## Giới hạn của kết luận

- Số finding tăng/giảm không phải phép đo precision hoặc recall; muốn đo hai chỉ số này cần ground truth gắn vị trí và điều kiện khai thác cho từng dự án.
- Một ứng viên POP riêng lẻ không chứng minh rằng đầu vào không tin cậy tới được `unserialize()` và tái tạo đúng object/thuộc tính. Kết quả Saloon, Monolog, TCPDF vì thế không được tự động nâng lên High/Critical.
- Ba finding High ở Drupal nằm ở các lời gọi `unserialize()` trong `MapItem.php`, `TestObjectItem.php`, `LinkItem.php` với mức evidence `unresolved_flow` và `conditional_path`; chúng không tự chứng minh CVE-2019-6340. Báo cáo còn cần kiểm tra entry point REST, cấu hình, quyền truy cập, runtime và đường gadget thực tế.
- Nhiều finding Info ở WordPress/Drupal là điểm rà soát. Độ chính xác của từng finding chưa được xác minh thủ công trong lượt quét này.
