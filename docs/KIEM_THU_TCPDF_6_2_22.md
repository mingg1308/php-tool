# Kiểm thử TCPDF 6.2.22

## Phạm vi và cấu hình

- Mẫu duy nhất trong `testcase`: `tcpdf-6.2.22`, gói `tecnickcom/tcpdf` phiên bản 6.2.22, commit `ac6e92fccc7d9383dfd787056831349621b1aca2`.
- Quét bằng `php_deserial_sast.cli`, PHP mục tiêu 7.2, ngưỡng `INFO`. Chạy mặc định và thêm `--library-mode`.
- JSON: [`default.json`](../reports/evaluation/tcpdf-6.2.22/default.json), [`library-mode.json`](../reports/evaluation/tcpdf-6.2.22/library-mode.json).

| Chỉ số | Mặc định | Chế độ thư viện |
|---|---:|---:|
| Tệp quét / lỗi | 227 / 0 | 227 / 0 |
| Thời gian | 38,68 giây | 38,50 giây |
| HIGH / MEDIUM / LOW / INFO | 0 / 0 / 1 / 102 | 0 / 16 / 1 / 102 |
| Ứng viên gadget | 5 | 5 |
| Chạm giới hạn gadget | Không | Không |

Trong mã TCPDF không có lời gọi `unserialize` trực tiếp. 102 cảnh báo INFO là các vị trí dùng API đường dẫn cần rà soát, không phải 102 lỗ hổng. Năm chuỗi gadget là các lớp con cùng kế thừa `TCPDF::__destruct → _destroy → array_map('unlink', ...)`, không phải năm đường khai thác độc lập.

## Đối chiếu CVE-2018-17057

[Advisory CVE-2018-17057](https://github.com/advisories/GHSA-5hw4-m7f3-hhx8) xác định phiên bản **trước 6.2.22** bị ảnh hưởng bởi giải tuần tự hóa ngầm qua `phar://`, và liệt kê 6.2.22 là bản đã vá. [Commit sửa của TCPDF](https://github.com/tecnickcom/TCPDF/commit/1861e33fe05f653b67d070f7c106463e7a5c26ed) thêm các wrapper kiểm tra đường dẫn và thay nhiều lời gọi `file_exists` bằng `TCPDF_STATIC::file_exists`.

Trong mẫu này, `TCPDF_STATIC::file_exists` (`include/tcpdf_static.php:1832–1848`) liệt kê stream wrapper và trả `false` khi tên tệp bắt đầu bằng một wrapper ngoài `http`/`https`, gồm `phar://`. Đường ảnh tại `tcpdf.php:6849` gọi helper trước `getimagesize($file)` ở dòng 6852; `_parsejpeg()` trong `include/tcpdf_images.php` cũng kiểm tra helper trước `getimagesize` và `file_get_contents`. Đây là bằng chứng tĩnh cho guard của các đường đã xem xét, phù hợp mục tiêu bản vá. Chưa có kiểm thử runtime PHAR.

## Đánh giá kết quả công cụ

- Lượt mặc định không báo HIGH/MEDIUM cho đường PHAR, phù hợp việc đây là bản đã vá. `sink_inventory` vẫn có 102 vị trí `no_tracked_source`; vắng cảnh báo không chứng minh mọi API tệp an toàn trong mọi ứng dụng sử dụng TCPDF.
- Chế độ thư viện thêm 16 `php-library-api-exposure` mức MEDIUM, confidence LOW. Chúng giả định tham số API công khai do bên ngoài kiểm soát; hai vị trí thuộc `examples`. Một số cảnh báo như `getimagesize` tại `tcpdf.php:6852` và `include/tcpdf_images.php:167` chưa chứng minh guard `TCPDF_STATIC::file_exists` ở caller. Đây là ứng viên cần kiểm tra điều kiện, không phải bằng chứng bản 6.2.22 vẫn mắc CVE-2018-17057.
- Các API đọc tệp trực tiếp, chẳng hạn `TCPDF_IMPORT::importPDF($filename)` ở `tcpdf_import.php:70`, vẫn nhận đường dẫn từ caller. Khả năng truyền `phar://` và điều kiện tiếp cận thực tế phụ thuộc ứng dụng tích hợp, PHP runtime, wrapper và cách caller kiểm soát `$filename`; lượt quét thư viện không xác nhận đường khai thác.
- Ứng viên POP tại `TCPDF::__destruct` tới `array_map('unlink', $tmpfiles)` bắt đầu từ `glob(K_PATH_CACHE.'__tcpdf_'.$this->file_id.'_*')` trong `_destroy()`. Báo cáo chưa chứng minh điểm giải tuần tự hóa, điều khiển thuộc tính, đường dẫn tùy ý hay file bị xóa. Vì vậy chỉ nên giữ ở mức rà soát gadget LOW.

**Kết luận:** trên ca âm tính TCPDF 6.2.22, công cụ không báo nhầm CVE-2018-17057 ở lượt mặc định và vẫn đưa ra các API/gadget cần rà soát. Độ chính xác của 16 cảnh báo chế độ thư viện chưa thể tính là lỗ hổng xác nhận. Để đo độ nhạy với CVE này cần quét đối chứng TCPDF 6.2.19 bằng cùng cấu hình và so sánh vị trí cùng guard, nhưng mẫu đó hiện không nằm trong `testcase`.
