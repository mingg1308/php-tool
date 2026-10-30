# Mở rộng bộ luật PHP insecure deserialization (29/10/2026)

## Phạm vi

Bộ quét hiện kết hợp luật YAML, phân tích luồng và luật có nhận biết kiểu receiver. Một khớp cú pháp chỉ tạo điểm cần rà soát; finding từ luồng source–sink có bằng chứng mạnh hơn. Không có bộ luật hữu hạn nào xác nhận chính xác mọi lỗ hổng trong mọi thư viện, cấu hình runtime và chuỗi gadget.

## Các nhóm đã bao phủ

| Nhóm | Cơ chế | Điều kiện cần xét |
| --- | --- | --- |
| `unserialize()` | Luồng taint, `allowed_classes`, luật request trực tiếp và hotspot | Nguồn không tin cậy, class được phép, guard và gadget |
| `igbinary_unserialize()` | Luồng taint và hotspot | Extension igbinary, dữ liệu không tin cậy, class/gadget |
| `wddx_deserialize()` | Luồng taint và hai luật YAML mới | PHP trước 7.4, WDDX khả dụng, packet chứa object |
| `session_decode()` | Luật request trực tiếp và hotspot | Handler session, trạng thái session, class/gadget |
| Phar | Luồng đường dẫn trước PHP 8 và `getMetadata()` tường minh có kiểu receiver | Phiên bản PHP, archive/metadata không tin cậy, object/gadget |
| PECL YAML | Luật bật `yaml.decode_php` và request đi trực tiếp vào `yaml_parse()`, `yaml_parse_file()`, `yaml_parse_url()` | PECL YAML, `yaml.decode_php=1`, tag `!php/object` |
| SPL | Luật có kiểu receiver cho `SplObjectStorage`, `ArrayObject`, `ArrayIterator`, `SplDoublyLinkedList`, `SplStack`, `SplQueue` | Đầu vào phương thức `unserialize()` không tin cậy, object/gadget |
| `Serializable::unserialize()` | Luật có nhận biết interface và side effect trực tiếp trong callback | Payload đúng định dạng legacy, class được nạp, entry untrusted |
| Gadget POP | Magic methods và call graph | Đường nạp class, điều khiển thuộc tính, dispatch và side effect |

## Quy tắc để hạn chế báo động sai

- `wddx_deserialize()` không được báo nếu cấu hình PHP là 7.4 trở lên. Khi chưa biết phiên bản, finding từ taint được hạ mức và ghi `legacy_wddx_runtime_unverified`.
- PECL YAML mặc định tắt `yaml.decode_php` ở các phiên bản hiện hành; vì vậy không có luật báo mọi lời gọi `yaml_parse*()` như lỗ hổng. Luật chỉ đánh dấu cấu hình bật rõ ràng hoặc dữ liệu request trực tiếp, luôn ghi điều kiện runtime. Tệp `Drupal/Component/Serialization/YamlPecl.php` đặt `yaml.decode_php=0` không tạo finding YAML trong phép thử đối chiếu.
- Nếu `ini_set('yaml.decode_php', 0)` chi phối lời gọi parse trong cùng scope và không có lần đặt lại ở giữa, rule request trực tiếp được loại. Đây là chứng minh cục bộ trong CFG đã hỗ trợ; cấu hình ở tệp bootstrap khác vẫn phải xác minh thủ công.
- Quy tắc SPL chỉ chạy khi xác định được receiver là lớp SPL built-in. Phương thức `unserialize()` của lớp ứng dụng khác không tự động bị xem là cùng sink.
- Quy tắc callback `Serializable` chỉ rà soát lời gọi nguy hiểm trực tiếp bên trong phương thức; lời gọi qua helper cần call graph và đánh giá riêng.
- Hàm người dùng trùng tên `wddx_deserialize` hoặc `yaml_parse*` được loại khi mô hình liên tệp giải quyết được lời gọi.
- `session_start()` và các bộ giải mã dữ liệu thông thường không được đánh dấu hàng loạt: cần chứng minh khả năng ghi/đổi dữ liệu session hoặc cấu hình cho phép khôi phục object.

## Kiểm chứng

Chạy `python -m unittest discover -s php_deserial_sast/tests -q` và `python -m php_deserial_sast.cli verify-rules`. Bộ kiểm thử mới có ca dương/âm về PHP 7.3/8.1, đường dữ liệu qua `base64_decode`, cấu hình YAML, hàm trùng tên và receiver SPL. Chạy riêng tệp `YamlPecl.php` của Drupal 8.6.9 cho 0 finding YAML và 0 lỗi quét.

## Tài liệu chính

- PHP: [unserialize](https://www.php.net/manual/en/function.unserialize.php), [igbinary_unserialize](https://www.php.net/manual/en/function.igbinary-unserialize.php), [wddx_deserialize](https://www.php.net/manual/en/function.wddx-deserialize.php).
- PHP: [PECL YAML parse](https://www.php.net/manual/en/function.yaml-parse.php), [yaml.decode_php](https://www.php.net/manual/en/yaml.configuration.php).
- PHP: [Phar::getMetadata](https://www.php.net/manual/en/phar.getmetadata.php), [Phar và thay đổi từ PHP 8](https://www.php.net/manual/en/class.phar.php).
- PHP: [SplObjectStorage::unserialize](https://www.php.net/manual/en/splobjectstorage.unserialize.php), [ArrayObject::unserialize](https://www.php.net/manual/en/arrayobject.unserialize.php), [ArrayIterator::unserialize](https://www.php.net/manual/en/arrayiterator.unserialize.php), [SplDoublyLinkedList::unserialize](https://www.php.net/manual/en/spldoublylinkedlist.unserialize.php).
- PHP: [Serializable interface](https://www.php.net/manual/en/class.serializable.php) và [Serializable::unserialize](https://www.php.net/manual/en/serializable.unserialize.php).
