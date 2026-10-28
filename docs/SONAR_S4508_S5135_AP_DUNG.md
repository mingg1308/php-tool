# Đối chiếu Sonar S4508 và S5135 với công cụ PHP deserialization SAST

## Nguồn tham khảo và phạm vi

- [Danh mục rule PHP của Sonar](https://rules.sonarsource.com/php/type/Security%20Hotspot/RSPEC-4508/): S4508, *Deserializing objects from an untrusted source is security-sensitive*, thuộc loại Security Hotspot. Vị trí `unserialize()` cần được kiểm tra ngữ cảnh; bản thân lời gọi không chứng minh một lỗ hổng.
- [Tài liệu security engine của Sonar](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/security-engine-custom-configuration): liệt kê S5135 cho PHP và mô tả mô hình source, sanitizer, validator, passthrough, sink để theo dõi dữ liệu không tin cậy.
- [Phân tích Melis Platform của Sonar](https://www.sonarsource.com/blog/remote-code-execution-in-melis-platform/): ví dụ truy vết dữ liệu HTTP qua các API framework và bước chuyển đổi trước `unserialize()`; việc chứng minh chuỗi gadget cần phân tích thêm.
- [Tài liệu PHP `unserialize()`](https://www.php.net/manual/en/function.unserialize.php): `allowed_classes=false` chặn tái tạo các lớp đối tượng, nhưng PHP vẫn khuyến cáo không đưa đầu vào không tin cậy vào hàm này bất kể tùy chọn.
- [Kho mã nguồn SonarPHP](https://github.com/SonarSource/sonar-php): kho công khai cung cấp frontend và một phần các check PHP. Cây mã nguồn công khai hiện tại không chứa tệp triển khai định danh S4508/S5135; do đó tài liệu này áp dụng *nguyên tắc phân tích* từ tài liệu chính thức, không tuyên bố tái hiện thuật toán nội bộ của Sonar.

## Ánh xạ vào công cụ

| Sonar | Thành phần hiện tại | Ý nghĩa kết quả |
| --- | --- | --- |
| S4508 | `php-unserialize-without-allowed-classes`, `php-unserialize-allows-all-classes`, `php-unserialize-review` | Rule cú pháp mức MEDIUM, `analysis_kind=security_hotspot_review`; cần xác minh nguồn dữ liệu và điều kiện thực thi. |
| S5135 | `php-unserialize-tainted-input` và rule trực tiếp cho superglobal | Taint engine theo dõi nguồn, bước truyền dữ liệu, điều kiện bảo vệ và sink. `detection_level` phân biệt luồng quan sát được với đường có giả định. |

Trước thay đổi này, rule cú pháp đánh dấu `unserialize(base64_decode(...))` và `unserialize(file_get_contents(...))` là CRITICAL dù đối số có thể là hằng hoặc file cục bộ. Hai mẫu đó đã được bỏ khỏi rule trực tiếp; taint engine vẫn nhận biết trường hợp nguồn HTTP thực sự đi qua `base64_decode()` hoặc `file_get_contents('php://input')`. Các rule chỉ dựa trên lời gọi `unserialize()` được hạ từ HIGH xuống MEDIUM vì thiếu bằng chứng nguồn không tin cậy. Metadata `methodology_reference` cho phép đọc kết quả theo cách phân biệt S4508 và S5135 mà không gán nhầm ID rule Sonar cho rule của dự án.

`allowed_classes=false` tiếp tục loại trừ kết luận **PHP object injection** tại lời gọi được chứng minh có tùy chọn này và vẫn xuất hiện trong `sink_inventory` với trạng thái `restricted_unserialize`. Đây không phải bằng chứng dữ liệu đầu vào an toàn đối với mọi rủi ro của `unserialize()`.

## Giới hạn đánh giá

Luồng source-to-sink là bằng chứng về khả năng dữ liệu không tin cậy đến điểm giải tuần tự hóa trong mô hình tĩnh. Khả năng khai thác còn phụ thuộc route runtime, lớp được nạp, gadget phù hợp và các điều kiện cấu hình. Kết quả `review_candidate` không được báo cáo là lỗ hổng đã xác nhận. Mô hình framework hiện chỉ bao phủ các API đã khai báo và không thể suy ra mọi nguồn hoặc sanitizer tùy biến của dự án khác.
