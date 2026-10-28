# Nâng cấp mức bằng chứng phát hiện và mở rộng kiểm thử

## Thay đổi

- `assessment.detection_level` có ba mức: `direct_untrusted_deserialization`, `conditional_path`, `review_candidate`. Mức trực tiếp chỉ áp dụng khi có luồng request quan sát được tới sink giải tuần tự hóa trực tiếp, không có guard chưa chứng minh, luồng không bất định và không có giới hạn phân tích được ghi nhận trên finding. Mọi mức vẫn giữ `exploitability_verified=false`.
- Console và HTML hiển thị mức phát hiện; JSON và SARIF chứa trường này trong assessment. Nhãn LLM trên console không còn tự gọi một đánh giá của mô hình là “confirmed true positive”.
- Thêm sink `igbinary_unserialize()` vào dataflow, sink inventory, coverage và luật rà soát. Hàm có thể khôi phục object và gọi magic methods theo tài liệu của [igbinary](https://github.com/igbinary/igbinary/blob/master/igbinary.php). Lời gọi do hàm người dùng cùng namespace định nghĩa không bị nhận nhầm là sink extension. Báo cáo ghi điều kiện extension phải có lúc chạy.

## Kết quả kiểm thử

Đợt quét 9 cấu hình dự án: `reports/evaluation/detection-level-full-2026-10-26/`. Kết quả ở đây được tạo trước thay đổi thêm `igbinary_unserialize()`; không có lời gọi hàm này trong thư mục `testcase`, nên tính năng mới không tác động các vị trí finding của bộ ca đó. So với đợt `conditional-assignment-full-2026-10-26`, tổng finding từng cấu hình giữ nguyên; cả 9 lượt có 0 lỗi quét.

| Dự án | Tệp | Finding | Trực tiếp | Có điều kiện | Chỉ rà soát |
|---|---:|---:|---:|---:|---:|
| XVWA | 304 | 36 | 1 | 1 | 34 |
| Saloon 3.0.0 | 332 | 1 | 0 | 0 | 1 |
| Monolog mới | 228 | 6 | 0 | 0 | 6 |
| Monolog 1.23.0 | 167 | 29 | 0 | 0 | 29 |
| Monolog 1.23.0 `src` sâu | 88 | 11 | 0 | 0 | 11 |
| TCPDF 6.2.22 | 227 | 103 | 0 | 0 | 103 |
| Laravel 5.6.29 | 1.174 | 123 | 0 | 1 | 122 |
| WordPress 5.8.2 | 1.212 | 571 | 0 | 70 | 501 |
| Drupal 8.6.9 | 8.855 | 832 | 0 | 3 | 829 |

`conditional_path` gồm các đường PHAR cần xác minh wrapper/runtime và các luồng `unserialize()` còn guard/dispatch chưa giải; không nên cộng nhóm đó thành số CVE. XVWA có một đường request tới `unserialize()` được hỗ trợ đầy đủ trong mô hình hiện tại. Gadget và tác động runtime vẫn cần kiểm chứng riêng.

Hai dự án ngoài `testcase` được quét ở `reports/evaluation/detection-level-external-2026-10-26/`: `progpilot/package/src` có 75 tệp, 0 finding, 0 lỗi; `psalm/src` có 1.247 tệp, 0 lỗi. Sau khi bổ sung sink mới, Psalm có 1 finding `review_candidate` tại `Internal/Fork/IgbinarySerializer.php:46` và 1 sink inventory cùng vị trí. Không có nguồn request được nối tới hàm này; đây không phải lỗ hổng Psalm đã xác nhận. `ProjectCacheProvider.php:59` dùng `unserialize()` với `allowed_classes => false` và không tạo cảnh báo object injection.

Kiểm thử: 14/14 test chuyên biệt và 108/108 ca nhỏ có nhãn đạt sau thay đổi sink. Bộ unit test toàn dự án đã được khởi chạy nhưng dừng do thời gian chạy quá dài; chưa có kết quả đạt cho toàn bộ suite ở đợt này.

## Việc còn thiếu để đánh giá CVE

- Drupal: giải quyết return flow REST/HAL và kiểm chứng cấu hình REST/normalizer lúc chạy.
- Laravel: xác minh MAC, `APP_KEY`, binding của ứng dụng và gadget khả dụng.
- WordPress: nối option database tới đường upgrade, kiểm tra multisite/quyền/phiên bản PHP và đối chứng bản vá.
- Thêm cặp dự án có lỗ hổng và đã vá với nhãn độc lập; số finding hiện tại không tính được precision/recall thực tế.
