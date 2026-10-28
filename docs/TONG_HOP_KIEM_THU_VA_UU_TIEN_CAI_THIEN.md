# Tổng hợp kiểm thử PHP insecure deserialization SAST

> **Tiến độ nâng cấp:** Đã sửa bước gộp gadget làm mất chuỗi Monolog/RCE1 và
> lỗi bỏ sót guard tại lời gọi nằm trong phép gán. Kết quả mới lưu trong
> [`after-gadget-upgrade.json`](../reports/evaluation/monolog-1.23.0/after-gadget-upgrade.json)
> và [`after-upgrade.json`](../reports/evaluation/xvwa-php-object-injection/after-upgrade.json).
> Các bảng bên dưới là mốc **trước nâng cấp**; các điểm WordPress, Laravel,
> Drupal và việc nối sink với gadget vẫn cần xử lý thêm.

## Phạm vi và cách đọc kết quả

Báo cáo này tổng hợp các lượt quét mới nhất của [Drupal 8.6.9](KIEM_THU_DRUPAL_SAU_SUA_LOI.md), [Laravel 5.6.29](KIEM_THU_LARAVEL_5_6_29.md), [Monolog 1.23.0](KIEM_THU_MONOLOG_1_23_0.md), [Saloon 3.0.0](KIEM_THU_SALOON_3_0_0.md), [WordPress 5.8.2](KIEM_THU_WORDPRESS_5_8_2.md), [TCPDF 6.2.22](KIEM_THU_TCPDF_6_2_22.md) và [XVWA PHP Object Injection](KIEM_THU_XVWA_PHP_OBJECT_INJECTION.md). So sánh dựa trên đường mã và điều kiện của từng ca; tổng số finding không phải số lỗ hổng, và các mẫu dùng PHP mục tiêu, phạm vi và cấu hình khác nhau nên thời gian quét không phải benchmark ngang hàng.

| Mẫu / chuẩn đối chiếu | Kết quả công cụ đáng tin cậy nhất | Phần còn thiếu hoặc dễ hiểu sai |
|---|---|---|
| XVWA, ca dương rõ ràng | `$_REQUEST['r'] → unserialize` được chứng minh; tìm đúng `__wakeup → eval`. Quét hẹp và toàn project nhất quán. | Hai bằng chứng chưa được nối thành một đường object injection hoàn chỉnh; gadget riêng vẫn LOW. |
| Saloon 3.0.0, CVE-2026-33942 | Đúng sink `AccessTokenAuthenticator.php:105`, nhận ra `allowed_classes => true`; library mode thấy tham số `$string` đi thẳng vào sink. | Không có ứng dụng caller, kho token hoặc dependency; HIGH confidence của luật chỉ là chắc chắn về cú pháp và cấu hình sink. |
| Drupal 8.6.9, CVE-2019-6340 | Bản cuối quét đủ 8.855 tệp, 0 lỗi; đánh dấu MapItem và LinkItem là HIGH/LOW-confidence theo mô hình framework. | Chưa có trace REST/HAL → field setter → sink dựa trên runtime được kiểm chứng; một HIGH nằm trong test. Các công cụ tham chiếu full scan không có báo cáo hợp lệ. |
| Laravel 5.6.29, CVE-2018-15133 và đường cookie | Tìm đúng `Encrypter.php:149`. | Không nối cookie/header qua interface và decrypt; library mode còn truyền taint từ `$key`/`$cipher` qua `openssl_decrypt`. Chưa ghi điều kiện MAC/`APP_KEY` và cờ `$unserialize`. |
| WordPress 5.8.2, CVE-2022-21663 | Quét đủ 1.212 tệp; định vị `upgrade_280()` tại `upgrade.php:1616`. | Chỉ khớp cú pháp, thiếu option DB, multisite và kích hoạt nâng cấp. CRITICAL khác đi qua `is_serialized_string()` bị đánh giá quá cao; HIGH widget thiếu mô hình hash guard. |
| Monolog 1.23.0, PHPGGC Monolog/RCE1 | Phát hiện magic method và một số sink động. | Quét sâu `src` không chạm ngân sách vẫn bỏ chuỗi `SyslogUdpHandler → BufferHandler` tự tham chiếu. Ứng viên nổi bật `array_filter` dùng closure cố định. |
| TCPDF 6.2.22, ca âm tính CVE-2018-17057 | Quét mặc định không gán HIGH/MEDIUM cho đường PHAR đã vá. | Library mode có 16 cảnh báo giả định API; chưa mô hình hóa đầy đủ helper chặn `phar://`. Thiếu mẫu 6.2.19 để đo độ nhạy cặp trước/sau vá. |

## Điểm mạnh đã kiểm chứng

1. Luồng nguồn trực tiếp tới sink và phát hiện magic method hoạt động trên XVWA; sink nguy hiểm có cấu hình rõ ràng được nhận diện trên Saloon.
2. Các lượt quét hoàn chỉnh mới nhất ở bảy mẫu đều ghi rõ lỗi/giới hạn; Drupal, WordPress và các thư viện lớn đã có JSON có thể tái kiểm tra. Không dùng lượt timeout hoặc ngân sách gadget bị chạm như kết quả âm tính.
3. `library-mode`, `sink_inventory`, `flow_evidence` và mức `analysis_completeness` đã tách được nhiều cảnh báo giả định khỏi nguồn request quan sát được. Đây là nền tảng để sửa cách xếp hạng, chưa phải bằng chứng exploitability.

## Ưu tiên cải thiện

### P0 — Chặn kết luận quá mức và giữ đúng tiền điều kiện

**Vấn đề:** WordPress có cảnh báo CRITICAL dù nhánh `_list_meta_row()` chỉ cho serialized string qua `is_serialized_string()`. Cảnh báo widget đi qua kiểm tra hash chưa được giải. Laravel cần xác thực MAC và `APP_KEY`; TCPDF cần nhận diện helper từ chối `phar://`. Một nhãn confidence cao cho luật cú pháp như Saloon dễ bị đọc thành khả năng khai thác đã chứng minh.

**Thay đổi:** trong `core/dataflow.py`, `core/taint_engine.py` và tầng xây dựng `assessment`, giữ trạng thái guard theo loại: chặn object payload, xác thực mật mã, điều kiện cấu hình, chưa nhận diện. Tách `sink_match_confidence`, `flow_confidence` và `exploitability_status`; không cho severity CRITICAL dựa vào nguồn request nếu guard liên quan chưa được giải. Mô hình hóa `openssl_decrypt` để dữ liệu đầu ra phụ thuộc ciphertext; `$key`/`$cipher` là điều kiện cấu hình, không phải nguồn nội dung bản rõ. Mọi kết luận phải kèm tiền điều kiện chưa xác minh.

**Điều kiện đạt:** cảnh báo WordPress `functions.php:624` không còn được xếp là object injection CRITICAL từ đường `_list_meta_row`; đường widget ghi rõ hash chưa xác minh; Laravel ghi rõ MAC/`APP_KEY`; Saloon vẫn tìm đúng sink mà không tuyên bố request reachability.

### P0 — Nối đúng luồng liên hàm và dữ liệu lưu trữ

**Vấn đề:** Drupal, Laravel và WordPress đều tìm thấy sink nhưng thiếu đường khai thác có điều kiện. Nguồn hiện thiên về superglobal; thiếu đường dữ liệu qua service container/interface, serializer dispatch và database option.

**Thay đổi:** mở rộng `core/call_graph.py`, `core/framework_dispatch.py` và `core/dataflow.py` bằng contract có điều kiện cho Drupal REST/HAL field dispatch, Laravel middleware → `Encrypter` interface, WordPress `wpdb->get_results()`/option read-write và điều kiện `db_version`. Theo dõi đối số mặc định hoặc cờ như `$unserialize = true/false`, cùng kiểu receiver và runtime configuration. Không dùng một contract tổng quát để gán mọi tham số thư viện là nguồn HTTP.

**Điều kiện đạt:** tạo được trace có tiền điều kiện cụ thể cho Drupal 8.6.9, Laravel 5.6.29 và WordPress 5.8.2; bản vá Drupal 8.6.10, Laravel 5.6.30, WordPress 5.8.3 không bị báo cùng một đường khai thác. Nếu thiếu cấu hình ứng dụng, kết quả phải được gắn `conditional` thay vì `confirmed`.

### P1 — Dựng gadget theo đối tượng và liên kết với sink

**Vấn đề:** Monolog/RCE1 bị bỏ sót ngay cả khi quét sâu không chạm ngân sách. Đồ thị ứng viên chưa giữ đủ receiver tự tham chiếu và override kế thừa. Các chuỗi có callback closure cố định bị coi là sink động. XVWA có đủ nguồn, sink và gadget nhưng chúng chưa được hợp nhất.

**Thay đổi:** bổ sung trạng thái kiểu đối tượng/alias theo đường vào `core/call_graph.py` và `core/gadget_finder.py`; theo dõi `$this->handler = $this` và `AbstractHandler::handleBatch → BufferHandler::handle`; cho phép lặp lớp/đối tượng có giới hạn nhưng vẫn tránh lặp trạng thái vô hạn. Chỉ đánh dấu callable nguy hiểm khi giá trị có thể điều khiển; xử lý closure cố định riêng. Nối gadget vào điểm `unserialize` khi lớp được nạp và thuộc tính serialized có thể kiểm soát; không tự động hợp nhất mọi gadget của cùng dự án.

**Điều kiện đạt:** tái dựng đúng PHPGGC Monolog/RCE1 trên 1.23.0 bằng fixture vô hại; ứng viên `array_filter` closure cố định không được diễn giải là thực thi hàm tùy ý; XVWA có báo cáo tổng hợp `request → unserialize → __wakeup → eval` với bằng chứng thuộc tính `inject`.

### P1 — Giảm nhiễu và bảo toàn phạm vi bằng chứng

**Vấn đề:** WordPress có 571 finding nhưng 486 là rà soát API PHAR; Laravel có 28/39 mẫu `unserialize` trong `tests`; TCPDF có 2/16 exposure trong `examples`. Library mode hữu ích nhưng dễ bị đọc thành lỗ hổng độc lập. Một số `gadget_chains` tồn tại trong JSON nhưng không xuất thành `findings` mà không có lý do rõ ràng.

**Thay đổi:** tách `production`, `tests`, `examples`, `vendor` trong báo cáo mà vẫn cho phép quét toàn bộ; nhóm finding cùng sink theo mức bằng chứng, hiển thị ứng viên nào bị lọc và vì sao. Đặt mặc định hiển thị theo `observed source`, `modeled conditional`, `library assumption`, `syntactic review`; số lượng từng lớp riêng. Với PHAR, đưa PHP version và trạng thái wrapper guard vào cùng dòng cảnh báo.

**Điều kiện đạt:** người đọc không thể suy 571 finding WordPress là 571 lỗ hổng; TCPDF 6.2.22 không bị gán CVE cũ từ exposure API giả định; các finding trong test/example không lẫn vào thống kê production.

### P1 — Hiệu năng khi bật side effects

**Vấn đề:** mặc định WordPress hoàn tất khoảng 105 giây, nhưng lượt `--experimental-side-effects` vượt thời gian thực nghiệm và phải dừng; Drupal từng có lượt side effects timeout, dù bản cuối hoàn tất khoảng 188 giây. Không thể bật tùy chọn này mặc định cho project lớn nếu chưa đo và giới hạn chi phí.

**Thay đổi:** profile theo pha, số summary/effect evaluations và hàng đợi worklist; cache theo hàm, giới hạn theo SCC hoặc nhu cầu sink, tránh lan truyền effect trên phần mã không liên quan. Khi chạm ngân sách, phát JSON `incomplete` với pha và nguyên nhân, thay vì thiếu báo cáo cuối.

**Điều kiện đạt:** lượt WordPress/Drupal bật side effects hoàn tất trong ngân sách đã định trên cùng máy hoặc xuất trạng thái incomplete có thể kiểm toán; kết quả ca nhỏ không hồi quy.

### P2 — Bộ kiểm thử đối chứng có nhãn và khả năng tái lập

**Thay đổi:** lưu manifest commit, PHP mục tiêu, tham số quét và nhãn kỳ vọng cho cặp vulnerable/patched: Laravel 5.6.29/5.6.30, Drupal 8.6.9/8.6.10, WordPress 5.8.2/5.8.3, Saloon 3.0.0/4.0.0, TCPDF 6.2.19/6.2.22; thêm XVWA dương và Monolog gadget. Chỉ tính precision/recall trên tập nhãn xác định và báo riêng lỗi quét, timeout, thiếu dependency. Công cụ tham chiếu Psalm/Progpilot chưa có kết quả full Drupal hợp lệ nên không lấy số 0 của chúng làm ground truth.

## Thứ tự thực hiện đề xuất

1. Sửa guard và cách xếp hạng trước để loại CRITICAL thiếu cơ sở.
2. Thêm mô hình đường Laravel, WordPress, Drupal và cặp trước/sau vá.
3. Hoàn thiện gadget Monolog và ghép bằng chứng trên XVWA.
4. Giảm nhiễu báo cáo, sau đó tối ưu side effects trên WordPress/Drupal.
5. Chạy lại toàn bộ ma trận theo manifest cố định và chỉ công bố số đo độ chính xác khi mỗi ca có nhãn cùng báo cáo hợp lệ.
