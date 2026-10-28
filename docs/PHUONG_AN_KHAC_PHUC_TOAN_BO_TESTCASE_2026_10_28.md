# Phương án nâng cấp engine theo toàn bộ testcase (28/10/2026)

## 1. Căn cứ và ranh giới kết luận

Bộ mốc là [lượt quét 28/10/2026](../reports/evaluation/retest-2026-10-28-open-source/ASSESSMENT.md): 9 lượt trên 8 thư mục, tất cả tệp được quét, 0 lỗi. Báo cáo gốc, cấu hình PHP và hash mã engine nằm trong cùng thư mục. Phương án này tập trung sửa **công cụ**; không sửa các dự án testcase. Một scanner tĩnh không thể chứng minh mọi điều kiện triển khai hay bảo đảm phát hiện mọi lỗ hổng PHP. Đích có thể kiểm chứng là: tìm đúng đường đã công bố, phân biệt điều kiện đã biết với giả định, không gán CVE sai phiên bản, và giữ kết quả âm tính ở bản vá.

Advisory và bản vá là nhãn kiểm thử, **không phải luật phát hiện**. Không được tạo finding chỉ vì tên package hoặc phiên bản khớp CVE. Phân biệt năm mức bằng chứng trong JSON:

1. `syntactic_sink`: thấy lời gọi nguy hiểm.
2. `observed_source_to_sink`: nguồn dữ liệu không tin cậy nối đến sink trong mã.
3. `conditional_source_to_sink`: trace cần guard, cấu hình hoặc dispatch chưa giải.
4. `compatible_gadget`: lớp/gadget có thể được tạo, nhưng quyền điều khiển thuộc tính hoặc kích hoạt chưa chứng minh.
5. `validated_chain`: đầy đủ nguồn → điều kiện → object → magic method → sink trong mô hình, kèm danh sách giả định runtime còn lại. Nhãn này không đồng nghĩa đã chạy exploit.

Giữ riêng `potential_impact` và `evidence_level`; không lấy High/Critical hay tổng số finding làm phép đo đúng/sai. Mọi route bị loại phải lưu nguyên nhân có thể kiểm toán; không âm thầm xóa khi bộ phân tích không đủ bằng chứng.

## 2. Thay đổi nền tảng cần làm trước các adapter dự án

### A. Đồ thị bằng chứng theo entrypoint và trạng thái thực thi

- Mở rộng [dataflow.py](../php_deserial_sast/core/dataflow.py), [class_loading.py](../php_deserial_sast/core/class_loading.py) và [framework_dispatch.py](../php_deserial_sast/core/framework_dispatch.py) để mỗi cạnh giữ: entrypoint/caller, kiểu nguồn, trường dữ liệu, điều kiện CFG phải thỏa, loại receiver, lớp được nạp, phạm vi production/test/vendor và mức chắc chắn `proven / conditional / unknown / excluded`.
- Tính reachable theo **entrypoint** thay vì một bảng symbol toàn project. Cùng tên lớp trong `test.php` tạo payload không được thay lớp production trong `libs`; include, Composer autoload và classmap chỉ được công nhận khi có bằng chứng nạp qua đường vào đang xét.
- Hợp nhất các đường tương đương theo chữ ký ngữ nghĩa `(source, entrypoint, sink, guard-set, receiver-set)`. Giữ số route bị gộp và đại diện của từng nhóm để tránh WordPress tạo hàng trăm route không thể thẩm định. Khi vượt ngân sách, đánh dấu coverage thiếu thay vì suy ra âm tính.
- Không gắn sink request với gadget chỉ vì chúng nằm cùng repository. [pop_evidence.py](../php_deserial_sast/core/pop_evidence.py) phải chứng minh chính site `unserialize` cho phép entry class đó, lớp có thể được nạp, thuộc tính dùng trong chuỗi có thể lấy từ serialized object, và magic method được kích hoạt bởi đúng sự kiện (wakeup, destructor, render, gọi method sau session, v.v.).

### B. Hợp đồng guard/transform và hiệu ứng dữ liệu

- Bổ sung miền dữ liệu cho `raw bytes`, `serialized-string`, `serialized-object`, `ciphertext`, `authenticated ciphertext`, `plaintext`, `local path`, `phar path`. `is_serialized_string()` chỉ loại object ở nhánh được chứng minh; `is_serialized()` đơn lẻ không phải sanitizer.
- Theo dõi ràng buộc giá trị của đối số (`allowed_classes`, `$unserialize`, PHP version), so sánh nhánh và điều kiện dominates sink. Hàm validator phải có contract về **giá trị trả về**, tham số nào đã được kiểm tra và liệu dữ liệu bị thay đổi sau kiểm tra; tên hàm hoặc một lời gọi `validMac()` không đủ để chứng minh an toàn.
- Mở rộng hiệu ứng liên hàm cho đọc/ghi property, array key, session, DB abstraction và callback, nhưng bật từng mô hình khi có ca hồi quy dương/âm. Dùng demand slicing từ sink để giảm chi phí ở WordPress/Drupal; báo rõ khi `summary_evidence_truncated` hoặc CFG fallback khiến kết luận chưa đủ.
- Tạo đặc tính runtime theo phiên bản PHP cho PHAR metadata và serialized object token; không giả định một đường PHAR ở PHP 8+ giống PHP 7.x.

### C. Không làm chìm gadget đúng trong bước xuất finding

- Sửa [scanner.py `_deduplicate_findings`](../php_deserial_sast/scanner.py) (hiện khóa POP dựa trên vị trí `AbstractHandler::__destruct` kế thừa và loại sink). Nhóm gadget theo entry class, magic method, sink location, receiver path và event kích hoạt; hiển thị top routes khác biệt hoặc một finding với danh sách chain đầy đủ, có thể truy cập ngay.
- Bảo toàn ID chuỗi trong `gadget_chains` và `findings`; JSON/SARIF/console phải thể hiện quan hệ đại diện và alternatives. Không nâng ứng viên gadget lên RCE xác nhận khi thiếu deserialization entry.
- Viết bài kiểm tra chống hồi quy bằng Monolog/RCE1: `c47409495791` hoặc chữ ký đường tương đương phải xuất hiện trong finding hiển thị, không chỉ metadata alternative.

## 3. Tiêu chí cụ thể cho từng testcase

| Mẫu | Mắt xích hiện thiếu và mã cần xử lý | Tiêu chí chấp nhận |
| --- | --- | --- |
| **XVWA PHP Object Injection** | [home.php](../testcase/xvwa/vulnerabilities/php_object_injection/home.php): `$_REQUEST['r'] → unserialize()` và `PHPObjectInjection::__wakeup → eval($inject)` hiện là hai finding, dù `pop_evidence.py` đã ghi `linked_source_sinks`. Bổ sung mô hình thuộc tính public từ object được giải tuần tự hóa và điều kiện `isset($inject)` là kiểm tra tồn tại, không phải sanitizer. | Một đường liên kết có đủ source, class, `inject`, magic method và eval; vẫn ghi `runtime_not_executed`. Thay `allowed_classes => false` hoặc loại `inject` thì đường liên kết biến mất. |
| **Saloon 3.0.0** | [AccessTokenAuthenticator.php](../testcase/saloon-3.0.0/src/Http/Auth/AccessTokenAuthenticator.php): `unserialize($string, ['allowed_classes' => true])`. [package_context.py](../php_deserial_sast/core/package_context.py) có advisory nhưng không biết caller token của ứng dụng. | Giữ đúng sink/CVE ở bản 3.0.0, `conditional_api_exposure` khi chỉ có library; không ghi RCE đã xác minh. Trên fixture caller lưu token không tin cậy, nâng bằng chứng source; trên caller hằng số hoặc allowlist chặn object, không nâng. Không gán advisory cho bản 4.0.0. [Advisory dự án](https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9). |
| **Monolog 1.23.0** | [AbstractHandler.php](../testcase/monolog-1.23.0/src/Monolog/Handler/AbstractHandler.php), `SyslogUdpHandler` và `BufferHandler`: chain RCE1 đã có trong `gadget_chains`, bị gộp ở `scanner.py`. Cần mô hình alias/tự tham chiếu receiver, các điều kiện `bufferSize`, `level`, `processors` và callback. | RCE1 có finding riêng/đại diện rõ; ghi `compatible_gadget` khi không có app sink. Fixture ứng dụng có object được nạp + nguồn serialize cho đường liên kết, fixture không nạp class hoặc sai callback chỉ còn ứng viên/loại. Đối chiếu [PHPGGC Monolog/RCE1](https://github.com/ambionics/phpggc/blob/master/gadgetchains/Monolog/RCE/1/chain.php). |
| **Monolog bản hiện tại** | Cùng cơ chế gadget, nhưng cấu trúc/phiên bản khác; không dùng nhãn RCE1 của 1.x cho mã 3.x. | Không gán CVE hoặc chuỗi gadget cũ chỉ từ tên package; mọi ứng viên có sink/callback/entry class và giả định riêng. Không coi thiếu `unserialize` trong thư viện là bằng chứng an toàn của app tích hợp. |
| **TCPDF 6.2.22** | [tcpdf_static.php](../testcase/tcpdf-6.2.22/include/tcpdf_static.php) từ chối `phar://` trong `TCPDF_STATIC::file_exists`; các caller ở `tcpdf.php`/`tcpdf_images.php` gọi helper trước API ảnh. Hiện auto library mode còn 16 Medium giả định. Mô hình contract path validator qua caller và kiểm tra đường dẫn không bị thay sau guard. | `CVE-2018-17057` là `outside_affected_range`; các đường đã chứng minh đi qua helper không được báo như PHAR exploit. API chưa có caller/guard vẫn giữ `conditional_api_exposure`, không biến mất vì version. Quét cặp trước vá 6.2.19 và bản vá 6.2.22 bằng cùng PHP/config để đo khác biệt đúng đường. [Commit vá](https://github.com/tecnickcom/TCPDF/commit/1861e33fe05f653b67d070f7c106463e7a5c26ed). |
| **Laravel 5.6.29** | [Encrypter.php](../testcase/laravel-5.6.29/src/Illuminate/Encryption/Encrypter.php) kiểm tra cấu trúc và MAC trước `openssl_decrypt`, rồi xét `$unserialize`; `framework_dispatch.py` đang thêm cạnh cookie và `X-XSRF-TOKEN` có điều kiện. Cần ràng buộc argument thứ hai và contract MAC/decrypt theo ciphertext/key, giữ APP_KEY là tiền điều kiện external. | Báo đúng sink 149 và cả hai caller liên quan, nhưng kết luận chỉ là đường có điều kiện khi không biết APP_KEY/binding; dữ liệu header tùy ý không được mô tả là RCE trực tiếp. Bản 5.6.30 không còn cùng đường cookie/header nếu truyền cờ vô hiệu hóa unserialize, dù sink thư viện vẫn tồn tại. [CVE-2018-15133](https://github.com/advisories/GHSA-qvqm-h22r-4cp9), [hướng dẫn bản vá](https://laravel.com/framework/docs/5.6/upgrade#upgrade-5.6.30). |
| **WordPress 5.8.2** | [upgrade.php](../testcase/wordpress-5.8.2/wp-admin/includes/upgrade.php) có đường `__get_option('db_version') → upgrade_280()` dưới `is_multisite()`, đọc `option_value` từ `$wpdb->get_results()` rồi gọi raw `unserialize` ở 1616. `dataflow.py` cần mô hình dữ liệu option qua DB và khác biệt `maybe_serialize`/`is_serialized` với token `C` trên PHP phù hợp; [guard_models.py](../php_deserial_sast/core/guard_models.py) đã loại một số route `is_serialized_string`, cần mở rộng cẩn trọng. | CVE-2022-21663 được nêu ở chính 1616 với DB source, điều kiện multisite/db_version và giả định quyền ghi option; không lấy 52 High PHAR hay High ở `functions.php:624` để nhận diện CVE. Bản 5.8.3 dùng `maybe_unserialize` không còn đường object tương đương. [Phân tích của nhóm phát hiện](https://www.sonarsource.com/blog/wordpress-object-injection-vulnerability/), [commit vá](https://github.com/WordPress/WordPress/commit/638ef7815ec29318434365ffde1d3cef7437b948). |
| **Drupal 8.6.9** | [RequestHandler.php](../testcase/drupal-8.6.9/core/modules/rest/src/RequestHandler.php) → serializer/normalizer → `MapItem::setValue`/`LinkItem::setValue`. `framework_dispatch.py` hiện thêm toàn bộ field class khả dĩ, nên trace vẫn `unresolved_return_flow`. Cần resolve `rest.resource`/format/module config, field schema và `target_instance`; dependency thiếu phải được báo là thiếu, không tự giả lập đã nạp. | Hai sink production được gắn với đúng điều kiện REST/HAL/field khi cấu hình fixture chứng minh; `TestObjectItem` trong tests không được tính là CVE sản phẩm. Không có cấu hình triển khai thì giữ `conditional`, không ghi CVE đã khai thác. Bản 8.6.10 không giữ đường không kiểm soát tương đương. [SA-CORE-2019-003](https://www.drupal.org/sa-core-2019-003). |

**Bộ phụ ngoài `testcase`:** Pokémon và workshop level 1/2 đã có JSON trước đó. Giữ làm hồi quy cho luồng upload → session → method/render, magic destructor và include-glob loại `Router`. Chúng hữu ích để kiểm tra A/C, nhưng không gộp vào phép đo 8 dự án mã nguồn mở.

## 4. Trình tự triển khai và phép kiểm chứng

1. **Nhãn chuẩn và đối chứng.** Tạo manifest machine-readable cho từng đường (package/version, entry, source, guard, sink, gadget, trạng thái mong đợi, nguồn advisory/commit). Cố định mã các bản vá tham chiếu trong bản sao riêng, không sửa `testcase` gốc. Với TCPDF/Laravel/WordPress/Drupal, dùng cặp vulnerable/patched cùng cấu hình PHP. Mọi nhãn phải có vị trí hoặc điều kiện cụ thể; không dùng tổng finding để tính precision/recall.
2. **Sửa gộp gadget và liên kết POP.** Làm trước vì Monolog là lỗi đã xác định và XVWA là ca nhỏ dương tính. Thêm ca âm: thiếu lớp, allowlist, callback cố định, thuộc tính sai, path destructor không tới sink. Chạy unit test liên quan và full scan XVWA/Monolog.
3. **Thêm hợp đồng guard/transform.** TCPDF wrapper, Laravel MAC/decrypt flag và WordPress serialized-string/token domain. Mỗi contract cần một ca dương và các phản ví dụ: validator bị shadow, path thay sau check, MAC thất bại, flag false, object token bị loại. Chạy bản trước/sau vá và so sánh route ID, không chỉ severity.
4. **Thêm hiệu ứng DB và cấu hình framework.** WordPress option DB/upgrade; Drupal normalizer/field/config. Ghi dependency chưa có thành `unknown` thay vì cạnh chắc chắn. Chạy fixture tối giản trước full scan 1.212/8.855 tệp; đặt ngân sách và theo dõi `summary_evidence_truncated`, CFG fallback, unresolved calls.
5. **Hiển thị và kiểm toán.** JSON, SARIF, console phải nhất quán về `evidence_level`, `assumptions`, `excluded_routes`, `alternative_gadget_chain_ids` và `source_scope`. Cảnh báo library API và PHAR review không được trình bày như CVE đã xác nhận. Chạy lại `scripts/retest_case_studies.py`, so manifest mã nguồn, 0 lỗi, đủ file và kiểm tra các vị trí nhãn; sau đó mới báo bảng case-level TP/FP/FN/TN cho tập đã gắn nhãn.

## 5. Tiêu chí hoàn tất

- Không mất các đường đúng của XVWA, Saloon, Monolog/RCE1, Laravel, WordPress và Drupal; các bản vá đối chứng không bị gán cùng đường CVE như bản lỗi.
- TCPDF 6.2.22 không bị báo CVE-2018-17057 như lỗ hổng hiện hữu; ứng viên API khác vẫn giữ điều kiện và nguồn cụ thể.
- Mỗi finding có thể truy đến source, guard, sink, gadget và tập giả định, hoặc chỉ rõ mắt xích nào `unknown`. Sự có mặt của advisory/version chỉ là ngữ cảnh.
- Mọi lượt full scan hoàn tất, không có parse/coverage/budget error bị che; nếu giới hạn phân tích xảy ra, báo cáo phải ghi `incomplete` và không tính là âm tính sạch.
- Không tuyên bố `exploitability_verified=true` khi chưa có kiểm thử runtime không gây hại trên đúng ứng dụng/cấu hình. Mục tiêu là độ chính xác có thể kiểm toán trong các testcase, không phải bảo đảm tuyệt đối cho mọi dự án PHP.
