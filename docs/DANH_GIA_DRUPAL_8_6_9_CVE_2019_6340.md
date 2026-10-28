# Kiểm thử Drupal 8.6.9 — CVE-2019-6340

Ngày thực hiện: 23/10/2026. Mã scanner: snapshot sau giai đoạn nâng cấp 14.

## 1. Kết luận

Công cụ hiện tại **định vị đúng sink liên quan CVE nhưng chưa phát hiện được
đường taint hoàn chỉnh từ request tới sink trong toàn dự án Drupal**.
`LinkItem.php:194` và `MapItem.php:67` được báo `php-unserialize-review`, mức
MEDIUM, evidence `syntactic_review`. Inventory của cả hai là
`no_tracked_source`, không phải kết luận an toàn.

Lượt bật side effects mới timeout. Psalm và Progpilot không hoàn tất phân tích
toàn bộ dự án thành công trong môi trường hiện tại. CodeQL không dùng được để
đối chiếu PHP. Do đó không thể kết luận công cụ chính chính xác hơn các công cụ
tham chiếu dựa trên tổng số cảnh báo hoặc các báo cáo lỗi/rỗng.

## 2. Phạm vi và môi trường

- Đầu vào: `testcase/drupal-8.6.9`; `Drupal::VERSION` là `8.6.9`.
- 8.855 file PHP và các phần mở rộng liên quan, 1.199.211 dòng được scanner ghi nhận.
- Không loại tests/core khỏi tập đầu vào. Psalm và Progpilot nhận cùng danh sách
  8.855 file; hash mã nguồn Drupal không thay đổi trong đợt chạy.
- Thư mục **không có `vendor/`**. Composer lock khai báo Guzzle 6.3.0, Symfony
  serializer/http-foundation 3.4.15; đây không phải các dependency đã được quét.
- Scanner: Python 3.12, PHP mục tiêu 7.4, demand summaries, không LLM;
  POP depth 10, tối đa 20.000 paths và 500.000 expansions; foreach CFG tắt.
- Lượt chính dùng cấu hình mặc định; lượt thử nghiệm bật
  `--experimental-side-effects`. Hai lượt có cùng source manifest.
- Psalm/Progpilot: image `php-sast-references:local`, PHP runtime 8.5.11,
  không mạng, 2 CPU, RAM 3 GB, PHP memory limit 2.500 MB; timeout 900 giây.
  Psalm được đặt `--php-version=7.4`, taint analysis, một worker, không cache.
  Progpilot đặt analyze-includes, giới hạn 60 giây/file, 10.000 definitions.
- Image ID: `sha256:09517784f31530e57947bf30b4a6139fe12b7bc0a72ef10a28a070386e417e6b`.
  Psalm báo phiên bản `dev-master@592d2061af6fcaded36b87b1c956c8e1eb8194fb`.

Các thời gian dưới đây là thời gian của lệnh quét; scanner chạy native,
reference chạy container với giới hạn khác nhau nên không dùng chúng để xếp
hạng hiệu năng engine trực tiếp. Không chạy website Drupal hay payload RCE.

## 3. Căn cứ CVE và đường xử lý

Theo [SA-CORE-2019-003](https://www.drupal.org/sa-core-2019-003), Drupal 8.6.x
trước 8.6.10 nằm trong dải ảnh hưởng. Điều kiện triển khai liên quan RESTful Web
Services cho phép GET/PATCH/POST hoặc module web services khác. Lần thử này
không xác minh cấu hình module/endpoint của một website đang chạy.

Đường dữ liệu được rà soát thủ công từ mã hiện có:

1. `core/modules/rest/src/RequestHandler.php:174`: `$request->getContent()`.
2. Cùng file, dòng 185 và 196: decode dữ liệu rồi dispatch denormalizer.
3. `serialization/.../FieldableEntityNormalizerTrait.php:121`: lấy field từ entity,
   truyền instance trong context vào serializer.
4. `serialization/.../FieldNormalizer.php:52`: dispatch denormalizer của field item.
5. `hal/.../FieldItemNormalizer.php:58`: gọi
   `$field_item->setValue($this->constructValue($data, $context))`.
6. `link/.../LinkItem.php:194`: `unserialize($values['options'])`, không giới hạn
   `allowed_classes`. Điều kiện `is_string()` không loại bỏ serialized object.

`core/lib/Drupal/Core/Field/Plugin/Field/FieldType/MapItem.php:67` là sink liên
quan khác, gọi `unserialize($values)` khi đầu vào không phải array/MapItem.
Đường trên là phân tích thủ công có điều kiện theo kiểu field; scanner chưa
xuất được trace end-to-end này.

Bản 8.6.10 bổ sung kiểm tra serialized strings trước khi truyền dữ liệu vào
field; trait kiểm tra dữ liệu string của các cột serialized. Điều này cho thấy
chỉ thấy `unserialize()` là chưa đủ để phân biệt luồng đã được chặn và luồng
vulnerable. Tham chiếu: [HAL normalizer 8.6.10](https://raw.githubusercontent.com/drupal/drupal/8.6.10/core/modules/hal/src/Normalizer/FieldItemNormalizer.php),
[SerializedColumnNormalizerTrait 8.6.10](https://raw.githubusercontent.com/drupal/drupal/8.6.10/core/modules/serialization/src/Normalizer/SerializedColumnNormalizerTrait.php).

## 4. Kết quả toàn dự án

| Công cụ/cấu hình | Thời gian | Kết quả thực tế | Giá trị đối chiếu CVE |
| --- | ---: | --- | --- |
| Scanner mặc định | 139,663 giây | Quét 8.855/8.855 file; 832 findings | Đúng vị trí sink, chưa có taint request tới sink |
| Scanner + side effects | 900,833 giây | Timeout, không có JSON finding cuối | Chưa đánh giá được khả năng phát hiện ở cấu hình này |
| Psalm | 275,676 giây | Crash, exit 1, không có JSON diagnostics hoàn chỉnh | Không coi là âm tính |
| Progpilot | 725,308 giây | Lỗi, exit 2; ghi nhận 1.248/8.855 file | JSON partial, không coi là âm tính |
| CodeQL | Không áp dụng | Java lỗi khởi động; không có PHP extractor trong bản cài | Không có kết quả phân tích PHP |

### Scanner mặc định

- 159 `php-unserialize-review`, 671 `php-phar-path-api-review`, 2 finding POP.
- Severity: 159 MEDIUM, 2 LOW, 671 INFO; không HIGH/CRITICAL.
- Evidence: 830 `syntactic_review`, 2 `candidate_call_chain`, không taint finding.
- Summary hội tụ; thời gian nội bộ 134,852 giây: parse/index/symbol 31,794;
  graph/summary 46,877; findings 55,029 giây.
- Giới hạn call graph bỏ 3.929 candidate edges. CLI exit 2 phản ánh giới hạn này,
  không phải crash. Có 4.154 scope CFG fallback trong 43.446 scope.
- Hai finding POP là các entry trong `Drupal\Core\Database\Driver\sqlite\Connection`
  và `Drupal\views\ViewExecutable`; không được coi là chuỗi khai thác CVE đã xác minh.
  Summary có 3 gadget chains, được tổng hợp thành 2 finding.

### Psalm

Lỗi: `Could not get class storage for symfony\component\httpkernel\terminableinterface`.
Đầu vào thiếu vendor phù hợp với dependency bị thiếu trong lỗi. Đây là lỗi kết
thúc phân tích của bản Psalm hiện tại, không chứng minh rằng Drupal không có
vulnerability hay rằng Psalm nói chung không phát hiện được CVE.

### Progpilot

Lỗi: `Call to a member function computeCallGraph() on null`.
`result.json` chứa `results: []`, `enumerated_files: 1248`, kèm trường `error`.
Không được trình bày danh sách rỗng này thành “quét đủ và không phát hiện”.

### CodeQL

Đã thử `version`, `resolve languages`, `resolve extractor --language=php`.
Launcher lỗi `could not find java.dll`. Thử đường dẫn ngắn ASCII và Java entrypoint
cùng bản cài tiếp tục lỗi `net.dll: Can't find dependent libraries`, có đường dẫn
bị biến dạng ký tự. Chưa xác định hoàn toàn nguyên nhân loader và không sửa
hệ thống Java để tránh làm thay đổi môi trường thử nghiệm.

Kiểm tra file cài đặt không có `php/codeql-extractor.yml`.
[Danh sách ngôn ngữ chính thức của CodeQL](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)
không hỗ trợ PHP. Kể cả sửa được Java, không thể dùng bộ CodeQL này như một
PHP insecure-deserialization scanner. Không có số “0 lỗ hổng” cho CodeQL.
Trường commit CodeQL do runner cũ ghi thừa kế repo cha không phải phiên bản
CodeQL; không sử dụng trường đó để định danh bản CLI.

## 5. Kiểm chứng ca biên từ hàm gốc

Tách nguyên văn hai method `setValue()` của LinkItem/MapItem, thêm parent stub
không làm gì và caller truyền trực tiếp đầu vào. Có hai ca dùng `$_POST` và hai
ca dùng chuỗi array cố định. Hash method và các giả định nằm trong `labels.json`.

| Ca | Nhãn | Scanner + effects | Psalm | Progpilot |
| --- | --- | --- | --- | --- |
| link_positive | Có untrusted deserialize | Phát hiện | TaintedUnserialize | Bỏ sót |
| link_negative | Không có nguồn không tin cậy | Không báo taint | Không báo taint | Không báo |
| map_positive | Có untrusted deserialize | Phát hiện | TaintedUnserialize | Bỏ sót |
| map_negative | Không có nguồn không tin cậy | Không báo taint | Không báo taint | Không báo |

Scanner đạt 4/4; Psalm có 2 `TaintedUnserialize` đúng ca dương và thêm 8 diagnostics
không phải taint (`MissingPureAnnotation`, `MissingOverrideAttribute`). Progpilot
hoàn tất 4 file, không lỗi nhưng không báo sink nào. Ca kiểm soát riêng
`unserialize($_POST['payload'])` được Progpilot phát hiện: cấu hình nguồn/sink
có hoạt động, giới hạn xuất hiện ở tình huống qua phương thức trong các fixture.
Không suy rộng tỷ lệ của bốn ca thành precision/recall trên Drupal.

Kiểm chứng runtime dùng PHP 8.5.11 trong cùng image với một `BoundaryProbe` mà
`__wakeup()` chỉ in `BENIGN_OBJECT_RESTORED`. Hai ca dương in dấu, hai ca âm
không in, cả bốn exit 0. Không có lệnh hệ thống/network/file write từ probe.
Đây chỉ chứng minh hành vi object restoration của method đã tách, **không phải
thực thi REST/HAL hoặc chứng minh RCE trên website Drupal**.

## 6. Nguyên nhân và ưu tiên tiếp theo

1. Thiếu mô hình dispatch của serializer/typed-data/plugin: class field và
   `target_instance` được tạo từ cấu hình runtime; resolver hiện chưa nối các
   mắt xích này tới setter. Ca biên phát hiện tốt nhưng full scan không có taint
   củng cố rằng khả năng nối luồng framework là hạn chế quan trọng.
2. Side effects chưa đủ hiệu năng cho Drupal: bật lên timeout ở cùng snapshot,
   còn mặc định hoàn tất. Cần profile worklist/effect binding trước khi bật mặc định;
   chưa có profile để quy toàn bộ thời gian cho một hàm cụ thể.
3. Coverage mới còn gắn `isset()` là `external_or_missing_function` trong metadata.
   Đây là chỗ phân loại intrinsic cần sửa, không phải bằng chứng thiếu hàm PHP đó.
4. Cần chuẩn bị dependency đúng composer.lock trong một bản sao riêng rồi quét lại
   để cải thiện điều kiện Psalm và kiểm tra gadget; chưa được gán kết quả scan hiện
   tại cho một bản Drupal có vendor đầy đủ.
5. Muốn đo độ chính xác CVE cần cả đường vulnerable và đường đã vá có ground truth,
   cùng trace tới sink. Không dùng CodeQL hoặc kết quả crash làm mẫu âm.

Trong đợt này không sửa engine scanner để chạy lại cho “đẹp số”; source manifest
khớp mã hiện tại. Chỉ thêm script điều phối, fixture và artifact đánh giá.

## 7. Artifact và tái lập

- [JSON đối chiếu tổng hợp](../reports/evaluation/drupal-cve-2019-6340-assessment/comparison.json).
- [JSON scanner mặc định](../reports/evaluation/drupal-cve-2019-6340-default/drupal-8.6.9.json).
- [Lượt thử nghiệm timeout](../reports/evaluation/drupal-cve-2019-6340-upgraded/runs.json).
- `reports/evaluation/drupal-cve-2019-6340-references/`: raw logs, file lists,
  config Psalm, JSON partial Progpilot, thời gian và lệnh từng công cụ.
- `reports/evaluation/drupal-cve-2019-6340-boundary-references/`: đối chiếu ca biên.
- `reports/evaluation/drupal-cve-2019-6340-control-reference/`: ca kiểm soát Progpilot.
- `reports/evaluation/drupal-cve-2019-6340-assessment/`: hash đầu vào, vị trí CVE,
  logs CodeQL, fixture và `boundary-runtime.json`.

Script điều phối: `scripts/evaluate_drupal_cve.py`; ca biên:
`scripts/evaluate_drupal_boundary.py`; tổng hợp:
`scripts/summarize_drupal_cve.py`. Các lệnh/cờ thực tế đều được lưu trong JSON
runs. Khi tạo đợt mới cần đổi label để giữ artifact của lần chạy hiện tại.
