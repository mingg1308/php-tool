# Kết quả sửa lỗi và đối chiếu công cụ PHP SAST

> Cập nhật sau đợt đánh giá này: [64 ca nhỏ mở rộng](KIEM_THU_NHO_MO_RONG.md)
> ghi các sửa đổi về readonly, options và evidence của guard. Các số liệu bên dưới
> thuộc snapshot `optimized` trước những sửa đổi đó và được giữ để đối chiếu.

## 1. Phạm vi và cách đọc

Đợt đánh giá ngày 15/10/2026 sử dụng tám thư mục trong `testcase`.
Kiến trúc và các vị trí mã nguồn của CodeQL, Progpilot, Psalm được phân tích trong
[tài liệu thiết kế](PHAN_TICH_CODEQL_PROGPILOT_PSALM.md).

CodeQL không hỗ trợ PHP trong bộ ngôn ngữ chính thức của phiên bản được khảo sát.
Vì vậy không có phép đo PHP CodeQL và không diễn giải điều này thành 0 finding.
Progpilot/Psalm được chạy thực tế bằng mã nguồn đã tải, có dependency Composer,
trong Docker PHP 8.5.11; phiên bản PHP mục tiêu được cấu hình riêng.
Không thực thi ứng dụng testcase và không dùng LLM trong các lượt đánh giá.

Các nhãn báo cáo:

- `before`: snapshot trước sửa, giới hạn 600 giây/dự án.
- `final`: bản trung gian đã sửa tính đúng đắn nhưng còn chậm.
- **`optimized`**: snapshot cuối của mã phân tích, quét đầy đủ tám thư mục.
- `library-final`: lượt riêng với `--library-mode` cho Saloon và Monolog 1.23.0.
- `external-final`: Progpilot/Psalm, giới hạn 600 giây.
- `external-retry`: chạy lại Progpilot Laravel, TCPDF, WordPress, giới hạn 180 giây.

Tất cả thời gian dưới đây là wall time của subprocess trong môi trường hiện tại.
Có các tác vụ chạy đồng thời và khác biệt Windows/Linux; không dùng số liệu này
để kết luận scanner nào nhanh hơn một cách tổng quát.

## 2. Kết quả scanner trước và sau sửa

| Dự án | Trước sửa (giây) | Sau sửa (giây) | Tổng finding | Vị trí request → unserialize | Giới hạn còn lại |
|---|---:|---:|---:|---:|---|
| Drupal 8.6.9 | timeout 600 | 136,532 | 495 | 0 | Call graph bị giới hạn |
| Laravel 5.6.29 | 168,839 | 17,379 | 35 | 0 | Call graph bị giới hạn |
| Monolog (thư mục `monolog`) | 15,902 | 5,063 | 1 | 0 | Call graph bị giới hạn |
| Monolog 1.23.0 | 8,173 | 3,501 | 23 | 0 | Call graph bị giới hạn |
| Saloon 3.0.0 | 5,017 | 2,639 | 1 | 0 | 3 tệp có lỗi parser |
| TCPDF 6.2.22 | 137,679 | 42,109 | 37 | 0 | Không có lỗi được báo trong lượt này |
| WordPress 5.8.2 | timeout 600 | 180,086 | 419 | 2 | Parser và call graph; cần xem mục 4 |
| XVWA | 6,492 | 3,780 | 25 | 1 | Call graph bị giới hạn |

**8/8 lượt hoàn tất và xuất JSON; không phải 8/8 lượt có coverage đầy đủ.** Tổng
finding gồm cả luật cú pháp và nhận xét cần rà soát, không phải số lỗ hổng POI.
Số 0 ở cột request chỉ có nghĩa chưa truy vết được nguồn request tới sink theo
mô hình hiện tại; không loại trừ luồng qua database, cache hoặc alias phức tạp.

### Nguyên nhân giảm thời gian

1. Summary liên hàm dùng worklist theo phụ thuộc, không lặp tất cả hàm theo vòng
   toàn cục. Chuỗi 40 hàm không bị mất kết quả vì giới hạn 24 vòng cũ.
2. Chỉ mục AST và phân cấp lớp giảm duyệt lại cây/các lớp trong call graph.
3. Reverse reachability từ sink loại nhánh POP không có đường tới sink trong
   graph hiện có; các giới hạn candidate vẫn được ghi trong báo cáo.
4. Cache đọc reaching definitions ngăn tính lặp chuỗi augmented assignment.
   Cache dùng chung vòng đời với cache biểu thức, được xóa khi tính lại summary.
5. Rule engine kiểm tra pattern tại node trước khi đi tìm ancestor cho
   `pattern-inside`. Không cần render/duyệt scope lớn cho node không thể khớp.

Đối chiếu riêng Drupal giữa `final` và `optimized`: 495 finding có cùng tập ID;
giai đoạn `findings` giảm từ khoảng 382,292 xuống 33,566 giây; toàn lượt từ
522,885 xuống 136,532 giây. Đây là bằng chứng bảo toàn đầu ra của trường hợp
này, không phải chứng minh mọi chương trình đều tương đương.

## 3. Đối chiếu với Progpilot và Psalm

Đơn vị là vị trí `(file tương đối, dòng sink unserialize)`. Với scanner hiện tại,
chỉ dùng taint finding có `source_assumption=observed_request`; mô hình framework,
library API, POP và luật cú pháp không cộng vào cột này. Progpilot lọc
`sink_name=unserialize`, dù công cụ gắn CWE_95; Psalm lọc `TaintedUnserialize`.

| Dự án | Scanner hiện tại | Progpilot | Psalm |
|---|---:|---|---|
| Drupal | 0, coverage không đầy đủ | Timeout 600 s | Lỗi, không có JSON hợp lệ |
| Laravel | 0, coverage không đầy đủ | Timeout 180 s ở lượt chạy lại | 0, có diagnostic |
| Monolog | 0, coverage không đầy đủ | 0 | 0, có diagnostic |
| Monolog 1.23.0 | 0, coverage không đầy đủ | Timeout 600 s | 0, có diagnostic |
| Saloon | 0, có lỗi parser | 0 | 0, có diagnostic |
| TCPDF | 0 | Timeout 180 s | Timeout 600 s |
| WordPress | 2 cần xem xét điều kiện bảo vệ | Timeout 180 s | 0, có diagnostic |
| XVWA | 1, coverage không đầy đủ | 1 trong báo cáo một phần, sau đó exception | 1, có diagnostic |

Psalm lỗi Drupal vì thiếu class storage của
`Symfony\Component\HttpKernel\TerminableInterface`. Mã testcase được sao chép
theo phần mở rộng PHP, không cài dependency của ứng dụng; kết quả có thể bị hạn
chế bởi thiếu dependency, include và bootstrap. Psalm còn báo các diagnostic như
MissingFile/UndefinedClass; một báo cáo JSON hợp lệ không đồng nghĩa mọi symbol
đã được resolve. Progpilot lỗi XVWA ở `computeCallGraph()` trên giá trị null.
Lượt Progpilot Laravel ban đầu còn gặp lỗi Docker; bảng dùng lượt chạy lại có
timeout hữu hạn, không dùng thời gian sự cố daemon làm benchmark.

Không có ground truth đầy đủ cho tám dự án, nên không tính precision/recall hoặc
tuyên bố công cụ vượt Psalm/Progpilot dựa trên số finding. Những lần lỗi hoặc
timeout là **không đủ dữ liệu**, không phải không tìm thấy lỗ hổng.

## 4. Kiểm tra thủ công các kết quả tiêu biểu

### 4.1. XVWA: đồng thuận tại sink trực tiếp

[`home.php:38`](../testcase/xvwa/vulnerabilities/php_object_injection/home.php)
gọi `unserialize($_REQUEST['r'])`. Cả ba báo cáo chứa vị trí này. Scanner hiện tại
ghi nguồn request trực tiếp và đường truyền tới sink. Đây là điểm deserialize
dữ liệu không tin cậy rõ ràng; tác động khai thác vẫn phụ thuộc lớp/gadget được
nạp. Không chạy payload khai thác trong đợt đánh giá.

### 4.2. Saloon: API thư viện không tương đương endpoint

[`AccessTokenAuthenticator.php:105`](../testcase/saloon-3.0.0/src/Http/Auth/AccessTokenAuthenticator.php)
gọi `unserialize($string, ['allowed_classes' => true])`. Chế độ thường có một
cảnh báo cú pháp, chưa có đường request từ ứng dụng sử dụng thư viện.
Lượt `library-final` có thêm một exposure MEDIUM với giả định tham số API công
khai có thể bị kiểm soát; tổng cộng hai finding. Progpilot/Psalm không báo taint
ở đây không đủ chứng minh hàm an toàn khi ứng dụng truyền đầu vào không tin cậy.

Ba lỗi parser nằm tại `BaseResource.php:12`,
`CustomOAuthAuthenticator.php:16`, `QueryParameterRequest.php:28`, liên quan thứ
tự modifier `readonly protected/public` trong constructor promotion. Đợt sửa
này chưa thay grammar; lỗi vẫn được báo thay vì bị bỏ qua.

### 4.3. Monolog: tách gadget khỏi nguồn deserialize

Monolog 1.23.0 có 23 finding ở chế độ thường; ở `library-final` có 32, trong đó
9 exposure từ tham số API công khai. Báo cáo ghi 35 gadget chain candidates;
không phải 35 lỗ hổng khai thác được. Có 485 cạnh candidate bị cắt bởi cap, nên
coverage POP chưa đầy đủ. Đối chiếu cột TaintedUnserialize của Psalm với tổng POP
candidate của scanner sẽ sai về đơn vị và mục tiêu phân tích.

### 4.4. WordPress: finding bổ sung không chứng minh chính xác hơn

Hai vị trí được scanner báo nhưng Psalm không báo:

1. `wp-includes/functions.php:624`: trace được chọn đi từ
   `wp-admin/includes/ajax-actions.php:1608`, qua `_list_meta_row`, tới
   `maybe_unserialize`. Tuy nhiên tại `wp-admin/includes/template.php:625–627`,
   nhánh này yêu cầu `is_serialized_string($entry['meta_value'])`; nhánh array/object
   trả về sớm. **Trace đại diện này chưa chứng minh POI** vì miền giá trị đã bị
   giới hạn thành chuỗi serialized. Báo cáo còn ghi năm luồng thay thế; cần xem
   từng caller trước khi kết luận cả sink là an toàn hoặc có lỗ hổng.
2. `wp-includes/class-wp-customize-widgets.php:1452`: trước sink có
   `hash_equals($this->get_instance_hash_key($decoded), $value['instance_hash_key'])`
   và return khi không khớp. Hàm tạo hash tại dòng 1393–1394 gọi `wp_hash`.
   Scanner chưa chứng minh kẻ tấn công vượt được kiểm tra tính toàn vẹn; finding
   HIGH/LOW hiện tại phải xem là yêu cầu kiểm tra thủ công, không phải POI xác thực.

Nguyên nhân còn lại là chưa có mô hình refinement theo điều kiện của hàm người
dùng và xác minh dữ liệu ký/MAC. Không thể đơn giản coi mọi `hash_equals` là
sanitizer: hai vế có thể đều do attacker kiểm soát. Tương tự, tự bỏ taint ở mọi
hàm bắt đầu `is_` sẽ tái tạo lỗi bỏ sót đã sửa. Cần mô hình có bằng chứng về
miền dữ liệu, khóa bí mật và dominance của nhánh bảo vệ.

WordPress cũng có parser error tại `general-template.php:4823`, hàm tên
`readonly` của mã PHP cũ, và 918 cạnh dispatch candidate bị cắt. Không tuyên bố
hai finding là hai CVE hay WordPress đã được kiểm tra toàn diện.

## 5. Kiểm thử hồi quy

`python -m unittest discover -s php_deserial_sast/tests -v`: **8 test methods đều
đạt**, bao gồm 34 ca nhỏ dạng subtest và các kiểm tra bổ sung: chuỗi 40 hàm,
chuỗi 40 augmented assignment với đầu vào an toàn/không an toàn, NUL trong chuỗi,
target không tồn tại, nguồn framework có nhãn giả định, inherited POP entry và
ranh giới function/closure của `pattern-inside`. `verify-rules` nạp thành công
10 luật YAML; đây là kiểm tra cấu hình luật, không chứng minh chất lượng phát hiện.

Trên 34 fixture, scanner có 19 ca được báo theo mô hình đã định nghĩa; Progpilot
có 11 và Psalm có 18. Không dùng ba số này làm thứ hạng độ chính xác: hai công cụ
tham chiếu có cảnh báo với `allowed_classes=false`/allowlist rỗng, trong khi mục
tiêu POI hiện tại không coi đây là tái tạo object tùy ý. Các ca nguồn framework và
hàm chưa resolve cũng có giả định khác nhau. Kết quả từng ca nằm ở
[`fixtures.json`](../reports/evaluation/comparison/fixtures.json).

## 6. Bằng chứng và tái lập

- [Bảng CSV tổng hợp](../reports/evaluation/comparison/summary.csv).
- [Vị trí chung/khác và trạng thái từng lượt](../reports/evaluation/comparison/sites.json).
- [Command, thời gian, lỗi và summary của 8 dự án](../reports/evaluation/optimized/runs.json).
- [SHA-256 mã nguồn scanner](../reports/evaluation/optimized/source_manifest.json).
- [Lượt library mode](../reports/evaluation/library-final/runs.json).
- [Môi trường công cụ tham chiếu](../reports/evaluation/external-final/environment.json).

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -v
py -3.12 -m php_deserial_sast.cli verify-rules
py -3.12 scripts/evaluate_scanner.py optimized --snapshot --timeout 600
py -3.12 scripts/compare_results.py --label optimized
```

Các đường dẫn dưới `reports` trỏ tới artifact cục bộ, bị Git ignore. Muốn chia sẻ
toàn bộ bằng chứng cần kèm artifact; hai tài liệu Markdown và script có thể đưa
vào quản lý phiên bản. Không tự động commit/push trong đợt công việc này.
