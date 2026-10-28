# PHP Insecure Deserialization SAST

Công cụ phân tích tĩnh mã PHP nhằm hỗ trợ phát hiện luồng dữ liệu có thể dẫn đến insecure deserialization (CWE-502) và các chuỗi gọi hàm kiểu Property-Oriented Programming (POP). Công cụ kết hợp phân tích AST, taint analysis, luật YAML và call graph; có thể xuất báo cáo JSON, SARIF hoặc HTML.

> Đây là công cụ hỗ trợ rà soát. Kết quả là phát hiện tĩnh/ứng viên cần được kiểm tra trong ngữ cảnh ứng dụng, phiên bản PHP và điều kiện triển khai thực tế.

## Tính năng

- Phân tích cú pháp PHP bằng Tree-sitter.
- Duyệt đệ quy toàn bộ thư mục dự án, bao gồm thư mục ẩn, `vendor/` và `node_modules/`; chỉ bỏ qua thư mục quản lý phiên bản (`.git`, `.svn`, `.hg`) và các thư mục được cấu hình loại trừ.
- Theo dõi một số nguồn request tới `unserialize()`, `igbinary_unserialize()` và các thao tác filesystem có thể xử lý đường dẫn `phar://`.
- Nhận diện nội dung `file_get_contents($_FILES[*]['tmp_name'])` là dữ liệu upload; chính chuỗi đường dẫn tạm vẫn không được coi là payload. Báo cáo các phương thức có thể được gọi trên object deserialize đã lưu vào `$_SESSION`, cùng các sink và lớp ứng viên, dưới dạng bằng chứng có điều kiện.
- Mô hình có điều kiện cho cookie và header `X-XSRF-TOKEN` của Laravel 5.6.29 qua `Encrypter::decrypt()`; báo cáo rõ kiểm tra MAC, `APP_KEY` và ràng buộc runtime chưa được xác minh.
- Rà soát lời gọi `Phar::getMetadata()` và `PharFileInfo::getMetadata()` khi xác định được kiểu receiver; trên PHP 8+ bỏ qua tùy chọn literal `allowed_classes => false` hoặc danh sách rỗng.
- Ghi inventory cho sink kể cả khi không tìm thấy luồng source đã hỗ trợ.
- Tự bật phân tích API thư viện khi `composer.json` ở gốc khai báo `type: library`; có thể đặt `--library-mode` hoặc `--application-mode` tường minh. Tham số API công khai chỉ là giả định có điều kiện.
- Phát hiện ứng viên POP qua call graph, bao gồm magic methods và một số lời gọi động.
- Luật YAML tích hợp và luật tùy chỉnh; kiểm tra bằng `verify-rules`.
- Luật rà soát `session_decode()` gồm trường hợp nhận trực tiếp `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST` và gợi ý INFO cho đầu vào khác. Kết quả cần xác minh `session.serialize_handler`, dữ liệu session và class được nạp.
- Luật rà soát thao tác nguy hiểm trực tiếp trong `__unserialize()`; một khớp cú pháp không chứng minh có đường giải tuần tự hóa từ dữ liệu không tin cậy.
- Báo cáo console, JSON, SARIF và HTML.
- Tùy chọn thẩm định bằng LLM qua OpenAI, Gemini hoặc Ollama. Mặc định tắt.
- Giới hạn kích thước tệp và số node AST tùy chọn; thống kê thời gian từng giai đoạn được ghi trong JSON.
- Phân tích POP dùng ngân sách duyệt đồ thị và phát rõ trạng thái chưa đầy đủ khi chạm giới hạn.
- Mặc định tính summary giá trị trả về theo nhu cầu; dùng `--eager-summaries` để đối chiếu với chế độ tính mọi return.
- Ghi coverage theo evidence/callee của từng finding và ràng buộc `allowed_classes` đối với ứng viên POP; không coi tương thích lớp là bằng chứng khai thác.

## Yêu cầu

- Python 3.9 trở lên.
- Windows, Linux hoặc macOS.

## Cài đặt

Từ thư mục dự án:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

Cài thêm thư viện client nếu muốn dùng LLM:

```powershell
pip install -e ".[llm]"
```

Trong `cmd.exe`, kích hoạt môi trường bằng `.venv\Scripts\activate.bat`. Các thư viện PHP dùng làm dữ liệu đánh giá không phải dependency cài đặt của scanner.

## Sử dụng

Quét thư mục hoặc một tệp PHP:

```powershell
php-deserial-sast scan C:\path\to\php-project
php-deserial-sast scan C:\path\to\php-project --format json --output report.json
php-deserial-sast scan C:\path\to\php-project --format sarif --output report.sarif
php-deserial-sast scan C:\path\to\php-project --format html --output report.html
```

Lệnh `scan` mặc định quét cả mã nguồn ứng dụng lẫn thư viện PHP đi kèm. Có thể dùng `--severity info` để lấy cả các cảnh báo cần xem xét và khai báo runtime để đánh giá đúng ngữ cảnh Phar:

```powershell
php-deserial-sast scan C:\path\to\php-project --severity info --php-version 8.2 --format json --output report.json
```

Có thể dùng module trực tiếp thay vì entry point:

```powershell
python -m php_deserial_sast.cli scan C:\path\to\php-project
```

Quét thư viện, đặt ngưỡng severity và chỉ định phiên bản PHP đích:

```powershell
php-deserial-sast scan C:\path\to\library --library-mode --php-version 7.4 --severity info --format json --output library-report.json
```

Tùy chọn chính:

| Tùy chọn | Tác dụng |
| --- | --- |
| `--library-mode` / `--application-mode` | Bật hoặc tắt phân tích tham số API công khai. Mặc định suy ra từ `composer.json` ở gốc; đây là giả định, không phải bằng chứng có request độc hại. |
| `--php-version 7.4` | Cung cấp phiên bản runtime để đánh giá hành vi liên quan đến Phar. Bỏ qua tùy chọn này thì phiên bản là chưa xác định. |
| `--severity info` | Chọn mức thấp nhất được đưa vào báo cáo: `critical`, `high`, `medium`, `low`, `info`. |
| `--max-file-mb N` | Bỏ qua tệp vượt giới hạn và đánh dấu lần quét chưa đầy đủ. Giá trị `0` là không giới hạn. |
| `--max-ast-nodes N` | Giới hạn số node AST được duyệt trên mỗi tệp. Giá trị `0` là không giới hạn; không giới hạn bộ nhớ parser. |
| `--max-depth N` | Giới hạn độ sâu tìm kiếm chuỗi POP. Mặc định là 6. |
| `--max-gadget-paths N` | Ngân sách số đường đi tới sink được kiểm tra (mặc định 10.000). |
| `--max-gadget-expansions N` | Ngân sách số cạnh call graph được duyệt (mặc định 250.000). |
| `--no-taint`, `--no-gadgets`, `--no-rules` | Tắt từng bộ phân tích tương ứng. |
| `--rules-dir PATH` | Nạp luật YAML từ thư mục chỉ định. |

Chỉ tìm chuỗi POP hoặc kiểm tra luật:

```powershell
php-deserial-sast find-gadgets C:\path\to\php-project --max-depth 6
php-deserial-sast verify-rules
php-deserial-sast verify-rules C:\path\to\custom-rules
```

### Mã thoát

- `0`: không có lỗi phân tích/quét và không có phát hiện Critical/High.
- `1`: có phát hiện Critical/High.
- `2`: có lỗi hoặc giới hạn khiến lần quét chưa đầy đủ; không nên xem kết quả là sạch.

Khi ngân sách POP bị chạm, báo cáo vẫn giữ các đường đi đã tìm thấy nhưng lần quét trả mã `2`. Tăng một trong hai ngân sách trên để tiếp tục phân tích; không được xem phần chưa duyệt là không có lỗ hổng. Để loại trừ thư mục build hoặc fixture riêng của dự án, đặt `exclude_dirs` trong `ScannerConfig`; mặc định không loại `vendor/`, `node_modules/` hay thư mục ẩn vì chúng có thể chứa mã PHP.

## Thẩm định bằng LLM (tùy chọn)

LLM chỉ hỗ trợ xem xét finding và không thay thế xác minh thủ công. Hiện công cụ chỉ gửi finding `CRITICAL` hoặc `HIGH` tới LLM; verdict được đính kèm báo cáo và không tự thay đổi severity tĩnh. Chỉ gửi mã nguồn cho nhà cung cấp mà bạn được phép chia sẻ mã với họ. Không ghi API key vào mã nguồn hoặc commit; đặt key trong biến môi trường.

```powershell
$env:OPENAI_API_KEY = "<your-key>"
php-deserial-sast scan C:\path\to\php-project --llm --llm-provider openai --llm-model gpt-4o-mini
```

Các provider khác:

```powershell
$env:GEMINI_API_KEY = "<your-key>"
php-deserial-sast scan C:\path\to\php-project --llm --llm-provider gemini --llm-model <model-name>

php-deserial-sast scan C:\path\to\php-project --llm --llm-provider ollama --llm-model <local-model>
```

Tên model phụ thuộc dịch vụ và cấu hình hiện tại của bạn. Không bật `--llm` thì scanner không gọi dịch vụ LLM.

## Luật YAML

Luật tích hợp nằm trong `php_deserial_sast/rules/definitions/`. Dùng `--rules-dir` để nạp bộ luật riêng. Có thể xem luật mẫu trong thư mục tích hợp và kiểm tra cú pháp bằng:

```powershell
php-deserial-sast verify-rules
```

Bộ máy hỗ trợ một tập con cú pháp Semgrep-like; đây không phải bản triển khai đầy đủ Semgrep. Tương thích cụ thể tùy dạng pattern và được kiểm tra bởi rule engine của dự án.

Các luật `session_decode` và `__unserialize` là luật **review**. Theo [tài liệu PHP về `session_decode()`](https://www.php.net/manual/en/function.session-decode.php), dữ liệu được giải mã bằng handler session đã cấu hình; [tài liệu magic methods](https://www.php.net/manual/en/language.oop5.magic.php) mô tả `__unserialize()` được gọi khi khôi phục object. Công cụ chưa dùng riêng các luật này để xác nhận khả năng khôi phục object, caller không tin cậy hoặc khai thác thực tế.

## Kiểm thử và kiểm tra nhanh

```powershell
python -m unittest discover -s php_deserial_sast\tests -v
php-deserial-sast verify-rules
```

## Cấu trúc mã nguồn

```text
php_deserial_sast/
  core/       Parser, AST, symbol table, dataflow, call graph, gadget finder
  llm/        Prompt, code slicing và tích hợp verifier
  reporters/  Console, JSON, SARIF và HTML
  rules/      Rule engine và các luật YAML tích hợp
  tests/      Kiểm thử hồi quy và fixture nhỏ
  cli.py      Giao diện dòng lệnh
  scanner.py  Điều phối các giai đoạn quét
```

## Cách đọc kết quả và giới hạn

- `assessment.detection_level` tách `direct_untrusted_deserialization` (đường request tới sink giải tuần tự hóa trực tiếp, không còn guard/giới hạn phân tích đã biết), `conditional_path` (có luồng nhưng còn điều kiện hoặc đoạn chưa giải) và `review_candidate` (chỉ có sink/ứng viên). Mức đầu là bằng chứng tĩnh về CWE-502, không xác nhận payload, gadget hoặc khai thác runtime.
- `igbinary_unserialize()` có thể khôi phục object; kết quả cần kiểm tra extension igbinary được cài và đầu vào thực tế. Lời gọi chỉ trong mã cache/thư viện không tự động là lỗ hổng. Xem [tài liệu igbinary](https://github.com/igbinary/igbinary/blob/master/igbinary.php) và [báo cáo kiểm thử mở rộng](docs/NANG_CAP_XAC_DINH_LO_HONG_VA_MO_RONG_2026_10_26.md).
- Taint finding cho biết công cụ đã truy vết được luồng theo mô hình hiện tại; vẫn cần kiểm tra xác thực, caller, runtime và khả năng khai thác.
- `conditional_library_api` cho biết tham số API công khai có thể đi tới sink trong giả định library mode. Nó không chứng minh ứng dụng truyền dữ liệu không tin cậy.
- `analysis.package_context` ghi tên, phiên bản và nguồn suy ra phiên bản. Đối chiếu advisory ngoại tuyến chỉ cung cấp ngữ cảnh phiên bản; phiên bản suy ra từ tên thư mục cần xác minh bằng nguồn phát hành. Tham chiếu gadget đã công bố và thuộc tính có thể điều khiển là bằng chứng hỗ trợ rà soát, không xác nhận đường khai thác.
- POP chain là đường đi trong call graph tới thao tác nguy hiểm; chưa chứng minh dữ liệu deserialize kiểm soát được thuộc tính cần thiết hoặc đường đi thực thi được.
- `metadata.deserialized_session_dispatch` liệt kê các ứng viên dispatch sau khi object được lưu vào session; `candidate_serialized_properties` là thuộc tính được tham chiếu trên đường gadget. Các trường này không xác minh thứ tự request, lớp được nạp hoặc thuộc tính thực sự do kẻ tấn công điều khiển.
- Phar phụ thuộc phiên bản PHP và ngữ cảnh sử dụng wrapper. Hãy khai báo đúng phiên bản khi có thể.
- Trên PHP 8+, mở archive không còn tự giải tuần tự hóa metadata, nhưng `getMetadata()` tường minh vẫn có thể làm vậy. Finding `php-phar-explicit-metadata-review` chỉ xác định thao tác có điều kiện; chưa chứng minh archive do kẻ tấn công kiểm soát. Luật dựa trên kiểu này chạy khi cả rules và taint analysis được bật.
- Phân tích tĩnh có thể thiếu luồng qua alias/heap phức tạp, include động, callable động và hành vi riêng của framework. Không có finding không chứng minh mã an toàn.
- Khi báo cáo có lỗi parse, lỗi phân tích hoặc resource limit, cần xử lý các lỗi đó trước khi kết luận.

## Phân tích và đối chiếu với các công cụ khác

- [Đánh giá sau nâng cấp và kết quả quét 9 dự án](docs/DANH_GIA_SAU_NANG_CAP_2026_10_27.md).
- [Kiến trúc, mã nguồn và workflow CodeQL, Progpilot, Psalm](docs/PHAN_TICH_CODEQL_PROGPILOT_PSALM.md).
- [Kết quả thực nghiệm và giới hạn đối chiếu](docs/KET_QUA_DOI_CHIEU.md).
- [64 ca kiểm thử nhỏ mở rộng và các lỗi đã sửa](docs/KIEM_THU_NHO_MO_RONG.md).
- [Sửa guard, wrapper và hằng đường dẫn từ project thực tế](docs/SUA_LOI_GUARD_DUONG_DAN.md).

`metadata.review_conditions` lưu điều kiện bảo vệ cần rà soát. Trạng thái
`guarded_flow_review` không chứng minh điều kiện đó an toàn và không xóa taint
finding hoặc tự hạ severity. `configured_local_path_review` giữ riêng giả định
về giá trị mặc định của hằng đường dẫn, kèm `path_prefix_assumptions` để kiểm tra.
Bộ kiểm thử độc lập từng mẫu có thể chạy bằng
`py -3.12 scripts/evaluate_small_cases.py`.

Các cải tiến gồm hàng đợi summary theo phụ thuộc caller/callee, truyền dữ liệu qua
`foreach`, named arguments, `use function`, nguồn `filter_input` và `php://input`.
Mô hình request của Symfony/Laravel yêu cầu kiểu receiver phù hợp và được ghi
`modeled_framework_request`; đây là giả định mô hình, không phải nguồn request đã
quan sát trực tiếp. Cache phép gán được xóa khi cập nhật summary; bộ luật kiểm tra
pattern trước khi duyệt ancestor để giảm chi phí trên dự án lớn.

Kết quả ghi rõ `call_graph_limit`, lỗi parse và trạng thái hội tụ. Các giới hạn này
có thể làm thiếu đường đi. CodeQL trong bộ đối chiếu không hỗ trợ PHP; không ghi
kết quả của nó là “0 lỗ hổng”.

```powershell
py -3.12 scripts/evaluate_scanner.py optimized --snapshot --timeout 600
py -3.12 scripts/compare_results.py --label optimized
```

Lệnh đầu quét mọi thư mục con trong `testcase`, lưu snapshot và SHA-256 mã scanner.
Lệnh sau cần các báo cáo Progpilot/Psalm đã tạo theo hướng dẫn trong tài liệu.
`reports/evaluation` chứa JSON, log, command và thời gian từng lượt; không đưa
các dữ liệu phát sinh này vào Git. Bảng so sánh dùng vị trí sink `unserialize`,
phân biệt kết quả đầy đủ, kết quả có lỗi, timeout và lần chưa chạy.

## Bằng chứng phân tích (nâng cấp giai đoạn 1)

JSON và SARIF bổ sung `flow_evidence` để giữ các đường taint còn lại sau phân
tích, cùng source, trace, guard và giả định đường dẫn của từng đường. Summary
phân biệt nội dung guard thay vì chỉ phân biệt có/không có guard; gộp finding
giữa các tệp cũng giữ lại các bằng chứng này. Các đường đã bị xấp xỉ ở bước
dataflow trước đó không được phục hồi tự động.

`assessment` tách mức tác động hiện có (`potential_impact`), loại bằng chứng
(`evidence_level`) và giới hạn (`analysis_completeness`, `limitations`).
`within_model` chỉ có nghĩa không ghi nhận giới hạn bổ sung trong mô hình hiện
tại; không chứng minh bao phủ mọi hành vi PHP hoặc khai thác được. Guard chưa
được chứng minh, nguồn giả định và lỗi scan được ghi rõ. `severity` và trace
đại diện cũ vẫn tồn tại để tương thích với báo cáo trước.

Rule engine chỉ nhận tập luật **search** được hỗ trợ: một `pattern` hoặc
`pattern-either`, tùy chọn `pattern-not` và `pattern-inside`. Pattern là chuỗi
hoặc phần tử `{pattern: chuỗi}`. Luật taint YAML, `patterns`, toán tử lồng nhau
và `pattern-regex` chưa được hỗ trợ sẽ tạo lỗi `rule_load`; không được âm thầm
coi là đã chạy. Mỗi rule lỗi được tách riêng để không chặn rule hợp lệ khác.
Engine taint Python vẫn hoạt động độc lập. Đây chưa phải tương thích đầy đủ
ngữ nghĩa Semgrep.

## CFG bước đầu

Taint engine dùng statement CFG cho scope gồm lệnh tuần tự, `if/elseif/else`
và kết thúc bằng `return`/`throw`. CFG loại sink/return không thể tới từ entry,
lọc định nghĩa không thể truyền tới điểm sử dụng, và chứng minh dominance cho
phép gán độc lập ở nhánh sống sót. Phép gán trong vế phải `&&`, `||`, `and`,
`or`, `??` vẫn được coi là có điều kiện.

Scope có `foreach` với binding phức tạp, `try/catch/finally`, `switch`, `goto`, yield hoặc lỗi cú pháp
sẽ fallback sang mô hình cũ; không dùng CFG chưa đầy đủ để loại luồng.
`analysis.control_flow` ghi số scope hỗ trợ và lý do fallback. Sink không thể
tới trong scope hỗ trợ có disposition `unreachable_in_scope_cfg` trong inventory.
Đây chưa phải IR/CFG đầy đủ của PHP hay bộ giải điều kiện. Phạm vi vòng lặp
được hỗ trợ được mô tả bên dưới.

### Reaching definitions trên CFG

Đối với biến được gán bằng lệnh độc lập trong scope CFG hỗ trợ, engine tính
GEN/KILL bằng worklist: hợp định nghĩa từ các khối tiền nhiệm, rồi thay bằng
định nghĩa mới tại khối ghi đè. Vì vậy nhiều nhánh cùng ghi đè thành hằng có
thể loại taint cũ ngay cả khi không có một phép gán riêng lẻ dominate sink.
Tham số đầu vào chỉ bị loại khi không còn đường nào giữ giá trị đầu vào.

Solver này chọn định nghĩa, không tính heap/alias hoặc giá trị predicate.
Phép gán field, biểu thức gán lồng nhau và scope CFG không hỗ trợ vẫn fallback.
Cache định nghĩa dựa trên cấu trúc AST/CFG; cache giá trị taint vẫn được xóa khi
summary thay đổi. `analysis.control_flow.definition_variables` và
`definition_evaluations` ghi khối lượng solver đã xử lý.

### Luồng dữ liệu vòng lặp

CFG bổ sung cạnh quay lại cho `while` và `do…while` trong scope không có cấu
trúc còn unsupported. Với biến đơn có phép gán độc lập, reaching definitions
và đánh giá taint lặp tới điểm bất động, phân biệt while có thể chạy 0 lần với
do…while chạy thân ít nhất một lần. Phép đọc đệ quy qua `.=` có chốt chu trình
và lấy trạng thái vòng tính trước. Giới hạn 128 vòng đánh giá tạo lỗi
`loop_fixed_point`; không được xem kết quả đó là đầy đủ.

Guard dựa trên thứ tự AST không được dùng để loại taint xuyên các lần lặp.
`break`/`continue` trong while/do/for có cạnh tới đích tương ứng, kể cả cấp lặp
lồng nhau viết bằng số thập phân dương. Cấp khác định dạng này hoặc vượt
độ sâu vòng lặp làm scope fallback với `unsupported_loop_jump`.
Vòng `for` có khối khởi tạo, điều kiện, thân và cập nhật riêng. `continue`
đi qua cập nhật; `break` đi thẳng ra ngoài. Header có nhiều biểu thức dấu phẩy
được xử lý theo thứ tự. Điều kiện bỏ trống không có cạnh thoát do điều kiện.
Tùy chọn thử nghiệm `--experimental-foreach-cfg` (tắt mặc định) mở CFG cho
`foreach` với binding value, key/value và destructuring theo giá trị: đánh giá
iterable trước vòng, ghi binding mỗi lượt, có đường thoát khi không còn phần tử.
Binding tham chiếu vẫn fallback với `foreach_binding`.
Chế độ thử nghiệm giới hạn scope foreach tối đa 256 node và ghi
`foreach_cfg_budget` khi vượt ngưỡng. Khi tắt, `foreach_cfg_disabled` ghi rõ
việc dùng phân tích cũ. Bản ngày 20/10 đã vượt qua hồi quy TCPDF khi bật tùy
chọn này; vẫn cần mở rộng kiểm chứng trước khi bật mặc định.
Switch có CFG cho case, default, fallthrough và break/continue.
Try/catch/finally dùng cạnh exception bảo thủ; chưa giải kiểu exception và
gộp các trạng thái hoàn tất qua finally. Goto vẫn fallback.
Alias biến cục bộ đã được bổ sung. Tác động qua tham số tham chiếu và
`global $name` cần bật `--experimental-side-effects` (tắt mặc định do
hồi quy timeout trên Drupal/WordPress). JSON ghi trạng thái tính năng và
giới hạn của chế độ đang dùng. Summary loại một số ghi bị ghi đè trước khi thoát hàm;
scope exception/fallback giữ tác động bảo thủ. Heap đối tượng, `$GLOBALS`,
tham chiếu động và side effect liên hàm vẫn chưa được mô hình hóa đầy đủ.
Scope vượt 5.000 node khi kiểm tra CFG cũng fallback, ghi `cfg_node_budget`
trong coverage. Đây là giới hạn tài nguyên, không phải chứng nhận scope an toàn.

Chạy đánh giá toàn bộ và kiểm tra artifact:

```powershell
py -3.12 scripts/evaluate_scanner.py upgrade-loops-validated --snapshot --timeout 600 --max-depth 10 --max-gadget-paths 20000 --max-gadget-expansions 500000
py -3.12 scripts/audit_upgrade.py upgrade-loops-validated
```

Audit phân biệt lỗi vận hành với giới hạn POP, kiểm tra schema JSON, số finding
và hash mã nguồn. Audit qua không phải chứng nhận phát hiện mọi lỗ hổng PHP.

### Xuất báo cáo và kết quả kiểm thử

JSON được ghi theo từng finding vào tệp tạm rồi thay thế đích khi ghi hoàn tất.
Mỗi finding hiển thị tối đa 32 route trong `flow_evidence`, ưu tiên các nhóm
source, uncertainty, guard và giả định khác nhau. Giới hạn này chỉ áp dụng
bằng chứng xuất ra; không giới hạn route đưa vào phát hiện taint. Khi cắt bớt,
metadata có `flow_evidence_truncated` và assessment có
`displayed_flow_evidence_truncated`. Sau khi gộp caller, `alternative_flow_count`
là số route đã ghi nhận tối thiểu, không phải tổng số đường thực thi PHP.

Kết quả ngày 19/10/2026: 52 unittest method và 64/64 ca nhỏ qua. Snapshot
engine vòng lặp đã quét 8 dự án, 12.499 tệp; không còn lỗi vận hành parser,
summary hoặc solver trong bộ báo cáo được audit. Một số dự án vẫn chạm giới
hạn POP. Các thay đổi xuất báo cáo sau snapshot được kiểm tra riêng; không
gắn nhãn các báo cáo cũ là lượt quét bằng mã nguồn mới nhất.

Chi tiết, bảng kết quả và phạm vi còn thiếu:
[Báo cáo nâng cấp vòng lặp](docs/NANG_CAP_ENGINE_GIAI_DOAN_4_LOOPS.md).

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -q
py -3.12 scripts/evaluate_small_cases.py --output reports/evaluation/upgrade-release-small
py -3.12 scripts/audit_upgrade.py upgrade-loops-validated --supplement upgrade-loop-tail-diagnosis
```

Các bản nâng cấp sau bộ quét tám dự án:

- [CFG cho break/continue](docs/NANG_CAP_ENGINE_GIAI_DOAN_5_LOOP_JUMPS.md).
- [CFG cho vòng for](docs/NANG_CAP_ENGINE_GIAI_DOAN_6_FOR.md).
- [CFG cho foreach theo giá trị](docs/NANG_CAP_ENGINE_GIAI_DOAN_7_FOREACH.md).
- [Sửa timeout summary và hồi quy guard TCPDF](docs/NANG_CAP_ENGINE_GIAI_DOAN_8_SUMMARY.md).
- [CFG mở rộng, alias, tác động tham chiếu và matcher AST](docs/NANG_CAP_ENGINE_GIAI_DOAN_9_EFFECTS.md).
- [Global, effect ở lối thoát và tối ưu duyệt AST](docs/NANG_CAP_ENGINE_GIAI_DOAN_10_GLOBALS.md).
- [Lập lịch summary theo SCC và kiểm thử hồi quy](docs/NANG_CAP_ENGINE_GIAI_DOAN_11_SCC.md).
- [Nâng cấp sáu nhóm: demand summary, heap, finally, POP, coverage và matcher](docs/NANG_CAP_ENGINE_GIAI_DOAN_12_TONG_HOP.md).
- [Thuộc tính constructor, helper summary và loại taint bị ghi đè](docs/NANG_CAP_ENGINE_GIAI_DOAN_13_CONSTRUCTOR.md).

Đợt 22/10/2026: 92 unittest, 78/78 ca nhỏ có nhãn; chế độ demand đã quét
hoàn tất tám dự án, gồm WordPress từng timeout. Foreach CFG và heap/side
effect vẫn là tùy chọn thử nghiệm. Xem báo cáo giai đoạn 12 để biết cấu hình,
snapshot, giới hạn coverage và phạm vi của các số liệu.

## Nâng cấp trước đợt quét lớn tiếp theo

Giai đoạn 14: thêm object-property effects, `$GLOBALS`, phân giải phương thức
qua alias, sửa luồng chết qua finally, mở rộng matcher AST và báo cáo lời gọi
chưa phân giải. Side effects vẫn cần `--experimental-side-effects`.

Kiểm chứng: 103 unittest; 108/108 ca nhỏ ở mỗi chế độ eager/demand; 24/24 ca
thư viện. Chưa quét dự án lớn bằng phiên bản này và chưa khẳng định công cụ
hoàn thiện mọi mô hình PHP. Xem [báo cáo thay đổi và giới hạn](docs/NANG_CAP_ENGINE_GIAI_DOAN_14_TRUOC_DU_AN_LON.md).

## Nguồn tham khảo

- [PHPGGC](https://github.com/ambionics/phpggc)
- [Semgrep](https://github.com/semgrep/semgrep)
- [SunWeb3Sec/llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner)

Cập nhật giai đoạn 13: 96 unittest, 24/24 lượt ca thư viện và 78/78 ca ứng dụng đạt. Ba dự án thư viện đối chiếu cùng cấu hình giữ nguyên tập cảnh báo; xem báo cáo giai đoạn 13 để biết phạm vi và các giới hạn còn lại.


### Cập nhật phân tích Drupal serializer

Công cụ hỗ trợ hợp đồng dispatch có điều kiện cho Drupal serializer/field normalizer. Tắt bằng `--no-framework-models`. JSON ghi rõ giả định lựa chọn field lúc chạy; finding không chứng minh khai thác thành công. Xem [bản sửa và kiểm chứng Drupal](docs/KHAC_PHUC_DRUPAL_DISPATCH.md) để biết kết quả và giới hạn còn lại.

### Cập nhật phân tích Laravel Encrypter

Mô hình dispatch có điều kiện nối cookie và header `X-XSRF-TOKEN` qua middleware Laravel tới `Encrypter::decrypt()`. Lời gọi với đối số `$unserialize` literal `false` không tạo cạnh này. Báo cáo ghi rõ kiểm tra cấu trúc payload, MAC và điều kiện runtime chưa xác minh; finding không xác nhận khai thác. Xem [báo cáo kiểm chứng Laravel](docs/LARAVEL_DISPATCH_VA_DIEU_KIEN_2026_10_26.md).


### Side effects theo nhu cầu

Khi bật `--experimental-side-effects`, chế độ mặc định chỉ tính summary side effects khi một phép đọc hoặc summary khác cần đến. `--eager-summaries` giữ chế độ tính toàn bộ để đối chiếu. Báo cáo JSON có `demanded_effect_functions`. Tối ưu này không loại bỏ luồng theo ngưỡng số lượng; các giới hạn về dispatch động và POP vẫn áp dụng.


### Kiểm thử Drupal sau sửa POP và bộ tham chiếu

Đồ thị POP giữ mọi đích được chỉ mục thay vì cắt cứng 4/12 ứng viên. Giới hạn tìm chuỗi vẫn được báo trong kết quả nếu bị chạm. Xem [báo cáo kiểm thử](docs/KIEM_THU_DRUPAL_SAU_SUA_LOI.md).

Runner tham chiếu hỗ trợ `--dependency-dir`, `--memory-mb` và `--local-progpilot-source`. Tùy chọn cuối dùng bản Progpilot đã sửa cục bộ, cần ghi rõ khi so sánh với upstream. Progpilot nhận phiên bản PHP mục tiêu và JSON ghi `parser_target_php_version`, cảnh báo và trạng thái coverage. `analysis_status` phân biệt kết thúc tiến trình với báo cáo hợp lệ; timeout không được coi là kết quả không có lỗ hổng.
