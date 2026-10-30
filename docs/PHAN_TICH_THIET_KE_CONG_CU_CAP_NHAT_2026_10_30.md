# PHÂN TÍCH VÀ THIẾT KẾ CÔNG CỤ DÒ QUÉT PHP INSECURE DESERIALIZATION

**Phiên bản mô tả:** mã nguồn tại `D:\đồ án`, ngày 30/10/2026. **Mục đích:** làm nội dung phân tích thiết kế hệ thống cho đồ án tốt nghiệp. Các mô tả dưới đây phân biệt chức năng đã hiện thực, kết quả kiểm thử và điều kiện chưa thể xác minh bằng phân tích tĩnh.

## 1. Bài toán và phạm vi hệ thống

PHP có thể khôi phục đối tượng từ chuỗi bằng `unserialize()` và một số API tương tự. Nếu dữ liệu đầu vào có thể bị thay đổi bởi bên ngoài, việc khôi phục đối tượng có thể gọi magic method hoặc tạo trạng thái đối tượng dẫn tới thao tác nguy hiểm. Tuy nhiên, sự xuất hiện của `unserialize()` riêng lẻ không chứng minh được lỗ hổng. Cần xác định nguồn dữ liệu, đường truyền tới đối số của sink, điều kiện kiểm tra, lớp có thể được nạp, thuộc tính có thể điều khiển, trigger và thao tác cuối cùng. Một số thông tin này nằm trong cấu hình hoặc trạng thái thực thi, ngoài phạm vi mã nguồn được cung cấp.

Công cụ PHP Deserialization SAST nhận một tệp hoặc thư mục PHP, dựng mô hình tĩnh và trả các cảnh báo có bằng chứng để người phân tích rà soát. Hệ thống kết hợp phân tích luồng dữ liệu, tìm ứng viên chuỗi POP, luật AST và các mô hình hành vi PHP/framework. Nó không chạy payload, không kết nối tới ứng dụng đích và không tự xác nhận khai thác runtime. LLM là bước thẩm định tùy chọn, mặc định tắt.

Đầu vào gồm đường dẫn mục tiêu, phiên bản PHP đích nếu biết, chế độ thư viện hoặc ứng dụng, cấu hình các engine, bộ luật YAML và giới hạn tài nguyên. Đầu ra gồm `ScanResult`, các finding, danh mục sink, route chứng cứ, ứng viên gadget, thống kê, lỗi và định dạng console, JSON, SARIF hoặc HTML. Không có cơ sở dữ liệu nội bộ: AST, bảng ký hiệu và summary tồn tại trong bộ nhớ của một lượt quét; báo cáo là hiện vật lưu trữ.

## 2. Phân tích yêu cầu

### 2.1. Tác nhân và mục tiêu

| Tác nhân | Mục tiêu | Tương tác |
| --- | --- | --- |
| Người phân tích bảo mật | Tìm vị trí cần kiểm tra và đọc chứng cứ | Chọn mục tiêu, cấu hình, xem finding và route |
| Nhà phát triển | Xác định đoạn mã, điều kiện và hướng sửa | Đọc trace, mức độ, giới hạn và báo cáo |
| Quy trình CI | Quét tự động và nhận trạng thái | Gọi CLI, lưu JSON/SARIF, đọc mã thoát |
| Dịch vụ LLM tùy chọn | Đánh giá bổ sung một lát cắt mã | Chỉ được gọi khi bật `--llm`; kết quả gắn vào finding |

### 2.2. Yêu cầu chức năng

| Mã | Yêu cầu | Kết quả quan sát được |
| --- | --- | --- |
| FR01 | Thu thập tệp PHP trong phạm vi mục tiêu | Danh sách tệp đã phát hiện, đã quét, lỗi duyệt và tệp bị giới hạn |
| FR02 | Phân tích cú pháp và khai báo | AST, chỉ mục node, class, method, function và quan hệ ký hiệu |
| FR03 | Nhận diện sink và nguồn dữ liệu | `sink_inventory`, nguồn request, tham số API hoặc nguồn được mô hình hóa |
| FR04 | Truy vết source tới sink | Finding kèm trace, điều kiện, trường dữ liệu và mức bất định |
| FR05 | Tính summary liên hàm và CFG | Quan hệ tham số, giá trị trả về, lời gọi chuyển tiếp, nhánh/loop hỗ trợ |
| FR06 | Tìm ứng viên POP | Đường từ magic method tới thao tác nhạy cảm, cùng giới hạn cạnh/độ sâu |
| FR07 | Nạp và đối chiếu luật YAML | Finding cú pháp AST; lỗi luật được báo riêng |
| FR08 | Tương quan và đánh giá chứng cứ | Khử trùng lặp, giữ route thay thế, phân biệt mức bằng chứng và phạm vi mã |
| FR09 | Ưu tiên rà soát | Điểm 0–100 có các hệ số giải thích, tách biệt severity |
| FR10 | Xuất kết quả | Console, JSON, SARIF, HTML và mã thoát 0/1/2 |
| FR11 | Thẩm định LLM tùy chọn | Verdict có cấu trúc trên finding được chọn, không thay chứng cứ tĩnh |
| FR12 | Kiểm soát phiên bản và ngân sách | PHP version, library mode, giới hạn AST/POP/side effects; báo coverage khi chạm ngưỡng |

### 2.3. Yêu cầu phi chức năng

**Tính đúng đắn trong phạm vi mô hình.** Cùng mã nguồn và cấu hình phải tạo cùng chữ ký finding. Cảnh báo cú pháp không được trình bày như đường khai thác đã chứng minh. `assessment`, `review_conditions`, `missing_edges` và `errors` giữ thông tin còn thiếu.

**Khả năng quan sát độ bao phủ.** Lỗi parse, tệp bị bỏ qua, summary không hội tụ và giới hạn POP/side effects phải xuất hiện trong báo cáo. Khi side effects thử nghiệm vượt ngân sách, scanner dựng lại summary mặc định và ghi `side_effect_budget`; finding không sử dụng summary dở dang.

**Khả năng mở rộng.** Công cụ lập chỉ mục AST, giải phóng sớm cây của tệp dữ liệu không cần phân tích liên tệp, tính summary theo nhu cầu và đặt ngân sách cho tìm kiếm. Báo cáo ghi số byte, AST node, thời gian từng pha và các giới hạn. Chưa có cam kết thời gian cố định hoặc cache tăng dần an toàn cho mọi dự án.

**An toàn dữ liệu và tích hợp.** Chế độ LLM mặc định tắt. JSON được tạo qua tệp tạm rồi thay thế sau khi hoàn tất; SARIF phục vụ CI. API key không được đưa vào mã nguồn hoặc báo cáo. Mã thoát `2` dành cho lỗi/coverage thiếu, `1` cho finding nghiêm trọng khi không có lỗi, `0` cho lượt quét còn lại.

## 3. Phân tích ca sử dụng

### 3.1. Danh mục use case

| Mã | Tên | Tác nhân chính | Tiền điều kiện | Hậu điều kiện |
| --- | --- | --- | --- | --- |
| UC01 | Quét dự án PHP | Người phân tích, CI | Mục tiêu đọc được | Có `ScanResult` và mã thoát |
| UC02 | Cấu hình phạm vi và engine | Người phân tích | Có lệnh CLI | `ScannerConfig` hợp lệ |
| UC03 | Xem chứng cứ finding | Người phân tích, nhà phát triển | Có báo cáo | Hiểu vị trí, trace, điều kiện và giới hạn |
| UC04 | Tìm riêng ứng viên POP | Người phân tích | Có tệp PHP | Danh sách gadget candidate |
| UC05 | Kiểm tra bộ luật | Người phân tích | Có thư mục YAML | Luật hợp lệ hoặc lỗi cụ thể |
| UC06 | Xuất báo cáo máy đọc | CI | Có kết quả quét | JSON/SARIF được lưu |
| UC07 | Thẩm định LLM | Người phân tích | Bật LLM và cấu hình provider | Verdict bổ sung hoặc lỗi dịch vụ |

### 3.2. Đặc tả UC01 Quét dự án PHP

**Luồng chính.** (1) Người dùng cung cấp mục tiêu, PHP version, engine và ngưỡng severity. (2) CLI kiểm tra tham số rồi tạo `ScannerConfig`. (3) Scanner phát hiện tệp, parse AST và trích xuất symbol. (4) Các engine được bật dựng call graph/summary và sinh ứng viên. (5) Scanner tương quan, khử trùng lặp, đánh giá chứng cứ, lọc mức độ, dựng route và thống kê. (6) Reporter xuất kết quả và CLI trả mã thoát.

**Luồng thay thế.** Tệp lỗi cú pháp được ghi `ScanError` nhưng phần AST phục hồi vẫn có thể được phân tích. Tệp vượt `max_file_bytes` hoặc `max_ast_nodes` bị đánh dấu coverage thiếu. Nếu side effects thử nghiệm hết 60 giây hoặc vượt 25.000 lần bind theo mặc định, scanner bỏ summary thử nghiệm, chạy lại chế độ cơ bản và ghi `budget_fallback`. LLM lỗi không làm biến verdict thành xác nhận khai thác.

**Bất biến.** `ScanResult.summary.total_findings` đếm finding sau tương quan/lọc; sink không nối được nguồn vẫn có thể xuất hiện ở `sink_inventory`. `errors` có ưu tiên cao nhất khi xác định mã thoát.

### 3.3. Đặc tả UC03 Xem chứng cứ finding

Người phân tích mở finding theo `rule_id` và `location`, đọc `severity`, `confidence`, `flow_evidence`, `assessment`, `review_priority` và các `RouteEvidence` liên kết bằng `source_finding_id`. Route `proven` chỉ có nghĩa cạnh tĩnh được mô hình hóa; `runtime_verified` vẫn là `False`. Nếu route `conditional` hoặc `unknown`, người phân tích phải kiểm tra `review_conditions` và `missing_edges` trước khi kết luận. Khi trace hiển thị bị cắt, metadata phải cho biết số đường đã bị giới hạn.

### 3.4. Quan hệ giữa các use case

UC01 bao gồm UC02 và UC06. UC03 theo sau UC01 khi người dùng rà soát kết quả. UC07 mở rộng UC01 khi bật `--llm`; UC04 và UC05 có thể chạy độc lập. CI nhận cả UC06 lẫn mã thoát của UC01.

## 4. Thiết kế kiến trúc và luồng xử lý

### 4.1. Phân rã thành phần

| Thành phần | Mã nguồn chính | Vai trò |
| --- | --- | --- |
| CLI và cấu hình | `cli.py`, `config.py` | Nhận lệnh, kiểm tra tham số, chọn reporter |
| Orchestrator | `scanner.py` | Điều phối pha, thu lỗi, tương quan và tạo kết quả |
| Parser và symbol | `core/parser.py`, `core/ast_visitor.py`, `core/symbol_table.py` | Tree-sitter PHP, ASTIndex, khai báo và tên đầy đủ |
| Luồng dữ liệu | `core/dataflow.py`, `core/control_flow.py`, `core/taint_engine.py` | CFG, reaching definition, summary, trace source–sink |
| Mô hình ngữ nghĩa | `core/framework_dispatch.py`, `core/class_loading.py`, `core/persistent_store.py` | Contract framework, class loading và dữ liệu lưu bền |
| POP | `core/call_graph.py`, `core/gadget_finder.py`, `core/pop_evidence.py` | Đồ thị lời gọi, ứng viên gadget và điều kiện object |
| Luật AST | `rules/engine.py`, `rules/matcher.py`, YAML | Khớp mẫu trong tập cú pháp được hỗ trợ |
| Đánh giá chứng cứ | `core/evidence.py`, `core/route_evidence.py`, `core/review_priority.py` | Mức bằng chứng, route, điểm ưu tiên |
| LLM | `llm/slicer.py`, `llm/verifier.py` | Lát cắt mã và verdict tùy chọn |
| Schema và reporter | `models.py`, `reporters/` | Dữ liệu dùng chung và bốn dạng xuất |

### 4.2. Luồng xử lý theo pha

1. **Khởi tạo:** xác định ngữ cảnh Composer, library mode, phiên bản PHP, bộ luật và parser. Mỗi `scan()` tạo lại symbol table để tránh rò trạng thái giữa các lần chạy.
2. **Thu thập và lập chỉ mục:** duyệt tệp PHP, kiểm tra giới hạn, parse bằng Tree-sitter, tạo `ASTIndex` và trích xuất khai báo. Tệp dữ liệu không cần phân tích liên tệp được chạy luật rồi giải phóng AST sớm.
3. **Dựng mô hình liên tệp:** từ symbol table tạo call graph nếu bật POP; `FlowProject` lập `FileFlow`, CFG, quan hệ phụ thuộc và summary theo worklist. Summary return/effect được yêu cầu theo nhu cầu.
4. **Sinh ứng viên:** taint engine truy nguồn tại sink; gadget finder duyệt magic method; rule engine khớp AST. Mô hình PHP version, `allowed_classes`, Phar, framework và dữ liệu lưu bền bổ sung điều kiện.
5. **Tương quan:** gộp finding cùng sink, loại cảnh báo cú pháp đã được chứng cứ mạnh hơn bao phủ, ghi đường thay thế, đánh giá mức bằng chứng và ưu tiên rà soát. `RouteEvidence` được dựng từ finding đã giữ.
6. **Xuất:** tạo `ScanSummary`, `analysis.performance`, coverage và `errors`; reporter ghi console/JSON/SARIF/HTML. `analysis.route_evidence.runtime_verified=False` nêu giới hạn của phân tích tĩnh.

### 4.3. Thiết kế theo lớp và luồng phụ thuộc

`ScannerConfig → PHPDeserializationScanner → PHPParser/ASTIndex → ProjectSymbolTable`. Từ bảng ký hiệu, luồng tách thành `FlowProject → TaintEngine`, `CallGraph → GadgetFinder` và `RuleEngine`. Các nhánh hội tụ thành `Finding → EvidenceAssessment/ReviewPriority → RouteEvidence → ScanResult → Reporter`. LLMVerifier chỉ được gọi trên nhánh tùy chọn; nó không thay đổi kết luận tĩnh thành chứng minh runtime.

## 5. Thiết kế dữ liệu dùng chung

### 5.1. Hai lớp dữ liệu

**Dữ liệu trung gian trong bộ nhớ** gồm AST node, `ASTIndex`, symbol table, `FileFlow`, CFG, call graph, summary và các tập candidate. Node dùng byte offset của nguồn gốc; parser có thể chuẩn hóa một số cú pháp cũ mà vẫn giữ offset. Các cấu trúc này được tạo lại cho mỗi lần quét và không phải bảng cơ sở dữ liệu.

**Dữ liệu công bố** dùng Pydantic trong `models.py`. `CodeLocation` lưu tệp và khoảng dòng/cột bắt đầu từ 1. `ScanResult` là nút gốc chứa `summary`, `analysis`, `findings`, `sink_inventory`, `routes`, `gadget_chains`, `all_classes` và `errors`.

### 5.2. Quan hệ và ý nghĩa trường

| Thực thể | Trường quan trọng | Quan hệ và quy tắc |
| --- | --- | --- |
| `Finding` | id, rule_id, severity, confidence, location, metadata | Một cảnh báo sau khử trùng lặp; có thể có nhiều đường luồng |
| `FlowEvidence` | source_kind, source_origin, fields, trace, uncertain, conditions | Nhiều bản ghi thuộc một finding; trace là các `TaintStep` |
| `EvidenceAssessment` | evidence_level, detection_level, completeness, limitations | Tối đa một trên finding; không đồng nghĩa severity |
| `ReviewPriority` | score, band, factors, model_version | Tối đa một trên assessment; điểm dùng xếp hàng rà soát, không phải CVSS |
| `RouteEvidence` | route_id, kind, status, source_finding_id, sink, missing_edges | Nhiều route thuộc một finding; có thể có store, trigger, gadget và class loading |
| `GadgetChain` | chain_id, entry, sink, steps, candidate properties | Ứng viên đường POP, không mặc định là exploit path |
| `SinkInventoryEntry` | location, sink_name, disposition | Ghi cả sink chưa chứng minh có nguồn điều khiển |
| `ScanError` | file_path, phase, message | Lỗi hoặc giới hạn có ảnh hưởng coverage |

`RouteEvidence.status` có ba mức `proven`, `conditional`, `unknown`. Mức `proven` chỉ áp dụng cho cạnh tĩnh cụ thể trong mô hình. `runtime_verified` luôn `False` trong lượt quét. `route_kind` phân biệt `source_to_sink`, `candidate_gadget`, `candidate_session_dispatch` và `candidate_persistent_store`. Trường `missing_edges` cho biết ví dụ đường ghi dữ liệu, nạp lớp, quyền truy cập hoặc thứ tự request chưa được nối. Một finding có thể có nhiều route; không ép các cạnh chưa chứng minh thành một đường khai thác duy nhất.

### 5.3. Thiết kế mức độ và điểm ưu tiên

`severity` mô tả tác động tiềm năng theo quy tắc engine; `confidence` mô tả độ tin cậy của finding. `EvidenceAssessment` mô tả loại chứng cứ (`syntactic_review`, `candidate_call_chain`, `assumed_api_flow`, `assumed_persistent_flow`, `modeled_source_flow`, `observed_source_flow`, `unresolved_flow`), mức phát hiện (`review_candidate`, `conditional_path`, `direct_untrusted_deserialization`) và mức đầy đủ (`within_model`, `limited`). `within_model` không có nghĩa đã bao phủ mọi hành vi PHP.

`ReviewPriority.score` nằm trong 0–100. Điểm cộng gồm tác động, mức bằng chứng, confidence và detection level; điểm trừ gồm giới hạn, lỗi và phạm vi tests/vendor/examples. Các trần giữ candidate hoặc luồng còn giả định khỏi mức ưu tiên quá cao. `factors` lưu phép cộng trừ để giải thích kết quả. Điểm này không phải xác suất khai thác, CVSS hay mức nghiêm trọng mới.

### 5.4. Định danh và vòng đời

Finding taint được nhóm theo vị trí, sink và đối số; rule finding gắn với rule/vị trí; gadget có `chain_id`. `RouteEvidence.route_id` được tạo từ danh tính ngữ nghĩa chuẩn hóa. Danh sách trace có giới hạn hiển thị; cờ `flow_evidence_truncated` và thống kê coverage cho biết khi có cắt bớt. JSON ghi qua tệp tạm ở cùng thư mục để tránh thay thế báo cáo cũ bằng tệp chưa hoàn thành.

## 6. Thiết kế thuật toán phát hiện

### 6.1. Luồng source tới sink

`FileFlow` lập chỉ mục phép gán, scope, lời gọi, alias hỗ trợ và vị trí dùng. Giá trị được đánh giá tại điểm dùng theo trường mảng/thuộc tính thay vì chỉ dò chuỗi. CFG loại một số nhánh không thể tới sink hoặc định nghĩa đã bị ghi đè. `FlowProject.build()` tính summary theo phụ thuộc callee và worklist; caller được lập lịch lại khi summary thay đổi. `TaintEngine` dùng summary để truyền luồng qua hàm và ghi lại trace. Khi nhận ra `allowed_classes=false` hoặc guard có ngữ nghĩa được hỗ trợ, engine không coi đường đó giống lời gọi khôi phục object không hạn chế.

Nguồn trực tiếp như request được phân biệt với tham số API thư viện và dữ liệu bền vững cần giả định. Mô hình framework có điều kiện theo phiên bản/giá trị mặc định; ví dụ cookie serialization của Laravel bản vá có thể bị lớp con bật lại. Với persistent store, đọc từ session hoặc DB chỉ tạo route đã chứng minh khi đường ghi và điều kiện liên quan đủ bằng chứng; nếu thiếu, finding giữ `review_conditions` hoặc `missing_edges`.

### 6.2. Ứng viên chuỗi POP

`CallGraph` nối lời gọi tĩnh và một số dispatch động có kiểu/ứng viên. `GadgetFinder` tìm từ magic method và trigger phù hợp tới thao tác nhạy cảm, với giới hạn độ sâu, số đường và số cạnh. Kết quả là ứng viên: class có thể chưa được nạp, thuộc tính serialized chưa chắc điều khiển được hoặc trigger chưa chắc xảy ra. `pop_evidence`, `class_loading` và `deserialized_dispatch` bổ sung điều kiện này vào báo cáo thay vì tự động nâng ứng viên thành lỗ hổng xác nhận.

### 6.3. Luật AST và tương quan

Rule engine nạp YAML, kiểm tra tập cú pháp hỗ trợ và đối chiếu node AST. Chỉ mục theo loại node và callee giảm việc so khớp vô ích. Luật bao phủ các mẫu như `unserialize`, session decode, Phar, WDDX và YAML theo điều kiện version/extension thích hợp. Cảnh báo từ luật là vị trí cần rà soát; scanner loại bản tổng quát khi finding luồng tại cùng sink đã chứa chứng cứ mạnh hơn. Lỗi nạp luật hiện trong `errors`, không bị coi là luật đã chạy thành công.

### 6.4. Ngân sách, fallback và LLM

`max_file_bytes`, `max_ast_nodes`, `max_gadget_paths` và `max_gadget_expansions` khống chế chi phí; khi giới hạn tác động coverage, báo cáo phải ghi rõ. Side effects liên hàm là tùy chọn thử nghiệm; mặc định có ngân sách 60 giây và 25.000 lần bind. Hết một trong hai ngưỡng, scanner dựng lại taint không dùng side effects và ghi `analysis.interprocedural_side_effects.status=budget_fallback` cùng `attempted_bindings`. Không dùng summary chưa hội tụ để tạo finding.

Khi bật LLM, `CodeSlicer` tạo ngữ cảnh cho một số finding Critical/High và `LLMVerifier` gọi provider đã cấu hình. Phản hồi được kiểm tra cấu trúc rồi lưu ở `llm_verification`. LLM có thể hỗ trợ ưu tiên rà soát nhưng không cung cấp quan sát runtime và không thay thế phân tích source–sink.

## 7. Giao diện và triển khai

Ví dụ: `python -m php_deserial_sast.cli scan <duong_dan> --php-version 7.4 --severity INFO --format json --output report.json`. Các cờ `--no-taint`, `--no-gadgets`, `--no-rules` tắt từng engine; `--experimental-side-effects` bật mô hình tham chiếu/global/property; `--max-side-effect-seconds` và `--max-side-effect-bindings` điều chỉnh ngân sách. Lệnh `find-gadgets` và `verify-rules` phục vụ kiểm tra chuyên biệt.

Đầu ra JSON/SARIF thích hợp tích hợp máy; HTML và console dành cho đọc thủ công. Mọi finding cần đọc cùng `analysis`, `assessment`, `routes` và `errors`. Chỉ số finding theo mức độ không phải số lỗ hổng đã được xác minh.

## 8. Truy vết yêu cầu và kiểm chứng

| Yêu cầu | Thành phần | Kiểm chứng hiện tại |
| --- | --- | --- |
| FR01–FR02 | scanner, parser, symbol_table | Test parse/discovery và quét dự án lớn |
| FR03–FR05 | dataflow, control_flow, taint_engine | Unit test source–sink, guard, loop, reference; cặp bản vá |
| FR06 | call_graph, gadget_finder, pop_evidence | Test magic method/dispatch và ứng viên ở Monolog |
| FR07 | rules/engine, matcher, YAML | Test luật dương/âm và `verify-rules` |
| FR08–FR09 | evidence, route_evidence, review_priority | Test mức bằng chứng/điểm và JSON route |
| FR10 | models, reporters, cli | Test JSON/SARIF và mã thoát; báo cáo 14 ca |
| FR11 | llm/slicer, verifier | Unit test tích hợp bằng mock; lượt đối chứng 14 ca không bật LLM |
| FR12 | config, scanner, dataflow | Test fallback và telemetry giới hạn |

Tại thời điểm viết, 246 unit test đều qua. Lượt kiểm thử 14 ca gồm 10 thư mục dự án trong `testcase`, phạm vi con Monolog và ba lab Pokémon/workshop; tổng 3.218 finding, `errors=[]`. So với các JSON mốc, chữ ký `(file, dòng, cột, rule, severity)` của 14/14 ca đều thiếu 0, thêm 0. Đây là hồi quy của công cụ, không phải phép đo precision/recall. XVWA cho route source–sink tĩnh rõ; Laravel 5.6.29/5.6.30 và Drupal 8.6.9/8.6.10 cho đối chứng bản vá; Pokémon và hai workshop cho sink trực tiếp nhưng route gadget/session còn điều kiện. WordPress có nhiều cảnh báo Phar chưa được chứng minh đường ghi và runtime riêng từng vị trí.

## 9. Giới hạn và hướng phát triển

Phân tích tĩnh không tự xác minh cấu hình triển khai, quyền truy cập endpoint, khóa/mã hóa, class được nạp thực tế, trạng thái object qua nhiều request hoặc payload khai thác. Alias/heap liên hàm, callable động và framework chưa có mô hình tổng quát; kết quả có thể âm tính giả hoặc tạo ứng viên cần rà soát. Các route persistent store chỉ nên được nâng mức khi chứng minh cùng key/bản ghi, quyền ghi, thứ tự request và trigger. POP cần nối nguồn, trạng thái thuộc tính, class loading và sink tác động trước khi gọi là exploit path.

Hiệu năng còn phụ thuộc số AST node, số lời gọi và số đường luồng. Lượt Drupal 8.6.9 mất khoảng 102 giây, RAM đỉnh khoảng 2,9 GiB; WordPress khoảng 61 giây, TCPDF khoảng 27 giây trong bộ thử ngày 30/10. Một lượt đo không đủ kết luận tối ưu tốc độ ổn định. Side effects thử nghiệm trên dự án lớn có thể chạm ngân sách và fallback; không nên bật mặc định trước khi summary được tối ưu và đo lặp lại trên cùng môi trường. Muốn tính precision/recall cần corpus có nhãn độc lập ở cấp vị trí và điều kiện khai thác, không dùng riêng số lượng finding.

## 10. Nguồn đối chiếu nội bộ

- `php_deserial_sast/cli.py`, `config.py`, `scanner.py`: giao diện và điều phối.
- `php_deserial_sast/core/` và `rules/`: mô hình, engine và luật.
- `php_deserial_sast/models.py`, `reporters/`: schema và đầu ra.
- `reports/evaluation/retest-2026-10-30-full-opt/ASSESSMENT.md`, `runs.json` và JSON từng ca: số liệu kiểm thử và cấu hình.
