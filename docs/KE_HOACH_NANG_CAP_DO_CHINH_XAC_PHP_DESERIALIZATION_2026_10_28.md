# Chẩn đoán sai lệch và kế hoạch nâng cấp công cụ quét PHP insecure deserialization

Ngày 28/10/2026. Phạm vi: mã engine hiện tại, lượt quét không bật LLM của tám dự án trong `testcase`, Monolog lượt quét sâu, Pokémon và workshop level 1/2. Đây là kế hoạch thiết kế; các kết luận về exploit cần được xác nhận bằng cấu hình và mã chạy tương ứng. Số finding không phải số lỗ hổng.

## 1. Tiêu chí đúng của công cụ

Công cụ phải tìm và phân loại **đường từ dữ liệu có thể bị kiểm soát đến thao tác giải tuần tự hóa**, sau đó đánh giá **lớp được phép và được nạp, trạng thái đối tượng, sự kiện kích hoạt và tác động của gadget**. Báo cáo tối thiểu phải phân biệt:

1. `sink_only`: có thao tác nguy hiểm nhưng chưa tìm thấy nguồn không tin cậy;
2. `conditional_api`: thư viện có API nhận tham số có thể đến sink, ứng dụng gọi chưa có trong phạm vi quét;
3. `source_to_sink`: có đường nguồn đến sink, kèm guard và giả định;
4. `reachable_gadget`: object có thể được tạo từ dữ liệu giải tuần tự hóa và chain đến tác động, với lớp/thuộc tính/trigger được kiểm tra;
5. `excluded` hoặc `unknown`: đường bị loại bởi điều kiện đã chứng minh, hoặc thiếu thông tin. `unknown` không được biến thành an toàn hay khai thác được.

`severity` biểu thị tác động *nếu điều kiện xảy ra*; `confidence` và `evidence_level` biểu thị chứng cứ hiện có. Một High do giả định nhiều bước không được trình bày như CVE đã xác nhận. `allowed_classes` hạn chế tập lớp, nhưng PHP vẫn cảnh báo không đưa dữ liệu không tin cậy vào `unserialize()` chỉ dựa vào tùy chọn này; PHP 8 cũng thay đổi cơ chế PHAR tự động giải metadata. [PHP `unserialize`](https://www.php.net/manual/en/function.unserialize.php), [PHP `Phar`](https://www.php.net/manual/en/class.phar.php), [CWE-502](https://cwe.mitre.org/data/definitions/502.html).

## 2. Chứng cứ nền và các sai lệch đã truy nguyên

Nguồn JSON: [`reports/evaluation/retest-2026-10-28-open-source`](../reports/evaluation/retest-2026-10-28-open-source/ASSESSMENT.md), [`runs.json`](../reports/evaluation/retest-2026-10-28-open-source/runs.json), [`source_manifest.json`](../reports/evaluation/retest-2026-10-28-open-source/source_manifest.json), [`Pokémon`](../reports/evaluation/pokemon-class-loading-2026-10-28.json), [`level 1`](../reports/evaluation/workshop-level1-class-loading-2026-10-28.json), [`level 2`](../reports/evaluation/workshop-level2-class-loading-2026-10-28.json). Các bản JSON phản ánh quét tĩnh trên những cây nguồn cụ thể; chưa phải kiểm chứng runtime. Tám dự án được tính là XVWA, Saloon, Monolog bản hiện tại, Monolog 1.23.0, TCPDF 6.2.22, Laravel 5.6.29, WordPress 5.8.2, Drupal 8.6.9.

| Ca / bằng chứng thực tế | Kết quả hiện tại và nguyên nhân trong engine | Kết quả cần đạt |
| --- | --- | --- |
| XVWA: `$_REQUEST['r'] → unserialize`; `PHPObjectInjection::__wakeup → eval($inject)` | Sink và gadget đã thấy, nhưng `pop_evidence.py` chỉ liên kết ở metadata, không có thực thể đường thống nhất mang thuộc tính `inject`, lớp và trigger. | Một finding có trace dữ liệu → object → `__wakeup` → `eval`, với điều kiện thuộc tính rõ ràng. Đổi `allowed_classes=false` hoặc loại thuộc tính thì chain không còn. |
| Saloon 3.0.0: `AccessTokenAuthenticator.php:105`, `allowed_classes=true` | Hai Medium nêu đúng API, song nguồn token của ứng dụng chưa ở cây nguồn. `library_mode` trong `taint_engine.py` giả định tham số public có thể bị kiểm soát; không thể suy ra RCE. | Giữ `conditional_api`, nhận diện version/advisory như ngữ cảnh; chỉ nâng lên `source_to_sink` khi quét cả caller thật. [Advisory của dự án](https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9). |
| Monolog 1.23.0: PHPGGC Monolog/RCE1 | Deep scan đã tạo chain `c47409495791` trong `gadget_chains`, nhưng `_deduplicate_findings()` ở `scanner.py` khóa theo file/dòng/cột/rule/sink type; các chain bắt đầu tại `AbstractHandler::__destruct` bị gộp, RCE1 thành `alternative_gadget_chain_ids` của chain khác. `gadget_finder.py` cũng chưa xác minh đầy đủ alias/callback/property. | RCE1 có bản ghi chain riêng, xác định `SyslogUdpHandler → BufferHandler` và điều kiện thuộc tính; thư viện độc lập chỉ là gadget, chưa có source-to-sink của app. [PHPGGC Monolog/RCE1](https://github.com/ambionics/phpggc/blob/master/gadgetchains/Monolog/RCE/1/chain.php). |
| Monolog bản hiện tại | Có ứng viên gadget nhưng không có `unserialize()` của ứng dụng. Tên package không đủ để dùng chain/version của 1.x. | Dựa trên mã/class thực tế và khoảng version; không áp nhãn của 1.23.0 sang 3.x. |
| TCPDF 6.2.22 | 16 Medium là đường PHAR API với giả định đầu vào. Bản này đã chặn `phar://` trong `TCPDF_STATIC::file_exists`, và cần chứng minh guard thống trị đúng lệnh sử dụng đường dẫn; chưa được coi là 16 lỗ hổng. | Phân biệt PHAR theo PHP <8/≥8, tóm tắt helper và nhánh caller; CVE-2018-17057 ở bản 6.2.22 phải `outside_affected_range`. Đối chiếu cùng một đường trên 6.2.19 và 6.2.22. [Bản vá TCPDF](https://github.com/tecnickcom/TCPDF/commit/1861e33fe05f653b67d070f7c106463e7a5c26ed). |
| Laravel 5.6.29: `Encrypter.php:149` | Có High `guarded_flow_review`, confidence Low. Trace hiện tại chứa cả cookie và `X-XSRF-TOKEN`; thiếu phân tích hợp đồng `validPayload`/MAC, kết quả giải mã, cờ `$unserialize`, APP_KEY. Cạnh caller được bổ sung trong `framework_dispatch.py`, chưa phải chứng cứ cấu hình chạy. | Giữ hai route riêng và tiền điều kiện khóa/MAC; bản 5.6.30 không còn cùng route nếu caller đặt cờ false. [Advisory](https://github.com/advisories/GHSA-qvqm-h22r-4cp9), [hướng dẫn nâng cấp](https://laravel.com/framework/docs/5.6/upgrade#upgrade-5.6.30). |
| WordPress 5.8.2: `upgrade.php:1616` | Sink CVE-2022-21663 chỉ là Medium cú pháp. Các High tại `functions.php`/PHAR là đường khác. Thiếu tác động đọc/ghi option DB, điều kiện multisite và `db_version`, phân biệt `maybe_serialize`/`is_serialized` với raw `unserialize` và token `C`. `guard_models.py` mới loại một số nhánh. 895 route thay thế nhưng chỉ hiển thị giới hạn, làm khó truy vết. | Báo đường từ option DB đến chính sink 1616 và các điều kiện; bản 5.8.3 không còn route tương đương. Không lấy các High khác để chấm CVE. [Phân tích của nhóm phát hiện](https://www.sonarsource.com/blog/wordpress-object-injection-vulnerability/), [commit vá](https://github.com/WordPress/WordPress/commit/638ef7815ec29318434365ffde1d3cef7437b948). |
| Drupal 8.6.9: `MapItem.php:67`, `LinkItem.php:194` | Hai High production đúng sink liên quan, nhưng `unresolved_return_flow`, confidence Low; High thứ ba thuộc tests. `framework_dispatch.py` chọn hàng loạt FieldItem class từ tên và hierarchy; chưa biết REST resource/format, field schema, `target_instance`, module và dependency Symfony của ứng dụng chạy. | Trace REST/serializer/normalizer/field có binding lớp và cấu hình; nếu không có cấu hình, giữ conditional. Loại test-only khỏi khẳng định CVE; so với 8.6.10. [Drupal SA-CORE-2019-003](https://www.drupal.org/sa-core-2019-003). |
| Pokémon | Upload `file_get_contents($_FILES[*]['tmp_name']) → unserialize` đã được phát hiện. Các tác động qua `$_SESSION['trainer']`, `Calculator::run→eval`, `TrumCuoi::fight` và `Database::__destruct→Logger::close→system` còn rời rạc; chọn lớp và thuộc tính sau khi nạp object chưa được chứng minh đồng thời. | Ghép qua session/request và sự kiện action/destructor; tách thay đổi logic trong game khỏi RCE, giữ điều kiện class/property/trigger. Xem [đối chiếu writeup cũ](../reports/evaluation/POKEMON_WRITEUP_COMPARISON_2026_10_27.md). |
| Workshop level 1 | Upload → unserialize → session → echo có ứng viên `Router::__toString→system`; `test.php` khai báo Router trùng tên có thể gây nhập nhằng trong bảng symbol toàn dự án. | Chọn lớp theo entrypoint và include/autoload; chỉ nối route khi Router đúng file được nạp và object từ session được render. |
| Workshop level 2 | Mô hình glob trong `class_loading.py` đã loại Router khi `index.php` bỏ qua `router.php`. Vẫn có ứng viên `Student::__toString→Calculator::get_result→eval` và `Thesis::__destruct→Student→Calculator→eval`; `test.php` chứa lớp trùng tên. | Duy trì loại Router; chứng minh property/receiver và trigger của hai chain còn lại, hoặc ghi `unknown` theo đúng mắt xích thiếu. |

**Lý do chung:** phân tích nguồn → sink, gadget, class loading, session dispatch và framework dispatch đang tạo các mảnh chứng cứ khác nhau. Khóa hợp nhất dựa vào tọa độ mã thay vì danh tính đường, bảng lớp/dispatch trên toàn cây thay vì entrypoint, và giới hạn route làm sai lệch cách đọc kết quả. `deserialized_dispatch.py` hiện đòi finding `DIRECT_UNSERIALIZE` có route request chắc chắn rồi tìm `$_SESSION` store và call/render; danh sách lớp lấy từ `get_all_unique_classes()` toàn dự án, có cờ `cross_request_execution_unverified`. `class_loading.py` chỉ nhận biết literal include chung và một kiểu glob/guard hẹp. Do đó không thể nâng metadata ứng viên thành chứng minh khai thác.

## 3. Học từ công cụ tham chiếu, giới hạn đối chiếu

| Nguồn mã/tài liệu | Cơ chế có thể chuyển thành thiết kế | Giới hạn khi dùng làm thước đo |
| --- | --- | --- |
| [`semgrep/src/tainting`](../semgrep/src/tainting/OSS_dataflow_tainting.ml) (`OSS_dataflow_tainting.ml`, `Taint_rule_inst.ml`, `OSS_taint_lval_env.ml`) | Khớp source/sink/sanitizer theo quy tắc rồi chạy transfer trên CFG và lvalue; giữ chứng cứ guard/propagator theo loại sink. | OSS taint là phân tích khả năng, không chứng minh runtime; trùng vị trí sink không chứng minh CVE. [Tài liệu Semgrep](https://semgrep.dev/docs/writing-rules/glossary). |
| [`psalm/src/Psalm/Internal/Codebase/TaintFlowResolution.php`](../psalm/src/Psalm/Internal/Codebase/TaintFlowResolution.php) | Trạng thái duyệt gồm node, ngữ cảnh lời gọi và assignment còn mở; lưu predecessor để khôi phục trace; hội tụ trạng thái để tránh nổ đường. | Psalm chỉ là phép kiểm tra độc lập cho luồng được mô hình hóa, không tự xác nhận gadget/điều kiện vận hành. [Tài liệu Psalm](https://psalm.dev/docs/security_analysis/). |
| [`progpilot/package/src/progpilot`](../progpilot/package/src/progpilot/Analysis/TaintAnalysis.php) | Validator phải gắn với nhánh và giá trị trả về; reaching definitions GEN/KILL là cơ sở cho guard và phép gán lại. | Danh sách sink/nhãn CWE có thể thiếu hoặc sai; không lấy JSON rule của nó làm nhãn chuẩn. |
| `codeql/` và `codeql-cli-binaries/` cục bộ | Học cách tách extractor, graph quan hệ, summary và truy vấn đường đi ở mức kiến trúc. | Bản `codeql/` hiện có các thư mục ngôn ngữ và binary, không có PHP extractor/query; không benchmark PHP bằng CodeQL. [GitHub nêu rõ PHP chưa được CodeQL hỗ trợ](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning). |
| [PHPGGC](https://github.com/ambionics/phpggc) | Oracle độc lập cho cấu trúc một số gadget, vector trigger và khoảng version. | Payload mẫu không chứng minh ứng dụng đang nhận dữ liệu không tin cậy hoặc đang nạp lớp. |

Không sao chép luật ngôn ngữ khác sang PHP mà thiếu semantics PHP, không dùng công cụ thứ hai làm ground truth. Nguồn nhãn phải là mã bản lỗi, bản vá, advisory của dự án và đường trigger được mô tả cụ thể.

## 4. Kiến trúc sửa theo năng lực tổng quát

### 4.1. Lớp chứng cứ và khóa danh tính đường

Thêm `RouteEvidence`/`GadgetEvidence` chuẩn ở `models.py` hoặc module mới: `entrypoint`, `source`, `store/load`, `sink`, `class_candidate`, `autoload`, `trigger`, `impact`, `guard`, `runtime_assumptions`, `missing_edges`, `scope`, `php_version`, `provenance`. Mọi engine ghi vào cùng graph chứng cứ; finding chỉ là phép chiếu để hiển thị. Đường không có app caller vẫn được lưu ở mức `conditional_api`.

Sửa `scanner.py::_deduplicate_findings`: với gadget, khóa theo `(entry class/method, toàn bộ bước chain, sink function/location, property constraints, trigger)`; gộp chỉ các route ngữ nghĩa tương đương và giữ đại diện cùng số route. `alternative_gadget_chain_ids` không được giấu chain tác động cao. Thêm test Monolog RCE1 và chain khác cùng dòng `__destruct`.

### 4.2. Phân tích PHP theo entrypoint và heap

Mở rộng `symbol_table.py`, `class_loading.py`, `call_graph.py`: build tập lớp khả dụng **cho từng entrypoint** qua literal include, Composer PSR autoload/classmap, bootstrap, glob và các include động với trạng thái `unknown`; giữ nhiều định nghĩa cùng tên ở các nhánh nạp khác nhau. Không chọn lớp từ `test.php` chỉ vì nó hiện diện trong cây. Ràng buộc receiver bằng type/hierarchy và object allocation, rồi mới thêm cạnh dynamic call.

Mở rộng `dataflow.py` và `object_effects.py` bằng summary liên hàm cho đọc/ghi property, array key, alias/self-reference, by-reference, callback, lời gọi động; trạng thái tối thiểu `(node, call context, object abstraction, field path, predicate set)`. Thêm store/load summary cho session, DB/cache/file và đánh dấu ranh giới request. Không nối hai request nếu key, write/read và trigger không khớp. Dùng phân tích ngược từ sink kết hợp summary tái sử dụng để tránh chạy toàn bộ graph trên mỗi sink.

### 4.3. Guard, PHP runtime và gadget event

`guard_models.py`, `phar_metadata_rules.py`, `source_models.py`: chuyển mô hình sanitizer thành hợp đồng ba trạng thái `allows/excludes/unknown`, gắn với đúng biến/giá trị, nhánh CFG và version. Bao gồm `allowed_classes`, filter/canonicalization đường dẫn, MAC/decrypt, serialized token format, `maybe_unserialize`, flag truyền qua call, PHP <8/≥8 PHAR; không coi hàm có tên `validate` là sanitizer. Sau phép gán lại hoặc path thay đổi, guard không tự duy trì.

`gadget_finder.py`, `pop_evidence.py`, `deserialized_dispatch.py`: thiết lập đồ thị sự kiện `unserialize → __unserialize/__wakeup`, `stored object → load → __toString/call`, `object release → __destruct`, callback và sink tác động. Tìm đường thỏa đồng thời class availability, `allowed_classes`, kiểu receiver, serializable property, alias, trigger và PHP version. Đường thiếu một mắt xích giữ `candidate` với lý do cụ thể; tuyệt đối không đổi nhãn vì có advisory trùng package.

### 4.4. Framework model và trình bày

`framework_dispatch.py` nên là registry model có version, điều kiện cấu hình, match chính xác signature/receiver, file provenance và test dương/âm. Trước mắt tách Drupal REST, Laravel decrypt, WordPress option DB thành model nhỏ độc lập; sau đó bổ sung model cho Composer/framework phổ biến qua cùng interface. Nếu thiếu config/vendor, ghi `unknown_dependency` hoặc `unknown_config` thay vì dựng cạnh chắc chắn.

`evidence.py`, `taint_engine.py`, JSON/SARIF: in graph trace theo `source → transform → guard → sink → object → trigger → impact`. `coverage` gồm file/AST lỗi, symbol unresolved, summary chưa hội tụ, route bị cắt và thiếu runtime config. Khi hết ngân sách, kết quả là `incomplete` chứ không phải âm tính. Tách `impact`, `confidence`, `exploitability` và `advisory_match` khỏi một thang severity chung.

## 5. Thứ tự triển khai và phép nghiệm thu

| Giai đoạn | Thay đổi cụ thể | Chặn hồi quy và điều kiện qua cổng |
| --- | --- | --- |
| 0. Ground truth | Manifest JSON cho từng ca: commit/version, PHP, entry, source, sink, guard, class, trigger, scope và đường vá; cố định hash lượt quét. Có cả ca chưa đủ chứng cứ và ca âm. | Không tính precision/recall trên toàn finding khi chưa có nhãn cho toàn finding. Mỗi route chuẩn có vị trí và nguồn tham chiếu. |
| 1. Finding identity | Sửa gộp gadget, graph chứng cứ; XVWA và Monolog là ca nhỏ. | Monolog RCE1 xuất hiện rõ; XVWA có đường thống nhất. Ca âm: thiếu thuộc tính/callback, `allowed_classes=false`, class không nạp không sinh chain xác nhận. |
| 2. Entrypoint + lifecycle | Lớp theo include/autoload, session store/load, object field/alias, event trigger. Pokémon, workshop 1/2. | Level 2 vẫn loại Router; level 1 chỉ nhận Router đúng bootstrap; hai workshop chỉ nâng mức khi đường object/trigger đầy đủ. |
| 3. Guard/format/runtime | Validator dominator + reassignment, serialized token domain, MAC/flag, PHP PHAR version. TCPDF, Laravel, WordPress. | Cặp 6.2.19/6.2.22, 5.6.29/5.6.30, 5.8.2/5.8.3 có khác biệt đúng **đường**; cùng sink cú pháp có thể còn, nhưng route CVE không còn ở bản vá. |
| 4. Framework + scale | Model cấu hình REST/field/DB, demand slicing và summary cache; Drupal, WordPress lớn. | Drupal 8.6.9 chỉ báo production route có cấu hình; 8.6.10 không có route cũ. Không lẫn `TestObjectItem`; số route hiển thị và route thật có metadata minh bạch. |
| 5. Tổng quát hóa | Nguồn và sink/rule registry, corpus held-out, kiểm thử biến thể. | Bản dự án PHP mới chưa dùng để viết model vẫn tìm direct source→sink; precision/recall đo theo route có nhãn. Không thêm nhánh `if project == ...` vào engine. |

Mỗi giai đoạn chạy unit tests của thành phần, ca tổng hợp dương/âm, rồi quét lại bộ lớn với cùng cấu hình và ngân sách. Chỉ mở rộng model khi có **một ca dương và ít nhất hai phản ví dụ** (guard đúng, class không nạp, flag false, callback cố định, v.v.). Hiệu năng ghi thời gian từng pha, RAM đỉnh, số file, số sink, số route và phần bị cắt; mục tiêu trước hết là không timeout/không âm tính giả do budget. Không hứa chứng minh mọi cấu hình runtime chỉ bằng quét tĩnh.

## 6. Dữ liệu kiểm định ngoài bộ hiện tại

Tạo hai tập tách biệt: `development` gồm các ca ở mục 2; `held-out` gồm các dự án PHP khác, giữ bí mật nhãn đến khi đã cố định engine của vòng đánh giá. Lấy các cặp commit trước/sau vá từ [advisory do maintainer công bố](https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9), [GitHub Security Advisories](https://github.com/advisories), [PHPGGC](https://github.com/ambionics/phpggc) để tham chiếu gadget; rà từng advisory/commit để xác nhận CWE và đường thật, không tự động gán nhãn theo từ khóa. Phủ các nhóm: trực tiếp `unserialize`, `igbinary_unserialize`, PHAR theo PHP version, session/cross-request, DB/cache persisted data, framework normalizer, gadget trong dependency và API thư viện chưa có caller. Bổ sung dự án sạch và biến thể âm (allowlist, MAC, class không load, guard thống trị, code chỉ trong tests).

Chấm ba mức độc lập: **sink detection**, **source-to-sink path**, **gadget/impact path**. Báo TP/FP/FN, precision/recall với mẫu số công khai, false alert/1.000 tệp, tỷ lệ `unknown`/`incomplete`, thời gian/RAM. Leave-one-project-out để phát hiện model đang ghi nhớ testcase; kiểm lại paired patch để tránh “trúng” chỉ vì biết tên CVE. Trường hợp không có dữ liệu runtime phải được ghi là conditional, không ép thành đúng/sai khai thác.

## 7. Quyết định triển khai đầu tiên

Ưu tiên sửa khóa gộp Monolog và chuẩn hóa graph chứng cứ vì đây là lỗi đã truy được tới dòng mã, sau đó giải bài toán entrypoint/session từ workshop và Pokémon. Guard/DB/framework model làm tiếp sau khi hình dạng route và trạng thái `unknown` ổn định. Cách này giúp mở rộng sang dự án PHP mới: engine học quan hệ mã nguồn và điều kiện chạy, còn advisory chỉ hỗ trợ đánh giá version và chứng cứ bên ngoài.
