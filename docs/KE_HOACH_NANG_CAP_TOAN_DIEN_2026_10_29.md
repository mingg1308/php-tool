# Kế hoạch nâng cấp và tối ưu hóa toàn diện công cụ PHP insecure deserialization SAST

Ngày lập: 29/10/2026. Phạm vi: `php_deserial_sast`, CLI, rule, báo cáo và bộ kiểm định. Đây là kế hoạch triển khai, chưa phải kết quả nâng cấp.

## 1. Đích và căn cứ

Đích của công cụ là phát hiện đường dữ liệu không tin cậy đến thao tác giải tuần tự hóa, xác định điều kiện tạo object và, khi có đủ chứng cứ, liên kết đến gadget gây tác động. Mỗi kết luận phải chỉ ra mã nguồn, đường đi, điều kiện đã chứng minh, điều kiện còn giả định và giới hạn phân tích. Quét tĩnh không xác nhận cấu hình triển khai hoặc trạng thái object trong một lần chạy thực tế nếu các dữ liệu đó không có trong đầu vào.

Mốc hiện tại là [lượt quét 29/10](../reports/evaluation/retest-2026-10-29-rules/ASSESSMENT.md), gồm 9 lượt trên các dự án trong `testcase` và 3 lab CyberJutsu; mọi lượt có `errors=[]`. Bộ kiểm thử gần nhất có 219 bài qua. Kết quả đã nhận đúng sink chính ở XVWA, Pokémon, workshop, Saloon và các vị trí đáng rà soát ở Drupal/Laravel. Giới hạn lớn nhất là các mảnh chứng cứ về source, guard, class loading, session và gadget chưa được kết hợp nhất quán; nhiều finding ở WordPress/TCPDF còn là giả định API hoặc PHAR. Số finding và mức High/Critical không phải số lỗ hổng đã xác minh.

Kế hoạch này kế thừa [chẩn đoán theo testcase](KE_HOACH_NANG_CAP_DO_CHINH_XAC_PHP_DESERIALIZATION_2026_10_28.md) và [phương án engine](PHUONG_AN_KHAC_PHUC_TOAN_BO_TESTCASE_2026_10_28.md), đồng thời bổ sung thứ tự triển khai, tối ưu hiệu năng, kiểm định độc lập và cổng nghiệm thu. Các thay đổi ngày 29/10 về [điểm ưu tiên rà soát](CHAM_DIEM_UU_TIEN_RA_SOAT_2026_10_29.md) và [phân tích include](NANG_CAP_PHAN_TICH_INCLUDE_2026_10_29.md) được xem là mốc đầu vào, không làm lại từ đầu.

## 2. Quy tắc thiết kế và đo lường

1. **Một mô hình chứng cứ chung.** `scanner.py`, dataflow, framework dispatch, POP/gadget và rule engine ghi các cạnh vào cùng một route theo entrypoint; finding là bản trình bày của route. Khóa danh tính bao gồm source, sink, lớp, trigger, điều kiện và phạm vi. Giữ đường thay thế có ý nghĩa, không gộp chỉ theo tọa độ dòng.
2. **Bốn trạng thái cho mỗi mắt xích:** `proven`, `conditional`, `excluded`, `unknown`. Giới hạn thời gian, thiếu file, dispatch động và summary bị cắt phải thành `unknown` hoặc coverage warning; không suy ra an toàn. `severity` là tác động giả định, `confidence` là độ chắc của bằng chứng, `review_priority` chỉ xếp thứ tự rà soát và không phải xác suất khai thác.
3. **Mô hình chung trước ngoại lệ dự án.** Advisory, tên package và bản vá dùng để gán nhãn kiểm thử; không tạo finding chỉ vì trùng CVE/version. Framework adapter phải công khai signature, version, cấu hình và giả định.
4. **Chấm ba tầng riêng:** nhận diện sink, source → sink, và source → object → gadget/impact. Với tập được gán nhãn đầy đủ ở từng tầng, báo TP/FP/FN, precision, recall, false alert/1.000 tệp, tỷ lệ `unknown` và coverage. Không tính precision/recall từ tổng finding chưa gán nhãn.
5. **Hiệu năng có tính đúng đắn.** Ghi thời gian từng pha, tổng thời gian, RAM đỉnh, số tệp/byte/AST node, số route, giới hạn bị chạm và cache hit. Chỉ so sánh các lượt chạy tuần tự trên cùng máy, cùng commit, cấu hình, phiên bản PHP và trạng thái cache.

## 3. Lộ trình triển khai theo thứ tự phụ thuộc

| Mốc | Việc triển khai chính | Kết quả bắt buộc để qua cổng |
| --- | --- | --- |
| **G0 — Bộ chuẩn tái lập** | Chốt manifest source/commit, phiên bản PHP, lệnh, cấu hình, phạm vi production/test/vendor và hash JSON. Tạo nhãn route dương/âm/không đủ chứng cứ theo mã lỗi, bản vá, advisory và writeup. Tách tập phát triển khỏi tập dự án chưa dùng để chỉnh engine. | Chạy lại cùng đầu vào cho danh tính route ổn định; mỗi nhãn có vị trí source, sink và nguồn chứng minh. Có kết quả thời gian/RAM chạy tuần tự, không dùng lượt chạy đồng thời 29/10 làm mốc hiệu năng chuẩn. |
| **G1 — IR và hợp nhất chứng cứ** | Thêm cấu trúc `RouteEvidence` với provenance, entrypoint, source/store/load/sink, guard, object class, property, trigger, impact, runtime assumption, missing edge, scope và coverage. Cho các engine phát sự kiện/cạnh vào cấu trúc đó; sửa dedup trong `scanner.py`; xuất cùng ID ở JSON/SARIF/console/HTML. | XVWA có một route đọc được từ request đến `__wakeup → eval` nếu đủ cạnh; Monolog/RCE1 không bị chìm trong alternative. Fixture không có property, callback hoặc `allowed_classes` hợp lệ không được nâng thành chain xác nhận. |
| **G2 — Độ chính xác PHP và entrypoint** | Củng cố parser/tree-sitter theo cú pháp và phiên bản PHP; index namespace, trait, inheritance, method/callback động. Tính tập lớp theo bootstrap/include/Composer autoload/classmap của từng entrypoint, giữ include động là `unknown`. Thêm alias và object field/array key có giới hạn ngữ cảnh. | Class `Router` của workshop level 1 chỉ được chọn từ file thực sự nạp; level 2 vẫn loại lớp đó. Class trùng trong `test.php` không thay class production. Cùng các phản ví dụ về include điều kiện, class chưa nạp và receiver khác kiểu. |
| **G3 — Luồng liên hàm, guard và dữ liệu bền vững** | Dùng CFG/reaching definitions và summary có effect đọc/ghi property, array, by-reference, session, DB/cache/file. Theo key và object identity qua request; nối hai request chỉ khi write/read và trigger khớp. Guard/transform có contract gắn với giá trị, nhánh thống trị sink và phép gán lại: `allowed_classes`, MAC/decrypt, cờ `$unserialize`, serialized token, path validator. | Pokémon và workshop trình bày riêng từng bước session/object/trigger, không tự động tuyên bố exploit; Laravel phân biệt hai caller và điều kiện APP_KEY/MAC; WordPress gắn đúng DB option → `upgrade.php:1616` và điều kiện multisite, hoặc ghi rõ cạnh chưa chứng minh. Guard bị vô hiệu sau reassignment trong fixture âm/dương. |
| **G4 — Mô hình giải tuần tự hóa và gadget** | Tập trung registry sink/transform có ngữ nghĩa PHP: native `unserialize`, session, igbinary, PHAR, WDDX/YAML theo extension/version, wrapper thư viện. Mô hình sự kiện `__unserialize`/`__wakeup`, `__destruct`, `__toString`, callback/SPL; chỉ nối gadget khi lớp có thể nạp, object/property có thể điều khiển và trigger phù hợp. PHAR tách PHP <8 với PHP ≥8. Rule YAML chỉ dùng tập cú pháp engine hỗ trợ; rule không hỗ trợ phải báo rõ. | TCPDF 6.2.19/6.2.22 cho khác biệt đúng đường PHAR dưới cấu hình PHP tương ứng; Saloon thư viện độc lập giữ `conditional_api`; Monolog 1.23.0 có chain RCE1 nhìn thấy nhưng không gán source ứng dụng chưa có. Không áp chain phiên bản cũ lên bản Monolog khác. |
| **G5 — Hiệu năng và độ bền dự án lớn** | Profile Drupal/WordPress/TCPDF theo pha. Bỏ quét AST lặp, thêm index tra cứu và slice ngược từ sink, summary theo SCC/worklist, memoization theo file hash + phiên bản cấu hình/model; cache phải invalidation chính xác. Chỉ song song hóa pha độc lập sau khi kết quả tuần tự ổn định. Đặt ngân sách CPU/RAM/path rõ ràng và ghi coverage khi chạm giới hạn. | Không mất route chuẩn ở G0–G4; JSON lặp lại có ID ổn định; cold/warm cache cho cùng kết quả; sửa một file chỉ invalidation phần phụ thuộc. Trên máy mốc, median 3 lượt chạy lạnh của mỗi dự án lớn không tăng quá 10% so với G0, RAM đỉnh không tăng quá 20%; nếu vượt, phải có phân tích pha và quyết định điều chỉnh trước khi qua cổng. |
| **G6 — Đánh giá ngoài tập và phát hành** | Chạy toàn bộ unit/integration, lab, các cặp dễ tổn thương/đã vá và dự án PHP chưa dùng để phát triển. So sánh Semgrep/Psalm/Progpilot khi cùng phạm vi và rule; CodeQL chỉ khi có bộ phân tích PHP khả dụng. Kiểm tra CLI, định dạng báo cáo, gói cài đặt, README và biểu đồ thiết kế. | Không hồi quy route đã chứng minh; không gán CVE sai bản vá; bảng TP/FP/FN theo tầng, thời gian/RAM/coverage và danh sách case còn `unknown`. Tài liệu mô tả đúng kiến trúc và giới hạn của bản mã được bàn giao. |

### Thứ tự ưu tiên trong từng mốc

- **P0:** Route evidence, dedup, entrypoint/class loading, guard, kết nối session/object, các ca âm cho bản vá. Đây là điều kiện để số cảnh báo phản ánh đường thực tế.
- **P1:** Summary liên hàm, framework contracts có version, PHAR runtime, tối ưu Drupal/WordPress, cache và định dạng báo cáo.
- **P2:** Mở rộng thêm sink/rule/extension và LLM tùy chọn sau khi P0/P1 ổn định. LLM chỉ hỗ trợ giải thích/ưu tiên, không được tự nâng mức chứng cứ hoặc khẳng định khai thác.

## 4. Ma trận nghiệm thu theo ca

| Ca | Route cần giữ hoặc bổ sung | Phản ví dụ bắt buộc |
| --- | --- | --- |
| XVWA; Pokémon; workshop 1/2 | Request/upload → deserialize, rồi gadget đúng lớp và trigger khi có chứng cứ. | Thiếu property/trigger; `Router` không nạp ở level 2; cùng tên class ở file test. |
| Saloon 3.0.0; Monolog 1.23.0 và bản khác | Saloon: sink API với caller còn điều kiện. Monolog 1.23: gadget chain riêng với điều kiện; không mặc định có app source. | Caller hằng số/allowlist; callback không điều khiển; class/version không khớp. |
| TCPDF 6.2.19/6.2.22; Laravel 5.6.29/5.6.30 | PHAR, guard path và PHP version; Laravel sink/caller/flag/MAC. | Bản vá mất đúng route CVE; PHP ≥8 không tự giải PHAR metadata lúc mở archive. |
| WordPress 5.8.2/5.8.3; Drupal 8.6.9/8.6.10 | Đúng sink CVE, DB/REST-field path và điều kiện runtime được phân biệt. | Test-only, PHAR route khác hoặc bản đã vá không được dùng để tuyên bố CVE. |

Mỗi model mới cần ít nhất một fixture dương và hai fixture âm khác nguyên nhân. Với case chưa đủ cấu hình hoặc caller, kết quả hợp lệ là `conditional`/`unknown` có `missing_edges`, không phải ép ra TP hay kết luận an toàn.

## 5. Tối ưu cấu trúc mã và quy trình

- Giữ ranh giới rõ: parse/index → project graph/summary → route evidence → phân loại/ranking → xuất báo cáo. Hợp nhất các helper trùng ngữ nghĩa sau khi có phép đo và test; không gộp file chỉ để giảm số lượng file.
- Registry hóa source/sink/guard/framework model với schema và kiểm tra cú pháp; rule chỉ làm pattern matching ở mức engine hỗ trợ. Bộ rule mới phải có ngữ nghĩa nguồn/đích và test phản ví dụ, tránh tăng nhiễu.
- Không để kết quả phân tích phụ thuộc thứ tự duyệt file, ngưỡng route hiển thị hay LLM. Giữ `analysis_incomplete` trong báo cáo nếu chạm budget. Tách production, test, vendor và library API bằng trường scope, không xóa bằng chứng phụ thuộc có ích.
- Bảo vệ API key: cấu hình qua biến môi trường, không ghi trong lệnh/báo cáo/cache; thêm kiểm tra secret trước khi phát hành. Gói cài đặt và ví dụ CLI phải chạy được từ thư mục khác ngoài repository.
- Cập nhật README, báo cáo chương 2, mô hình dữ liệu, activity/component diagram sau khi G1–G4 ổn định; ghi rõ mức chứng cứ và cách chấm `review_priority` trong đầu ra.

## 6. Cách vận hành kế hoạch

Thực hiện G0 → G6 theo cổng; sau mỗi mốc, chạy fixture thành phần và toàn bộ bộ hồi quy, lưu manifest/JSON/hiệu năng và bảng sai lệch. Nếu một mốc làm tăng false alert hoặc mất route chuẩn, sửa nguyên nhân trước khi mở rộng rule. Chỉ công bố đạt mục tiêu khi các cặp trước/sau vá phân biệt được đúng route, tập dự án chưa dùng để chỉnh engine có kết quả định lượng, và mọi kết luận còn phụ thuộc runtime được thể hiện là điều kiện.

Các ngưỡng hiệu năng ở G5 là mục tiêu đề xuất để kiểm soát hồi quy, không phải số đo đã đạt. Các con số precision/recall phải được điền sau khi G0 hoàn tất gán nhãn đầy đủ.

## 7. Tiến độ triển khai 29/10/2026

Đã bổ sung `RouteEvidence` trong JSON/SARIF, nối ứng viên gadget và session, giữ định nghĩa lớp trùng tên để kiểm tra theo file, xét thứ tự include trước sink/render, nhận diện bảng `options` trong truy vấn WordPress, lập chỉ mục tên hàm cho rule engine và báo rõ khi tìm sink qua session chạm giới hạn. Bộ 231 bài kiểm thử qua. Ba lab giữ số finding 4/33/33; workshop level 1 còn route Router, level 2 không có. Đối chiếu chữ ký từng finding với JSON mốc cho TCPDF, WordPress và Drupal cho kết quả thiếu 0, thêm 0, lỗi quét 0. Trên các lượt đo hiện có, pha finding của TCPDF giảm khoảng 9,0 → 2,8 giây; WordPress 48,0 → 21,7 giây; Drupal 38,5 → 20,7 giây. Đây là các lượt đo riêng lẻ, chưa phải benchmark median ba lần theo G5.

**Chưa qua cổng G0–G6:** chưa có corpus được gán nhãn đầy đủ và bản vá tương ứng trong workspace; chưa chứng minh đường ghi option WordPress, cấu hình REST/HAL Drupal, trạng thái object và thứ tự request tại runtime; Composer autoload mới có nhận diện PSR-4 có điều kiện, còn heap/alias liên hàm và cache tăng dần mới được xử lý một phần hoặc chưa triển khai. Vì vậy chưa tính precision/recall và chưa tuyên bố công cụ hoàn thiện trên mọi dự án PHP. Các mục này là việc tiếp theo theo đúng thứ tự phụ thuộc ở bảng lộ trình.

### Tiếp tục tối ưu và kiểm tra

Ngày 30/10, G3: đã xuất `candidate_persistent_store` cho ứng viên ghi request qua `$wpdb->insert/update/replace` có cùng bảng/cột với dữ liệu được đọc vào sink. Đã sửa cách đọc biểu thức `$wpdb->options`. Route vẫn có trạng thái `conditional` vì quyền ghi, danh tính bản ghi và thứ tự request chưa được chứng minh. 233 bài kiểm thử qua. WordPress 5.8.2 khớp chữ ký finding JSON mốc (thiếu 0, thêm 0, lỗi 0), nhưng chưa có ứng viên ghi trực tiếp; đường `update_option` đi qua `$update_args` vẫn cần mô hình liên hàm.

Ngày 30/10, G0: runner case study đã ghi hash của toàn bộ tệp dự án đích và kiểm tra hash này trước khi dùng `--resume`, bên cạnh manifest mã công cụ. Các lượt chạy cũ chưa có hash đích phải chạy lại để tạo mốc tái lập. Việc này chưa thay thế gán nhãn TP/FP/FN hay tạo cặp dễ tổn thương/đã vá.

Ngày 30/10, G6: runner có thêm `--compare` để xuất `comparison.json` theo chữ ký vị trí/file/rule/mức độ. Lượt quét 9 dự án tại `reports/evaluation/retest-2026-10-30-rss` đều có `errors=[]`; cả 9 dự án và ba lab Pokémon/workshop 1/2 đều thiếu 0, thêm 0 finding so với mốc 29/10. Đây là kiểm tra hồi quy, không phải đánh giá độ chính xác so với lỗ hổng đã xác nhận.

Lượt xác nhận có RAM tại `reports/evaluation/retest-2026-10-30-rss` bổ sung manifest phiên bản Python và 9 thư viện, hash tệp đích, cấu hình lệnh, peak RSS và `comparison.json`. Chín báo cáo hợp lệ, `errors=[]`, tổng 1.895 finding; cả 9 dự án và ba lab đều thiếu 0/thêm 0 so với mốc. RAM đỉnh một lượt ở TCPDF/WordPress/Drupal lần lượt 1.004/1.157/2.861 MiB. TCPDF bật side effects vẫn chạm ngân sách 60 giây và fallback; các thử nghiệm tối ưu worklist/property effects/phép ghi đè không cải thiện điểm nghẽn nên đã hoàn nguyên. Cổng G0/G5/G6 vẫn chưa hoàn tất vì chưa có nhãn độc lập, cặp bản vá, median thời gian/RAM và side effects hội tụ trên TCPDF.

Kiểm tra `wp-includes/option.php` của WordPress 5.8.2 cho thấy `update_option()` chuyển giá trị qua `maybe_serialize()` trước khi `$wpdb->update`; với chuỗi đã có dạng serialized, hàm này serialize thêm một lần. Vì vậy không được tự coi một request truyền vào `update_option()` là đường ghi payload object trực tiếp. Đã thêm fixture âm cho giá trị ghi qua `maybe_serialize`; 234 bài kiểm thử qua.

Rule engine hiện lập chỉ mục callee cho các mẫu gọi hàm cố định, giới hạn `pattern-either` vào mẫu ứng với callee và chỉ giải mã toàn bộ nội dung tệp khi cần tạo đoạn mã minh họa. Dataflow tái sử dụng danh sách call theo scope và các điều kiện kiểm tra tại cùng call site khi chuyển tiếp nhiều sink. Bộ 231 bài kiểm thử qua; ba lab Pokémon, workshop level 1 và level 2 giữ lần lượt 4/33/33 finding, không có lỗi quét. Các lượt đối chiếu riêng trước thay đổi thử nghiệm cuối cho TCPDF 6.2.22 và WordPress 5.8.2 giữ nguyên chữ ký finding; Drupal 8.6.9 sau đó cũng thiếu 0, thêm 0, lỗi 0 (97,14 giây). Một thử nghiệm bỏ bước tạo danh sách ứng viên tổng quát trong rule engine đã được hoàn nguyên vì lượt đo TCPDF tiếp theo không hoàn tất; bản chụp ngăn xếp lúc đó cho thấy thời gian ở bước dựng dataflow, chưa chứng minh được nguyên nhân. Không dùng các lượt đơn lẻ này làm kết luận hiệu năng G5. Cần đo median thời gian và RAM trên tiến trình riêng sau khi ổn định môi trường đo.

Ngày 30/10: xác định các lượt TCPDF quá chậm đã bật `experimental_side_effects=True`, trong khi cấu hình mặc định là `False`. Ở chế độ mặc định, TCPDF 6.2.22 quét 25,56 giây, khớp 107 finding của JSON mốc (thiếu 0, thêm 0, lỗi 0). Khi bật side effects, solver có 713 hàm; sau 60 giây mới xử lý khoảng 485 lượt summary và đang tính lại hiệu ứng property của `TCPDF::MultiCell()` sau khi summary các callee thay đổi. Lượt đầu của riêng `property_effects` cho hàm này mất khoảng 0,18 giây, còn lượt tính lại chưa hoàn tất trong cửa sổ profile 100 giây. Đã cho bước này dùng danh sách call theo scope; 231 bài kiểm thử qua nhưng thay đổi đó không làm hết điểm nghẽn. Không suy ra chế độ side effects hoàn tất hoặc giữ đúng mức RAM trên TCPDF; cần giới hạn chi phí tái tính hiệu ứng, đánh dấu coverage khi chạm giới hạn và kiểm tra kết quả so với fixture có hiệu ứng thực sự trước khi bật mặc định.

Đã thêm ngân sách 60 giây mặc định cho solver side effects thử nghiệm; hết ngân sách thì quét lại taint ở chế độ mặc định và ghi `side_effect_budget`/`budget_fallback`, không dùng summary dở dang. TCPDF với ngân sách cố ý đặt 0,1 giây khớp JSON mốc (thiếu 0, thêm 0), có đúng một lỗi coverage; 232 bài kiểm thử qua. Đây là biện pháp bảo vệ tài nguyên và bảo toàn kết quả mặc định, **chưa** làm cho side effects hội tụ nhanh trên TCPDF. Phần tối ưu summary gia tăng và đo RAM vẫn là công việc G5.
