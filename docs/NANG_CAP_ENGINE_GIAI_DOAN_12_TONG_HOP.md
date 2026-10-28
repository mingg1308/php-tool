# Giai đoạn 12: nâng cấp sáu nhóm chức năng phân tích

Ngày thực hiện: 22/10/2026. Không sử dụng LLM trong đợt kiểm chứng này.

## 1. Phạm vi đã triển khai

| Nhóm | Thay đổi trong mã nguồn | Giới hạn còn lại |
| --- | --- | --- |
| Hiệu năng summary | Tái sử dụng nhóm binding giống nhau; tính summary giá trị trả về theo nhu cầu; tái lập lịch khi phát sinh dependency mới | Chưa bảo đảm thời gian quét cho mọi dự án; miền trường vẫn giới hạn chiều sâu 4 |
| Heap, alias, side effect | Nhận diện đối tượng từ allocation site trong scope luồng thẳng, truyền identity qua gán biến, phân biệt gán lại đối tượng và ghi thuộc tính qua alias | Vẫn thử nghiệm; chưa có heap liên hàm đầy đủ, `$GLOBALS`, clone, alias qua nhánh, magic property và mutation động |
| CFG và exception | Loại giá trị return đang chờ khi finally chắc chắn kết thúc đột ngột và thay thế return đó | Chưa tách toàn bộ trạng thái return/throw/break qua finally; chưa giải kiểu exception |
| Bằng chứng POP | Đối chiếu entry class với `allowed_classes`, giữ trạng thái compatible/excluded/unknown; bỏ ưu tiên tên hàm đặc thù trong chọn route đại diện | Chưa chứng minh class được nạp lúc chạy, property controllability hoặc entry thực sự dẫn tới chain |
| Coverage từng finding | Thu thập scope trên evidence và các callee đã resolve; ghi fallback/exception/missing file; tách giới hạn POP khỏi assessment taint | Dependency động và trace đã rút gọn chưa được bao phủ đầy đủ; JSON ghi rõ graph chưa hoàn chỉnh |
| Matcher và đánh giá | Matcher AST cho member/static/nullsafe/namespaced/dynamic calls; mở rộng bộ ca có nhãn và xuất confusion matrix | Không tương đương toàn bộ ngữ nghĩa Semgrep; chưa có ground truth đại diện mọi dự án PHP |

Đây là các nâng cấp cụ thể ở cả sáu nhóm. Không đồng nghĩa mọi giới hạn
phân tích đã được giải quyết hoặc tất cả ứng viên đều khai thác được.

## 2. Summary theo nhu cầu

Lịch SCC của giai đoạn 11 giảm số lần tính lại caller nhưng vẫn tính mọi
giá trị return của mọi hàm. Trên WordPress, tập trường của các hàm xử lý
schema đệ quy vẫn gây nhiều phép kết hợp dù không phải toàn bộ giá trị đó
đều cần cho truy vấn sink.

Chế độ mới duy trì tập `return_demands`. Khi bộ phân tích thực sự đọc giá
trị một lời gọi, callee được thêm vào tập này. Bộ lập lịch vẫn xây summary
sink và effect cho các hàm; chỉ trì hoãn phần return chưa được yêu cầu.
Nếu một dependency phát sinh sau khi nhóm callee đã được xử lý, callee và
các caller bị ảnh hưởng được đưa lại vào hàng đợi. Các lời gọi ở top-level
được kiểm tra lại trước khi xác nhận hội tụ.

Không giảm danh sách tệp quét và không cắt bỏ fact theo số lượng để đạt tốc
độ này. Các giới hạn miền dữ liệu sẵn có vẫn áp dụng và được báo trong JSON.

Sau kiểm chứng, chế độ theo nhu cầu được bật mặc định:

```powershell
py -3.12 -m php_deserial_sast.cli scan "D:\đồ án\testcase\wordpress-5.8.2" --php-version 7.4 --severity info --format json --output wordpress.json
```

Để đối chiếu với lịch tính mọi return:

```powershell
py -3.12 -m php_deserial_sast.cli scan "D:\đồ án\testcase\saloon-3.0.0" --eager-summaries --php-version 8.1 --format json --output saloon-eager.json
```

`--demand-summaries` bật tường minh chế độ mặc định.
`--experimental-demand-summaries` vẫn được nhận như alias cũ.
Tên trường cấu hình Python `experimental_demand_summaries` được giữ để
tương thích; JSON bổ sung `return_summary_mode` để diễn đạt chế độ hiện tại.

## 3. Kiểm thử tính đúng

- 92 unittest method đạt sau thay đổi cuối cùng, bao gồm nullsafe call lồng nhau trong pipeline luật.
- 78/78 ca nhỏ có nhãn đạt ở cả eager và demand: 46 dương, 32 âm.
- Trong bộ ca này: TP=46, TN=32, FP=0, FN=0. Precision/recall bằng 1 chỉ
  trong phạm vi các fixture này; không phải kết luận về mọi mã nguồn PHP.
- Chạy thêm 17 test global/reference/alias/loop/exception với demand được
  ép bật: tất cả đạt.
- Kiểm tra demand closure riêng trên WordPress: không có return dependency
  mới xuất hiện sau khi summary đã hội tụ; taint-only scan có 70 findings,
  không lỗi scan, khoảng 44,3 giây.
- Heap được kiểm thử cả alias hai chiều, hai đối tượng riêng biệt, gán lại
  biến, giữ alias cũ, ghi đè và tách thuộc tính sibling.
- Finally được kiểm thử override an toàn/nguy hiểm, return có điều kiện,
  override qua hai nhánh, throw, finally lồng nhau và giữ giá trị đã return
  dù biến bị gán lại trong finally.
- POP được kiểm thử `false`, mảng rỗng, allowlist chứa/không chứa entry class,
  cấu hình động, tên lớp namespace có escape và thư viện không có entry ứng dụng.

Artifact ca nhỏ cuối: `reports/evaluation/upgrade-models-final-small/`.
Mỗi ca có PHP fixture và JSON của toàn pipeline; `summary.json` chứa nhãn,
cấu hình side effect từng ca, confusion matrix và trạng thái lỗi.
Các tham chiếu Progpilot/Psalm trong script là artifact lịch sử nếu có;
đợt này không chạy lại các công cụ ngoài. Các ca mới chưa có tham chiếu
ngoài được ghi `null`, không suy diễn thành âm tính.

Lệnh tái lập kiểm thử:

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -q
py -3.12 scripts/evaluate_small_cases.py --include-upgrade-cases --output reports/evaluation/recheck-demand-small
py -3.12 scripts/evaluate_small_cases.py --include-upgrade-cases --eager-summaries --output reports/evaluation/recheck-eager-small
```

## 4. Kiểm chứng dự án thực tế trước khi bật mặc định

Hai snapshot `upgrade-demand-seven` và `upgrade-demand-wordpress` hoàn tất
cả tám dự án. Audit xác nhận tám báo cáo hợp lệ, không lỗi audit và không
khác manifest tại thời điểm kiểm chứng đó.

| Dự án | Finding | Giây | Giới hạn được báo |
| --- | ---: | ---: | --- |
| Drupal 8.6.9 | 832 | 185,819 | Call graph |
| Laravel 5.6.29 | 122 | 19,288 | Call graph |
| Monolog (`monolog`) | 6 | 13,895 | Call graph và POP budget |
| Monolog 1.23.0 | 29 | 4,340 | Call graph |
| Saloon 3.0.0 | 1 | 2,919 | Không có lỗi scan |
| TCPDF 6.2.22 | 103 | 36,697 | Không có lỗi scan |
| WordPress 5.8.2 | 571 | 130,994 | Call graph |
| XVWA | 36 | 4,397 | Call graph |

Tất cả summary hội tụ. Ngân sách POP: depth 10, 20.000 paths, 500.000
expansions. Bảy dự án bật foreach CFG thử nghiệm; WordPress tắt. Side effect
thử nghiệm tắt ở cả tám. Có lượt chạy đồng thời, do đó bảng không phải một
benchmark thời gian được kiểm soát hoàn toàn.

WordPress trước đó vượt 600 giây ở cả lịch SCC và bản chỉ tối ưu nhóm binding.
Lượt demand hoàn tất trong 131 giây, với khoảng 9,3 giây parse/index,
27,9 giây graph/summary và 86,2 giây sinh findings. Đây là bằng chứng xử lý
được trường hợp timeout đã quan sát, không bảo đảm cùng tốc độ trên máy khác.

Bảy dự án không thêm/mất cảnh báo theo khóa rule/file/line/column/severity
so với `upgrade-bind-dedup-seven`. WordPress so với snapshot hoàn tất cũ
`upgrade-full-remaining`: không mất cảnh báo, tăng 152, gồm 140 INFO
`php-phar-path-api-review` và 12 MEDIUM `php-unserialize-review`. Phần tăng
là rà soát cú pháp, không phải 152 lỗ hổng hay luồng taint mới được chứng minh.
Baseline WordPress cũ khác phiên bản engine và cấu hình foreach, nên không
dùng nó làm phép so sánh eager/demand tuyệt đối.

## 5. Cách đọc coverage và POP mới

`metadata.dependency_coverage` ghi cơ sở thu thập dependency, danh sách file,
số scope, scope fallback, scope exception và file chưa phân tích. Cơ sở là
evidence còn giữ lại cộng với các callee đã resolve, không phải toàn bộ đường
thực thi. `complete_dependency_graph=false` được giữ tường minh.

`metadata.deserialization_constraints` trên ứng viên POP ghi các entry
`unserialize()` quan sát được. `compatible` chỉ có nghĩa policy lớp không
loại trừ entry class; không chứng minh payload, class loading hay runtime
reachability. `excluded` chỉ áp dụng với site được ghi, không loại bỏ ứng
viên thư viện vì còn có thể có caller bên ngoài. Mỗi finding giữ tối đa 32
site để trình bày; tổng số và trạng thái rút gọn vẫn được ghi.

## 6. Các giới hạn vẫn cần nghiên cứu tiếp

Foreach CFG và side effect/heap vẫn opt-in. Heap chỉ mới xử lý allocation
và alias cục bộ trong luồng thẳng; chưa phải mô hình heap toàn chương trình.
Exception CFG còn bảo thủ; việc loại return bị finally ghi đè không thay
thế cho phân tích đầy đủ từng kiểu hoàn tất. POP vẫn là ứng viên; class loading
và quyền kiểm soát thuộc tính chưa được chứng minh. Giới hạn dispatch và POP
budget vẫn tồn tại trên một số dự án. Kiểm chứng ground truth trên lỗ hổng
thực tế và đối chiếu mới với các công cụ ngoài vẫn là phần việc tiếp theo.

## 7. Kết quả bàn giao cuối cùng

Snapshot và JSON: `reports/evaluation/upgrade-models-final/`. Bộ ca nhỏ cùng manifest:
`reports/evaluation/upgrade-models-final-small/`. Cả tám lượt dùng demand mặc định,
tắt foreach CFG và side effect thử nghiệm; POP depth 10, 20.000 paths, 500.000 expansions.

| Dự án | Finding | Giây | Summary hội tụ |
| --- | ---: | ---: | --- |
| drupal-8.6.9 | 832 | 146.911 | Có |
| laravel-5.6.29 | 122 | 20.707 | Có |
| monolog | 6 | 10.933 | Có |
| monolog-1.23.0 | 29 | 4.535 | Có |
| saloon-3.0.0 | 1 | 2.96 | Có |
| tcpdf-6.2.22 | 103 | 40.0 | Có |
| wordpress-5.8.2 | 571 | 103.124 | Có |
| xvwa | 36 | 4.127 | Có |

Audit: **8 reports, 0 failures, 0 changed source files**. Đối chiếu với
`upgrade-demand-seven` và `upgrade-demand-wordpress`: cả tám dự án **0 added,
0 removed** theo khóa rule/file/line/column/severity. Các giới hạn call graph
và POP budget vẫn được giữ trong JSON, không được coi là coverage đầy đủ.

Các báo cáo `upgrade-models-release` là lượt trung gian trước bản sửa nullsafe
lồng nhau; dùng `upgrade-models-final` khi cần báo cáo khớp mã nguồn bàn giao.

```powershell
py -3.12 scripts/audit_upgrade.py upgrade-models-final
py -3.12 scripts/compare_scan_reports.py upgrade-models-final --baseline upgrade-demand-seven upgrade-demand-wordpress
```
