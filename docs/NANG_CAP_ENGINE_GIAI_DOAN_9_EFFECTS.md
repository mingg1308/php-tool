# Giai đoạn 9: CFG mở rộng, alias, tác động tham chiếu và matcher AST

Ngày kiểm chứng: 20/10/2026.

## 1. Thay đổi đã triển khai

- Foreach thử nghiệm nhận key/value, destructuring vị trí, phần tử bỏ trống,
  khóa literal và destructuring lồng nhau. Luồng khóa mảng được tách khỏi
  luồng giá trị. Binding tham chiếu vẫn fallback; tùy chọn vẫn tắt mặc định.
- Switch có cạnh kiểm tra case, default, fallthrough và xử lý mức
  break/continue trong switch lồng vòng lặp.
- Try/catch/finally có cạnh exception bảo thủ và đi qua finally khi hoàn tất
  bằng return, throw hoặc nhảy ra khỏi phạm vi. Kiểu exception và trạng thái
  hoàn tất chưa được phân hoạch chính xác; báo cáo ghi rõ giới hạn này.
- Alias biến đơn trong scope thẳng dùng mô hình ô tham chiếu và tái gán
  tham chiếu. Alias trong nhánh dùng hợp các khả năng, đánh dấu không chắc chắn.
- Summary tham số `&` truyền tác động ghi về đối số ở caller, bao gồm đối số
  có tên, trường mảng và hàm trung gian. Worklist theo dõi cả thay đổi effect
  để đánh giá lại caller. Ghi đè cục bộ chắc chắn sau lời gọi loại tác động cũ.
- Effect summary là tập các ghi có thể xảy ra. Nó không chứng minh giá trị
  cuối cùng của callee, không dùng lời gọi như một phép xóa taint chắc chắn.
  Bằng chứng qua effect được đánh dấu `uncertain` và có bước giải thích.
- Matcher dùng AST cho pattern lời gọi hàm parse được: biểu thức lồng nhau,
  comment, metavariable lặp và ellipsis đối số. Ellipsis nhận cả không đối số;
  biến PHP phân biệt hoa/thường, tên hàm không phân biệt. Pattern khác vẫn
  dùng matcher cũ; đây chưa phải bộ ngôn ngữ luật Semgrep đầy đủ.

## 2. Kiểm thử

- 68 unittest method đạt; mỗi method tham số hóa có thể chứa nhiều tình huống.
- 64/64 ca end-to-end nhỏ đạt, trong đó 40 ca positive kỳ vọng.
- Artifact ca nhỏ: `reports/evaluation/upgrade-effects-validated-small`.
- Snapshot và JSON bốn dự án: `reports/evaluation/upgrade-effects-validated`.

| Dự án | Finding | Thời gian tiến trình | Giới hạn còn ghi nhận |
|---|---:|---:|---|
| Monolog 1.23.0 | 29 | 3,735 giây | call_graph_limit |
| Saloon 3.0.0 | 1 | 2,612 giây | Không có lỗi vận hành |
| TCPDF 6.2.22 | 103 | 32,843 giây | Không có lỗi vận hành |
| XVWA | 36 | 3,845 giây | call_graph_limit |

Báo cáo được đọc lại bằng schema `ScanResult`. Không có lỗi parser/summary
vận hành trong bốn báo cáo trên. CFG vẫn có scope fallback và giới hạn node;
không có lỗi vận hành không đồng nghĩa phân tích đầy đủ.

Thời gian là một lượt chạy, không phải benchmark nhiều lần hay chứng minh
mức tăng tốc. PHP giả định 7.4 cho Monolog/TCPDF/XVWA và 8.1 cho Saloon;
bật foreach thử nghiệm, chế độ ứng dụng, không dùng LLM.

### Đối chiếu với snapshot giai đoạn 8

Đối chiếu đa tập rule, tệp, dòng và severity: không mất finding cũ.

- Monolog thêm 6 INFO `php-phar-path-api-review`.
- TCPDF thêm 66 INFO `php-phar-path-api-review`.
- XVWA thêm 9 INFO cùng rule và 2 MEDIUM `php-unserialize-review`.
- Saloon không thay đổi.

Các thay đổi là đối sánh cú pháp mở rộng, không phải các luồng taint mới
đã chứng minh. Ví dụ matcher mới nhận được
`file_exists(dirname(__FILE__).'/lang/eng.php')` và
`unserialize(serialize($profile))`. Những lời gọi này không tự chứng minh
đầu vào do kẻ tấn công điều khiển. Hai MEDIUM mới của XVWA nằm trong Twig:
`Profiler/Profile.php:148` và `Tests/Profiler/ProfileTest.php:86`; cần đọc
assessment và nguồn dữ liệu thay vì coi số finding là số lỗ hổng thực tế.

### Lỗi hồi quy đã phát hiện và sửa

Lượt `upgrade-effects` có lỗi TCPDF:
`taint_summary: 'str' object has no attribute 'key'`.
Cache chỉ mục effect đã dùng chung cache luồng mà solver vòng lặp đọc.
Đã tách `effect_index`, xóa cache khi summary thay đổi, thêm test gọi hàm
tham chiếu trong vòng lặp và chạy lại bằng snapshot mới.
Lượt lỗi được giữ để truy vết, không được dùng làm bằng chứng đạt kiểm thử.

## 3. Phần còn lại của kế hoạch nâng cấp

1. Chạy lại Drupal, WordPress, Laravel và Monolog mới trên snapshot giai đoạn 9.
   Bộ tám dự án giai đoạn 8 đã được audit, nhưng không đại diện mã hiện tại.
2. Hoàn thiện tham chiếu foreach, heap/property identity, tác động global,
   constructor và tham chiếu động. Effect xảy ra sau use trong lượt lặp trước
   chưa được mô hình hóa đầy đủ bằng chỉ mục effect hiện tại.
3. Thu hẹp may-write summary theo các lối thoát của callee để giảm cảnh báo
   từ ghi taint rồi ghi đè an toàn; xử lý chính xác hơn alias trong nhánh.
4. Gắn chứng cứ POP với entry deserialization, quyền điều khiển thuộc tính,
   lớp được nạp và allowed_classes. Call chain vẫn chỉ là ứng viên.
5. Coverage theo dependency của từng finding, thay cho các cờ giới hạn ở
   phạm vi project hiện tại.
6. Mở rộng matcher AST cho các cấu trúc ngoài lời gọi hàm và đo precision/
   recall bằng nhãn được kiểm chứng. Không suy ra độ chính xác toàn bộ công cụ
   từ 64 ca nhỏ.

Giai đoạn này hoàn tất các phần triển khai và kiểm thử nêu trên, chưa hoàn tất
toàn bộ kế hoạch nâng cấp.
