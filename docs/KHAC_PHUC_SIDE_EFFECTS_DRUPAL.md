# Khắc phục hiệu năng side effects trên Drupal

## Nguyên nhân và thay đổi

Solver trước đây tính side effects cho cả những hàm chưa được luồng phân tích nào yêu cầu. Việc bind nhiều field paths cũng tạo các luồng trùng, dựng lại trace và duyệt lại phần tích lũy.

Bản sửa tách `effect_demands` khỏi `return_demands`. Side effects chỉ được tính khi phép đọc hoặc summary của hàm gọi cần đến. Nhu cầu mới đưa callee trở lại worklist, sau đó thay đổi được truyền tới caller. Hai tập nhu cầu được theo dõi độc lập để không bỏ qua hàm vừa trả về giá trị vừa sửa biến.

Việc gộp side effects dùng dictionary tích lũy; khóa ngữ nghĩa và độ dài trace được kiểm tra trước khi tạo trace trùng cho global/object binding. Không cắt số lượng luồng để đạt tốc độ. Chế độ `--eager-summaries` được giữ để đối chiếu. JSON bổ sung `demanded_effect_functions`.

## Kiểm chứng

- **119/119 unittest đạt**: có kiểm thử đối chiếu ngữ nghĩa gộp luồng cũ, nhu cầu return/effect độc lập và hàm không được dùng.
- **108/108 ca có nhãn đạt** trong cả demand và eager: 64 ca dương, 44 ca âm.
- Đối chiếu 108 JSON theo rule, vị trí, severity và confidence: **0 sai khác**.

| Cấu hình Drupal 8.6.9 | Tệp đã quét | Thời gian nội bộ | Hội tụ | Lỗi ghi nhận |
|---|---:|---:|---|---|
| Side effects, tắt POP | 8855 | 140.99 giây | Có | Không |
| Side effects và POP | 8855 | 169.37 giây | Có | Giới hạn cạnh POP |

Lần bật POP yêu cầu side effects của **1620 hàm**, return summary của **268 hàm**, với **40942** lượt đánh giá summary. Ba finding HIGH, confidence LOW vẫn tại MapItem:67, LinkItem:194 và TestObjectItem:56. Finding thứ ba thuộc mã kiểm thử Drupal.

Bản experimental side effects trước đây vượt giới hạn 900 giây. Các lần mới đã hoàn tất, nhưng không suy ra tỷ lệ tăng tốc chính xác vì bản cũ không hoàn tất và điều kiện/cấu hình có khác biệt. Lần profile 180 giây sau tối ưu gộp luồng vẫn bị ngắt; kết quả hoàn tất đạt được sau khi bổ sung demand effects.

## Giới hạn còn lại

- POP vẫn bỏ 3.955 cạnh ứng viên do giới hạn dispatch; JSON giữ lỗi coverage. Summary hội tụ không đồng nghĩa POP coverage đầy đủ.
- Các luồng Drupal phụ thuộc hợp đồng framework và cấu hình runtime, chưa chứng minh khai thác RCE.
- Chưa chạy lại hoặc sửa lỗi môi trường Psalm/Progpilot trong đợt này.
- Side effects vẫn là tùy chọn experimental. Chưa chứng minh tương đương eager trên toàn Drupal vì bản eager lớn chưa hoàn tất. Tập ca nhỏ không bảo đảm độ chính xác cho mọi chương trình PHP.

## Bằng chứng

- `reports/evaluation/drupal-fixes/effects-demand-with-pop.json`: kết quả đầy đủ với side effects và POP.
- `reports/evaluation/drupal-fixes/effects-demand-full.json`: kết quả khi tắt POP.
- `reports/evaluation/drupal-fixes/effects-demand-validation.json`: tổng hợp kiểm chứng và SHA-256 mã Python.
- `reports/evaluation/drupal-fixes/effects-demand-small/` và `effects-eager-small/`: ca nhỏ và JSON từng ca.

Mã Drupal gốc không bị sửa; chưa commit hoặc push.
