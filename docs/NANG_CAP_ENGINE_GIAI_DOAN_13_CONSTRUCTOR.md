# Giai đoạn 13: thuộc tính constructor và summary liên hàm

Ngày kiểm chứng: 22/10/2026. Phạm vi chính: chế độ `--library-mode`.

## Các lỗi tái hiện và bản sửa

1. **Bỏ sót constructor truyền dữ liệu qua helper.** Trước sửa, map thuộc tính
   được tạo khi return summary chưa sẵn sàng. Ví dụ `$this->payload=identity($x)`
   không tạo luồng từ tham số constructor tới phương thức gọi `unserialize()`.
   Sau sửa, map được tính lại ở điểm hội tụ; khi map thay đổi, các hàm phụ thuộc
   được tính lại. Getter trả về thuộc tính cũng được cập nhật trong summary.
2. **Giữ taint đã bị ghi đè.** Việc gom mọi phép gán constructor khiến
   `$this->payload=$x; $this->payload='safe';` vẫn báo API exposure. Bản sửa chỉ
   giữ may-write còn có thể thoát constructor mà không bị ghi đè chắc chắn.
   Ghi đè có điều kiện vẫn giữ nhánh có khả năng mang taint.
3. **Gộp tên thuộc tính khác hoa/thường.** Map cũ chuyển cả tên thuộc tính về
   lowercase. Bản sửa chỉ chuẩn hóa tên lớp, giữ nguyên tên thuộc tính: `$Payload`
   và `$payload` không còn bị coi là cùng storage.
4. **Constructor luôn throw.** Phân tích effect dùng cho tham chiếu thông thường
   phải giữ ghi trước throw vì caller có thể quan sát qua catch. Với nguồn khởi
   tạo đối tượng từ constructor, bản sửa thêm chế độ xét lối thoát bình thường:
   constructor luôn throw không tạo giả định đối tượng đã khởi tạo thành công.
   CFG exception/fallback vẫn giữ hành vi bảo thủ; đây chưa phải giải đầy đủ
   mọi tổ hợp try/catch/finally.

Map thuộc tính được thay thế khi tính lại, thay vì tích lũy taint cũ mãi mãi.
Các cache biểu thức và effect được làm mới trước khi tính map. Bộ lập lịch
không xác nhận hội tụ nếu ngân sách hết trước bước kiểm tra ổn định cuối.

## Kiểm thử

- **96 unittest method đạt**.
- **12 ca thư viện × 2 chế độ eager/demand = 24/24 lượt đạt**, chạy toàn pipeline
  và lưu JSON. Ca gồm helper an toàn/nguy hiểm, overwrite, conditional overwrite,
  unreachable write, throw, return sớm, tên thuộc tính khác case, constructor
  private và thuộc tính kế thừa.
- Ca riêng xác nhận constructor qua helper cập nhật được return summary của getter;
  build lần hai cho cùng tập fact và không xuất hiện return dependency muộn.
- **78/78 ca ứng dụng vẫn đạt**, gồm 46 ca dương và 32 ca âm theo mô hình.
- Không dùng LLM. Phát hiện thư viện vẫn mang giả định `library_public_api_parameter`,
  không được đổi thành nguồn request đã quan sát hay khai thác đã xác minh.

Artifact:

- `reports/evaluation/upgrade-library-properties-small/`: 24 JSON thư viện và nhãn.
- `reports/evaluation/upgrade-library-properties-application-small/`: 78 JSON ca ứng dụng.
- `reports/evaluation/upgrade-library-properties-before/`: baseline dùng snapshot
  `upgrade-models-final/source` của giai đoạn 12.
- `reports/evaluation/upgrade-library-properties-after/`: báo cáo bằng mã đã sửa,
  snapshot, manifest, `comparison.json` và `targeted_audit.json`.

## Đối chiếu thư viện thực tế

Cả baseline và bản sửa dùng library mode, demand summary, tắt foreach CFG/side
 effect thử nghiệm; POP depth 10, 20.000 paths, 500.000 expansions.

| Dự án | Trước | Sau | Thêm/mất cảnh báo | Giới hạn sau sửa |
| --- | ---: | ---: | --- | --- |
| Monolog (`monolog`) | 6 | 6 | 0/0 | Call graph và POP budget |
| Monolog 1.23.0 | 38 | 38 | 0/0 | Call graph |
| Saloon 3.0.0 | 2 | 2 | 0/0 | Không lỗi scan |

Cả ba summary hội tụ. Audit xác nhận schema, số finding và manifest khớp
mã nguồn hiện tại, không lỗi vận hành ngoài các giới hạn được báo. So sánh
finding dùng rule/file/line/column/severity; không chứng minh mọi trace
hoặc độ chính xác trên dự án thực tế là tuyệt đối.

Đợt này kiểm chứng ba dự án thư viện và các ca hồi quy. Bộ tám dự án ở giai
đoạn 12 vẫn là snapshot lịch sử, không được gắn nhãn là quét lại toàn bộ tám
project bằng mã giai đoạn 13.

## Tái lập

```powershell
py -3.12 -m unittest discover -s php_deserial_sast/tests -q
py -3.12 scripts/evaluate_library_cases.py --output reports/evaluation/recheck-library-properties
py -3.12 scripts/evaluate_scanner.py recheck-library-projects --snapshot --library-mode --projects saloon-3.0.0 monolog-1.23.0 monolog --timeout 180 --max-depth 10 --max-gadget-paths 20000 --max-gadget-expansions 500000
```

`evaluate_scanner.py --source-snapshot <thư mục source>` cho phép chạy lại
baseline bằng mã nguồn cũ với cùng runner và tham số. Manifest được lấy từ
source được chọn; chế độ resume từ chối trộn phiên bản source khác nhau.

## Giới hạn còn lại

Chưa có heap liên hàm đầy đủ cho mọi setter, alias động, clone, thuộc tính
private trùng tên qua kế thừa hoặc trạng thái đối tượng theo từng allocation
trong chế độ thư viện. Các scope có exception hay CFG fallback vẫn có thể giữ
thêm may-write. Các kết quả thư viện tiếp tục yêu cầu kiểm tra caller thực tế
và điều kiện tái tạo đối tượng trước khi kết luận lỗ hổng có thể khai thác.
