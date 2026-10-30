# Nâng cấp phân tích mã nguồn: đường `include` và trạng thái nạp lớp

## Cơ sở thiết kế

Các công cụ tham chiếu đều dùng thông tin vượt quá phép tìm chuỗi: [CodeQL](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) phân biệt luồng cục bộ, liên hàm và taint; [Semgrep](https://semgrep.dev/docs/writing-rules/glossary) tách source, sink, propagator và sanitizer; [Psalm](https://psalm.dev/docs/security_analysis/) theo dữ liệu qua gán, lời gọi và thuộc tính. Ở mức triển khai, mã [Psalm `IncludeAnalyzer`](../psalm/src/Psalm/Internal/Analyzer/Statements/Expression/IncludeAnalyzer.php) tính chuỗi include hằng qua nối chuỗi, `dirname`, `__DIR__` và `__FILE__`; [Semgrep constant propagation](../semgrep/src/analyzing/Constant_propagation.mli) có bước đánh giá biểu thức hằng; [Progpilot `IncludeAnalysis`](../progpilot/package/src/progpilot/Analysis/IncludeAnalysis.php) dùng giá trị đã biết để thử giải đường include.

Engine hiện tại đã có phân tích taint liên hàm và ứng viên dispatch qua session, nhưng mô đun nạp lớp trước đây chỉ hiểu `include('literal.php')`. Khi mã dùng `__DIR__ . '/file.php'` hoặc `dirname(__FILE__) . '/file.php'`, quan hệ giữa điểm vào, tệp render và lớp gadget bị bỏ trống. Ngược lại, một include trong nhánh điều kiện từng bị coi là lớp chắc chắn được nạp.

## Thay đổi

- [`core/class_loading.py`](../php_deserial_sast/core/class_loading.py) đánh giá **chỉ** đường include xác định từ chuỗi, hai magic constant, `dirname()` builtin một đối số và phép nối `.`. Độ sâu biểu thức bị chặn ở 8. Đường dẫn có biến request, hàm do dự án định nghĩa lại, scheme hoặc biểu thức không hỗ trợ vẫn không được giải đoán.
- Include hằng ở cấp cao nhất có thể chứng minh lớp được nạp trong mô hình điểm vào. Include nằm trong `if`, loop, switch, `try` hoặc hàm chỉ cho trạng thái `unknown`, không khẳng định `included`.
- Tệp tự gọi `session_start()` ở cấp cao nhất, không có tệp cha include nó, có thể là điểm vào ghi session. Bằng chứng này nối với điểm vào đọc session nhưng không chứng minh endpoint được web server phục vụ, hai request thuộc cùng session hoặc thứ tự request.

## Kiểm chứng

Test dương tính: writer tự khởi động session; reader và lớp được nối qua `__DIR__`/`dirname(__FILE__)`. Test âm tính: `session_start()` trong hàm không gọi, include phụ thuộc `$_GET`, `dirname` bị định nghĩa lại và include lớp trong `if`. Các test không tự nâng mức độ lỗ hổng từ ứng viên lên xác nhận khai thác.

Quét lại Pokémon và workshop level 1–2 với PHP 7.3, LLM tắt: lần lượt 18/18, 125/125 và 125/125 tệp; 0 lỗi; giữ nguyên 4, 33 và 33 finding và toàn bộ chữ ký `(rule, file, line, severity)` so với mốc 29/10. Pokémon có hai điểm vào và `session_start()` trên cả hai đường của các ứng viên `fight`/`run`. Workshop level 1 vẫn có `Router: included`; level 2 vẫn loại `Router` theo guard glob. JSON: [Pokémon](../reports/evaluation/pokemon-analysis-upgrade-2026-10-29.json), [level 1](../reports/evaluation/workshop-level1-analysis-upgrade-2026-10-29.json), [level 2](../reports/evaluation/workshop-level2-analysis-upgrade-2026-10-29.json).

Giới hạn còn lại: biến được gán một đường dẫn hằng, alias, include động, autoload Composer và cấu hình `DOCUMENT_ROOT` chưa được giải tổng quát. Trạng thái `included` là kết luận trong mô hình AST/entrypoint nêu trên, không phải xác nhận runtime của triển khai cụ thể.
