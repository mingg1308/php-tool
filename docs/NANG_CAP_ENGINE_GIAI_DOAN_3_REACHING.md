# Giai đoạn 3 — Reaching definitions trên CFG

Ngày: 18/10/2026.

## Triển khai

`ScopeCFG.reaching_definitions()` tính tập định nghĩa tại đầu mỗi block bằng
worklist. Entry có một định nghĩa đại diện giá trị đầu vào. Với phép gán biến
độc lập, OUT chỉ chứa định nghĩa mới; tại điểm hợp nhánh, IN là hợp OUT của các
tiền nhiệm. Chỉ các block reachable tham gia solver.

`FileFlow._read()` dùng tập này để chọn phép gán cần đánh giá và quyết định có
giữ nguồn tham số đầu vào hay không. Nó đọc IN của block, nên `$x = $x` hoặc
`$x .= 'suffix'` vẫn đọc được giá trị trước phép gán. Các biểu thức và summary
liên hàm tiếp tục được đánh giá bằng cơ chế hiện tại.

Cache của solver chỉ chứa quan hệ định nghĩa trên AST/CFG bất biến, không chứa
taint của caller. Vì vậy không phải xóa nó mỗi lần cập nhật summary; cache giá
trị biểu thức và phép đọc cũ vẫn được xóa theo vòng đời summary.

## Lỗi được xử lý

```php
$x = $_GET['payload'];
if ($_GET['flag']) {
    $x = 'safe-a';
} else {
    $x = 'safe-b';
}
unserialize($x);
```

Mỗi phép gán riêng lẻ không dominate sink, nhưng mọi đường tới sink đều đã ghi
đè `$x`. Solver mới loại định nghĩa request ban đầu. Nếu thiếu else, một nhánh
giữ taint, hoặc giá trị mới phụ thuộc `$x` cũ thì vẫn giữ cảnh báo.

## Phạm vi và giới hạn

Hỗ trợ các phép gán/augmented assignment độc lập vào biến đơn, trong scope mà
CFG giai đoạn 2 hỗ trợ. Từ “scalar” trong metadata chỉ phạm vi truy cập biến
đơn, không có nghĩa engine đã chứng minh kiểu PHP của giá trị là scalar.

Nếu biến có phép ghi field hoặc phép gán lồng trong biểu thức, solver không
dùng GEN/KILL này cho biến đó. Truy cập field và scope chứa loop/exception/goto
vẫn dùng cách phân tích trước. Chưa giải alias, reference, side effect liên hàm
hoặc reaching definitions cho vòng lặp. Không thay đổi bộ tìm POP.

## Kiểm chứng

46 unittest method qua, gồm năm method mới với nhiều subcase: hợp nhánh đầy đủ
và thiếu nhánh, elseif, nhánh lồng, augmented assignment, tham số bị ghi đè,
đọc giá trị cũ ở RHS, fallback cho field/short-circuit/loop và summary liên hàm.

| Dự án | Tệp | Finding trước → sau | Biến qua solver | Lượt đánh giá block |
|---|---:|---:|---:|---:|
| XVWA, PHP 7.4 | 304 | 25 → 25 | 300 | 2.138 |
| Saloon, PHP 8.1, library mode | 332 | 2 → 2 | 289 | 1.582 |

XVWA vẫn giữ POI tại `php_object_injection/home.php:38` và cảnh báo filesystem
tại `ssrf_xspa/home.php:33`; call graph POP vẫn bỏ 242 cạnh ứng viên do giới hạn.
Saloon giữ API exposure tại `AccessTokenAuthenticator.php:105`, không có lỗi
scan. Tổng finding không phải số lỗ hổng đã xác nhận.

JSON: `reports/evaluation/upgrade-reaching-xvwa.json` và
`reports/evaluation/upgrade-reaching-saloon.json`. Các lượt chạy không bật LLM
và không thực thi ứng dụng/payload. Số finding không đổi ở hai dự án này chỉ là
kiểm tra hồi quy; hiệu quả sửa lỗi được thể hiện ở các test hợp nhánh có oracle.

## Bước tiếp theo

Mở rộng IR và transfer function trước khi thêm loop fixed-point cho giá trị
taint; sau đó xử lý summary property/reference side effect. Không bật cạnh
vòng lặp đơn thuần trong CFG rồi giữ nguyên phép đọc theo thứ tự byte, vì cách
đó vẫn bỏ sót định nghĩa từ lần lặp trước.
