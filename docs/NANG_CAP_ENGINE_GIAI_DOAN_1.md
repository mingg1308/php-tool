# Nâng cấp engine — giai đoạn 1

## Phạm vi đã triển khai

- `FlowEvidence`: lưu source, trace, điều kiện guard và giả định đường dẫn của
  từng route còn được engine giữ lại. Trace cũ vẫn là đường đại diện.
- `Sink.key()` phân biệt nội dung điều kiện, tránh gộp hai guard khác nhau thành
  cùng summary chỉ vì đều có guard. Không thay đổi miền taint `Flow.key()`.
- Gộp finding từ nhiều tệp giữ hợp các route; không chỉ giữ finding đầu tiên.
- `EvidenceAssessment`: phân biệt bằng chứng cú pháp, ứng viên POP, nguồn request,
  nguồn framework, tham số thư viện giả định và truyền dữ liệu chưa giải quyết.
- Lỗi scan, summary không hội tụ và giả định chưa chứng minh được ghi thành
  limitations. Lỗi ở tệp khác cũng được phản ánh bảo thủ vì chưa có coverage
  theo dependency riêng cho từng finding.
- JSON và SARIF chứa evidence/assessment. Severity cũ vẫn được giữ; chưa đổi
  hệ thống tính mức tác động hoặc giao diện HTML/console để hiển thị mọi route.
- Rule loader từ chối ngữ nghĩa chưa hỗ trợ; lỗi từng rule không làm mất rule
  hợp lệ còn lại trong tệp. Loại bỏ cơ chế giả sanitizer bằng tìm mẫu văn bản
  trong search matcher. Taint Python không bị tắt bởi thay đổi này.

## Kiểm chứng

Trước sửa: 29 unittest method qua. Sau sửa: 35 method, gồm 6 method mới kiểm tra
route liên tệp, hai guard trong summary, unknown call, schema luật, rule lỗi cạnh
rule hợp lệ, builtin rules; có kiểm tra round-trip JSON và xuất SARIF.

Lượt Saloon với PHP 8.1, library mode và severity INFO:

```powershell
py -3.12 -m php_deserial_sast.cli scan testcase/saloon-3.0.0 --php-version 8.1 --library-mode --severity info --format json --output reports/evaluation/upgrade-evidence-saloon.json
```

Quét 332 tệp, không có lỗi phân tích, hai finding: một `syntactic_review` và một
`assumed_api_flow`. Đây không phải hai lỗ hổng đã xác nhận. Exit code 1 là quy ước
CLI khi có cảnh báo mức cao, không phải lỗi lưu báo cáo.

## Giới hạn và bước tiếp theo

`within_model` không có nghĩa phân tích đầy đủ mọi hành vi PHP. Bước dataflow
trước đó vẫn có thể hợp mất trace; độ sâu field, độ dài trace và giới hạn POP
vẫn tồn tại. Chưa phục hồi mọi đường đi khả thi, chưa xác minh khai thác.

Giai đoạn tiếp theo là IR/CFG với test cho early return, loop và exception, sau
đó nâng summary side effect/alias và xác minh property-taint trong ứng viên POP.
Các phần này chưa được triển khai ở giai đoạn 1. Không thay engine nền bằng một
CFG chưa được kiểm chứng trong cùng thay đổi về evidence.
