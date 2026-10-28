# Cải thiện engine và kiểm thử lại ngày 25/10/2026

> **Báo cáo lịch sử:** các kết quả dưới đây phản ánh bản engine trước khi bổ sung
> mô hình guard đã kiểm chứng. Kết quả mới nhất nằm trong
> [Nâng cấp guard và retest cuối](NANG_CAP_GUARD_VA_RETEST_CUOI_2026_10_25.md).

## Thay đổi mã nguồn

1. `openssl_decrypt` được mô hình hóa theo tham số ciphertext (kể cả lời gọi PHP có named arguments). Taint ở key, cipher, IV hoặc tag không tự trở thành taint nội dung bản rõ. Đường từ ciphertext vẫn được giữ với trạng thái `uncertain=True`, vì khóa và điều kiện xác thực chưa được chứng minh. Hàm cùng tên do dự án tự định nghĩa vẫn đi qua cơ chế giải quyết lời gọi của dự án.
2. Điều kiện cần rà soát được đối chiếu theo đường truy cập phần tử mảng. Guard trên `$entry['meta_key']` không còn bị gắn cho lời gọi dùng `$entry['meta_value']`; guard trên chính trường dữ liệu vẫn được giữ. Write hoàn tất trước lời gọi vẫn làm mất hiệu lực guard theo logic hiện có.
3. Thêm hai bài hồi quy cho phần tử mảng và `openssl_decrypt`, gồm trường hợp ciphertext, key và named arguments.

## Kết quả xác minh

- Unit test: **128/128 đạt**.
- [Bộ ca nhỏ có nhãn](../reports/evaluation/retest-2026-10-25-improved/small/summary.json): **108/108 đạt**, gồm 64 ca dương và 44 ca âm theo nhãn fixture, 0 lỗi quét. Chỉ số này không ước lượng precision/recall trên dự án thực tế.
- [Chín lượt quét](../reports/evaluation/retest-2026-10-25-improved/runs.json) trên tám thư mục testcase và lượt Monolog 1.23.0 quét sâu: **đều quét đủ tệp, 0 lỗi/giới hạn**. Bản SHA-256 của engine dùng cho các lượt này có trong [source_manifest.json](../reports/evaluation/retest-2026-10-25-improved/source_manifest.json).
- So với đợt [24/10](DANH_GIA_RETEST_TESTCASE_2026_10_25.md), trên cả chín lượt không có vị trí `(rule_id, tệp, dòng, severity)` nào được thêm hoặc mất. Số gadget cũng không đổi; thay đổi lần này nằm ở đường bằng chứng.

| Mẫu | Tệp | Finding | CRITICAL/HIGH | Gadget | Đánh giá trọng tâm |
|---|---:|---:|---:|---:|---|
| XVWA | 304 | 36 | 1/1 | 1 | Giữ `$_REQUEST → unserialize` và `__wakeup → eval` riêng biệt. |
| Saloon 3.0.0 | 332 | 1 | 0/1 | 0 | Giữ sink `allowed_classes => true` tại dòng 105. |
| Monolog bản mới | 228 | 6 | 0/0 | 128 | Năm MEDIUM nằm trong test, POP vẫn là ứng viên. |
| Monolog 1.23.0 | 167 | 29 | 0/0 | 148 | Quét sâu `src` riêng: 88 tệp, 11 finding, 173 gadget; giữ chuỗi tham chiếu. |
| TCPDF 6.2.22 | 227 | 103 | 0/0 | 5 | Không có HIGH/MEDIUM cho bản đã vá trong chế độ mặc định. |
| Laravel 5.6.29 | 1.174 | 123 | 0/0 | 181 | Số finding giữ nguyên; xem phân tích route bên dưới. |
| WordPress 5.8.2 | 1.212 | 571 | 1/53 | 7 | Guard không liên quan đã bị loại khỏi trace; CRITICAL còn cần chứng minh. |
| Drupal 8.6.9 | 8.855 | 832 | 0/3 | 3 | Ba HIGH vẫn LOW confidence và `unresolved_return_flow`. |

### Laravel library mode

[JSON mới](../reports/evaluation/retest-2026-10-25-improved/laravel-library.json) đối chiếu với [JSON cũ](../reports/evaluation/laravel-5.6.29/library-mode.json): tại `Encrypter.php:149`, `alternative_flow_count` giảm **16 → 2**. Hai route còn lại đều bắt đầu từ tham số `$payload`, trường `value`; những route xuất phát từ key/cipher đã biến mất. Tổng số finding vẫn là 162 vì chúng vốn được gộp theo cùng vị trí sink. MAC hợp lệ, `APP_KEY` và đường header/cookie thực tế vẫn chưa được chứng minh.

### WordPress

[JSON mới](../reports/evaluation/retest-2026-10-25-improved/wordpress-5.8.2.json) vẫn ghi CRITICAL ở `wp-includes/functions.php:624`. Evidence còn guard `is_serialized()` và `is_serialized_string($entry['meta_value'])` từ `template.php`; guard `is_protected_meta($entry['meta_key'], 'post')` không còn bị gắn nhầm. Sink đang gộp 783 route; engine chưa chứng minh route nào loại object payload và route nào thực sự đi qua caller đó. Không coi CRITICAL này là object injection đã xác nhận.

### Các giới hạn còn lại

1. Cần phân loại route theo caller và guard, chứng minh ngữ nghĩa predicate loại object trước khi giảm hoặc loại cảnh báo WordPress.
2. Cần mô hình điều kiện MAC/APP_KEY và luồng middleware/header/cookie của Laravel; sửa mô hình ciphertext mới chỉ loại nguồn sai từ key/cipher.
3. Cần nối REST/HAL đến sink và xử lý phần return chưa rõ ở Drupal; nối nguồn giải tuần tự hóa với điều kiện thuộc tính/callback gadget ở Monolog và XVWA.
