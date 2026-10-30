# Điểm ưu tiên rà soát tĩnh cho PHP insecure deserialization

## Nguyên tắc

Đây là mô hình `review-priority-v1` của công cụ, **không phải CVSS, EPSS hoặc xác suất khai thác**. `severity` tiếp tục mô tả tác động tiềm năng của rule/finding; `confidence` mô tả độ chắc của phân tích; `assessment` ghi bằng chứng và giới hạn. Điểm mới chỉ giúp xếp hàng công việc rà soát. Không dùng điểm để đổi severity, xóa finding, khẳng định CVE hay xác nhận runtime.

Thiết kế tham khảo ba cách phân tách trong công cụ khác:

- [GitHub CodeQL code scanning](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning-alerts) tách security severity của query khỏi vị trí/path và phân loại mã test/thư viện. CodeQL dùng dữ liệu CVE/CVSS của CWE cho security severity ở mức query; công cụ này không sao chép công thức đó vì chưa có tập nhãn CVE đầy đủ cho từng rule và không muốn gọi sai một điểm tự đặt là CVSS.
- [SonarQube Security Hotspots](https://docs.sonarsource.com/sonarqube-server/10.4/user-guide/security-hotspots/) tách điểm cần xem xét khỏi lỗ hổng đã xác nhận. Vì vậy finding chỉ dựa vào cú pháp hoặc gadget ứng viên bị chặn trần ưu tiên.
- [Semgrep Reachability Analysis](https://semgrep.dev/assets/content/whitepapers/semgrep-reachabilityanalysis-whitepaper-1225.pdf) dùng khả năng tới được mã để giảm nhiễu, đồng thời phân biệt reachable với exploitable. Vì vậy điểm thưởng lớn nhất cần luồng nguồn → sink; guard và cấu hình chưa giải được làm giảm ưu tiên.

## Công thức và dữ liệu đầu vào

`score = clamp(impact + evidence + confidence + detection - limitations - scope, 0, 100)`, sau đó áp dụng các trần có điều kiện. Mỗi số cộng/trừ và trần xuất hiện trong `assessment.review_priority.factors`; tổng các factor bằng `score`. Mã tại [`core/review_priority.py`](../php_deserial_sast/core/review_priority.py).

| Thành phần | Điểm |
| --- | --- |
| Tác động `CRITICAL/HIGH/MEDIUM/LOW/INFO` | 35 / 28 / 20 / 10 / 4 |
| Bằng chứng nguồn request quan sát được / framework modeled / persistent giả định / API caller giả định / unresolved / gadget candidate / cú pháp | 30 / 22 / 12 / 10 / 14 / 5 / 2 |
| Confidence `HIGH/MEDIUM/LOW` | 15 / 9 / 3 |
| Detection `direct_untrusted_deserialization/conditional_path/review_candidate` | 20 / 8 / 0 |
| Có giới hạn phân tích | −5 |
| Guard chưa chứng minh / propagation chưa giải / cấu hình path giả định | −12 / −10 / −10 |
| Caller thư viện giả định / nguồn persistent chưa chứng minh đường ghi / thiếu dependency | −5 / −8 / −8 |
| Vị trí test / vendor hoặc example | −12 / −8 |

Các giới hạn nhỏ khác được liệt kê trong mã. Tổng trừ do giới hạn cụ thể không vượt 18 điểm để nhiều nhãn cùng mô tả một khoảng trống phân tích không hạ finding về 0. Finding `review_candidate` hoặc gadget candidate có trần 29; luồng giả định/chưa giải có trần 49; `conditional_path` có trần 79; finding ngoài production có trần 59. Gadget candidate có sàn 10 và site cần rà soát có sàn 5. Nhãn: `URGENT` ≥80, `HIGH` ≥60, `MEDIUM` ≥30, còn lại `LOW`.

## Kiểm tra trên ca thực tế

Sau khi áp dụng mô hình vào JSON của đợt quét 29/10 và chạy lại XVWA/Saloon:

| Finding | Severity / confidence | Điểm rà soát | Cách hiểu |
| --- | --- | ---: | --- |
| XVWA `home.php:38`, request → `unserialize()` | CRITICAL / HIGH | 100, URGENT | Ưu tiên điều tra cao; `exploitability_verified` vẫn false. |
| Pokémon `save-load.php:30`, upload → `unserialize()` | CRITICAL / HIGH | 79, HIGH | Có nguồn trực tiếp, nhưng session và request tiếp theo chưa xác nhận. |
| Saloon `AccessTokenAuthenticator.php:105`, API exposure | MEDIUM / LOW | 31, MEDIUM | Đúng sink, caller bên ngoài còn giả định. |
| Saloon cùng vị trí, luật cú pháp `allowed_classes` | MEDIUM / MEDIUM | 29, LOW | Chỉ là điểm rà soát cấu hình sink. |
| Drupal hai sink `MapItem`/`LinkItem` | HIGH / LOW | 30, MEDIUM | Luồng REST/HAL chưa giải được; cần người kiểm tra. |
| Monolog/RCE1 gadget đứng riêng | LOW / theo call graph | 10, LOW | Chưa có entry deserialize của ứng dụng hoặc property control. |

Các điểm là thứ tự rà soát trong **mô hình hiện tại**, không được hiệu chuẩn bằng precision/recall hay dữ liệu triển khai. Đợt thử nghiệm không đổi số finding, severity hoặc bằng chứng đường đi. LLM nếu bật lưu verdict/điểm riêng và không chi phối điểm ưu tiên này.
