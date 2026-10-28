"""Summarize verified runs without interpreting failures as clean scans."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'reports/evaluation/drupal-final-fixes'

def read(path):
    return json.loads(path.read_text(encoding='utf8')) if path.exists() else None

own = read(OUT / 'own.json')
references = {}
for label, tool, project in [
    ('drupal-final-references','psalm','drupal-8.6.9'),
    ('drupal-final-references','progpilot','drupal-8.6.9'),
    ('drupal-final-psalm-local-deps','psalm','drupal-8.6.9'),
    ('drupal-final-progpilot-php74','progpilot','drupal-8.6.9'),
    ('drupal-final-slice-references-v2','psalm','slice'),
    ('drupal-final-slice-php74','progpilot','slice'),
    ('drupal-final-control','progpilot','reference-control'),
    ('drupal-final-control-php74-v2','progpilot','reference-control'),
]:
    folder = ROOT / 'reports/evaluation' / label
    runs = read(folder / (tool + '-runs.json'))
    data = read(folder / tool / project / 'result.json')
    entry = {'runs': runs, 'report_available': data is not None}
    if isinstance(data, list):
        entry['issue_count'] = len(data)
        entry['tainted_unserialize_count'] = sum(item.get('type') == 'TaintedUnserialize' for item in data)
    elif isinstance(data, dict):
        entry.update({k:v for k,v in data.items() if k != 'results'})
        entry['finding_count'] = len(data.get('results', []))
    references[label + '/' + tool] = entry
sources = ['php_deserial_sast/core/call_graph.py','scripts/evaluate_external.py',
           'scripts/reference_entrypoint.sh','scripts/progpilot_scan.php','scripts/reference_process.py','.gitattributes',
           'progpilot/package/src/progpilot/Analyzer.php',
           'progpilot/package/src/progpilot/Analysis/VisitorAnalysis.php',
           'progpilot/package/src/progpilot/Outputs/MyOutputsInternalApi.php',
           'progpilot/package/src/progpilot/Utils.php']
result = {'own_summary':own['summary'],'own_errors':own['errors'],
          'own_call_graph':own['analysis']['call_graph'],
          'unittest_passed':124,'references':references,
          'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},
          'notes':['Progpilot source was locally patched; it is not an untouched upstream baseline.',
                   'Psalm full run initially used 3 GiB, increased live to 5 GiB; local-deps rerun used 5 GiB from start.',
                   'No valid full reference report must not be counted as zero vulnerabilities.']}
(OUT/'comparison.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'own_seconds':own['summary']['scan_duration_seconds'],
                  'own_errors':len(own['errors']),
                  'reference_reports':{k:v['report_available'] for k,v in references.items()}}))

prog = references['drupal-final-progpilot-php74/progpilot']
prog_status = (prog['runs'] or [{}])[-1].get('status', 'pending')
prog_exit = (prog['runs'] or [{}])[-1].get('exit_code')
report = f"""# Sửa lỗi còn lại và kiểm thử Drupal 8.6.9

## Thay đổi đã kiểm chứng

1. POP: bỏ cắt cứng 4 đích của property dispatch và 12 đích override. Đồ thị giữ mọi ứng viên được chỉ mục; giới hạn tìm chuỗi vẫn hoạt động và vẫn báo thiếu coverage nếu bị chạm.
2. Progpilot: kiểm tra đồ thị trước khi gọi computeCallGraph sau khi cơ chế giới hạn bộ nhớ giải phóng representations. Cảnh báo được lưu trong JSON, không biến tình huống thiếu đồ thị thành kết luận an toàn.
3. Progpilot: parser dùng phiên bản PHP mục tiêu, cụ thể 7.4 cho Drupal. Sửa lỗi cú pháp truy cập ký tự bằng dấu ngoặc nhọn do parser trước đó mặc định PHP mới nhất.
4. Psalm: bổ sung 46 dependency production theo composer.lock của Drupal vào thư mục riêng. Không chạy plugin/script Composer, không sửa target Drupal. Dependency PHP được đóng gói vào container; tránh liên kết tài liệu không đọc được trên Windows.
5. Runner: timeout kiểm tra thời gian thực mỗi giây để xử lý suspend/resume, được kiểm thử với tiến trình thật và bước nhảy đồng hồ. Shell dùng LF và được bảo vệ bằng .gitattributes; kết quả phân biệt tiến trình kết thúc và báo cáo hợp lệ. Bản Progpilot có sửa nguồn được ghi rõ là bản vá cục bộ, không phải baseline upstream nguyên bản.

## Công cụ hiện tại

- **124/124 unittest đạt**, gồm ca có 18 override và 8 property targets vượt giới hạn cũ.
- Quét đủ **{own['summary']['total_files_scanned']} tệp**, **{own['summary']['total_lines_scanned']} dòng**, bật side effects và POP.
- Thời gian nội bộ **{own['summary']['scan_duration_seconds']:.2f} giây**.
- **0 lỗi được ghi nhận**, **0 cạnh dispatch bị cắt** (trước sửa: 3.955 cạnh).
- 832 finding: 3 HIGH, 156 MEDIUM, 2 LOW, 671 INFO. Ba luồng taint ở MapItem:67, LinkItem:194 và TestObjectItem:56; vị trí cuối thuộc mã kiểm thử Drupal.
- Finding HIGH vẫn confidence LOW, phụ thuộc mô hình framework và runtime. Không phải xác nhận RCE. Không suy ra precision/recall toàn Drupal từ số cảnh báo này.

## Kết quả công cụ tham chiếu

- Progpilot control: phát hiện được ca unserialize từ POST; không cảnh báo nội bộ.
- Progpilot trên phần mã liên quan: đủ 29 tệp, parser 7.4, exit 0, không cảnh báo, 0 finding. Đây là hạn chế truy vết trong phạm vi đó; không chứng minh mã an toàn.
- Psalm trên phần mã liên quan: có JSON, 133 chẩn đoán chủ yếu thiếu lớp/annotation, không có TaintedUnserialize. Tập mã nhỏ thiếu phần còn lại của Drupal, nên không lấy các chẩn đoán đó làm đánh giá chất lượng toàn dự án.
- Full Drupal, lần đầu sau sửa môi trường: cả hai công cụ vượt 900 giây, không có báo cáo hợp lệ.
- Full Psalm, lần tiếp theo dùng dependency trong container và RAM 5 GB: exit 9 sau 664,55 giây, không có JSON. Log không xác định nguyên nhân; truy vấn sự kiện Docker không trả về bằng chứng OOM, nên không kết luận chắc chắn là hết bộ nhớ.
- Full Progpilot, parser PHP 7.4: trạng thái tiến trình **{prog_status}**, exit **{prog_exit}**; báo cáo hợp lệ: **{prog['report_available']}**. Lần này bị dừng thủ công khi quá hạn sau khoảng gián đoạn dài, không phải hoàn tất phân tích. Chi tiết lệnh, thời gian và giới hạn nằm trong comparison.json và runs.json.

**Phần chưa hoàn tất:** chưa có đối chiếu toàn Drupal thành công bằng cả Psalm và Progpilot. Không dùng timeout/exit bất thường như kết quả 0 lỗ hổng. Đã sửa những lỗi xác định được, nhưng không khẳng định mọi giới hạn của các công cụ upstream đã được giải quyết.

## Tệp bằng chứng

- reports/evaluation/drupal-final-fixes/own.json
- reports/evaluation/drupal-final-fixes/comparison.json
- reports/evaluation/drupal-final-progpilot-php74/
- reports/evaluation/drupal-final-psalm-local-deps/
- reports/evaluation/drupal-final-slice-php74/
- reports/evaluation/drupal-final-slice-references-v2/

Không commit/push trong đợt này. Mã Drupal gốc không được sửa.
"""
(ROOT/'docs/KIEM_THU_DRUPAL_SAU_SUA_LOI.md').write_text(report,encoding='utf8')
