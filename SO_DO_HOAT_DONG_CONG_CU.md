# Sơ đồ luồng hoạt động của PHP Deserialization SAST

## 1. Luồng xử lý tổng thể

```mermaid
flowchart TD
    A[Người dùng hoặc CI/CD] --> B[CLI: scan]
    B --> C[Khởi tạo ScannerConfig]
    C --> D[Thu thập tệp PHP]
    D --> E[PHPParser tạo AST bằng Tree-sitter]
    E --> F[ASTVisitor trích xuất ký hiệu và lời gọi]
    F --> G[(ProjectSymbolTable)]
    G --> H[CallGraph dùng FQCN và MultiDiGraph]

    G --> I[TaintEngine tạo function summaries]
    E --> J[TaintEngine phân tích source-to-sink]
    E --> K[RuleEngine đối chiếu luật YAML]
    H --> L[GadgetFinder tìm đường magic method đến sink]

    I --> J
    J --> M[Tập Finding ứng viên]
    K --> M
    L --> M

    M --> N[Khử trùng lặp và tương quan kết quả]
    N --> O[Lọc theo ngưỡng severity]
    O --> P{Có bật LLM?}
    P -- Không --> R[Đóng gói ScanResult]
    P -- Có --> Q[Thẩm định Finding High hoặc Critical]
    Q --> R

    E -. lỗi parse .-> X[ScanError]
    I -. lỗi summary .-> X
    J -. lỗi taint .-> X
    K -. lỗi rule .-> X
    Q -. lỗi API/schema .-> X
    X --> R

    R --> S{Chọn định dạng đầu ra}
    S --> T[Rich Console]
    S --> U[JSON]
    S --> V[SARIF 2.1.0]
    S --> W[HTML đã escape dữ liệu]

    R --> Y{Trạng thái CLI}
    Y -- Có ScanError --> Y2[Exit code 2]
    Y -- Có High/Critical --> Y1[Exit code 1]
    Y -- Không có lỗi nghiêm trọng --> Y0[Exit code 0]
```

## 2. Luồng hoạt động chi tiết

```mermaid
sequenceDiagram
    actor User as Người dùng/CI
    participant CLI
    participant Scanner
    participant Parser as PHPParser
    participant Symbols as ASTVisitor + SymbolTable
    participant Graph as CallGraph
    participant Detect as Taint + Rules + Gadget
    participant LLM as LLMVerifier
    participant Report as Reporter

    User->>CLI: scan target và các tùy chọn
    CLI->>Scanner: ScannerConfig
    Scanner->>Scanner: Reset trạng thái và thu thập tệp

    loop Mỗi tệp PHP
        Scanner->>Parser: parse_file()
        Parser-->>Scanner: AST và source bytes
        Scanner->>Symbols: extract_all()
        Symbols-->>Scanner: class, method, property, call, sink
    end

    Scanner->>Graph: Xây đồ thị lời gọi toàn project
    Scanner->>Detect: Tạo taint summaries
    Scanner->>Detect: Tìm POP chains

    loop Mỗi tệp đã parse thành công
        Scanner->>Detect: Phân tích taint
        Scanner->>Detect: Áp dụng rule YAML
        Detect-->>Scanner: Findings
    end

    Scanner->>Scanner: Deduplicate, correlate, severity filter

    opt LLM được bật
        loop Finding High/Critical
            Scanner->>LLM: Code slice và metadata
            LLM-->>Scanner: Verdict JSON hoặc lỗi có cấu trúc
        end
    end

    Scanner->>Scanner: Tạo summary, errors và ScanResult
    Scanner-->>CLI: ScanResult
    CLI->>Report: Console, JSON, SARIF hoặc HTML
    Report-->>User: Báo cáo và mã thoát
```

## 3. Vai trò của từng giai đoạn

| Giai đoạn | Đầu vào | Xử lý | Đầu ra |
|---|---|---|---|
| Thu thập | Đường dẫn tệp/thư mục | Lọc phần mở rộng PHP và thư mục loại trừ | Danh sách tệp đã sắp xếp |
| Parse | Mã nguồn PHP | Tree-sitter tạo cây cú pháp | AST và source bytes |
| Trích xuất | AST | Lấy namespace, FQCN, lớp, hàm, phương thức, thuộc tính và sink | ProjectSymbolTable |
| Call graph | Symbol table | Tạo đa cạnh cho direct call, dynamic dispatch và magic method | MultiDiGraph |
| Taint | AST và summaries | Theo dấu nguồn dữ liệu đến `unserialize()` hoặc Phar sink | Finding và dataflow trace |
| Rule | AST và YAML | So khớp pattern trên các node phù hợp | Custom-rule Finding |
| Gadget | Call graph | DFS có giới hạn từ magic method tới sink | POP candidates và blueprint |
| Hậu xử lý | Tất cả Finding | Tương quan, khử trùng lặp và lọc severity | Danh sách Finding cuối |
| LLM | Finding High/Critical | Cắt lát mã, gọi provider và kiểm tra JSON nghiêm ngặt | `llm_verification` hoặc ScanError |
| Báo cáo | ScanResult | Chuyển sang giao diện hoặc định dạng trao đổi | Console, JSON, SARIF, HTML |

## 4. Nguyên tắc diễn giải kết quả

- Taint finding cho biết công cụ tìm thấy một đường dữ liệu khả nghi; nó chưa chứng minh payload khai thác thành công.
- POP chain là ứng viên đường gọi từ magic method tới sink. Khả năng khai thác còn phụ thuộc khả năng điều khiển thuộc tính, kiểu, autoload và điều kiện runtime.
- Rule finding là kết quả so khớp heuristic, cần được đối chiếu với ngữ cảnh chương trình.
- LLM chỉ bổ sung nhận định và không xóa Finding gốc.
- Nếu một pha lỗi, lỗi được đưa vào `ScanError`; báo cáo không được xem là một lần quét sạch hoàn chỉnh.

