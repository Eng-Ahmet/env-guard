# EnvGuard — System Architecture Specification

## 1. High-Level Architecture

EnvGuard operates as an in-memory execution pipeline. Requests containing raw `.env` content or multiple files are passed directly to the Go backend via HTTP/REST endpoints using Fiber.

```text
[ Browser UI / HTML ]
        │  (HTTP POST /api/v1/audit - Multipart / JSON)
        ▼
[ Fiber HTTP Router ]
        │
        ├──► [ In-Memory Parser ] ────► Tokenizes Keys & Values
        │
        ├──► [ Regex & Entropy Scanner ] ──► Flags AWS Keys, JWTs, Secrets
        │
        └──► [ Drift Analyzer ] ────► Compares Key Sets across files
        │
        ▼
[ JSON Compliance Report ] ──► Rendered on UI / Downloadable as .env.example
```

## 2. Component Breakdown

* **Fiber HTTP Server:** Listens on local port (e.g. `:8080`), serving static HTML assets and exposing a single API route `/api/v1/audit`.
* **In-Memory Line Parser:** Scans file content line-by-line using Go's `bufio.Scanner`, ignoring comments (`#`) and empty lines.
* **Entropy Scanner:** Evaluates string randomness for values using Shannon Entropy calculation to identify leaked passwords and unmasked secret tokens.
* **Sanitization Engine:** Replaces value strings with standard placeholders (e.g., `YOUR_API_KEY_HERE`) to produce safe `.env.example` templates.

## 3. Data Processing Flow

1. User drops files onto the web page.
2. Web UI sends payload to backend endpoint `/api/v1/audit`.
3. Backend processes content strictly in RAM (no file writing to disk).
4. Analysis result JSON returned within <15ms.
5. RAM buffer is immediately cleared by Go Garbage Collector.

## 4. Security Boundaries

* **No Storage Persistence:** No databases, disk buffers, or logging of actual secret values.
* **CORS & Local Scope:** Configured to accept traffic only from localhost by default when run as a developer CLI tool.
