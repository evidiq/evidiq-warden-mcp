<p align="center">
  <img src="https://raw.githubusercontent.com/evidiq/evidiq-warden-mcp/main/assets/evidiq-warden.png" width="200" alt="EVIDIQ Warden" />
</p>

# EVIDIQ Warden (`evidiq-warden-mcp`)

**Deterministic, AST-Based Code-Review Gate for AI Agents**

EVIDIQ Warden is a high-performance, deterministic AST review gate for source code written by AI agents. It uses `web-tree-sitter` grammars (TypeScript, TSX/JSX, JavaScript, Python) to enforce security, reliability, hygiene, and structural metric policies before code is committed or merged into production.

---

## 1. Features & Design Principles

- **Tree-Sitter AST Parsing**: Deterministic grammar parsing across TypeScript, TSX/JSX, JavaScript, and Python. No LLM-in-the-loop, no nondeterminism.
- **Diff-Aware Review**: Unified diff parsing tags findings as introduced by a change (`context: "changed"`) versus pre-existing (`context: "existing"`).
- **Policy Profiles**: Four pre-built profiles (`agent-written-code`, `security-baseline`, `library-publish`, `pre-commit`) mapping findings to `PASS`, `REVIEW`, or `BLOCK` verdicts.
- **Signed Review Reports & Attestations**: Reports carry canonical SHA-256 digests and EIP-191 signatures with optional 0G storage anchoring.
- **Zero Source Retention**: Code is parsed in-memory; findings return line ranges and rule IDs only — never matched source code.

---

## 2. Public Endpoints & Discovery

- **MCP Endpoint**: `https://mcp.evidiq.dev/warden/mcp`
- **Agent Skill Document**: `https://mcp.evidiq.dev/warden/skill.md`
- **x402 Discovery**: `https://mcp.evidiq.dev/warden/x402`
- **Health Check**: `https://mcp.evidiq.dev/warden/health`

### Quick Connection via Claude Code
```bash
claude mcp add --transport http evidiq-warden https://mcp.evidiq.dev/warden/mcp
```

---

## 3. Tool Catalog & Pricing

### Paid Tools (x402 Payment Gated on X Layer `eip155:196` in USD₮0)

| Tool Name | Price (USD₮0) | Atomic Units | Description |
|-----------|--------------:|-------------:|-------------|
| `review_diff` | `0.005 USDT0` | `5000` | Unified diff review; tags findings by change context |
| `review_files` | `0.01 USDT0` | `10000` | Whole-file AST review across an inline file set |
| `analyze_complexity` | `0.015 USDT0` | `15000` | Cyclomatic complexity, nesting depth, length, parameter count, and duplicate blocks |
| `check_policy` | `0.02 USDT0` | `20000` | Policy profile evaluation returning `PASS`, `REVIEW`, or `BLOCK` verdict |
| `attest_review` | `0.03 USDT0` | `30000` | Cryptographic verdict attestation signed via EIP-191 with optional 0G anchoring |

### Free Preflight & Verification Tools

| Tool Name | Cost | Description |
|-----------|------|-------------|
| `warden_capabilities` | **Free** | Returns complete rule catalog, supported languages, policy profiles, thresholds, and limits |
| `validate_source` | **Free** | Parse-checks input files and returns finding counts by severity without returning findings or charging |
| `estimate_cost` | **Free** | Returns exact atomic and human-readable price for any tool |
| `verify_review_report` | **Free** | Recomputes SHA-256 digest and verifies EIP-191 signature of a Warden report |
| `get_artifact` | **Free** | Retrieves a stored report or attestation by artifact ID within its 10-minute TTL |

---

## 4. Rule Families & Severity Hierarchy

### Injection and Execution
- `EVAL_DYNAMIC_CODE` (Blocker, CWE-95): Dynamic string evaluation via `eval()`, `new Function()`, `vm` module.
- `SHELL_INTERPOLATION` (Blocker, CWE-78): Passing interpolated strings to shell commands (`exec`, `subprocess`).
- `SQL_STRING_BUILD` (Blocker, CWE-89): SQL queries built via string concatenation or template interpolation.
- `PATH_FROM_INPUT` (High, CWE-22): Path joining without containment validation.
- `URL_FROM_INPUT` (Medium, CWE-918): Dynamic URL construction (SSRF risk).
- `UNSAFE_DESERIALIZE` (Blocker, CWE-502): Unsafe deserialization with `pickle` or `yaml.load`.

### Correctness and Reliability
- `FLOATING_PROMISE` (Medium, CWE-703): Asynchronous call neither awaited, returned, nor caught.
- `SWALLOWED_ERROR` (High, CWE-391): Empty catch block or `except: pass`.
- `BROAD_EXCEPT` (Medium, CWE-391): Catching bare `except:` or `except Exception`.
- `MUTABLE_DEFAULT_ARG` (High, CWE-665): Python mutable default argument retention (`def f(x=[])`).
- `NO_NETWORK_TIMEOUT` (Medium, CWE-400): HTTP client call without explicit timeout.
- `AWAIT_IN_LOOP` (Low, CWE-400): Awaiting operations inside loops sequentially.

### Security Hygiene
- `WEAK_HASH_FOR_AUTH` (High, CWE-327): MD5/SHA1 used in authentication contexts.
- `INSECURE_RANDOM` (Medium, CWE-330): `Math.random()` or `random.random()` producing keys or tokens.
- `HARDCODED_CREDENTIAL_SHAPE` (High, CWE-798): Hardcoded API key or credential pattern.
- `PERMISSIVE_CORS` (High, CWE-942): Wildcard CORS origin alongside credentialed requests.
- `DEBUG_LEFTOVER` (Low, CWE-489): Leftover `debugger` statement or secret logging.

### Structural Metrics
- `COMPLEXITY_EXCEEDED` (Medium, CWE-1075): Function cyclomatic complexity exceeds threshold.
- `NESTING_EXCEEDED` (Medium, CWE-1075): Deeply nested control structures.
- `FUNCTION_TOO_LONG` (Low, CWE-1075): Function length exceeds maximum recommended lines.
- `TOO_MANY_PARAMS` (Low, CWE-1075): Parameter count exceeds threshold.
- `DUPLICATE_BLOCK` (Medium, CWE-1041): Identical block of code duplicated across file.

---

## 5. Local Development & Testing

```bash
# Install dependencies
npm install

# Run unit tests
npm test

# Build TypeScript production bundle
npm run build

# Start local server (port 3000)
npm start
```

---

## 6. License

MIT License. Copyright (c) 2026 EVIDIQ Team.
