# EVIDIQ Warden (`evidiq-warden-mcp`) — Agent Skill Document

**EVIDIQ Warden** (`evidiq-warden-mcp`) is a high-performance, deterministic AST review gate for source code written by AI agents. It parses code using tree-sitter grammars (TypeScript, TSX/JSX, JavaScript, Python), applies an explicit versioned rule set, and returns findings, a policy verdict, and a signed, verifiable report with zero source retention.

---

## 1. When to use Warden

Use Warden **between writing code and committing it**:
- After an agent edits or generates files, before creating a git commit.
- In CI/CD pipelines before merging pull requests.
- As a verifiable attestation mechanism for counterparty review.

Do **NOT** route dependency or license checks here (use **EVIDIQ Lineage**). Do **NOT** route endpoint/Skill security scanning here (use **EVIDIQ Sentinel**). For deep PII/secret redaction, route content to **EVIDIQ Redact**.

---

## 2. Public Endpoints & Connection

| Surface | URL |
|---------|-----|
| MCP Transport | `https://mcp.evidiq.dev/warden/mcp` |
| Agent Skill | `https://mcp.evidiq.dev/warden/skill.md` |
| x402 Discovery | `https://mcp.evidiq.dev/warden/x402` |
| Health Check | `https://mcp.evidiq.dev/warden/health` |

Connect via Claude Code or any MCP client:
```bash
claude mcp add --transport http evidiq-warden https://mcp.evidiq.dev/warden/mcp
```

---

## 3. Tool Catalog & Pricing

### Paid Tools (x402 Gated on X Layer `eip155:196` in USD₮0)

| Tool | Cost | Atomic | Description |
|------|------|-------:|-------------|
| `review_diff` | `0.005 USDT0` | `5000` | Review a unified diff; tags findings as introduced by the change or pre-existing |
| `review_files` | `0.01 USDT0` | `10000` | Whole-file AST review of a small inline file set |
| `analyze_complexity` | `0.015 USDT0` | `15000` | Per-function cyclomatic complexity, nesting depth, function length, and duplicate block detection |
| `check_policy` | `0.02 USDT0` | `20000` | Evaluate a file set against a named policy profile -> `PASS` / `REVIEW` / `BLOCK` with violations |
| `attest_review` | `0.03 USDT0` | `30000` | Bind a verdict to a content digest and optional commit sha, sign it, and anchor digest on 0G |

### Free Preflight & Verification Tools

| Tool | Cost | Description |
|------|------|-------------|
| `warden_capabilities` | Free | Return rule catalog with IDs, severities, CWE refs, supported languages, policy profiles, limits, and pricing |
| `validate_source` | Free | Parse-check input files and return finding counts by severity without returning findings or charging |
| `estimate_cost` | Free | Return exact atomic and human-readable price for any paid tool |
| `verify_review_report` | Free | Recompute SHA-256 digest and verify EIP-191 signature of a Warden report |
| `get_artifact` | Free | Retrieve a stored report or attestation by artifact ID within its 10-minute TTL |

---

## 4. Supported Languages & Policy Profiles

### Supported Languages
- TypeScript (`.ts`, `.mts`, `.cts`)
- TSX / JSX (`.tsx`, `.jsx`)
- JavaScript (`.js`, `.mjs`, `.cjs`)
- Python (`.py`, `.pyi`)

Unsupported extensions are reported as `language: "unsupported"` and excluded from clean verdicts.

### Policy Profiles
- `agent-written-code` (default): BLOCK on injection/execution risks; REVIEW on reliability & hygiene.
- `security-baseline`: BLOCK on all security/injection and credential hygiene findings.
- `library-publish`: BLOCK on injection, hygiene, and debug leftovers.
- `pre-commit`: Fast check, BLOCK on blocker severities only.

---

## 5. Security & Zero Retention

- **In-Memory AST Parsing**: Source code is processed in-memory only and never written to disk or git repositories.
- **Line References Only**: Findings carry file names, line ranges, rule IDs, and suggested fixes — **never the matched source line**.
- **SHA-256 & EIP-191 Integrity**: All reports carry a canonical SHA-256 digest signed via EIP-191 secp256k1 signature.
- **Bounded Artifact Cache**: Artifacts are stored in a bounded in-memory LRU with a 10-minute TTL.
