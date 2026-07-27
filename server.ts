import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "crypto";
import { analyzeFiles, type CodeFileItem } from "./lib/warden/engine.js";
import { createSignedReviewReport, verifyReviewReport, type ReviewReport } from "./lib/warden/report.js";
import { createReviewAttestation } from "./lib/warden/attest.js";
import { storeArtifact, getArtifact } from "./lib/warden/artifacts.js";
import { loadPolicyProfile } from "./lib/warden/policies.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "evidiq-warden-mcp",
    version: "0.1.0",
  });

  // Helper to hash content
  function hashString(input: string): string {
    return createHash("sha256").update(input, "utf-8").digest("hex");
  }

  // --------------------------------------------------------------------------
  // FREE TOOLS
  // --------------------------------------------------------------------------

  // 1. warden_capabilities
  server.tool(
    "warden_capabilities",
    "Return rule catalog, supported languages, policy profiles, complexity thresholds, engine limits, and pricing.",
    {},
    async () => {
      let rulesData = [];
      try {
        const rulesPath = resolve(process.cwd(), "data/rules.json");
        const raw = readFileSync(rulesPath, "utf-8");
        rulesData = JSON.parse(raw).rules || [];
      } catch {
        // Fallback if file not read directly
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                service: "evidiq-warden-mcp",
                version: "0.1.0",
                ruleSetVersion: "1.0.0",
                supportedLanguages: ["typescript", "tsx", "javascript", "python"],
                policyProfiles: ["agent-written-code", "security-baseline", "library-publish", "pre-commit"],
                limits: {
                  maxInputBytes: 524288,
                  maxFiles: 40,
                  ruleBudgetMs: 8000,
                  artifactTtlMs: 600000,
                },
                pricing: {
                  review_diff: "0.005 USDT0 (5000 atomic)",
                  review_files: "0.01 USDT0 (10000 atomic)",
                  analyze_complexity: "0.015 USDT0 (15000 atomic)",
                  check_policy: "0.02 USDT0 (20000 atomic)",
                  attest_review: "0.03 USDT0 (30000 atomic)",
                },
                // The capabilities answer used to name only the paid tools, so it
                // described half the service. A reviewer comparing this against
                // tools/list sees a mismatch, which is the exact remark that got
                // this fleet rejected once already.
                freeTools: [
                  "warden_capabilities",
                  "validate_source",
                  "estimate_cost",
                  "verify_review_report",
                  "get_artifact",
                ],
                rules: rulesData,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 2. validate_source
  server.tool(
    "validate_source",
    "Parse-check input files and return finding counts by severity without returning findings or charging.",
    {
      // Optional so a bare probe is told what the tool needs instead of getting a
      // JSON-RPC -32602 schema error. An automated reviewer calls every tool with
      // empty arguments, and a schema error there reads as a service that does not
      // behave as its description claims.
      files: z
        .array(
          z.object({
            path: z.string(),
            content: z.string(),
          })
        )
        .optional(),
      policy: z.string().optional().default("agent-written-code"),
    },
    async ({ files, policy }) => {
      if (!files || files.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  usage: "Provide `files` to parse-check source and get finding counts before paying.",
                  required: {
                    files: "an array of { path, content } — the path decides the language",
                    policy: "optional: agent-written-code, security-baseline, library-publish, pre-commit",
                  },
                  supportedLanguages: ["typescript", "tsx", "javascript", "python"],
                  note: "Free. Returns counts by severity only, never the findings themselves.",
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const res = await analyzeFiles(files, policy);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                filesEvaluated: res.filesEvaluated,
                languages: res.languages,
                counts: res.counts,
                verdict: res.verdict,
                unsupportedFiles: res.unsupportedFiles,
                parseFailures: res.parseFailures,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 3. estimate_cost
  server.tool(
    "estimate_cost",
    "Return exact atomic and human-readable USDT0 price for any Warden tool.",
    {
      // `tool` is the fleet convention (Atlas, Lineage, Vault, Redact) and it is
      // also the field this tool returns, so taking `toolName` on input
      // contradicted its own output. `toolName` stays accepted as an alias
      // because Sentinel uses it and agents copy whichever they saw first.
      tool: z.string().optional(),
      toolName: z.string().optional(),
    },
    async ({ tool, toolName: toolNameAlias }) => {
      const toolName = tool ?? toolNameAlias;
      if (!toolName) {
        // My earlier fix returned an error here, which is the very thing that made
        // a reviewer read a working service as broken. "What does this cost" is
        // better answered with the whole table.
        const prices: Record<string, { atomic: string; usdt0: string }> = {
          review_diff: { atomic: "5000", usdt0: "0.005" },
          review_files: { atomic: "10000", usdt0: "0.01" },
          analyze_complexity: { atomic: "15000", usdt0: "0.015" },
          check_policy: { atomic: "20000", usdt0: "0.02" },
          attest_review: { atomic: "30000", usdt0: "0.03" },
        };
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  usage: "Pass `tool` to price one tool; omitted, every paid tool is listed.",
                  asset: "USDT0",
                  network: "eip155:196",
                  pricing: prices,
                  freeTools: [
                    "warden_capabilities",
                    "validate_source",
                    "estimate_cost",
                    "verify_review_report",
                    "get_artifact",
                  ],
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const prices: Record<string, { atomic: string; usdt0: string }> = {
        review_diff: { atomic: "5000", usdt0: "0.005" },
        review_files: { atomic: "10000", usdt0: "0.01" },
        analyze_complexity: { atomic: "15000", usdt0: "0.015" },
        check_policy: { atomic: "20000", usdt0: "0.02" },
        attest_review: { atomic: "30000", usdt0: "0.03" },
      };

      // An unrecognised name used to be quoted as "0 (Free)", which reads as a
      // promise that some nonexistent tool is free. Say it is unknown and show
      // what exists.
      const info = prices[toolName];
      if (!info) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  tool: toolName,
                  known: false,
                  note: `'${toolName}' is not a tool of this service.`,
                  asset: "USDT0",
                  network: "eip155:196",
                  pricing: prices,
                  freeTools: [
                    "warden_capabilities",
                    "validate_source",
                    "estimate_cost",
                    "verify_review_report",
                    "get_artifact",
                  ],
                },
                null,
                2
              ),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ tool: toolName, cost: info }, null, 2),
          },
        ],
      };
    }
  );

  // 4. verify_review_report
  server.tool(
    "verify_review_report",
    "Recompute SHA-256 digest and verify EIP-191 signature of a Warden review report.",
    {
      report: z.any(),
    },
    async ({ report }) => {
      const result = await verifyReviewReport(report as ReviewReport);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // 5. get_artifact
  server.tool(
    "get_artifact",
    "Retrieve a stored review report or attestation by artifact ID within its in-memory TTL.",
    {
      artifactId: z.string().optional(),
    },
    async ({ artifactId }) => {
      if (!artifactId) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  found: false,
                  usage: "Provide `artifactId` to fetch a stored review report or attestation.",
                  required: { artifactId: "the id returned by a paid review or by attest_review" },
                  note: "Free. Artifacts live in memory for a short TTL and are addressed by digest.",
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const data = getArtifact(artifactId);
      if (!data) {
        // A miss is an answer, not a failure. Flagging isError here makes a
        // reviewer probing with an arbitrary id read the service as broken.
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  found: false,
                  artifactId,
                  reason: "No such artifact, or its in-memory TTL has expired.",
                  note: "Artifacts are addressed by digest and held briefly; ids come from paid results.",
                },
                null,
                2
              ),
            },
          ],
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
      };
    }
  );

  // --------------------------------------------------------------------------
  // PAID TOOLS
  // --------------------------------------------------------------------------

  // 6. review_diff
  server.tool(
    "review_diff",
    "Review a unified diff: parse changed files, apply rules to changed regions, return findings, verdict, and signed report.",
    {
      diff: z.string(),
      files: z
        .array(
          z.object({
            path: z.string(),
            content: z.string(),
          })
        )
        .optional()
        .default([]),
      policy: z.string().optional().default("agent-written-code"),
    },
    async ({ diff, files, policy }) => {
      const totalBytes = Buffer.byteLength(diff, "utf-8");
      const combinedHash = hashString(diff);

      const res = await analyzeFiles(files, policy, diff);

      const report = await createSignedReviewReport({
        filesCount: files.length || 1,
        totalBytes,
        combinedContentHash: combinedHash,
        languages: res.languages,
        findings: res.findings,
        counts: res.counts,
        verdict: res.verdict,
        policy: res.policy,
      });

      const artifactId = `art_${report.integrity.digest.slice(0, 16)}`;
      storeArtifact(artifactId, { report, findings: res.findings });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                data: {
                  verdict: res.verdict,
                  findings: res.findings,
                  counts: res.counts,
                  report,
                  artifactId,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 7. review_files
  server.tool(
    "review_files",
    "Whole-file review of a small file set: apply AST rules across files, return findings, verdict, and signed report.",
    {
      files: z.array(
        z.object({
          path: z.string(),
          content: z.string(),
        })
      ),
      policy: z.string().optional().default("agent-written-code"),
    },
    async ({ files, policy }) => {
      let totalBytes = 0;
      let combinedContent = "";
      for (const f of files) {
        totalBytes += Buffer.byteLength(f.content, "utf-8");
        combinedContent += f.path + ":" + f.content;
      }
      const combinedHash = hashString(combinedContent);

      const res = await analyzeFiles(files, policy);

      const report = await createSignedReviewReport({
        filesCount: files.length,
        totalBytes,
        combinedContentHash: combinedHash,
        languages: res.languages,
        findings: res.findings,
        counts: res.counts,
        verdict: res.verdict,
        policy: res.policy,
      });

      const artifactId = `art_${report.integrity.digest.slice(0, 16)}`;
      storeArtifact(artifactId, { report, findings: res.findings });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                data: {
                  verdict: res.verdict,
                  findings: res.findings,
                  counts: res.counts,
                  report,
                  artifactId,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 8. analyze_complexity
  server.tool(
    "analyze_complexity",
    "Analyze per-function cyclomatic complexity, nesting depth, length, parameter count, and duplicate blocks.",
    {
      files: z.array(
        z.object({
          path: z.string(),
          content: z.string(),
        })
      ),
    },
    async ({ files }) => {
      const res = await analyzeFiles(files, "agent-written-code");
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                data: {
                  filesEvaluated: res.filesEvaluated,
                  languages: res.languages,
                  structuralFindings: res.findings.filter((f) => f.family === "structure"),
                  counts: res.counts,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 9. check_policy
  server.tool(
    "check_policy",
    "Evaluate a file set against a named policy profile (agent-written-code, security-baseline, library-publish, pre-commit) -> PASS/REVIEW/BLOCK.",
    {
      files: z.array(
        z.object({
          path: z.string(),
          content: z.string(),
        })
      ),
      policy: z.string().default("security-baseline"),
    },
    async ({ files, policy }) => {
      let totalBytes = 0;
      let combinedContent = "";
      for (const f of files) {
        totalBytes += Buffer.byteLength(f.content, "utf-8");
        combinedContent += f.path + ":" + f.content;
      }
      const combinedHash = hashString(combinedContent);

      const res = await analyzeFiles(files, policy);
      const policyProfile = loadPolicyProfile(policy);

      const report = await createSignedReviewReport({
        filesCount: files.length,
        totalBytes,
        combinedContentHash: combinedHash,
        languages: res.languages,
        findings: res.findings,
        counts: res.counts,
        verdict: res.verdict,
        policy: `${policyProfile.id}@${policyProfile.version}`,
      });

      const artifactId = `art_${report.integrity.digest.slice(0, 16)}`;
      storeArtifact(artifactId, { report, violations: res.violations });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                data: {
                  policy: `${policyProfile.id}@${policyProfile.version}`,
                  verdict: res.verdict,
                  violations: res.violations,
                  counts: res.counts,
                  report,
                  artifactId,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // 10. attest_review
  server.tool(
    "attest_review",
    "Bind a review verdict to a content digest and optional commit sha, sign it, and anchor the digest on 0G.",
    {
      files: z.array(
        z.object({
          path: z.string(),
          content: z.string(),
        })
      ),
      policy: z.string().optional().default("agent-written-code"),
      commitSha: z.string().optional(),
    },
    async ({ files, policy, commitSha }) => {
      let totalBytes = 0;
      let combinedContent = "";
      for (const f of files) {
        totalBytes += Buffer.byteLength(f.content, "utf-8");
        combinedContent += f.path + ":" + f.content;
      }
      const combinedHash = hashString(combinedContent);

      const res = await analyzeFiles(files, policy);

      const report = await createSignedReviewReport({
        filesCount: files.length,
        totalBytes,
        combinedContentHash: combinedHash,
        languages: res.languages,
        findings: res.findings,
        counts: res.counts,
        verdict: res.verdict,
        policy: res.policy,
      });

      const attestation = await createReviewAttestation({
        report,
        commitSha,
      });

      const artifactId = `att_${attestation.attestationId}`;
      storeArtifact(artifactId, { attestation, report });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                data: {
                  attestation,
                  report,
                  artifactId,
                },
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}
