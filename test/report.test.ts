import { describe, it, expect } from "vitest";
import { createSignedReviewReport, verifyReviewReport } from "../lib/warden/report.js";

// A well-known throwaway test key. Production signs with
// WARDEN_SIGNER_PRIVATE_KEY; there is deliberately no fallback key in the source,
// because this repository is public and a signature anyone can produce is not one.
const TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

describe("Warden Signed Review Report Integrity", () => {
  it("creates a signed report and successfully verifies signature round-trip", async () => {
    const report = await createSignedReviewReport({
      signerPrivateKey: TEST_KEY,
      filesCount: 2,
      totalBytes: 1500,
      combinedContentHash: "a1b2c3d4e5f60718293041526374859607182930415263748596071829304152",
      languages: { typescript: 2 },
      findings: [
        {
          rule: "EVAL_DYNAMIC_CODE",
          family: "injection",
          severity: "blocker",
          file: "src/eval.ts",
          line: 12,
          endLine: 12,
          context: "changed",
          cwe: "CWE-95",
          why: "Evaluating dynamic string input as code can lead to arbitrary code execution.",
          fix: "Avoid eval(), new Function(), or exec() on dynamic input.",
        },
      ],
      counts: { blocker: 1, high: 0, medium: 0, low: 0, info: 0 },
      verdict: "BLOCK",
      policy: "agent-written-code@1.0.0",
    });

    expect(report.engine).toBe("EVIDIQ-Warden/1.0");
    expect(report.verdict).toBe("BLOCK");
    expect(report.integrity.signature).toMatch(/^0x/);

    const verification = await verifyReviewReport(report);
    expect(verification.valid).toBe(true);
    expect(verification.digestMatch).toBe(true);
    expect(verification.signatureValid).toBe(true);
  });

  it("prohibits echoing source code content inside report findings", async () => {
    const report = await createSignedReviewReport({
      filesCount: 1,
      totalBytes: 50,
      combinedContentHash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      languages: { typescript: 1 },
      findings: [
        {
          rule: "HARDCODED_CREDENTIAL_SHAPE",
          family: "hygiene",
          severity: "high",
          file: "secret.ts",
          line: 1,
          endLine: 1,
          context: "changed",
          cwe: "CWE-798",
          why: "Hardcoded credential shape detected.",
          fix: "Store credentials in environment variables.",
        },
      ],
      counts: { blocker: 0, high: 1, medium: 0, low: 0, info: 0 },
      verdict: "REVIEW",
      policy: "agent-written-code@1.0.0",
    });

    const jsonText = JSON.stringify(report);
    expect(jsonText).not.includes("AKIAIOSFODNN7EXAMPLE");
    expect(report.findings[0].why).not.includes("AKIAIOSFODNN7EXAMPLE");
  });

  it("returns an UNSIGNED report when no signer is configured, and never invents one", async () => {
    const previous = process.env.WARDEN_SIGNER_PRIVATE_KEY;
    delete process.env.WARDEN_SIGNER_PRIVATE_KEY;
    try {
      const report = await createSignedReviewReport({
        filesCount: 1,
        totalBytes: 10,
        combinedContentHash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        languages: { typescript: 1 },
        findings: [],
        counts: { blocker: 0, high: 0, medium: 0, low: 0, info: 0 },
        verdict: "PASS",
        policy: "agent-written-code@1.0.0",
      });

      expect(report.integrity.signature).toBeUndefined();
      expect(report.integrity.signer).toBeUndefined();

      // The digest still checks out; authenticity does not.
      const verification = await verifyReviewReport(report);
      expect(verification.digestMatch).toBe(true);
      expect(verification.signatureValid).toBe(false);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain("no signature");
    } finally {
      if (previous !== undefined) process.env.WARDEN_SIGNER_PRIVATE_KEY = previous;
    }
  });
});
