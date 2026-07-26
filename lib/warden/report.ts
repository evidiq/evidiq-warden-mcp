import { createHash } from "crypto";
import { privateKeyToAccount } from "viem/accounts";
import { verifyMessage } from "viem";
import type { Finding } from "./engine.js";
import type { PolicyVerdict } from "./policies.js";

export type ReviewReport = {
  engine: string;
  ruleSetVersion: string;
  policy: string;
  input: {
    files: number;
    bytes: number;
    sha256: string;
  };
  languages: Record<string, number>;
  findings: Finding[];
  counts: {
    blocker: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  verdict: PolicyVerdict;
  integrity: {
    algorithm: "SHA-256";
    digest: string;
    signature: string;
    signer: string;
  };
};

function hashText(text: string): string {
  return createHash("sha256").update(text, "utf-8").digest("hex");
}

export async function createSignedReviewReport(params: {
  filesCount: number;
  totalBytes: number;
  combinedContentHash: string;
  languages: Record<string, number>;
  findings: Finding[];
  counts: { blocker: number; high: number; medium: number; low: number; info: number };
  verdict: PolicyVerdict;
  policy: string;
  signerPrivateKey?: string;
}): Promise<ReviewReport> {
  const engine = "EVIDIQ-Warden/1.0";
  const ruleSetVersion = "1.0.0";
  const policy = params.policy;

  const canonicalEnvelope = JSON.stringify({
    engine,
    ruleSetVersion,
    policy,
    input: {
      files: params.filesCount,
      bytes: params.totalBytes,
      sha256: params.combinedContentHash,
    },
    languages: params.languages,
    findings: params.findings,
    counts: params.counts,
    verdict: params.verdict,
  });

  const digest = hashText(canonicalEnvelope);

  const rawKey =
    params.signerPrivateKey ??
    process.env.WARDEN_SIGNER_PRIVATE_KEY ??
    "0x710003befbfe8dbb063ed4936c9fb94a012987e2720fa46f36202d1190e05c66";

  const formattedKey = (rawKey.startsWith("0x") || rawKey.startsWith("0X") ? rawKey : "0x" + rawKey) as `0x${string}`;

  let account;
  try {
    account = privateKeyToAccount(formattedKey);
  } catch (err: any) {
    throw new Error(`Invalid WARDEN_SIGNER_PRIVATE_KEY: ${err?.message || err}`);
  }

  const signature = await account.signMessage({ message: digest });

  return {
    engine,
    ruleSetVersion,
    policy,
    input: {
      files: params.filesCount,
      bytes: params.totalBytes,
      sha256: params.combinedContentHash,
    },
    languages: params.languages,
    findings: params.findings,
    counts: params.counts,
    verdict: params.verdict,
    integrity: {
      algorithm: "SHA-256",
      digest,
      signature,
      signer: account.address,
    },
  };
}

export async function verifyReviewReport(report: ReviewReport): Promise<{
  valid: boolean;
  digestMatch: boolean;
  signatureValid: boolean;
  error?: string;
}> {
  try {
    const canonicalEnvelope = JSON.stringify({
      engine: report.engine,
      ruleSetVersion: report.ruleSetVersion,
      policy: report.policy,
      input: report.input,
      languages: report.languages,
      findings: report.findings,
      counts: report.counts,
      verdict: report.verdict,
    });

    const expectedDigest = hashText(canonicalEnvelope);
    const digestMatch = expectedDigest === report.integrity.digest;

    const signatureValid = await verifyMessage({
      address: report.integrity.signer as `0x${string}`,
      message: report.integrity.digest,
      signature: report.integrity.signature as `0x${string}`,
    });

    return {
      valid: digestMatch && signatureValid,
      digestMatch,
      signatureValid,
    };
  } catch (err: any) {
    return {
      valid: false,
      digestMatch: false,
      signatureValid: false,
      error: err.message,
    };
  }
}
