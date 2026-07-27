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
    // Optional: a report is signed only when a signer key is configured.
    signature?: string;
    signer?: string;
    signed?: false;
    note?: string;
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

  // No hardcoded fallback signer. This file is in a public repository, so a key
  // literal here is a key anyone can sign with — and a signature anyone can
  // produce proves nothing while looking exactly like proof.
  const rawKey = params.signerPrivateKey ?? process.env.WARDEN_SIGNER_PRIVATE_KEY?.trim();

  let signature: string | undefined;
  let signer: string | undefined;
  if (rawKey) {
    const formattedKey = (rawKey.startsWith("0x") || rawKey.startsWith("0X")
      ? rawKey
      : "0x" + rawKey) as `0x${string}`;
    try {
      const account = privateKeyToAccount(formattedKey);
      signature = await account.signMessage({ message: digest });
      signer = account.address;
    } catch (err: any) {
      console.warn(
        "[warden] WARDEN_SIGNER_PRIVATE_KEY is set but unusable — report returned UNSIGNED:",
        err?.message || err
      );
    }
  }

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
      ...(signature && signer
        ? { signature, signer }
        : { signed: false, note: "No signer configured; the digest is verifiable, the origin is not." }),
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

    // An unsigned report is neither invalid nor verified. Report which question
    // was actually answered instead of throwing on the missing signature.
    if (!report.integrity.signature || !report.integrity.signer) {
      return {
        valid: false,
        digestMatch,
        signatureValid: false,
        error: digestMatch
          ? "Report carries no signature: the digest matches, but the origin cannot be attributed."
          : "Report carries no signature, and the digest does not match either.",
      };
    }

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
