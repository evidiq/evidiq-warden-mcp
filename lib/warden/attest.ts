import { createHash } from "crypto";
import { privateKeyToAccount } from "viem/accounts";
import { anchorBestEffort } from "../og/storage.js";
import type { ReviewReport } from "./report.js";

export type Attestation = {
  attestationId: string;
  engine: string;
  timestamp: string;
  contentHash: string;
  commitSha?: string;
  verdict: string;
  policy: string;
  reportDigest: string;
  anchor: {
    storageRoot?: string;
    storageTx?: string;
    note?: string;
  } | null;
  signature: string;
  signer: string;
};

export async function createReviewAttestation(params: {
  report: ReviewReport;
  commitSha?: string;
  signerPrivateKey?: string;
}): Promise<Attestation> {
  const engine = "EVIDIQ-Warden/1.0";
  const timestamp = new Date().toISOString();
  const reportDigest = params.report.integrity.digest;
  const contentHash = params.report.input.sha256;
  const verdict = params.report.verdict;
  const policy = params.report.policy;

  // No hardcoded fallback signer: see lib/warden/report.ts. An attestation is
  // nothing but its signature, so signing with a key from a public repository
  // would make the whole tool a decoration.
  const rawKey = params.signerPrivateKey ?? process.env.WARDEN_SIGNER_PRIVATE_KEY?.trim();
  if (!rawKey) {
    throw new Error(
      "attest_review requires a configured signer: WARDEN_SIGNER_PRIVATE_KEY is not set. " +
        "An unsigned attestation would attest to nothing."
    );
  }

  const formattedKey = (rawKey.startsWith("0x") || rawKey.startsWith("0X") ? rawKey : "0x" + rawKey) as `0x${string}`;
  const account = privateKeyToAccount(formattedKey);

  const payloadToSign = JSON.stringify({
    engine,
    timestamp,
    contentHash,
    commitSha: params.commitSha,
    verdict,
    policy,
    reportDigest,
  });

  const signature = await account.signMessage({ message: payloadToSign });

  const attestationId = `att_${createHash("sha256").update(signature).digest("hex").slice(0, 16)}`;

  // Best-effort 0G digest anchoring
  let anchor = null;
  try {
    const ogRes = await anchorBestEffort({ reportDigest, contentHash, verdict, attestationId }, `attestation_${attestationId}.json`);
    if (ogRes.storageRoot || ogRes.storageTx || ogRes.storageNote) {
      anchor = {
        storageRoot: ogRes.storageRoot,
        storageTx: ogRes.storageTx,
        note: ogRes.storageNote,
      };
    }
  } catch (err: any) {
    anchor = { note: `0G anchor error: ${err?.message || err}` };
  }

  return {
    attestationId,
    engine,
    timestamp,
    contentHash,
    commitSha: params.commitSha,
    verdict,
    policy,
    reportDigest,
    anchor,
    signature,
    signer: account.address,
  };
}
