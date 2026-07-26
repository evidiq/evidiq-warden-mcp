import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import type { Finding } from "./engine.js";

export type PolicyVerdict = "PASS" | "REVIEW" | "BLOCK";

export type PolicyProfile = {
  id: string;
  version: string;
  description: string;
  rules: {
    blockOnFamilies?: string[];
    reviewOnFamilies?: string[];
    blockOnSeverities?: string[];
    reviewOnSeverities?: string[];
    thresholds: {
      complexity: number;
      nesting: number;
      functionLength: number;
      maxParams: number;
    };
  };
};

const policyCache = new Map<string, PolicyProfile>();

function getPoliciesDir(): string {
  const custom = process.env.WARDEN_POLICIES_DIR?.trim();
  if (custom && existsSync(custom)) return custom;
  const inProject = resolve(process.cwd(), "data/policies");
  if (existsSync(inProject)) return inProject;
  const distParent = resolve(process.cwd(), "../data/policies");
  if (existsSync(distParent)) return distParent;
  return inProject;
}

export function loadPolicyProfile(policyId: string = "agent-written-code"): PolicyProfile {
  if (policyCache.has(policyId)) return policyCache.get(policyId)!;

  const policiesDir = getPoliciesDir();
  const filePath = join(policiesDir, `${policyId}.json`);

  if (!existsSync(filePath)) {
    // Fallback to agent-written-code default profile
    const defaultPath = join(policiesDir, "agent-written-code.json");
    if (existsSync(defaultPath)) {
      const content = readFileSync(defaultPath, "utf-8");
      const profile = JSON.parse(content) as PolicyProfile;
      policyCache.set(policyId, profile);
      return profile;
    }
    return {
      id: "agent-written-code",
      version: "1.0.0",
      description: "Default policy profile",
      rules: {
        blockOnFamilies: ["injection"],
        reviewOnFamilies: ["reliability", "hygiene", "structure"],
        thresholds: { complexity: 25, nesting: 6, functionLength: 120, maxParams: 7 },
      },
    };
  }

  const content = readFileSync(filePath, "utf-8");
  const profile = JSON.parse(content) as PolicyProfile;
  policyCache.set(policyId, profile);
  return profile;
}

export function evaluateVerdict(
  findings: Finding[],
  policy: PolicyProfile
): { verdict: PolicyVerdict; violations: Finding[] } {
  const violations: Finding[] = [];
  let isBlock = false;
  let isReview = false;

  for (const f of findings) {
    if (f.severity === "blocker") {
      isBlock = true;
      violations.push(f);
    } else if (policy.rules.blockOnFamilies?.includes(f.family)) {
      isBlock = true;
      violations.push(f);
    } else if (policy.rules.blockOnSeverities?.includes(f.severity)) {
      isBlock = true;
      violations.push(f);
    } else if (policy.rules.reviewOnFamilies?.includes(f.family) || policy.rules.reviewOnSeverities?.includes(f.severity)) {
      isReview = true;
    }
  }

  if (isBlock) return { verdict: "BLOCK", violations };
  if (isReview || findings.length > 0) return { verdict: "REVIEW", violations: [] };
  return { verdict: "PASS", violations: [] };
}
