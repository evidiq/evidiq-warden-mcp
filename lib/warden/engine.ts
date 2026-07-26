import type Parser from "web-tree-sitter";
import { parseSource, type SupportedLanguage } from "./parse.js";
import { checkInjectionRules } from "./rules/injection.js";
import { checkReliabilityRules } from "./rules/reliability.js";
import { checkHygieneRules } from "./rules/hygiene.js";
import { checkStructureRules } from "./metrics.js";
import { loadPolicyProfile, evaluateVerdict, type PolicyVerdict, type PolicyProfile } from "./policies.js";
import { parseUnifiedDiff, isLineInDiffChanged } from "./diff.js";

export type RuleSeverity = "blocker" | "high" | "medium" | "low" | "info";
export type RuleFamily = "injection" | "reliability" | "hygiene" | "structure";

export type Finding = {
  rule: string;
  family: RuleFamily;
  severity: RuleSeverity;
  file: string;
  line: number;
  endLine: number;
  context: "changed" | "existing";
  cwe?: string;
  why: string;
  fix: string;
  heuristic?: boolean;
};

export type CodeFileItem = {
  path: string;
  content: string;
};

export type AnalysisResult = {
  ruleSetVersion: string;
  policy: string;
  filesEvaluated: number;
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
  violations: Finding[];
  unsupportedFiles: string[];
  parseFailures: Array<{ file: string; error: string }>;
};

export async function analyzeFiles(
  files: CodeFileItem[],
  policyId: string = "agent-written-code",
  diffText?: string
): Promise<AnalysisResult> {
  const policy = loadPolicyProfile(policyId);
  const rawFindings: Finding[] = [];
  const languages: Record<string, number> = { typescript: 0, tsx: 0, javascript: 0, python: 0, unsupported: 0 };
  const unsupportedFiles: string[] = [];
  const parseFailures: Array<{ file: string; error: string }> = [];

  const diffMap = diffText ? parseUnifiedDiff(diffText) : undefined;

  let effectiveFiles = [...files];
  if (effectiveFiles.length === 0 && diffText && diffMap) {
    for (const [path, diffFile] of diffMap.entries()) {
      if (path) {
        effectiveFiles.push({
          path,
          content: diffFile.postImageContent || "",
        });
      }
    }
  }

  for (const item of effectiveFiles) {
    const parseOut = await parseSource(item.path, item.content);
    languages[parseOut.language] = (languages[parseOut.language] || 0) + 1;

    if (parseOut.language === "unsupported") {
      unsupportedFiles.push(item.path);
      continue;
    }

    if (!parseOut.parsed || !parseOut.tree) {
      parseFailures.push({ file: item.path, error: parseOut.error || "Failed to parse AST" });
      continue;
    }

    const changedLines = diffMap?.get(item.path)?.changedLines;

    // Run all rule checkers
    const matches = [
      ...checkInjectionRules(item.path, parseOut.language, parseOut.tree, item.content),
      ...checkReliabilityRules(item.path, parseOut.language, parseOut.tree, item.content),
      ...checkHygieneRules(item.path, parseOut.language, parseOut.tree, item.content),
      ...checkStructureRules(item.path, parseOut.language, parseOut.tree, item.content, policy.rules.thresholds),
    ];

    for (const m of matches) {
      const isChanged = changedLines ? isLineInDiffChanged(changedLines, m.line, m.endLine) : true;
      rawFindings.push({
        rule: m.ruleId,
        family: m.family,
        severity: m.severity,
        file: item.path,
        line: m.line,
        endLine: m.endLine,
        context: isChanged ? "changed" : "existing",
        cwe: m.cwe,
        why: m.why,
        fix: m.fix,
        heuristic: m.heuristic,
      });
    }
  }

  // Deduplicate findings
  const findings = deduplicateFindings(rawFindings);

  const counts = {
    blocker: findings.filter((f) => f.severity === "blocker").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  const { verdict, violations } = evaluateVerdict(findings, policy);

  return {
    ruleSetVersion: "1.0.0",
    policy: `${policy.id}@${policy.version}`,
    filesEvaluated: effectiveFiles.length,
    languages,
    findings,
    counts,
    verdict,
    violations,
    unsupportedFiles,
    parseFailures,
  };
}

function deduplicateFindings(raw: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const f of raw) {
    const key = `${f.rule}:${f.file}:${f.line}:${f.endLine}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(f);
    }
  }
  return result;
}
