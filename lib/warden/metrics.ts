import type Parser from "web-tree-sitter";
import type { SupportedLanguage } from "./parse.js";
import { walkAst, getNodeText, type RuleMatch } from "./rules/common.js";

export type FunctionMetrics = {
  name: string;
  line: number;
  endLine: number;
  cyclomaticComplexity: number;
  nestingDepth: number;
  lineCount: number;
  paramCount: number;
};

export type ComplexityReport = {
  file: string;
  language: SupportedLanguage | "unsupported";
  functions: FunctionMetrics[];
  duplicateBlocks: Array<{
    lines: [number, number];
    duplicateOf: [number, number];
    lineCount: number;
  }>;
};

export type MetricThresholds = {
  complexity: number;
  nesting: number;
  functionLength: number;
  maxParams: number;
};

export const DEFAULT_THRESHOLDS: MetricThresholds = {
  complexity: 25,
  nesting: 6,
  functionLength: 120,
  maxParams: 7,
};

export function analyzeFileMetrics(
  file: string,
  language: SupportedLanguage,
  tree: Parser.Tree,
  sourceCode: string
): ComplexityReport {
  const functions: FunctionMetrics[] = [];
  const lines = sourceCode.split("\n");

  walkAst(tree.rootNode, (node) => {
    if (isFunctionNode(node, language)) {
      const fnName = getFunctionName(node, sourceCode);
      const startLine = node.startPosition.row + 1;
      const endLine = node.endPosition.row + 1;
      const lineCount = endLine - startLine + 1;
      const paramCount = countParameters(node, language);
      const cyclomaticComplexity = computeComplexity(node);
      const nestingDepth = computeNestingDepth(node);

      functions.push({
        name: fnName,
        line: startLine,
        endLine,
        cyclomaticComplexity,
        nestingDepth,
        lineCount,
        paramCount,
      });
    }
  });

  const duplicateBlocks = findDuplicateBlocks(lines);

  return {
    file,
    language,
    functions,
    duplicateBlocks,
  };
}

export function checkStructureRules(
  file: string,
  language: SupportedLanguage,
  tree: Parser.Tree,
  sourceCode: string,
  thresholds: MetricThresholds = DEFAULT_THRESHOLDS
): RuleMatch[] {
  const report = analyzeFileMetrics(file, language, tree, sourceCode);
  const matches: RuleMatch[] = [];

  for (const fn of report.functions) {
    if (fn.cyclomaticComplexity > thresholds.complexity) {
      matches.push({
        ruleId: "COMPLEXITY_EXCEEDED",
        family: "structure",
        severity: "medium",
        line: fn.line,
        endLine: fn.endLine,
        cwe: "CWE-1075",
        why: `Function '${fn.name}' cyclomatic complexity (${fn.cyclomaticComplexity}) exceeds threshold (${thresholds.complexity}).`,
        fix: "Refactor complex conditional logic into smaller helper functions.",
      });
    }

    if (fn.nestingDepth > thresholds.nesting) {
      matches.push({
        ruleId: "NESTING_EXCEEDED",
        family: "structure",
        severity: "medium",
        line: fn.line,
        endLine: fn.endLine,
        cwe: "CWE-1075",
        why: `Function '${fn.name}' nesting depth (${fn.nestingDepth}) exceeds threshold (${thresholds.nesting}).`,
        fix: "Use guard clauses and early returns to flatten nested blocks.",
      });
    }

    if (fn.lineCount > thresholds.functionLength) {
      matches.push({
        ruleId: "FUNCTION_TOO_LONG",
        family: "structure",
        severity: "low",
        line: fn.line,
        endLine: fn.endLine,
        cwe: "CWE-1075",
        why: `Function '${fn.name}' length (${fn.lineCount} lines) exceeds threshold (${thresholds.functionLength}).`,
        fix: "Split long function into cohesive single-responsibility functions.",
      });
    }

    if (fn.paramCount > thresholds.maxParams) {
      matches.push({
        ruleId: "TOO_MANY_PARAMS",
        family: "structure",
        severity: "low",
        line: fn.line,
        endLine: fn.endLine,
        cwe: "CWE-1075",
        why: `Function '${fn.name}' parameter count (${fn.paramCount}) exceeds threshold (${thresholds.maxParams}).`,
        fix: "Group related parameters into an options object or data structure.",
      });
    }
  }

  for (const dup of report.duplicateBlocks) {
    matches.push({
      ruleId: "DUPLICATE_BLOCK",
      family: "structure",
      severity: "medium",
      line: dup.lines[0],
      endLine: dup.lines[1],
      cwe: "CWE-1041",
      why: `Identical block of ${dup.lineCount} lines detected (duplicate of lines ${dup.duplicateOf[0]}-${dup.duplicateOf[1]}).`,
      fix: "Extract duplicate logic into a shared helper function.",
    });
  }

  return matches;
}

function isFunctionNode(node: Parser.SyntaxNode, language: SupportedLanguage): boolean {
  if (language === "typescript" || language === "javascript" || language === "tsx") {
    return (
      node.type === "function_declaration" ||
      node.type === "function_expression" ||
      node.type === "arrow_function" ||
      node.type === "method_definition"
    );
  } else if (language === "python") {
    return node.type === "function_definition";
  }
  return false;
}

function getFunctionName(node: Parser.SyntaxNode, sourceCode: string): string {
  const nameNode = node.childForFieldName("name");
  if (nameNode) return getNodeText(nameNode, sourceCode).trim();
  const parent = node.parent;
  if (parent && parent.type === "variable_declarator") {
    const name = parent.childForFieldName("name");
    if (name) return getNodeText(name, sourceCode).trim();
  }
  return "anonymous";
}

function countParameters(node: Parser.SyntaxNode, language: SupportedLanguage): number {
  const params = node.childForFieldName("parameters") || node.childForFieldName("params");
  if (!params) return 0;
  return params.namedChildCount;
}

function computeComplexity(node: Parser.SyntaxNode): number {
  let complexity = 1;
  walkAst(node, (child) => {
    const t = child.type;
    if (
      t === "if_statement" ||
      t === "if_clause" ||
      t === "elif_clause" ||
      t === "while_statement" ||
      t === "for_statement" ||
      t === "for_in_statement" ||
      t === "catch_clause" ||
      t === "except_clause" ||
      t === "case_clause" ||
      t === "binary_expression" && (child.text.includes("&&") || child.text.includes("||") || child.text.includes("??"))
    ) {
      complexity++;
    }
  });
  return complexity;
}

function computeNestingDepth(node: Parser.SyntaxNode): number {
  let maxDepth = 0;
  function walk(current: Parser.SyntaxNode, currentDepth: number) {
    if (currentDepth > maxDepth) maxDepth = currentDepth;
    const isControl =
      current.type === "if_statement" ||
      current.type === "while_statement" ||
      current.type === "for_statement" ||
      current.type === "for_in_statement" ||
      current.type === "try_statement";
    const nextDepth = isControl ? currentDepth + 1 : currentDepth;
    for (let i = 0; i < current.childCount; i++) {
      const child = current.child(i);
      if (child) walk(child, nextDepth);
    }
  }
  walk(node, 0);
  return maxDepth;
}

function findDuplicateBlocks(lines: string[]): Array<{
  lines: [number, number];
  duplicateOf: [number, number];
  lineCount: number;
}> {
  const duplicates: Array<{
    lines: [number, number];
    duplicateOf: [number, number];
    lineCount: number;
  }> = [];

  const minLines = 6;
  const normalized = lines.map((l) => l.trim());
  const seenBlocks = new Map<string, number>();

  for (let i = 0; i <= normalized.length - minLines; i++) {
    const chunk = normalized.slice(i, i + minLines).filter((l) => l.length > 0);
    if (chunk.length < minLines) continue;
    const hash = chunk.join("\n");
    if (seenBlocks.has(hash)) {
      const prevLine = seenBlocks.get(hash)!;
      if (i + 1 > prevLine + minLines) {
        duplicates.push({
          lines: [i + 1, i + minLines],
          duplicateOf: [prevLine, prevLine + minLines - 1],
          lineCount: minLines,
        });
      }
    } else {
      seenBlocks.set(hash, i + 1);
    }
  }

  return duplicates;
}
