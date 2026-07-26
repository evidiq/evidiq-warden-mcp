import type Parser from "web-tree-sitter";
import type { SupportedLanguage } from "../parse.js";

export type RuleMatch = {
  ruleId: string;
  family: "injection" | "reliability" | "hygiene" | "structure";
  severity: "blocker" | "high" | "medium" | "low" | "info";
  line: number;
  endLine: number;
  cwe?: string;
  why: string;
  fix: string;
  heuristic?: boolean;
};

export type RuleChecker = (
  file: string,
  language: SupportedLanguage,
  tree: Parser.Tree,
  sourceCode: string
) => RuleMatch[];

export function walkAst(
  node: Parser.SyntaxNode,
  callback: (node: Parser.SyntaxNode) => void
): void {
  callback(node);
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) walkAst(child, callback);
  }
}

export function getNodeText(node: Parser.SyntaxNode, sourceCode: string): string {
  return sourceCode.slice(node.startIndex, node.endIndex);
}
