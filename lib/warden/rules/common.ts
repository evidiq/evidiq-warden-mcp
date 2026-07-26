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

/**
 * Is this argument a fixed command string the caller cannot influence?
 *
 * Only a plain literal — or a template with no substitutions — counts. Anything
 * else (an identifier, a call, a concatenation, an f-string) is caller-controlled
 * as far as a single-file rule can tell, and a shell sink fed by it is a finding.
 *
 * The first version of the shell rules required a template literal or a binary
 * expression, which meant the most dangerous and most common shape of all —
 * `execSync(cmd)` / `subprocess.run(cmd, shell=True)`, a bare variable straight
 * from a caller — produced no finding at all.
 */
export function isFixedCommandArg(
  node: Parser.SyntaxNode,
  sourceCode: string
): boolean {
  const text = getNodeText(node, sourceCode).trim();

  if (node.type === "template_string") {
    // A substitution makes it dynamic; without one it is just a literal.
    return !node.descendantsOfType(["template_substitution"]).length;
  }

  if (node.type === "string" || node.type === "concatenated_string") {
    // Python f-strings, %-formatting and .format() are dynamic despite being
    // string nodes.
    if (/^[a-zA-Z]*f["']/.test(text)) return false;
    if (node.descendantsOfType(["interpolation"]).length > 0) return false;
    return true;
  }

  return false;
}
