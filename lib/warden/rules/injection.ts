import type Parser from "web-tree-sitter";
import type { SupportedLanguage } from "../parse.js";
import { walkAst, getNodeText, type RuleMatch } from "./common.js";

export function checkInjectionRules(
  file: string,
  language: SupportedLanguage,
  tree: Parser.Tree,
  sourceCode: string
): RuleMatch[] {
  const matches: RuleMatch[] = [];

  walkAst(tree.rootNode, (node) => {
    const text = getNodeText(node, sourceCode);
    const startLine = node.startPosition.row + 1;
    const endLine = node.endPosition.row + 1;

    // 1. EVAL_DYNAMIC_CODE
    if (language === "typescript" || language === "tsx" || language === "javascript") {
      if (node.type === "call_expression") {
        const fnNode = node.childForFieldName("function") || node.child(0);
        if (fnNode) {
          const fnName = getNodeText(fnNode, sourceCode).trim();
          if (fnName === "eval" || fnName === "vm.runInNewContext" || fnName === "vm.runInThisContext") {
            const args = node.childForFieldName("arguments");
            if (args && args.namedChildCount > 0) {
              const argText = getNodeText(args.namedChild(0)!, sourceCode);
              if (!isLiteral(args.namedChild(0)!, language, sourceCode)) {
                matches.push({
                  ruleId: "EVAL_DYNAMIC_CODE",
                  family: "injection",
                  severity: "blocker",
                  line: startLine,
                  endLine,
                  cwe: "CWE-95",
                  why: "Evaluating dynamic string input as code can lead to arbitrary code execution.",
                  fix: "Avoid eval(), new Function(), or exec() on dynamic input. Use safe data parsing or static dispatch.",
                });
              }
            }
          }
        }
      } else if (node.type === "new_expression") {
        const constructorNode = node.childForFieldName("constructor") || node.child(0);
        if (constructorNode && getNodeText(constructorNode, sourceCode).trim() === "Function") {
          matches.push({
            ruleId: "EVAL_DYNAMIC_CODE",
            family: "injection",
            severity: "blocker",
            line: startLine,
            endLine,
            cwe: "CWE-95",
            why: "new Function(...) constructs code dynamically at runtime.",
            fix: "Avoid new Function() with dynamic argument strings.",
          });
        }
      }
    } else if (language === "python") {
      if (node.type === "call") {
        const fnNode = node.childForFieldName("function") || node.child(0);
        if (fnNode) {
          const fnName = getNodeText(fnNode, sourceCode).trim();
          if (fnName === "eval" || fnName === "exec") {
            const args = node.childForFieldName("arguments");
            if (args && args.namedChildCount > 0) {
              matches.push({
                ruleId: "EVAL_DYNAMIC_CODE",
                family: "injection",
                severity: "blocker",
                line: startLine,
                endLine,
                cwe: "CWE-95",
                why: "Evaluating dynamic string input as Python code enables arbitrary execution.",
                fix: "Avoid eval() or exec() on untrusted user input.",
              });
            }
          }
        }
      }
    }

    // 2. SHELL_INTERPOLATION
    if (language === "typescript" || language === "tsx" || language === "javascript") {
      if (node.type === "call_expression") {
        const fnNode = node.childForFieldName("function") || node.child(0);
        if (fnNode) {
          const fnName = getNodeText(fnNode, sourceCode).trim();
          if (
            fnName === "exec" ||
            fnName === "execSync" ||
            fnName.endsWith(".exec") ||
            fnName.endsWith(".execSync") ||
            fnName === "child_process.exec"
          ) {
            const args = node.childForFieldName("arguments");
            if (args && args.namedChildCount > 0) {
              const firstArg = args.namedChild(0)!;
              if (firstArg.type === "template_string" || firstArg.type === "binary_expression") {
                matches.push({
                  ruleId: "SHELL_INTERPOLATION",
                  family: "injection",
                  severity: "blocker",
                  line: startLine,
                  endLine,
                  cwe: "CWE-78",
                  why: "Passing interpolated strings into a shell command enables command injection.",
                  fix: "Use execFile or spawn with an explicit array of argument strings instead of shell command concatenation.",
                });
              }
            }
          }
        }
      }
    } else if (language === "python") {
      if (node.type === "call") {
        const fnNode = node.childForFieldName("function") || node.child(0);
        if (fnNode) {
          const fnName = getNodeText(fnNode, sourceCode).trim();
          if (
            fnName === "os.system" ||
            fnName === "os.popen" ||
            fnName.startsWith("subprocess.")
          ) {
            const args = node.childForFieldName("arguments");
            if (args && args.namedChildCount > 0) {
              const argStr = getNodeText(args, sourceCode);
              if (argStr.includes("shell=True") || fnName === "os.system") {
                const firstArg = args.namedChild(0)!;
                if (firstArg.type === "string" || firstArg.type === "binary_operator" || firstArg.type === "format_specifier") {
                  const argText = getNodeText(firstArg, sourceCode);
                  if (argText.startsWith('f"') || argText.startsWith("f'") || argText.includes("%") || argText.includes(".format(")) {
                    matches.push({
                      ruleId: "SHELL_INTERPOLATION",
                      family: "injection",
                      severity: "blocker",
                      line: startLine,
                      endLine,
                      cwe: "CWE-78",
                      why: "Passing formatted/interpolated strings to shell execution enables command injection.",
                      fix: "Pass arguments as a list to subprocess.run(..., shell=False).",
                    });
                  }
                }
              }
            }
          }
        }
      }
    }

    // 3. SQL_STRING_BUILD
    if (
      (node.type === "template_string" || node.type === "binary_expression" || node.type === "string") &&
      !isInsideComment(node)
    ) {
      if (text.match(/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/i)) {
        if (language === "typescript" || language === "tsx" || language === "javascript") {
          if (node.type === "template_string" && node.childCount > 2) {
            matches.push({
              ruleId: "SQL_STRING_BUILD",
              family: "injection",
              severity: "blocker",
              line: startLine,
              endLine,
              cwe: "CWE-89",
              why: "Constructing SQL queries via template string interpolation enables SQL injection.",
              fix: "Use parameterized queries or prepared statements with parameter placeholders ($1, ?).",
            });
          } else if (node.type === "binary_expression" && text.includes("+")) {
            matches.push({
              ruleId: "SQL_STRING_BUILD",
              family: "injection",
              severity: "blocker",
              line: startLine,
              endLine,
              cwe: "CWE-89",
              why: "Constructing SQL queries via string concatenation enables SQL injection.",
              fix: "Use parameterized queries or ORM query builders.",
            });
          }
        } else if (language === "python") {
          if (node.type === "string" && (text.startsWith('f"') || text.startsWith("f'") || text.includes("%"))) {
            matches.push({
              ruleId: "SQL_STRING_BUILD",
              family: "injection",
              severity: "blocker",
              line: startLine,
              endLine,
              cwe: "CWE-89",
              why: "Constructing SQL queries via f-strings or % formatting enables SQL injection.",
              fix: "Use parameterized query placeholders (%s, :1) in db.execute(query, params).",
            });
          }
        }
      }
    }

    // 4. PATH_FROM_INPUT
    if (node.type === "call_expression" || node.type === "call") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (
          fnName.startsWith("fs.") ||
          fnName === "readFile" ||
          fnName === "readFileSync" ||
          fnName === "writeFile" ||
          fnName === "writeFileSync" ||
          fnName === "open"
        ) {
          const args = node.childForFieldName("arguments");
          if (args && args.namedChildCount > 0) {
            const firstArg = args.namedChild(0)!;
            const argText = getNodeText(firstArg, sourceCode);
            if (
              firstArg.type === "binary_expression" ||
              firstArg.type === "template_string" ||
              (language === "python" && (argText.startsWith('f"') || argText.startsWith("f'")))
            ) {
              if (!sourceCode.includes("path.resolve") && !sourceCode.includes("relative") && !sourceCode.includes("containment")) {
                matches.push({
                  ruleId: "PATH_FROM_INPUT",
                  family: "injection",
                  severity: "high",
                  line: startLine,
                  endLine,
                  cwe: "CWE-22",
                  why: "Joining file system paths with unvalidated user input creates path traversal risk.",
                  fix: "Sanitize path inputs or verify path containment using path.resolve() / path.relative() check.",
                });
              }
            }
          }
        }
      }
    }

    // 5. URL_FROM_INPUT
    if (node.type === "call_expression" || node.type === "call") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (
          fnName === "fetch" ||
          fnName === "axios" ||
          fnName.startsWith("axios.") ||
          fnName.startsWith("requests.") ||
          fnName === "http.get" ||
          fnName === "https.get"
        ) {
          const args = node.childForFieldName("arguments");
          if (args && args.namedChildCount > 0) {
            const firstArg = args.namedChild(0)!;
            if (!isLiteral(firstArg, language, sourceCode)) {
              matches.push({
                ruleId: "URL_FROM_INPUT",
                family: "injection",
                severity: "medium",
                line: startLine,
                endLine,
                cwe: "CWE-918",
                why: "Constructing outbound HTTP requests from non-literal URL inputs creates Server-Side Request Forgery (SSRF) risk.",
                fix: "Validate URL schemes and hostname allowlists before initiating outbound requests.",
                heuristic: true,
              });
            }
          }
        }
      }
    }

    // 6. UNSAFE_DESERIALIZE
    if (node.type === "call_expression" || node.type === "call") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (
          fnName === "pickle.loads" ||
          fnName === "pickle.load" ||
          fnName === "yaml.load" ||
          fnName === "marshal.loads"
        ) {
          const args = node.childForFieldName("arguments");
          const argsText = args ? getNodeText(args, sourceCode) : "";
          if (fnName === "yaml.load" && argsText.includes("Loader=SafeLoader")) {
            // safe
          } else {
            matches.push({
              ruleId: "UNSAFE_DESERIALIZE",
              family: "injection",
              severity: "blocker",
              line: startLine,
              endLine,
              cwe: "CWE-502",
              why: "Deserializing untrusted data with pickle or unsafe yaml.load enables arbitrary code execution.",
              fix: "Use yaml.safe_load, json.loads, or safe data interchange formats.",
            });
          }
        }
      }
    }
  });

  return matches;
}

function isLiteral(node: Parser.SyntaxNode, language: SupportedLanguage, sourceCode: string): boolean {
  if (node.type === "string" || node.type === "number" || node.type === "true" || node.type === "false") {
    return true;
  }
  if (node.type === "template_string" && node.childCount <= 2) {
    return true;
  }
  return false;
}

function isInsideComment(node: Parser.SyntaxNode): boolean {
  let curr: Parser.SyntaxNode | null = node;
  while (curr) {
    if (curr.type === "comment" || curr.type === "line_comment" || curr.type === "block_comment") {
      return true;
    }
    curr = curr.parent;
  }
  return false;
}
