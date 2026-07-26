import type Parser from "web-tree-sitter";
import type { SupportedLanguage } from "../parse.js";
import { walkAst, getNodeText, type RuleMatch } from "./common.js";

export function checkReliabilityRules(
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

    // 1. FLOATING_PROMISE
    if ((language === "typescript" || language === "javascript" || language === "tsx") && node.type === "call_expression") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (
          fnName.startsWith("async") ||
          fnName.includes("fetch") ||
          fnName.includes("axios") ||
          fnName.includes("Promise.") ||
          fnName.endsWith("Async")
        ) {
          const parent = node.parent;
          if (
            parent &&
            parent.type === "expression_statement" &&
            !text.startsWith("await ") &&
            !text.includes(".catch(") &&
            !text.includes(".then(")
          ) {
            matches.push({
              ruleId: "FLOATING_PROMISE",
              family: "reliability",
              severity: "medium",
              line: startLine,
              endLine,
              cwe: "CWE-703",
              why: "An asynchronous Promise call is neither awaited, returned, nor caught, causing unhandled promise rejections.",
              fix: "Await the promise, return it, or attach a .catch() handler.",
            });
          }
        }
      }
    }

    // 2. SWALLOWED_ERROR
    if ((language === "typescript" || language === "javascript" || language === "tsx") && node.type === "catch_clause") {
      const body = node.childForFieldName("body");
      if (body) {
        const bodyText = getNodeText(body, sourceCode).replace(/[{}]/g, "").trim();
        if (!bodyText || bodyText.length === 0 || bodyText === ";") {
          matches.push({
            ruleId: "SWALLOWED_ERROR",
            family: "reliability",
            severity: "high",
            line: startLine,
            endLine,
            cwe: "CWE-391",
            why: "Catching an exception without logging, handling, or rethrowing hides unexpected system failures.",
            fix: "Log the error, handle the failure condition explicitly, or rethrow.",
          });
        }
      }
    } else if (language === "python" && node.type === "except_clause") {
      const parent = node.parent;
      if (parent) {
        const blockText = getNodeText(parent, sourceCode);
        if (blockText.includes("pass") || blockText.includes("...")) {
          const lines = blockText.split("\n");
          if (lines.some((l) => l.trim() === "pass" || l.trim() === "...")) {
            matches.push({
              ruleId: "SWALLOWED_ERROR",
              family: "reliability",
              severity: "high",
              line: startLine,
              endLine,
              cwe: "CWE-391",
              why: "Catching an exception with 'except: pass' hides unexpected failures silently.",
              fix: "Log the error, handle the failure condition explicitly, or rethrow.",
            });
          }
        }
      }
    }

    // 3. BROAD_EXCEPT
    if (language === "python" && node.type === "except_clause") {
      const exceptText = getNodeText(node, sourceCode).trim();
      if (exceptText === "except:" || exceptText.startsWith("except Exception")) {
        const parent = node.parent;
        const blockText = parent ? getNodeText(parent, sourceCode) : "";
        if (!blockText.includes("raise") && !blockText.includes("logger.") && !blockText.includes("logging.")) {
          matches.push({
            ruleId: "BROAD_EXCEPT",
            family: "reliability",
            severity: "medium",
            line: startLine,
            endLine,
            cwe: "CWE-391",
            why: "Catching bare except or except Exception catches system signals and unrecoverable errors indiscriminately.",
            fix: "Catch specific exception classes or re-raise after logging.",
          });
        }
      }
    }

    // 4. MUTABLE_DEFAULT_ARG
    if (language === "python" && (node.type === "function_definition" || node.type === "parameters")) {
      if (node.type === "parameters") {
        for (let i = 0; i < node.namedChildCount; i++) {
          const param = node.namedChild(i)!;
          if (param.type === "default_parameter") {
            const valNode = param.childForFieldName("value");
            if (valNode) {
              const valText = getNodeText(valNode, sourceCode).trim();
              if (valText.startsWith("[") || valText.startsWith("{") || valText.startsWith("set(")) {
                matches.push({
                  ruleId: "MUTABLE_DEFAULT_ARG",
                  family: "reliability",
                  severity: "high",
                  line: startLine,
                  endLine,
                  cwe: "CWE-665",
                  why: "Using mutable default arguments (e.g., def f(x=[])) retains state across function calls.",
                  fix: "Use None as the default argument value and initialize the mutable object inside the function body.",
                });
              }
            }
          }
        }
      }
    }

    // 5. NO_NETWORK_TIMEOUT
    if (node.type === "call_expression" || node.type === "call") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (
          fnName === "fetch" ||
          fnName.startsWith("axios.") ||
          fnName.startsWith("requests.get") ||
          fnName.startsWith("requests.post")
        ) {
          const args = node.childForFieldName("arguments");
          const argsText = args ? getNodeText(args, sourceCode) : "";
          if (!argsText.includes("timeout") && !argsText.includes("signal")) {
            matches.push({
              ruleId: "NO_NETWORK_TIMEOUT",
              family: "reliability",
              severity: "medium",
              line: startLine,
              endLine,
              cwe: "CWE-400",
              why: "Network request initiated without explicit timeout configuration can hang indefinitely.",
              fix: "Pass a timeout option or set signal / AbortController timeout on HTTP client calls.",
              heuristic: true,
            });
          }
        }
      }
    }

    // 6. AWAIT_IN_LOOP
    if (
      node.type === "for_statement" ||
      node.type === "for_in_statement" ||
      node.type === "while_statement" ||
      node.type === "for_statement"
    ) {
      walkAst(node, (innerNode) => {
        if (innerNode.type === "await_expression" || (language === "python" && getNodeText(innerNode, sourceCode).startsWith("await "))) {
          matches.push({
            ruleId: "AWAIT_IN_LOOP",
            family: "reliability",
            severity: "low",
            line: innerNode.startPosition.row + 1,
            endLine: innerNode.endPosition.row + 1,
            cwe: "CWE-400",
            why: "Awaiting asynchronous operations inside a loop runs operations sequentially when parallel execution may be possible.",
            fix: "Use Promise.all() or asyncio.gather() if loop iterations have no ordering dependencies.",
          });
        }
      });
    }
  });

  return matches;
}
