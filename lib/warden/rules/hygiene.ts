import type Parser from "web-tree-sitter";
import type { SupportedLanguage } from "../parse.js";
import { walkAst, getNodeText, type RuleMatch } from "./common.js";

const CREDENTIAL_PATTERNS = [
  { name: "AWS Key", regex: /\b(AKIA[0-9A-Z]{16})\b/ },
  { name: "Stripe Key", regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/ },
  { name: "OpenAI Key", regex: /\b(sk-[a-zA-Z0-9]{32,})\b/ },
  { name: "GitHub Token", regex: /\b(ghp_[a-zA-Z0-9]{36})\b/ },
  { name: "EVM Private Key", regex: /\b(0x[a-fA-F0-9]{64})\b/ },
];

export function checkHygieneRules(
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

    // 1. WEAK_HASH_FOR_AUTH
    if (
      (node.type === "call_expression" || node.type === "call") &&
      (text.includes("createHash('md5')") ||
        text.includes('createHash("md5")') ||
        text.includes("createHash('sha1')") ||
        text.includes('createHash("sha1")') ||
        text.includes("hashlib.md5") ||
        text.includes("hashlib.sha1"))
    ) {
      if (
        sourceCode.includes("password") ||
        sourceCode.includes("auth") ||
        sourceCode.includes("token") ||
        sourceCode.includes("secret")
      ) {
        matches.push({
          ruleId: "WEAK_HASH_FOR_AUTH",
          family: "hygiene",
          severity: "high",
          line: startLine,
          endLine,
          cwe: "CWE-327",
          why: "Using MD5 or SHA1 in authentication, password, or security token contexts is cryptographically broken.",
          fix: "Use bcrypt, argon2, scrypt, or SHA-256/SHA-512 for cryptographic integrity.",
          heuristic: true,
        });
      }
    }

    // 2. INSECURE_RANDOM
    if (
      node.type === "call_expression" ||
      node.type === "call" ||
      node.type === "member_expression" ||
      node.type === "attribute"
    ) {
      if (text === "Math.random()" || text === "random.random()" || text === "random.randint") {
        const parentText = node.parent ? getNodeText(node.parent, sourceCode) : "";
        if (
          parentText.includes("token") ||
          parentText.includes("secret") ||
          parentText.includes("key") ||
          parentText.includes("nonce") ||
          parentText.includes("id")
        ) {
          matches.push({
            ruleId: "INSECURE_RANDOM",
            family: "hygiene",
            severity: "medium",
            line: startLine,
            endLine,
            cwe: "CWE-330",
            why: "Math.random() or random.random() is not cryptographically secure for generating keys, nonces, or tokens.",
            fix: "Use crypto.getRandomValues(), crypto.randomBytes(), or secrets module in Python.",
            heuristic: true,
          });
        }
      }
    }

    // 3. HARDCODED_CREDENTIAL_SHAPE
    if (node.type === "string" || node.type === "string_literal" || node.type === "literal") {
      const val = text.replace(/['"]/g, "").trim();
      for (const pattern of CREDENTIAL_PATTERNS) {
        if (pattern.regex.test(val)) {
          matches.push({
            ruleId: "HARDCODED_CREDENTIAL_SHAPE",
            family: "hygiene",
            severity: "high",
            line: startLine,
            endLine,
            cwe: "CWE-798",
            why: `Hardcoded credential shape detected (${pattern.name}).`,
            fix: "Store credentials in environment variables or a secret vault. For deep secret scanning, route content to EVIDIQ Redact.",
          });
          break;
        }
      }
    }

    // 4. PERMISSIVE_CORS
    if (
      (node.type === "pair" || node.type === "property_assignment" || node.type === "binary_expression") &&
      (text.includes("Access-Control-Allow-Origin") || text.includes("cors"))
    ) {
      if (text.includes("'*'") || text.includes('"*"')) {
        matches.push({
          ruleId: "PERMISSIVE_CORS",
          family: "hygiene",
          severity: "high",
          line: startLine,
          endLine,
          cwe: "CWE-942",
          why: "Configuring Access-Control-Allow-Origin: * alongside credentialed requests allows unauthorized cross-site data access.",
          fix: "Specify trusted origin domains explicitly instead of wildcard '*'.",
        });
      }
    }

    // 5. DEBUG_LEFTOVER
    if (node.type === "debugger_statement" || text.trim() === "debugger;") {
      matches.push({
        ruleId: "DEBUG_LEFTOVER",
        family: "hygiene",
        severity: "low",
        line: startLine,
        endLine,
        cwe: "CWE-489",
        why: "Debugger statement left in production code.",
        fix: "Remove debugger statement before committing.",
      });
    } else if (node.type === "call_expression" || node.type === "call") {
      const fnNode = node.childForFieldName("function") || node.child(0);
      if (fnNode) {
        const fnName = getNodeText(fnNode, sourceCode).trim();
        if (fnName === "console.log" || fnName === "print") {
          const args = node.childForFieldName("arguments");
          if (args) {
            const argsText = getNodeText(args, sourceCode);
            if (
              argsText.includes("secret") ||
              argsText.includes("password") ||
              argsText.includes("privateKey") ||
              argsText.includes("apiKey")
            ) {
              matches.push({
                ruleId: "DEBUG_LEFTOVER",
                family: "hygiene",
                severity: "low",
                line: startLine,
                endLine,
                cwe: "CWE-489",
                why: "Logging potential secret or key identifier in debug output.",
                fix: "Remove console.log / print of secret variables before committing.",
              });
            }
          }
        }
      }
    }
  });

  return matches;
}
