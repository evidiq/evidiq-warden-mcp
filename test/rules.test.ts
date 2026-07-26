import { describe, it, expect } from "vitest";
import { parseSource } from "../lib/warden/parse.js";
import { checkInjectionRules } from "../lib/warden/rules/injection.js";
import { checkReliabilityRules } from "../lib/warden/rules/reliability.js";
import { checkHygieneRules } from "../lib/warden/rules/hygiene.js";

describe("Warden Rule Engine Tests (True Positives & Near-Miss Negatives)", () => {
  // 1. EVAL_DYNAMIC_CODE
  it("EVAL_DYNAMIC_CODE: true positive for eval(dynamicVar) & near-miss negative for eval of literal string or comment", async () => {
    const tpCode = `const cmd = "console.log(1)"; eval(cmd);`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkInjectionRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "EVAL_DYNAMIC_CODE")).toBe(true);

    const fpCode = `// eval(cmd) inside comment is safe\nconst evalResult = "eval";`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkInjectionRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "EVAL_DYNAMIC_CODE")).toBe(false);
  });

  // 2. SHELL_INTERPOLATION
  it("SHELL_INTERPOLATION: true positive for exec(`rm -rf ${userDir}`) & near-miss negative for execFile('ls', ['-la'])", async () => {
    const tpCode = `import { exec } from 'child_process'; const userDir = '/tmp'; exec(\`rm -rf \${userDir}\`);`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkInjectionRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "SHELL_INTERPOLATION")).toBe(true);

    const fpCode = `import { execFile } from 'child_process'; execFile('ls', ['-la']);`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkInjectionRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "SHELL_INTERPOLATION")).toBe(false);
  });

  // 3. SQL_STRING_BUILD
  it("SQL_STRING_BUILD: true positive for interpolated SQL & near-miss negative for parameterized query", async () => {
    const tpCode = `const query = \`SELECT * FROM users WHERE id = \${userId}\`;`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkInjectionRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "SQL_STRING_BUILD")).toBe(true);

    const fpCode = `const query = "SELECT * FROM users WHERE id = $1";`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkInjectionRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "SQL_STRING_BUILD")).toBe(false);
  });

  // 4. FLOATING_PROMISE
  it("FLOATING_PROMISE: true positive for un-awaited async call & near-miss negative for awaited promise", async () => {
    const tpCode = `async function fetchData() {} function run() { fetchData(); }`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkReliabilityRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "FLOATING_PROMISE")).toBe(true);

    const fpCode = `async function fetchData() {} async function run() { await fetchData(); }`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkReliabilityRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "FLOATING_PROMISE")).toBe(false);
  });

  // 5. SWALLOWED_ERROR
  it("SWALLOWED_ERROR: true positive for empty catch & near-miss negative for handled catch", async () => {
    const tpCode = `try { doWork(); } catch (err) {}`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkReliabilityRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "SWALLOWED_ERROR")).toBe(true);

    const fpCode = `try { doWork(); } catch (err) { console.error(err); }`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkReliabilityRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "SWALLOWED_ERROR")).toBe(false);
  });

  // 6. HARDCODED_CREDENTIAL_SHAPE
  it("HARDCODED_CREDENTIAL_SHAPE: true positive for AWS key literal & near-miss negative for env variable read", async () => {
    const tpCode = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const tpAst = await parseSource("test.ts", tpCode);
    const tpMatches = checkHygieneRules("test.ts", "typescript", tpAst.tree!, tpCode);
    expect(tpMatches.some((m) => m.ruleId === "HARDCODED_CREDENTIAL_SHAPE")).toBe(true);

    const fpCode = `const key = process.env.AWS_ACCESS_KEY_ID;`;
    const fpAst = await parseSource("test.ts", fpCode);
    const fpMatches = checkHygieneRules("test.ts", "typescript", fpAst.tree!, fpCode);
    expect(fpMatches.some((m) => m.ruleId === "HARDCODED_CREDENTIAL_SHAPE")).toBe(false);
  });
});
