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

describe("SHELL_INTERPOLATION — a non-literal command is the whole point", () => {
  async function rules(path: string, content: string) {
    const parsed = await parseSource(path, content);
    if (!parsed.tree) throw new Error(`fixture did not parse: ${parsed.error}`);
    return checkInjectionRules(path, parsed.language, parsed.tree, content).map((m) => m.ruleId);
  }

  // The first implementation only looked for a template literal or a formatted
  // string, so a bare variable reaching a shell — the most common and most
  // dangerous shape there is — produced no finding at all.
  it("flags execSync called with a variable", async () => {
    expect(
      await rules("a.ts", 'import { execSync } from "child_process";\nexport const r = (cmd: string) => execSync(cmd);\n')
    ).toContain("SHELL_INTERPOLATION");
  });

  it("flags subprocess.run(cmd, shell=True) with a variable", async () => {
    expect(
      await rules("b.py", "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    ).toContain("SHELL_INTERPOLATION");
  });

  it("flags os.system with a variable", async () => {
    expect(await rules("c.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")).toContain(
      "SHELL_INTERPOLATION"
    );
  });

  it("flags an interpolated template literal", async () => {
    expect(
      await rules("d.ts", 'import { execSync } from "child_process";\nexport const r = (b: string) => execSync(`git checkout ${b}`);\n')
    ).toContain("SHELL_INTERPOLATION");
  });

  it("stays quiet on a fixed literal command", async () => {
    expect(
      await rules("e.ts", 'import { execSync } from "child_process";\nexport const v = () => execSync("git --version");\n')
    ).not.toContain("SHELL_INTERPOLATION");
    expect(
      await rules("f.ts", 'import { execSync } from "child_process";\nexport const v = () => execSync(`git --version`);\n')
    ).not.toContain("SHELL_INTERPOLATION");
    expect(
      await rules("g.py", 'import subprocess\n\ndef v():\n    return subprocess.run("git --version", shell=True)\n')
    ).not.toContain("SHELL_INTERPOLATION");
  });

  it("stays quiet when the word appears in a string", async () => {
    expect(
      await rules("h.ts", 'export const help = "run exec to evaluate a shell command";\n')
    ).not.toContain("SHELL_INTERPOLATION");
  });
});
