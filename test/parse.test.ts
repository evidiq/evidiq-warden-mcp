import { describe, it, expect } from "vitest";
import { parseSource, detectLanguage } from "../lib/warden/parse.js";
import { analyzeFiles } from "../lib/warden/engine.js";

describe("Warden Parser (tree-sitter)", () => {
  it("detects languages accurately from filename extensions", () => {
    expect(detectLanguage("main.ts")).toBe("typescript");
    expect(detectLanguage("Component.tsx")).toBe("tsx");
    expect(detectLanguage("app.js")).toBe("javascript");
    expect(detectLanguage("script.py")).toBe("python");
    expect(detectLanguage("document.md")).toBe("unsupported");
    expect(detectLanguage("config.json")).toBe("unsupported");
  });

  it("parses TypeScript source code into a valid AST", async () => {
    const code = `const x: number = 42; function add(a: number, b: number): number { return a + b; }`;
    const res = await parseSource("index.ts", code);
    expect(res.language).toBe("typescript");
    expect(res.parsed).toBe(true);
    expect(res.tree).toBeDefined();
    expect(res.tree?.rootNode.type).toBe("program");
  });

  it("parses TSX / JSX source code into a valid AST", async () => {
    const code = `export const Button = ({ label }: { label: string }) => <button>{label}</button>;`;
    const res = await parseSource("Button.tsx", code);
    expect(res.language).toBe("tsx");
    expect(res.parsed).toBe(true);
    expect(res.tree).toBeDefined();
  });

  it("parses JavaScript source code into a valid AST", async () => {
    const code = `function hello(name) { console.log('Hello ' + name); }`;
    const res = await parseSource("hello.js", code);
    expect(res.language).toBe("javascript");
    expect(res.parsed).toBe(true);
    expect(res.tree).toBeDefined();
  });

  it("parses Python source code into a valid AST", async () => {
    const code = `def greet(name: str) -> str:\n    return f"Hello {name}"\n`;
    const res = await parseSource("greet.py", code);
    expect(res.language).toBe("python");
    expect(res.parsed).toBe(true);
    expect(res.tree).toBeDefined();
    expect(res.tree?.rootNode.type).toBe("module");
  });

  it("returns unsupported for non-supported file formats without throwing", async () => {
    const res = await parseSource("file.rs", 'fn main() { println!("Hello"); }');
    expect(res.language).toBe("unsupported");
    expect(res.parsed).toBe(false);
    expect(res.tree).toBeUndefined();
  });
});

describe("nothing unreviewed is ever reported as clean", () => {
  it("treats syntactically broken source as a parse failure, not a clean parse", async () => {
    // tree-sitter is error-tolerant and returns a tree with ERROR nodes, so a
    // truthy tree used to be accepted as a successful parse and the file was
    // reviewed against a partial tree — then reported clean.
    const parsed = await parseSource("broken.ts", "export function ( { { broken\n");
    expect(parsed.parsed).toBe(false);
    expect(parsed.error).toBeTruthy();
  });

  it("still parses valid source in every supported language", async () => {
    for (const [path, content] of [
      ["a.ts", "export const x: number = 1;\n"],
      ["b.tsx", "export const C = () => <div>hi</div>;\n"],
      ["c.js", "export const y = 2;\n"],
      ["d.py", "def f():\n    return 1\n"],
    ] as const) {
      const parsed = await parseSource(path, content);
      expect(parsed.parsed, `${path}: ${parsed.error ?? ""}`).toBe(true);
    }
  });

  it("does not return PASS when a file could not be reviewed", async () => {
    const unsupported = await analyzeFiles([{ path: "main.go", content: "package main\nfunc main() {}\n" }]);
    expect(unsupported.verdict).not.toBe("PASS");
    expect(unsupported.filesEvaluated).toBe(0);
    expect(unsupported.filesSkipped).toBe(1);

    const broken = await analyzeFiles([{ path: "broken.ts", content: "export function ( { {\n" }]);
    expect(broken.verdict).not.toBe("PASS");
    expect(broken.parseFailures.length).toBe(1);
  });

  it("still returns PASS for clean, fully reviewed source", async () => {
    const clean = await analyzeFiles([
      { path: "ok.ts", content: "export function add(a: number, b: number): number {\n  return a + b;\n}\n" },
    ]);
    expect(clean.verdict).toBe("PASS");
    expect(clean.filesEvaluated).toBe(1);
    expect(clean.filesSkipped).toBe(0);
  });
});
