import { describe, it, expect } from "vitest";
import { parseSource, detectLanguage } from "../lib/warden/parse.js";

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
