import Parser from "web-tree-sitter";
import { resolve, join } from "node:path";
import { existsSync } from "node:fs";

export type SupportedLanguage = "typescript" | "tsx" | "javascript" | "python";

let isInitialized = false;
const languageMap = new Map<SupportedLanguage, Parser.Language>();

function getGrammarDir(): string {
  const custom = process.env.WARDEN_GRAMMAR_DIR?.trim();
  if (custom && existsSync(custom)) return custom;
  const inProject = resolve(process.cwd(), "data/grammars");
  if (existsSync(inProject)) return inProject;
  const distParent = resolve(process.cwd(), "../data/grammars");
  if (existsSync(distParent)) return distParent;
  return inProject;
}

export async function initWardenParser(): Promise<void> {
  if (isInitialized) return;

  const grammarDir = getGrammarDir();
  const wasmPath = join(grammarDir, "tree-sitter.wasm");

  await Parser.init({
    locateFile(scriptName: string, scriptDirectory: string) {
      if (scriptName === "tree-sitter.wasm") return wasmPath;
      return scriptDirectory + scriptName;
    },
  });

  const langs: Array<{ name: SupportedLanguage; file: string }> = [
    { name: "typescript", file: "tree-sitter-typescript.wasm" },
    { name: "tsx", file: "tree-sitter-tsx.wasm" },
    { name: "javascript", file: "tree-sitter-javascript.wasm" },
    { name: "python", file: "tree-sitter-python.wasm" },
  ];

  for (const item of langs) {
    const langWasm = join(grammarDir, item.file);
    if (existsSync(langWasm)) {
      const lang = await Parser.Language.load(langWasm);
      languageMap.set(item.name, lang);
    }
  }

  isInitialized = true;
}

export function detectLanguage(filename: string): SupportedLanguage | "unsupported" {
  const ext = filename.toLowerCase().split(".").pop() ?? "";
  switch (ext) {
    case "ts":
    case "mts":
    case "cts":
      return "typescript";
    case "tsx":
    case "jsx":
      return "tsx";
    case "js":
    case "mjs":
    case "cjs":
      return "javascript";
    case "py":
    case "pyi":
      return "python";
    default:
      return "unsupported";
  }
}

export type ParseOutput = {
  language: SupportedLanguage | "unsupported";
  parsed: boolean;
  tree?: Parser.Tree;
  error?: string;
};

export async function parseSource(filename: string, content: string): Promise<ParseOutput> {
  const lang = detectLanguage(filename);
  if (lang === "unsupported") {
    return { language: "unsupported", parsed: false, error: `Unsupported file extension for ${filename}` };
  }

  await initWardenParser();
  const language = languageMap.get(lang);
  if (!language) {
    return { language: lang, parsed: false, error: `Grammar WASM not loaded for language: ${lang}` };
  }

  try {
    const parser = new Parser();
    parser.setLanguage(language);
    const tree = parser.parse(content);
    return { language: lang, parsed: true, tree };
  } catch (err: any) {
    return { language: lang, parsed: false, error: err?.message || String(err) };
  }
}
