import { describe, it, expect } from "vitest";
import { parseUnifiedDiff, isLineInDiffChanged } from "../lib/warden/diff.js";

describe("Warden Diff Parser", () => {
  it("parses changed lines from a unified diff format", () => {
    const diff = `--- a/src/index.ts
+++ b/src/index.ts
@@ -1,5 +1,6 @@
 import { foo } from "./foo";
-const a = 1;
+const a = 2;
+eval(input);
 function bar() {}`;

    const res = parseUnifiedDiff(diff);
    expect(res.has("src/index.ts")).toBe(true);

    const fileDiff = res.get("src/index.ts")!;
    expect(fileDiff.changedLines.has(2)).toBe(true);
    expect(fileDiff.changedLines.has(3)).toBe(true);
    expect(fileDiff.changedLines.has(1)).toBe(false);

    expect(isLineInDiffChanged(fileDiff.changedLines, 3, 3)).toBe(true);
    expect(isLineInDiffChanged(fileDiff.changedLines, 1, 1)).toBe(false);
  });
});
