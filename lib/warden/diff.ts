export type DiffFile = {
  oldPath: string;
  newPath: string;
  changedLines: Set<number>;
  postImageContent?: string;
};

export function parseUnifiedDiff(diffText: string): Map<string, DiffFile> {
  const result = new Map<string, DiffFile>();
  const lines = diffText.split("\n");

  let currentFile: DiffFile | null = null;
  let currentNewLineNum = 0;
  let postImageLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (typeof line !== "string") continue;

    if (line.startsWith("--- ")) {
      if (currentFile && currentFile.newPath) {
        currentFile.postImageContent = postImageLines.join("\n");
        result.set(currentFile.newPath, currentFile);
      }
      const oldPath = line.replace(/^---\s+([ab]\/)?/, "").trim();
      currentFile = {
        oldPath,
        newPath: "",
        changedLines: new Set<number>(),
      };
      postImageLines = [];
    } else if (line.startsWith("+++ ") && currentFile) {
      const newPath = line.replace(/^\+\+\+\s+([ab]\/)?/, "").trim();
      currentFile.newPath = newPath;
    } else if (line.startsWith("@@ ") && currentFile) {
      const match = line.match(/@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
      if (match && match[1]) {
        currentNewLineNum = parseInt(match[1], 10);
      }
    } else if (currentFile) {
      if (line.startsWith("+") && !line.startsWith("+++")) {
        currentFile.changedLines.add(currentNewLineNum);
        postImageLines.push(line.slice(1));
        currentNewLineNum++;
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        // deleted line
      } else {
        // context line
        postImageLines.push(line.startsWith(" ") ? line.slice(1) : line);
        currentNewLineNum++;
      }
    }
  }

  if (currentFile && currentFile.newPath) {
    currentFile.postImageContent = postImageLines.join("\n");
    result.set(currentFile.newPath, currentFile);
  }

  return result;
}

export function isLineInDiffChanged(
  changedLines: Set<number>,
  startLine: number,
  endLine: number
): boolean {
  for (let l = startLine; l <= endLine; l++) {
    if (changedLines.has(l)) return true;
  }
  return false;
}
