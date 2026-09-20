import fs from "node:fs";
import { filenameGlobMatch, matchesGlob } from "../globs.js";
import { occurrenceId } from "../ids.js";
import type { Occurrence } from "../types.js";
import type { ClassifiedFile } from "../walk.js";
import type { NativeRule } from "./rules.js";

export function indexToLineCol(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  const end = Math.max(0, Math.min(index, text.length));
  for (let i = 0; i < end; i += 1) {
    if (text[i] === "\n") {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

export function runNativeRules(
  files: ClassifiedFile[],
  rules: NativeRule[],
  onFinding?: (occurrence: Occurrence) => void,
): Occurrence[] {
  const occurrences: Occurrence[] = [];
  const add = (occurrence: Occurrence): void => {
    occurrences.push(occurrence);
    onFinding?.(occurrence);
  };
  const globRules = rules.filter((rule) => rule.type === "glob");
  const regexRules = rules.filter((rule) => rule.type === "regex");

  for (const file of files) {
    for (const rule of globRules) {
      if (!filenameGlobMatch(file.relPosix, rule.pattern)) continue;
      add({
        occurrenceId: occurrenceId({
          scanner: "native",
          rootId: file.rootId,
          path: file.relPosix,
          lineStart: 1,
          lineEnd: 1,
          ruleId: rule.id,
          source: { kind: "workingTree" },
        }),
        scanner: "native",
        matchKind: "filename",
        rootId: file.rootId,
        path: file.relPosix,
        lineStart: 1,
        lineEnd: 1,
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        ...(rule.message === undefined ? {} : { message: rule.message }),
        source: { kind: "workingTree" },
        extraction: "inexact",
      });
    }
  }

  const scannable = files.filter((file) => file.kind === "scannable");
  for (const file of scannable) {
    let text: string | undefined;
    for (const rule of regexRules) {
      if (rule.pathGlob && !matchesGlob(file.relPosix, rule.pathGlob)) continue;
      if (text === undefined) text = fs.readFileSync(file.absPath, "utf8");
      const regex = new RegExp(rule.pattern, "g");
      for (const match of text.matchAll(regex)) {
        const index = match.index ?? 0;
        const raw = match[0] ?? "";
        const captured = match[1];
        const start = indexToLineCol(text, index);
        const end = indexToLineCol(text, index + raw.length);
        const candidate = captured && captured.length > 0 ? captured : raw;
        add({
          occurrenceId: occurrenceId({
            scanner: "native",
            rootId: file.rootId,
            path: file.relPosix,
            lineStart: start.line,
            lineEnd: end.line,
            columnStart: start.column,
            columnEnd: end.column,
            ruleId: rule.id,
            source: { kind: "workingTree" },
          }),
          scanner: "native",
          rootId: file.rootId,
          path: file.relPosix,
          lineStart: start.line,
          lineEnd: end.line,
          columnStart: start.column,
          columnEnd: end.column,
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          ...(rule.message === undefined ? {} : { message: rule.message }),
          source: { kind: "workingTree" },
          extraction: "exact",
          candidate,
        });
      }
    }
  }
  return occurrences;
}
