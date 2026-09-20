import { expect, it } from "vitest";
import { SourceMatcher } from "../src/classifier/matcher.js";

it("matches overlaps, suffixes, Unicode and separate sources like exhaustive indexOf", () => {
  const patterns = ["he", "she", "hers", "his", "a", "aa", "aaa", "aba", "😀", "😀é", "é"];
  const sources = ["ushers his she aaaa ababa 😀é😀", "s", "he"];
  const matcher = new SourceMatcher(patterns, () => {});
  for (const source of sources) {
    const actual: string[] = [],
      expected: string[] = [];
    matcher.scan(source, (pattern, start) => actual.push(`${pattern}:${start}`));
    patterns.forEach((pattern, id) => {
      let at = source.indexOf(pattern);
      while (at >= 0) {
        expected.push(`${id}:${at}`);
        at = source.indexOf(pattern, at + 1);
      }
    });
    expect(actual.sort()).toEqual(expected.sort());
  }
});

it("bounds trie construction before retaining excessive pattern state", () => {
  let remaining = 1024;
  expect(
    () =>
      new SourceMatcher(["a".repeat(10000)], (n) => {
        remaining -= n + 1;
        if (remaining < 0) throw new Error("resolution-limit");
      }),
  ).toThrow("resolution-limit");
});
