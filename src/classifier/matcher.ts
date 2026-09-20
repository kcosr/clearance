type Node = {
  edges: Map<number, number>;
  fail: number;
  output: number;
  pattern: number;
};

/** Aho-Corasick: one scan per source segment, including overlapping/suffix matches. */
export class SourceMatcher {
  private nodes: Node[] = [];

  constructor(
    private patterns: string[],
    private charge: (bytes: number) => void,
  ) {
    const node = () => {
      // Bound retained trie storage as well as work; output links avoid copied suffix lists.
      charge(255);
      this.nodes.push({ edges: new Map(), fail: 0, output: 0, pattern: -1 });
      return this.nodes.length - 1;
    };
    node();
    patterns.forEach((text, pattern) => {
      if (!text.length) throw new Error("invalid-finding");
      let at = 0;
      for (let i = 0; i < text.length; i++) {
        charge(0);
        const c = text.charCodeAt(i);
        let next = this.nodes[at]!.edges.get(c);
        if (next === undefined) {
          next = node();
          this.nodes[at]!.edges.set(c, next);
        }
        at = next;
      }
      this.nodes[at]!.pattern = pattern;
    });
    const queue = [...this.nodes[0]!.edges.values()];
    for (let head = 0; head < queue.length; head++) {
      const at = queue[head]!;
      for (const [c, next] of this.nodes[at]!.edges) {
        let fail = this.nodes[at]!.fail;
        while (fail && !this.nodes[fail]!.edges.has(c)) {
          charge(0);
          fail = this.nodes[fail]!.fail;
        }
        const fallback = this.nodes[fail]!.edges.get(c) ?? 0;
        this.nodes[next]!.fail = fallback;
        this.nodes[next]!.output =
          this.nodes[fallback]!.pattern >= 0 ? fallback : this.nodes[fallback]!.output;
        queue.push(next);
      }
    }
  }

  scan(text: string, match: (pattern: number, start: number) => void): void {
    this.charge(Buffer.byteLength(text));
    let at = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      while (at && !this.nodes[at]!.edges.has(c)) {
        this.charge(0);
        at = this.nodes[at]!.fail;
      }
      at = this.nodes[at]!.edges.get(c) ?? 0;
      for (let output = at; output; output = this.nodes[output]!.output) {
        const pattern = this.nodes[output]!.pattern;
        if (pattern < 0) continue;
        this.charge(0);
        match(pattern, i + 1 - this.patterns[pattern]!.length);
      }
    }
  }
}
