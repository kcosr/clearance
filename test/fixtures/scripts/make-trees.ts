import fs from "node:fs";
import path from "node:path";
import { git, initRepo, SLACK_LINE, writeTree, writeZip } from "../../helpers.js";

export function makeClean(root: string): void {
  writeTree(root, {
    "README.md": "ok\n",
    "src/ok.ts": "export const ok = 1;\n",
  });
}

export function makeCurrentSecret(root: string): void {
  writeTree(root, { "app.env": SLACK_LINE });
}

export function makeHistoryRemoved(root: string): void {
  initRepo(root);
  writeTree(root, { "app.env": SLACK_LINE });
  git(root, ["add", "app.env"]);
  git(root, ["commit", "-m", "introduce"], {
    GIT_AUTHOR_DATE: "2024-01-01T00:00:00 +0000",
    GIT_COMMITTER_DATE: "2024-01-01T00:00:00 +0000",
  });
  writeTree(root, { "app.env": `${SLACK_LINE}# n\n` });
  git(root, ["commit", "-am", "comment"], {
    GIT_AUTHOR_DATE: "2024-01-02T00:00:00 +0000",
    GIT_COMMITTER_DATE: "2024-01-02T00:00:00 +0000",
  });
  writeTree(root, { "other.env": `${SLACK_LINE}# n\n` });
  git(root, ["add", "other.env"]);
  git(root, ["commit", "-m", "copy"], {
    GIT_AUTHOR_DATE: "2024-01-03T00:00:00 +0000",
    GIT_COMMITTER_DATE: "2024-01-03T00:00:00 +0000",
  });
  fs.rmSync(path.join(root, "app.env"));
  fs.rmSync(path.join(root, "other.env"));
  git(root, ["add", "-A"]);
  git(root, ["commit", "-m", "delete"], {
    GIT_AUTHOR_DATE: "2024-01-04T00:00:00 +0000",
    GIT_COMMITTER_DATE: "2024-01-04T00:00:00 +0000",
  });
}

export function makeZipOnly(root: string): void {
  makeClean(root);
  writeZip(path.join(root, "secret.zip"), { "secret.txt": SLACK_LINE });
}
