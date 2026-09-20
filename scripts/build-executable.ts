import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const packageJson = (await Bun.file(path.join(root, "package.json")).json()) as {
  version: string;
};
const readText = (relativePath: string): Promise<string> =>
  Bun.file(path.join(root, relativePath)).text();
const [nativeRules, gitleaksConfig, gitleaksIgnore] = await Promise.all([
  readText("examples/rules.d/default.toml"),
  readText("examples/gitleaks.toml"),
  readText("examples/gitleaks.ignore"),
]);
const outfile = path.join(
  root,
  "dist",
  process.platform === "win32" ? "clearance.exe" : "clearance",
);

const result = await Bun.build({
  entrypoints: [path.join(root, "src", "cli.ts")],
  root,
  minify: true,
  sourcemap: "linked",
  define: {
    CLEARANCE_BUILD_VERSION: JSON.stringify(packageJson.version),
    CLEARANCE_NATIVE_RULES_TEXT: JSON.stringify(nativeRules),
    CLEARANCE_GITLEAKS_CONFIG_TEXT: JSON.stringify(gitleaksConfig),
    CLEARANCE_GITLEAKS_IGNORE_TEXT: JSON.stringify(gitleaksIgnore),
  },
  compile: {
    outfile,
    execArgv: ["--use-system-ca"],
    // A scan root is untrusted and is commonly also the process working
    // directory. Never let its .env or bunfig.toml configure Clearance.
    autoloadDotenv: false,
    autoloadBunfig: false,
  },
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exitCode = 1;
} else {
  console.log(outfile);
}
