#!/usr/bin/env node
// A fixed-rule processor example. No model, network, or Clearance imports.
const instructions =
  "Report every EXAMPLE_PRIVATE_ marker followed by one or more uppercase ASCII letters or digits.";
const category = {
  id: "confidential",
  reasons: ["private_marker"],
  inclusion: ["Literal EXAMPLE_PRIVATE_ markers."],
  exclusion: [],
  examples: ["EXAMPLE_PRIVATE_DEMO"],
};
const fail = (code) => {
  throw new Error(code);
};
const keys = (value, expected, optional = []) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    expected.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !expected.includes(key) && !optional.includes(key))
  )
    fail("invalid_request");
};
const progress = (completed) => {
  if (process.argv.includes("--progress"))
    process.stderr.write(
      JSON.stringify({
        version: 1,
        type: "progress",
        stage: "classifying",
        completed,
        total: 1,
      }) + "\n",
    );
};

let result;
try {
  if (process.argv.slice(2).some((arg) => arg !== "--progress")) fail("configuration_error");
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 64 * 1024 * 1024) fail("invalid_request");
    chunks.push(chunk);
  }
  // Clearance generates the JSON request. This teaching example uses Node's
  // JSON parser; it is not a reusable strict parser for arbitrary untrusted callers.
  const request = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
  );
  keys(request, ["version", "policy", "target"]);
  keys(request.target, ["kind", "path", "text"]);
  if (
    request.version !== 4 ||
    request.target.kind !== "file" ||
    typeof request.target.path !== "string" ||
    !request.target.path ||
    typeof request.target.text !== "string" ||
    !request.target.text ||
    Buffer.byteLength(request.target.text) > 8 * 1024 * 1024
  )
    fail("invalid_request");
  keys(request.policy, ["instructions", "categories"]);
  if (
    request.policy.instructions !== instructions ||
    !Array.isArray(request.policy.categories) ||
    request.policy.categories.length !== 1
  )
    fail("configuration_error");
  const supplied = request.policy.categories[0];
  keys(supplied, Object.keys(category), ["description"]);
  // Descriptions are optional display metadata for this fixed-rule processor.
  if (
    supplied.description !== undefined &&
    (typeof supplied.description !== "string" ||
      !supplied.description ||
      Buffer.byteLength(supplied.description) > 512 ||
      /[\p{Cc}\uD800-\uDFFF]/u.test(supplied.description))
  )
    fail("invalid_request");
  if (
    Object.entries(category).some(
      ([key, value]) => JSON.stringify(supplied[key]) !== JSON.stringify(value),
    )
  )
    fail("configuration_error");
  progress(0);
  const unique = new Set();
  for (const match of request.target.text.matchAll(/EXAMPLE_PRIVATE_[A-Z0-9]+/g)) {
    if (Buffer.byteLength(match[0]) > 65536) fail("output_limit");
    unique.add(match[0]);
    if (unique.size > 4096) fail("output_limit");
  }
  result = {
    version: 2,
    status: "complete",
    findings: [...unique].map((text) => ({
      text,
      category: category.id,
      reason: category.reasons[0],
    })),
  };
  if (Buffer.byteLength(JSON.stringify(result)) > 1048576) fail("output_limit");
  progress(1);
} catch (error) {
  const code = ["invalid_request", "configuration_error", "output_limit"].includes(error.message)
    ? error.message
    : "invalid_request";
  result = { version: 2, status: "error", code };
  process.exitCode = 1;
}
// Let Node flush stdout naturally; an immediate process.exit() can truncate it.
process.stdout.write(JSON.stringify(result) + "\n");
