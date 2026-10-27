// Cross-platform test runner — a trimmed copy of apps/api/run-tests.mjs.
// We walk src/ for *.test.ts ourselves (shell globs don't expand on Windows)
// and hand the list to `node --test` with tsx loaded.

import { readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function findTests(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...findTests(full));
    else if (entry.endsWith(".test.ts")) out.push(full);
  }
  return out;
}

const tests = findTests(join(here, "src"));
if (tests.length === 0) {
  console.error("No test files found under src/");
  process.exit(1);
}

const tsxLoader = pathToFileURL(require.resolve("tsx/esm")).href;
const result = spawnSync(process.execPath, ["--test", ...tests], {
  stdio: "inherit",
  env: {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --import ${tsxLoader}`.trim(),
  },
});
process.exit(result.status ?? 1);
