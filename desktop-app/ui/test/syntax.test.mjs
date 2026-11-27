// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// Every script the windows load parses as an ES module. One syntax error anywhere in the import
// graph leaves the window blank (release builds have no devtools), and most views are not
// imported by the other tests.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const UI = fileURLToPath(new URL("..", import.meta.url));

function scripts(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "test" ? [] : scripts(path);
    return name.endsWith(".js") ? [path] : [];
  });
}

test("every UI script parses as an ES module", () => {
  const files = scripts(UI);
  assert.ok(files.length > 10, `found only ${files.length} scripts under ${UI}`);
  const broken = files.flatMap((file) => {
    const run = spawnSync(process.execPath, ["--input-type=module", "--check"], {
      input: readFileSync(file),
      encoding: "utf8",
    });
    if (run.status === 0) return [];
    const reason = run.stderr.split("\n").find((line) => line.includes("Error")) || run.stderr.trim();
    return [`${file.slice(UI.length)}: ${reason.trim()}`];
  });
  assert.deepEqual(broken, []);
});
