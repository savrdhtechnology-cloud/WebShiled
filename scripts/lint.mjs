import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const roots = ["app", "components", "lib"];
const problems = [];
async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (/\.(ts|tsx)$/.test(entry.name)) {
      const text = await readFile(path, "utf8");
      if (/\bconsole\.(log|debug)\(/.test(text)) problems.push(`${path}: debug console statement`);
      if (/service[_-]?role/i.test(text)) problems.push(`${path}: possible privileged Supabase secret reference`);
      if (/(?:^|[^A-Za-z])sk_live_|sb_secret_/i.test(text)) problems.push(`${path}: possible committed secret`);
    }
  }
}
for (const root of roots) await walk(root);
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log("WebShield lint checks passed.");
