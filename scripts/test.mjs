import { readFile, access } from "node:fs/promises";

const required = [
  "app/page.tsx", "app/login/page.tsx", "app/app/[[...slug]]/page.tsx",
  "app/admin/[[...slug]]/page.tsx", "lib/security-engine/index.ts",
  "supabase/migrations/0001_webshield_v1.sql", ".env.example", "README.md"
];
for (const file of required) await access(file);
const env = await readFile(".env.example", "utf8");
if (/service_role|sb_secret_/i.test(env)) throw new Error("Privileged key must not be exposed in .env.example");
const pkg = JSON.parse(await readFile("package.json", "utf8"));
if (pkg.dependencies.next !== "16.3.4") throw new Error("Unexpected Next.js version");
console.log("WebShield foundation tests passed.");
