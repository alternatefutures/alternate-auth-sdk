// prepublishOnly guard for every package: the build output must already exist.
// It must NOT rebuild: `changeset publish` runs the packages' `npm publish`
// concurrently, and a rebuild here (tsup clean: true) wiped ac-auth/dist while
// ac-auth-next's declaration build was reading it (publish run 36628232697,
// 2026-09-29, TS7016 in core.ts). The publish workflow builds every package in
// dependency order before publishing; locally, run `npm run build` at the root.
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const cwd = process.cwd();
const required = ['dist/index.js', 'dist/index.d.ts'];
const missing = required.filter((rel) => !existsSync(resolve(cwd, rel)));
if (missing.length > 0) {
  console.error(`[check-dist] ${cwd}: missing ${missing.join(', ')}. Run "npm run build" at the workspace root first; prepublishOnly never rebuilds.`);
  process.exit(1);
}
