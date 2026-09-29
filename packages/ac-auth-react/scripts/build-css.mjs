#!/usr/bin/env node
/**
 * Compile dist/styles.css with Tailwind v4 from the component sources (the
 * shadcn primitives are copied from the web app into src/ui, so one scan of
 * src covers everything).
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = resolve(here, '..');
const require = createRequire(import.meta.url);
const entry = resolve(pkg, 'src/styles/index.css');
const tmpDir = resolve(pkg, '.tmp-css');
mkdirSync(tmpDir, { recursive: true });
const tmpEntry = resolve(tmpDir, 'entry.css');
writeFileSync(tmpEntry, `@import "${entry}";\n@source "${resolve(pkg, 'src')}";\n`);
mkdirSync(resolve(pkg, 'dist'), { recursive: true });
const cliPkg = require.resolve('@tailwindcss/cli/package.json');
const cli = resolve(dirname(cliPkg), JSON.parse(readFileSync(cliPkg, 'utf8')).bin.tailwindcss);
execFileSync(process.execPath, [cli, '-i', tmpEntry, '-o', resolve(pkg, 'dist/styles.css'), '--minify'], { stdio: 'inherit', cwd: pkg });
rmSync(tmpDir, { recursive: true, force: true });
console.log('wrote dist/styles.css');
