import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  external: ['react', 'react-dom', '@alternatefutures/ac-auth', '@alternatefutures/ui', '@alternatefutures/tokens'],
  // One bundle drops the per-file directives; the App Router needs it at the top.
  banner: { js: '"use client";' },
})
