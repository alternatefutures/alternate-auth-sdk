import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: ['src/index.ts', 'src/proxy.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: false,
    sourcemap: true,
    target: 'es2022',
    platform: 'neutral',
    external: ['next', 'next/headers', 'next/server', 'react', 'react-dom', 'jose', '@alternatefutures/ac-auth', '@alternatefutures/ac-auth-react'],
  },
  {
    entry: ['src/react.tsx'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    target: 'es2022',
    external: ['react', 'react-dom', '@alternatefutures/ac-auth', '@alternatefutures/ac-auth-react'],
    banner: { js: '"use client";' },
  },
])
