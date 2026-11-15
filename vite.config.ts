import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    emptyOutDir: true,
    lib: {
      entry: {
        index: resolve(import.meta.dirname, 'src/index.ts'),
        next: resolve(import.meta.dirname, 'src/next.ts'),
      },
      formats: ['es', 'cjs'],
      fileName: (format, entryName) => `${entryName}.${format === 'es' ? 'js' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['react', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-dom', 'axios'],
      output: {
        banner: (chunk) => (chunk.isEntry && chunk.name === 'index' ? "'use client';\n" : ''),
      },
    },
  },
});
