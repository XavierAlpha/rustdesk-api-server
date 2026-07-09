import { defineConfig } from 'vite';

export default defineConfig({
  base: '/js/dist/',
  build: {
    target: 'es2019',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: './src/main.ts',
      output: {
        entryFileNames: 'web_bridge.js',
        chunkFileNames: 'web_bridge.[hash].js',
        assetFileNames: 'web_bridge.[hash][extname]'
      }
    }
  }
});
