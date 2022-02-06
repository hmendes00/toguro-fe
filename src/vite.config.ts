import typescript from '@rollup/plugin-typescript';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';
import { defineConfig } from 'vite';

const resolvePath = (file: string) => resolve(__dirname, file);

export default defineConfig({
  server: {
    port: 8080,
    strictPort: true, // throw error if port in use
    fs: {
      strict: false
    }
  },
  plugins: [
    vue({
      script: {
        refSugar: true
      },
      template: {
        compilerOptions: {
          // treat any tag that starts with ion- as custom elements
          isCustomElement: (tag) => tag.startsWith('toguro-') //stands for toguro custom app
        }
      }
    }),
    typescript({
      target: 'es2020',
      rootDir: resolvePath('.'),
      declaration: true,
      declarationDir: resolvePath('dist'),
      exclude: resolvePath('node_modules/**'),
      allowSyntheticDefaultImports: true
    })
  ],
  resolve: {
    dedupe: ['vue'],
    alias: {
      '@': resolvePath('./src'),
      '@assets': resolvePath('./src/assets'),
      '@styles': resolvePath('./src/assets/styles'),

      // Views
      '@components': resolvePath('./src/views/components'),
      '@containers': resolvePath('./src/views/containers'),
      '@pages': resolvePath('./src/views/pages'),
      '@layouts': resolvePath('./src/views/layouts'),

      // Services
      '@services': resolvePath('./src/services'),

      // Helpers
      '@helpers': resolvePath('./src/helpers'),

      // Helpers
      '@models': resolvePath('./src/models'),

      // Store
      '@store': resolvePath('./src/store')
    }
  }
});
