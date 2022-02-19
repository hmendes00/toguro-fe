import typescript from '@rollup/plugin-typescript';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';
import { defineConfig } from 'vite';
import inject from '@rollup/plugin-inject';
import builtins from 'rollup-plugin-polyfill-node';
import NodeModulesPolyfills from '@esbuild-plugins/node-modules-polyfill';

const resolvePath = (file: string) => resolve(__dirname, file);

export default defineConfig(({ mode }) => {
  return {
    server: {
      port: 8080,
      strictPort: true, // throw error if port in use
      fs: {
        strict: false
      }
    },
    define: {
      global: 'globalThis'
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
        allowSyntheticDefaultImports: true,
        sourceMap: mode !== 'production',
        inlineSources: mode !== 'production'
      }),
      insertBuiltinsPlugin,
      NodeModulesPolyfills
    ],
    build: {
      rollupOptions: {
        output: {
          sourcemap: mode !== 'production',
          rollupOptions: {
            plugins: [inject({ Buffer: ['buffer', 'Buffer'] })]
          }
        }
      }
    },
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

        // Models
        '@models': resolvePath('./src/models'),

        // Store
        '@store': resolvePath('./src/store')
      }
    }
  };
});

function insertBuiltinsPlugin() {
  return {
    name: 'my-project:insert-builtins-plugin',
    options(options) {
      const plugins = options.plugins;
      const idx = plugins.findIndex((plugin) => plugin.name === 'node-resolve');
      // @ts-ignore
      plugins.splice(idx, 0, { ...builtins({ crypto: true, buffer: true }), name: 'rollup-plugin-node-builtins' });
      return options;
    }
  };
}
