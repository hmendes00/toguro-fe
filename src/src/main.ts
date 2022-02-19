/* eslint-disable @typescript-eslint/ban-ts-ignore */
import '@/helpers/global-shared-libs';
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';

const app = createApp(App);
app.use(router);
app.mount('#app');
