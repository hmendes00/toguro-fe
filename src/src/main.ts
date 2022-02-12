/* eslint-disable @typescript-eslint/ban-ts-ignore */
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import * as vueUse from '@vueuse/core';
import * as vue3 from 'vue';

//@ts-ignore;
window.vueUse = vueUse;
//@ts-ignore;
window.vue3 = vue3;

const app = createApp(App);
app.use(router);
app.mount('#app');
