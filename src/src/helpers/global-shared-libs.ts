import * as vueUse from '@vueuse/core';
import * as vue3 from 'vue';

//@ts-ignore;
window.vueUse = vueUse;
//@ts-ignore;
window.vue3 = vue3;

/**
 * If you are using login-mx-app (or you want to use matrix-js-sdk) in this project,
 * make sure you have the imports bellow uncommented
 */

import * as Buffer from 'buffer';
// @ts-ignore
window.global = window.global || globalThis;
// @ts-ignore
global = window;
// @ts-ignore
window.Buffer = window.Buffer || Buffer.Buffer;
import * as MxJsSdk from 'matrix-js-sdk';
//@ts-ignore;
window.mxJsSdk = MxJsSdk;
