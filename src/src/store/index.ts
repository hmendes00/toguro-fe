import { createStore } from 'vuex';
import app from './modules/app';
import self from './modules/self';

export const appStore = createStore(app);

export const selfStore = createStore(self);
