import { RouteRecordRaw } from 'vue-router';
import { selfStore } from './../store/index';
import { getClient, getUserId } from './../helpers/matrix';
import TfeHomePage from '@pages/home/home.vue';
import CustomPageApp from '@pages/custom-page-app/custom-page-app.vue';

const appRoutes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: TfeHomePage
  },
  {
    path: '/custom-page-app/:appId',
    name: 'custom-page-app',
    component: CustomPageApp
  },
  {
    path: '/login',
    name: 'login',
    component: () => import(/* webpackChunkName: "login" */ '@pages/login/login.vue')
  },

  {
    path: '/profile/:userId?',
    name: 'profile',
    component: () => import(/* webpackChunkName: "profile" */ '@pages/profile/profile.vue')
  }
];

export default appRoutes;
