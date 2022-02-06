import GsnHomePage from '@pages/home/home.vue';
import CustomPageApp from '@pages/custom-page-app/custom-page-app.vue';

const appRoutes = [
  {
    path: '/',
    name: 'Home',
    component: GsnHomePage
  },
  {
    path: '/custom-page-app/:appId',
    name: 'Custom Page App',
    component: CustomPageApp
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import(/* webpackChunkName: "login" */ '@pages/login/login.vue')
  },

  {
    path: '/sign-up',
    name: 'Sign Up',
    component: () => import(/* webpackChunkName: "sign-up" */ '@pages/sign-up/sign-up.vue')
  }
];

export default appRoutes;
