import { SET_LOGGED_IN } from '@/store/modules/self/actions';
import { selfStore } from '@/store';
import router from '@/router';

// when events are {any} here is for custom events
const loginUpdated = (event: any) => {
  if (event.detail && event.detail.accessToken) {
    selfStore.dispatch(SET_LOGGED_IN, {
      isLoggedIn: true,
      logoutFunction: event.detail.logoutFunction || function () {}
    });
    router.push(event.detail.redirectTo);
  }
};

export const registerGlobalListeners = () => {
  window.addEventListener('toguro-events:login-updated', loginUpdated);
};

export const removeGlobalListeners = () => {
  window.removeEventListener('toguro-events:login-updated', loginUpdated);
};
