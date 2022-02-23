import { SET_LOGGED_IN } from '@/store/modules/self/actions';
import { selfStore } from '@/store';
import router from '@/router';

// when events are {any} here is for custom events
const loginUpdated = async (event: any) => {
  if (event.detail && event.detail.accessToken) {
    await selfStore.dispatch(SET_LOGGED_IN, {
      isLoggedIn: true,
      accessToken: event.detail.accessToken,
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
