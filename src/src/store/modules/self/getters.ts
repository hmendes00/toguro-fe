import { SelfState } from './state';
import { GetterTree } from 'vuex';

const getters: GetterTree<SelfState, {}> = {
  isLoggedIn(state: SelfState): boolean {
    return state.isLoggedIn;
  },
  email(state: SelfState): string {
    return state.email;
  },
  username(state: SelfState): string {
    return state.username;
  },
  appLogoutFunction(state: SelfState): Function {
    return state.appLogoutFunction!;
  }
};

export default getters;
